#!/usr/bin/env python3
# att-tunnel-hub 面板机（机器1）：只用 Python 标准库，无外部依赖、无 CDN。
#
# 角色：
#   机器1 面板机  = 本程序。不过流量，只管理转发机。
#   机器2/3 转发机 = att-tunnel A 端 + att-hub-agent（主动回连本面板，转发机无需开端口）。
#   落地机（若干）  = att-tunnel B 端，主动外拨连转发机，自己零入站；与节点 1:1。
#
# 通信：agent 全程主动外拨 long-poll 本面板，面板从不去连转发机，
#       也不保存转发机的 SSH 密码。面板发给 agent 的只有「转发到本机 att-tunnel 面板的 HTTP 请求」，
#       没有任意命令通道。
#
# 安全：随机端口 + 随机路径 + 密码；Cookie HttpOnly/SameSite=Strict；POST 需会话 + CSRF；
#       登录失败限速；每台转发机一个独立 token，token 只在生成一键代码时显示。
import hmac
import http.cookies
import http.server
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse

VERSION = 'HUB_VERSION'
ENVF = os.environ.get('HUB_ENV', '/etc/att-hub/hub.env')
STATEF = os.environ.get('HUB_STATE', '/var/lib/att-hub/state.json')
SESSION_TTL = 12 * 3600
POLL_WAIT = 25.0          # agent long-poll 挂起上限
REQ_TIMEOUT = 360.0       # 普通代理请求上限；升级使用独立后台任务
UPGRADE_TIMEOUT = 420.0   # 下载60s + 安装330s，仅后台等待
UPGRADE_OK_TTL = 300      # 成功后「✓ 更新成功」保留 5 分钟；之后按钮恢复为「更新」
OFFLINE_AFTER = 45        # 超过这么多秒没 poll 视为离线
NAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
SUB_RE = re.compile(r'^[A-Za-z0-9_-]{20,64}$')     # att-tunnel 面板的订阅 token
IP_RE = re.compile(r'^[A-Za-z0-9.:_-]{3,253}$')


def log(*a):
    print(time.strftime('%F %T'), *a, file=sys.stderr, flush=True)


def now():
    return int(time.time())


def load_env(path):
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return env


ENV = load_env(ENVF)
PORT = int(ENV['WEB_PORT'])
PREFIX = '/' + ENV['WEB_PATH'].strip('/')
PASS = ENV['WEB_PASS']
LISTEN = ENV.get('WEB_LISTEN', '127.0.0.1')
RAW_URL = ENV.get('HUB_RAW_URL', '')
HUB_URL = ENV.get('HUB_URL', '').rstrip('/')
COOKIE_SECURE = ENV.get('WEB_COOKIE_SECURE', '0') == '1'
TRUST_PROXY = ENV.get('WEB_TRUST_PROXY', '0') == '1'
if len(PASS) < 8 or PREFIX == '/':
    sys.exit('hub.env 不完整：WEB_PASS 至少 8 位，WEB_PATH 不能为空')

lock = threading.RLock()
save_lock = threading.Lock()
state = {'forwarders': {}, 'started': 0}
sessions = {}
fails = {}


# ---------------------------------------------------------------- 状态持久化
def load_state():
    global state
    try:
        with open(STATEF) as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get('forwarders'), dict):
            state = d
            state.setdefault('started', 0)
    except (OSError, ValueError):
        pass


def save_state():
    with save_lock:
        os.makedirs(os.path.dirname(STATEF), exist_ok=True)
        tmp = '%s.tmp.%d' % (STATEF, threading.get_ident())
        with lock:
            data = json.dumps(state, ensure_ascii=False)
        with open(tmp, 'w') as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATEF)


def safe_save():
    try:
        save_state()
    except OSError as e:
        log('保存状态失败:', e)

# ---------------------------------------------------------------- 转发机记录
def fwd_all():
    with lock:
        return dict(state['forwarders'])


def fwd_get(name):
    with lock:
        return state['forwarders'].get(name)


def fwd_by_token(token):
    if not token:
        return None, None
    with lock:
        for name, rec in state['forwarders'].items():
            if hmac.compare_digest(rec['token'], token):
                return name, rec
    return None, None


def fwd_online(rec):
    return now() - int(rec.get('last_seen') or 0) <= OFFLINE_AFTER


def fwd_add(name, ip, note):
    rec = {
        'name': name,
        'ip': ip,
        'note': note,
        'token': secrets.token_urlsafe(24),
        'added': now(),
        'last_seen': 0,
        'agent': {},
    }
    with lock:
        state['forwarders'][name] = rec
    safe_save()
    return rec


def fwd_del(name):
    with lock:
        rec = state['forwarders'].pop(name, None)
    if rec:
        bus.drop(name)
        safe_save()
    return rec

def fwd_edit(old, new_name, ip, note):
    """改名称 / IP / 备注。

    token 不动，所以改名不用重装 agent：agent 是拿 token 鉴权的，不认名字。
    但转发机在 state 和 Bus 待办队列里都是按名字做键的，所以要一并迁。
    """
    with lock:
        rec = state['forwarders'].get(old)
        if not rec:
            return None, '转发机 %s 不存在' % old
        renamed = new_name != old
        if renamed and new_name in state['forwarders']:
            return None, '名称 %s 已被占用' % new_name
        rec['ip'] = ip
        rec['note'] = note
        if renamed:
            rec['name'] = new_name
            # 按顺序重建，保持卡片次序稳定
            items = [(new_name, rec) if k == old else (k, v)
                     for k, v in state['forwarders'].items()]
            state['forwarders'] = dict(items)
    if renamed:
        # 旧名下还没回包的代理请求已经指不到人了，放掉让前端重试新路径
        bus.drop(old)
    safe_save()
    return rec, None


# ---------------------------------------------------------------- 请求中转总线
# 面板 -> agent 的唯一通道：agent long-poll 取走一个待办 HTTP 请求，
# 在本机打给 att-tunnel 面板，再 POST 回响应。没有任意命令执行通道。
class Bus:
    def __init__(self):
        self.cv = threading.Condition()
        self.pending = {}      # fwd -> [job]
        self.jobs = {}         # job_id -> job

    def submit(self, fwd, req):
        job = {'id': secrets.token_urlsafe(12), 'req': req, 'resp': None, 'fwd': fwd}
        with self.cv:
            self.jobs[job['id']] = job
            self.pending.setdefault(fwd, []).append(job)
            self.cv.notify_all()
        return job

    def take(self, fwd, timeout):
        """agent 端：等一个待办请求，没有就挂到超时返回 None。"""
        end = time.monotonic() + timeout
        with self.cv:
            while True:
                q = self.pending.get(fwd) or []
                if q:
                    return q.pop(0)
                left = end - time.monotonic()
                if left <= 0:
                    return None
                self.cv.wait(left)

    def answer(self, job_id, resp):
        with self.cv:
            job = self.jobs.get(job_id)
            if not job:
                return False
            job['resp'] = resp
            self.cv.notify_all()
        return True

    def wait(self, job, timeout):
        end = time.monotonic() + timeout
        with self.cv:
            while job['resp'] is None:
                left = end - time.monotonic()
                if left <= 0:
                    break
                self.cv.wait(left)
            self.jobs.pop(job['id'], None)
            q = self.pending.get(job['fwd'])
            if q and job in q:
                q.remove(job)
            return job['resp']

    def drop(self, fwd):
        with self.cv:
            for job in self.pending.pop(fwd, []):
                job['resp'] = {'status': 410, 'body': '', 'ctype': 'text/plain'}
            self.cv.notify_all()


bus = Bus()


def finish_upgrade(rec, jid, resp):
    with lock:
        u = rec.get('upgrade') or {}
        if u.get('id') != jid or u.get('state') != 'running':
            return
        if resp is None:
            result, message = 'unknown', '未收到完成回执，请核对转发机日志；不要连续重复更新'
        elif resp.get('status') == 200:
            result, message = 'ok', '更新成功（安装脚本已正常完成）'
        else:
            result, message = 'error', '更新失败，请检查转发机 agent 日志'
        # 不保存安装输出，避免凭据进入面板状态。
        rec['upgrade'] = dict(u, state=result, message=message, finished=now())
    safe_save()


def wait_upgrade(rec, job):
    finish_upgrade(rec, job['id'], bus.wait(job, UPGRADE_TIMEOUT))


def recover_upgrades():
    # 重启丢失内存总线；在线/版本相同不等于更新成功。
    for rec in fwd_all().values():
        u = rec.get('upgrade') or {}
        if u.get('state') == 'running':
            finish_upgrade(rec, u['id'], None)

# ---------------------------------------------------------------- 会话 / 限速
def new_session():
    sid = secrets.token_urlsafe(32)
    with lock:
        sessions[sid] = {'exp': now() + SESSION_TTL, 'csrf': secrets.token_urlsafe(24)}
        for k, v in list(sessions.items()):
            if v['exp'] < now():
                sessions.pop(k, None)
    return sid


def rate_limited(ip):
    with lock:
        t, n = fails.get(ip, (0, 0))
        return n >= 8 and now() - t < 600


def note_fail(ip):
    with lock:
        t, n = fails.get(ip, (0, 0))
        if now() - t > 600:
            n = 0
        fails[ip] = (now(), n + 1)


def status_json():
    out = []
    for name, rec in sorted(fwd_all().items()):
        out.append({
            'name': name,
            'ip': rec['ip'],
            'note': rec.get('note', ''),
            'online': fwd_online(rec),
            'last_seen': rec.get('last_seen') or 0,
            'added': rec.get('added') or 0,
            'agent': rec.get('agent') or {},
            'paneled': bool((rec.get('agent') or {}).get('web')),
            'upgrade': visible_upgrade(rec.get('upgrade')),
        })
    return {
        'version': VERSION,
        'started': state.get('started') or 0,
        'now': now(),
        'hub_url': HUB_URL,
        'forwarders': out,
    }


def visible_upgrade(u):
    """成功结果只展示一段时间，避免按钮永远停在「更新成功」。

    失败/未确认保留到下一次更新，因为它们需要用户注意或重试；
    只有 ok 在 UPGRADE_OK_TTL 后从面板状态里隐去（记录本身留在 state 里）。
    """
    if not u:
        return {}
    if u.get('state') == 'ok':
        fin = u.get('finished') or u.get('started') or 0
        if not fin or now() - fin > UPGRADE_OK_TTL:
            return {}
    return dict(u)

# ---------------------------------------------------------------- 落地节点汇总
def collect_nodes(timeout=40.0):
    """并发向所有在线转发机拉它们 att-tunnel 面板的 /api/status，汇总落地节点。

    先把所有请求一起投进总线，再统一等：多台转发机是并行的，
    用绝对截止时间而不是每台各等 timeout，否则 N 台最坏要等 N*timeout。
    """
    jobs = []
    metas = []
    for name, rec in sorted(fwd_all().items()):
        meta = {'name': name, 'ip': rec.get('ip', ''), 'note': rec.get('note', ''),
                'online': fwd_online(rec), 'count': 0, 'error': ''}
        if not meta['online']:
            meta['error'] = '转发机不在线'
        elif not (rec.get('agent') or {}).get('web'):
            meta['error'] = '转发机面板未就绪'
        else:
            jobs.append((meta, bus.submit(name, {'method': 'GET', 'path': '/api/status',
                                                 'body': '', 'ctype': ''})))
        metas.append(meta)

    nodes = []
    end = time.monotonic() + timeout
    for meta, job in jobs:
        left = max(1.0, end - time.monotonic())
        resp = bus.wait(job, left)
        if resp is None:
            meta['error'] = '没有在超时前应答'
            continue
        if (resp.get('status') or 0) != 200:
            meta['error'] = '转发机面板返回 HTTP %s' % resp.get('status')
            continue
        try:
            d = json.loads(resp.get('body') or '{}')
        except ValueError:
            meta['error'] = '转发机面板返回的不是 JSON'
            continue
        if d.get('error'):
            meta['error'] = str(d['error'])[:200]
        for n in d.get('nodes') or []:
            nodes.append({
                'fwd': meta['name'],
                'fwd_ip': meta['ip'],
                'name': n.get('name', ''),
                'port': n.get('port', ''),
                'sni': n.get('sni', ''),
                'exit': n.get('exit', ''),
                'online': bool(n.get('online')),
                'ip': n.get('ip', ''),
                'up': n.get('up') or 0,
                'down': n.get('down') or 0,
                'total': n.get('total') or 0,
                'rate_up': n.get('rate_up') or 0,
                'rate_down': n.get('rate_down') or 0,
                'probe_err': n.get('probe_err', ''),
            })
            meta['count'] += 1
    return {'now': now(), 'nodes': nodes, 'forwarders': metas}


# ---------------------------------------------------------------- 一键代码
def agent_cmd(rec):
    """转发机（机器2/3）跟的一键代码。

    形式与 duola 项目的添加服务器命令一致：下载脚本 + -a 地址 -s 密钥，
    执行时不问任何问题（伪装域名由脚本自己定，不可用时自动换）。
    """
    url = RAW_URL or 'https://raw.githubusercontent.com/dabao9037/att-tunnel-hub/main/install.sh'
    hub = HUB_URL or '(面板外网地址未配置)'
    return ('curl -L %s -o ./install.sh && chmod +x ./install.sh && '
            './install.sh -a %s -s %s' % (url, hub, rec['token']))


def status_line(rec):
    if not rec.get('last_seen'):
        return '待安装'
    return '在线' if fwd_online(rec) else '离线'

# ---------------------------------------------------------------- 页面（统一视觉：靛蓝渐变 + 卡片式布局）
CSS = '''
:root{--bg:#f5f6fb;--card:#fff;--card2:#fafbff;--fg:#111827;--mut:#6b7280;--line:#e8eaf1;
--pri:#4f46e5;--pri2:#4338ca;--pri-soft:#eef0ff;--grad:linear-gradient(135deg,#6366f1,#8b5cf6 55%,#06b6d4);
--ok:#059669;--okb:#d1fae5;--bad:#dc2626;--badb:#fee2e2;--warn:#b45309;--warnb:#fef3c7;
--sh:0 1px 2px #0f172a08,0 10px 30px -18px #0f172a2e;--shl:0 20px 50px -20px #4f46e560;--r:18px}
@media(prefers-color-scheme:dark){:root{--bg:#0a0f1e;--card:#131a2b;--card2:#0f1626;--fg:#e5e9f2;--mut:#94a3b8;--line:#243149;
--pri:#818cf8;--pri2:#a5b4fc;--pri-soft:#312e8155;--grad:linear-gradient(135deg,#4f46e5,#7c3aed 55%,#0891b2);
--ok:#34d399;--okb:#065f4655;--bad:#f87171;--badb:#7f1d1d55;--warn:#fbbf24;--warnb:#78350f55;
--sh:0 1px 2px #0004,0 10px 30px -18px #000a;--shl:0 20px 50px -20px #6366f155}}
*{box-sizing:border-box}html,body{margin:0}
body{font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
background:var(--bg);color:var(--fg);-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:
radial-gradient(900px 520px at 8% -12%,#c7d2fe66,transparent 62%),
radial-gradient(760px 480px at 102% -6%,#bae6fd55,transparent 58%),
radial-gradient(700px 420px at 48% 112%,#ddd6fe55,transparent 62%)}
@media(prefers-color-scheme:dark){body::before{background:
radial-gradient(900px 520px at 8% -12%,#312e8166,transparent 62%),
radial-gradient(760px 480px at 102% -6%,#0e749055,transparent 58%),
radial-gradient(700px 420px at 48% 112%,#4c1d9566,transparent 62%)}}
button,input,select{font:inherit;color:inherit}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--line);
background:var(--card);color:var(--fg);padding:8px 14px;border-radius:11px;cursor:pointer;white-space:nowrap;
font-weight:500;text-decoration:none;transition:border-color .15s,box-shadow .15s,transform .15s,background .15s}
.btn:hover{border-color:#c7cbe0;box-shadow:0 4px 12px -6px #0f172a33;transform:translateY(-1px)}
@media(prefers-color-scheme:dark){.btn:hover{border-color:#3a4a6b}}
.btn:active{transform:translateY(0)}
.btn:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--pri);outline-offset:2px}
.btn.p{background:var(--grad);border-color:transparent;color:#fff;box-shadow:0 8px 20px -10px #4f46e5aa}
.btn.p:hover{filter:brightness(1.06);box-shadow:0 12px 26px -10px #4f46e5bb}
.btn.d{color:var(--bad)}.btn.d:hover{border-color:var(--bad);background:var(--badb)}
.btn.s{padding:6px 11px;font-size:13px;border-radius:9px}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none;filter:none}
input,select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:11px;background:var(--card2);
transition:border-color .15s,box-shadow .15s}
input:focus,select:focus{border-color:var(--pri);box-shadow:0 0 0 4px var(--pri-soft);outline:none}
label{display:block;font-size:13px;font-weight:600;color:var(--mut);margin:12px 0 5px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--sh)}
.mut{color:var(--mut)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all}
.err{color:var(--bad)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;font-size:12px;
font-weight:600;line-height:1.6;white-space:nowrap}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;flex:none}
.pill.on{color:var(--ok);background:var(--okb)}
.pill.on::before{animation:pulse 2.2s infinite}
.pill.off{color:var(--bad);background:var(--badb)}
.pill.w{color:var(--warn);background:var(--warnb)}
@keyframes pulse{0%{box-shadow:0 0 0 0 #05966966}70%{box-shadow:0 0 0 5px #05966900}100%{box-shadow:0 0 0 0 #05966900}}
@media(prefers-reduced-motion:reduce){.pill.on::before{animation:none}.btn,.fcard{transition:none}}
'''

PAGE_LOGIN = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>att-tunnel-hub 登录</title><style>{CSS}
body{min-height:100vh;display:grid;place-items:center;padding:20px}
.lg{width:min(400px,100%);padding:34px 30px 26px;position:relative;overflow:hidden}
.lg::before{content:"";position:absolute;inset:0 0 auto;height:4px;background:var(--grad)}
.mark{width:52px;height:52px;border-radius:16px;background:var(--grad);display:flex;align-items:center;
justify-content:center;font-size:26px;box-shadow:var(--shl);margin-bottom:16px}
.lg h1{font-size:22px;margin:0;letter-spacing:-.02em}
.lg .sub{margin:4px 0 18px;font-size:13.5px}
.lg .btn{width:100%;margin-top:20px;padding:11px}
.foot{margin:18px 0 0;text-align:center;font-size:12px}
</style></head>
<body><form class="card lg" method="post" action="{P}/login"><div class="mark" aria-hidden="true">🛰️</div>
<h1>att-tunnel-hub</h1><p class="sub mut">转发机统一管理面板</p>{E}
<label for="pw">密码</label><input id="pw" type="password" name="password" autocomplete="current-password" required autofocus>
<button class="btn p" type="submit">登 录</button>
<p class="foot mut">安全登录 · 仅限授权用户</p></form></body></html>'''
PAGE_MAIN = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>att-tunnel-hub 面板</title><style>{CSS}
.wrap{max-width:1200px;margin:0 auto;padding:20px 18px 44px}
.topbar{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;
padding:16px 18px;margin-bottom:18px;position:relative;overflow:hidden}
.topbar::after{content:"";position:absolute;inset:0 0 auto;height:3px;background:var(--grad);opacity:.95}
.brand{display:flex;gap:13px;align-items:center;min-width:0}
.mark{width:44px;height:44px;border-radius:14px;background:var(--grad);display:flex;align-items:center;
justify-content:center;font-size:22px;box-shadow:var(--shl);flex:none}
h1{font-size:19px;margin:0;letter-spacing:-.01em;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.ver{font-size:11px;font-weight:600;color:var(--pri);background:var(--pri-soft);padding:2px 8px;
border-radius:999px;letter-spacing:0}
.sub{font-size:12.5px;margin-top:3px;overflow:hidden;text-overflow:ellipsis;max-width:min(560px,70vw)}
.acts{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:20px}
.stat{padding:16px 18px;display:flex;flex-direction:column;gap:2px;position:relative;overflow:hidden}
.stat .ico{position:absolute;right:14px;top:11px;font-size:20px;opacity:.45}
.stat .lab{font-size:12.5px;font-weight:600;color:var(--mut);letter-spacing:.02em}
.stat b{font-size:28px;line-height:1.25;font-weight:700;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stat .hint{font-size:12px;color:var(--mut)}
.alert{padding:13px 16px;margin-bottom:16px;border-color:var(--bad);color:var(--bad);background:var(--badb);
display:none;white-space:pre-wrap;border-radius:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(345px,1fr));gap:16px}
.fcard{padding:18px;display:flex;flex-direction:column;transition:box-shadow .2s,transform .2s,border-color .2s}
.fcard:hover{box-shadow:0 18px 44px -24px #0f172a45;transform:translateY(-2px);border-color:#d7dbea}
.fhead{display:flex;align-items:center;justify-content:space-between;gap:10px}
.fname{display:flex;align-items:center;gap:9px;min-width:0}
.avatar{width:34px;height:34px;border-radius:10px;background:var(--pri-soft);color:var(--pri);display:flex;
align-items:center;justify-content:center;font-weight:700;font-size:15px;flex:none;text-transform:uppercase}
.fhead h2{font-size:16.5px;margin:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fmeta{font-size:12.5px;color:var(--mut);margin:8px 0 0;display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.metrics{display:grid;grid-template-columns:1fr 1fr;gap:11px 14px;margin:14px 0 0;padding:14px 0;
border-top:1px dashed var(--line);border-bottom:1px dashed var(--line)}
.metric{min-width:0}
.metric span{display:block;font-size:11.5px;color:var(--mut);font-weight:600;letter-spacing:.02em}
.metric b{display:block;font-size:14px;font-weight:600;margin-top:2px;font-variant-numeric:tabular-nums;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.metric.wide{grid-column:1/-1}
.metric.wide b{white-space:normal;overflow:visible}
.nact{display:flex;flex-direction:column;gap:8px;margin-top:14px}
.nact .row{display:flex;gap:7px;flex-wrap:wrap;align-items:center}
.nact .row .grow{flex:1}
.mainbtn .btn{width:100%}
.upmsg{width:100%;font-size:12px;margin-top:9px;color:var(--mut);line-height:1.55}
.sec{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin:24px 2px 12px}
.sec h3{margin:0;font-size:16px;letter-spacing:-.01em}
.empty{padding:46px 22px;text-align:center;line-height:1.9}
.empty b{display:block;font-size:16px;margin-bottom:2px}
dialog{border:1px solid var(--line);border-radius:20px;background:var(--card);color:var(--fg);padding:0;
width:min(620px,94vw);box-shadow:0 30px 80px -20px #0006}
dialog::backdrop{background:#0b102066;backdrop-filter:blur(4px)}
.dh{padding:18px 22px;border-bottom:1px solid var(--line);font-weight:700;display:flex;align-items:center;gap:8px}
.db{padding:6px 22px 18px}
.df{padding:14px 22px;border-top:1px solid var(--line);display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap}
.copy{display:flex;gap:8px;align-items:flex-start;background:var(--card2);border:1px solid var(--line);
border-radius:12px;padding:10px 12px;margin-top:6px}
.copy .mono{flex:1;max-height:260px;overflow:auto}
#toasts{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:9px;z-index:20;
max-width:min(400px,92vw)}
.toast{padding:11px 15px;border-radius:12px;color:#fff;background:#111827;box-shadow:0 16px 40px -12px #0006;
font-size:14px;animation:slideIn .28s ease}
.toast.ok{background:linear-gradient(135deg,#059669,#10b981)}
.toast.bad{background:linear-gradient(135deg,#b91c1c,#ef4444)}
@keyframes slideIn{from{transform:translateX(24px);opacity:0}to{transform:none;opacity:1}}
@media(max-width:760px){.wrap{padding:12px 10px 36px}.topbar{padding:14px}
.acts{width:100%}.grid{grid-template-columns:1fr}.sub{max-width:80vw}}
@media(max-width:560px){.stats{grid-template-columns:repeat(3,1fr);gap:8px}
.stat{padding:12px 10px}.stat b{font-size:22px}.stat .hint,.stat .ico{display:none}
.stat .lab{font-size:11px}
.acts{display:grid;grid-template-columns:1fr 1fr;gap:8px}.acts form{display:block}.acts form .btn{width:100%}}
</style></head><body><div class="wrap">
<header class="topbar card">
<div class="brand"><div class="mark" aria-hidden="true">🛰️</div>
<div style="min-width:0"><h1>att-tunnel-hub <span class="ver">v{V}</span></h1>
<div class="sub mut" id="hinfo">加载中…</div></div></div>
<div class="acts"><button class="btn p" id="bAdd" type="button">＋ 添加转发机</button>
<a class="btn" href="{P}/nodes">🌐 落地节点汇总</a>
<button class="btn" id="bRef" type="button">↻ 刷新</button>
<form method="post" action="{P}/logout" style="margin:0"><input type="hidden" name="csrf" value="{C}"><button class="btn" type="submit">退出</button></form></div></header>
<div class="card alert" id="err" role="alert"></div>
<div class="stats" id="sum"></div>
<div class="sec"><h3>转发机</h3><span class="mut" style="font-size:12.5px" id="meta" aria-live="polite"></span></div>
<div class="grid" id="list"></div></div>
<div id="toasts" aria-live="polite"></div>
'''
PAGE_MAIN += '''
<dialog id="dAdd" aria-labelledby="dAddH"><form id="fAdd" method="dialog"><div class="dh" id="dAddH">＋ 添加转发机</div><div class="db">
<p class="mut" style="font-size:13px;margin-top:14px">填转发机的公网 IP，面板会生成该机专属的一键代码。把代码贴到那台机器跑完，它会自动回连本面板。</p>
<label for="aName">名称</label><input id="aName" name="name" required placeholder="如 fwd2" pattern="[A-Za-z0-9_-]{1,32}">
<label for="aIp">公网 IP 或域名</label><input id="aIp" name="ip" required placeholder="如 1.2.3.4">
<label for="aNote">备注（可空）</label><input id="aNote" name="note" placeholder="如 香港入口">
</div><div class="df"><button class="btn" type="button" id="aCancel">取消</button>
<button class="btn p" id="aOk" type="submit">生成一键代码</button></div></form></dialog>

<dialog id="dCmd" aria-labelledby="dCmdH"><div class="dh" id="dCmdH">⚡ 一键安装代码</div><div class="db">
<p class="mut" style="font-size:13px;margin-top:14px">在这台转发机上用 root 跑下面这条命令，全程不会问任何问题。它会装好 att-tunnel 入口端和上报 agent，装完这里会变成「在线」。<br>代码里带着该机的专属密钥，请当密码保管。</p>
<div class="copy"><code class="mono" id="cmdText"></code><button class="btn s" type="button" id="cmdCopy">复制</button></div>
</div><div class="df"><button class="btn p" type="button" id="cmdClose">知道了</button></div></dialog>

<dialog id="dDel" aria-labelledby="dDelH"><form id="fDel" method="dialog"><div class="dh" id="dDelH">删除转发机</div><div class="db">
<p style="margin-top:14px">仅从面板里移除记录，<b>不会</b>去动那台机器上的 att-tunnel。如要彻底卸载，在那台机上跑 <code class="mono">att-tunnel</code> 菜单里的卸载。</p>
<label for="dName">输入名称确认：<b id="dWho"></b></label><input id="dName" name="confirm" required autocomplete="off">
</div><div class="df"><button class="btn" type="button" id="dCancel">取消</button>
<button class="btn d" id="dOk" type="submit">确认删除</button></div></form></dialog>

<dialog id="dEdit" aria-labelledby="dEditH"><form id="fEdit" method="dialog"><div class="dh" id="dEditH">编辑转发机</div><div class="db">
<p class="mut" style="font-size:13px;margin-top:14px">密钥不变，所以改完<b>不用重装</b>，转发机上的 agent 和落地机都不受影响。<br>IP 只是面板里的备忘记录，改它不会去改那台机器的配置。</p>
<input type="hidden" id="eOld" name="name">
<label for="eName">名称</label><input id="eName" name="new_name" required pattern="[A-Za-z0-9_-]{1,32}">
<label for="eIp">公网 IP 或域名</label><input id="eIp" name="ip" required>
<label for="eNote">备注（可空）</label><input id="eNote" name="note">
</div><div class="df"><button class="btn" type="button" id="eCancel">取消</button>
<button class="btn p" id="eOk" type="submit">保存</button></div></form></dialog>
'''
PAGE_MAIN += '''
<script>
const P="{P}", C="{C}";
let FWD=[];
const UPGRADES=new Map(), SUBMITTING=new Set();
function upgradeButton(name){
  const u=UPGRADES.get(name);
  return '<button class="btn s" type="button" data-upgrade="'+esc(name)+'"'
    +(u&&u.state==='running'?' disabled':'')
    +(u&&u.state==='ok'?' style="color:#059669"':'')+'>'
    +(u?(u.state==='running'?'更新中…':u.state==='ok'?'✓ 更新成功':u.state==='unknown'?'结果未确认':'更新失败，重试'):'更新')+'</button>';
}
const $=s=>document.querySelector(s);
function toast(m,k,long){const d=document.createElement("div");d.className="toast "+(k||"");d.textContent=m;
  $("#toasts").appendChild(d);setTimeout(()=>d.remove(),long?6500:4200);}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function ago(t){if(!t)return "从未";const s=Math.max(0,Math.floor(Date.now()/1000)-t);
  if(s<60)return s+" 秒前";if(s<3600)return Math.floor(s/60)+" 分钟前";
  if(s<86400)return Math.floor(s/3600)+" 小时前";return Math.floor(s/86400)+" 天前";}
function fb(n){n=+n||0;const u=["B","KB","MB","GB","TB","PB"];let i=0;
  while(n>=1024&&i<5){n/=1024;i++}return(i?n.toFixed(n<10?2:n<100?1:0):n)+" "+u[i];}
async function api(path,data){
  const r=await fetch(P+path,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded","X-CSRF-Token":C},
    body:new URLSearchParams(Object.assign({csrf:C},data||{}))});
  if(r.status===401){location.href=P+"/";return;}
  let j={};try{j=await r.json();}catch(e){}
  if(!r.ok)throw new Error(j.error||("HTTP "+r.status));
  return j;}
function showCmd(cmd){$("#cmdText").textContent=cmd;$("#dCmd").showModal();}
function card(f){
  const cls=f.online?"on":(f.last_seen?"off":"w");
  const txt=f.online?"在线":(f.last_seen?"离线":"待安装");
  const a=f.agent||{};
  const initial=esc(String(f.name||"?").slice(0,1));
  const manage=f.online&&f.paneled
    ? '<a class="btn p s" href="'+P+'/f/'+encodeURIComponent(f.name)+'/">管理落地机</a>'
    : '<button class="btn s" type="button" disabled title="转发机在线后可用">管理落地机</button>';
  return '<article class="card fcard"><div class="fhead"><div class="fname">'
    +'<span class="avatar" aria-hidden="true">'+initial+'</span><h2>'+esc(f.name)+'</h2></div>'
    +'<span class="pill '+cls+'">'+txt+'</span></div>'
    +'<div class="fmeta"><span class="mono">'+esc(f.ip)+'</span>'
    +(f.note?'<span class="mut">·</span><span>'+esc(f.note)+'</span>':'')+'</div>'
    +'<div class="metrics">'
    +'<div class="metric"><span>落地机</span><b>'+(a.nodes!==undefined?esc(a.nodes)+' 个':'—')+'</b></div>'
    +'<div class="metric"><span>最后上报</span><b>'+ago(f.last_seen)+'</b></div>'
    +'<div class="metric wide"><span>实时速率</span><b>'+(a.rate_rx!==undefined
        ?'↓ '+fb(a.rate_rx)+'/s ↑ '+fb(a.rate_tx)+'/s'
        :'<span class="mut">—</span>')+'</b></div>'
    +'<div class="metric wide"><span>累计流量</span><b>'+(a.rx!==undefined
        ?'↓ '+fb(a.rx)+' ↑ '+fb(a.tx)
        :'<span class="mut">—</span>')+'</b></div>'
    +'</div><div class="nact"><div class="mainbtn">'+manage+'</div><div class="row">'
    +'<button class="btn s" type="button" data-edit="'+esc(f.name)+'">编辑</button>'
    +'<button class="btn s" type="button" data-cmd="'+esc(f.name)+'">一键代码</button>'
    +((f.online||UPGRADES.has(f.name))?upgradeButton(f.name):'')
    +'<span class="grow"></span>'
    +'<button class="btn d s" type="button" data-del="'+esc(f.name)+'">删除</button></div></div>'
    +((a.ver||(f.upgrade&&f.upgrade.message))?'<div class="upmsg">'
        +(a.ver?'管理代理 '+esc(a.ver):'')
        +(a.ver&&f.upgrade&&f.upgrade.message?' · ':'')
        +((f.upgrade&&f.upgrade.message)?esc(f.upgrade.message):'')+'</div>':'')
    +'</article>';
}
async function load(){
  try{
    const r=await fetch(P+"/api/status",{headers:{"Accept":"application/json"}});
    if(r.status===401){location.href=P+"/";return;}
    const d=await r.json();
    const fs=d.forwarders||[], on=fs.filter(f=>f.online).length;
    fs.forEach(f=>{
      const u=f.upgrade, prev=UPGRADES.get(f.name);
      if(SUBMITTING.has(f.name))return;
      if(!u||!u.id){if(prev&&prev.id)UPGRADES.delete(f.name);return;}
      if(prev&&prev.state==='running'&&prev.id===u.id&&u.state!=='running')
        toast('转发机「'+f.name+'」'+u.message,u.state==='ok'?'ok':'bad',true);
      UPGRADES.set(f.name,u);
    });
    FWD=fs;
    const nodes=fs.reduce((s,f)=>s+(parseInt((f.agent||{}).nodes,10)||0),0);
    $("#sum").innerHTML=
      '<div class="stat card"><span class="ico" aria-hidden="true">🛰️</span><span class="lab">转发机</span><b>'+fs.length+'</b><span class="hint">已登记</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">🟢</span><span class="lab">在线</span><b>'+on+'</b><span class="hint">'+fs.length+' 台中在线</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">🌐</span><span class="lab">落地机（节点）</span><b>'+nodes+'</b><span class="hint">全部转发机合计</span></div>';
    $("#hinfo").innerHTML='<span>面板地址 <span class="mono">'+esc(d.hub_url||"未配置")+'</span></span>';
    $("#list").innerHTML=fs.length?fs.map(card).join("")
      :'<div class="card empty"><b>还没有转发机</b><span class="mut">点右上角「＋ 添加转发机」填 IP，把生成的一键代码跑在那台机器上。</span></div>';
    $("#meta").textContent="更新于 "+new Date().toLocaleTimeString();
    $("#err").style.display="none";
    $("#list").querySelectorAll("[data-cmd]").forEach(b=>b.onclick=async()=>{
      try{const j=await api("/api/cmd",{name:b.dataset.cmd});showCmd(j.cmd);}catch(e){toast(e.message,"bad");}});
    $("#list").querySelectorAll("[data-del]").forEach(b=>b.onclick=()=>{
      $("#dWho").textContent=b.dataset.del;$("#dName").value="";$("#dDel").showModal();});
    $("#list").querySelectorAll("[data-edit]").forEach(b=>b.onclick=()=>{
      const f=(FWD||[]).find(x=>x.name===b.dataset.edit);if(!f)return;
      $("#eOld").value=f.name;$("#eName").value=f.name;
      $("#eIp").value=f.ip;$("#eNote").value=f.note||"";
      $("#dEdit").showModal();});
    $("#list").querySelectorAll("[data-upgrade]").forEach(b=>b.onclick=async()=>{
      if(!confirm('确认更新转发机「'+b.dataset.upgrade+'」的 att-tunnel 到最新版？\\n\\n更新期间（约 1-2 分钟），该机的所有落地机会短暂断开，然后自动重连。'))return;
      const name=b.dataset.upgrade;
      if(SUBMITTING.has(name)||UPGRADES.get(name)?.state==='running')return;
      SUBMITTING.add(name);
      UPGRADES.set(name,{state:'running'});
      b.disabled=true;b.textContent='更新中…';
      try{
        const j=await api("/api/upgrade",{name});
        if(!j||!j.ok||!j.upgrade)throw new Error('未收到更新任务确认');
        UPGRADES.set(name,j.upgrade);
        toast('转发机「'+name+'」更新任务已提交，完成后会显示结果','ok',true);
      }catch(e){
        UPGRADES.set(name,{state:'unknown'});
        toast('转发机「'+name+'」更新请求未确认：'+e.message+'；正在读取任务状态','bad',true);
      }finally{SUBMITTING.delete(name);await load();}
    });
  }catch(e){$("#err").textContent="读取状态失败："+e.message;$("#err").style.display="block";}
}
load();setInterval(load,10000);
$("#cmdCopy").onclick=async()=>{try{await navigator.clipboard.writeText($("#cmdText").textContent);toast("已复制","ok");}
  catch(e){toast("复制失败，请手动选中","bad");}};
$("#cmdClose").onclick=()=>$("#dCmd").close();
$("#bAdd").onclick=()=>{$("#fAdd").reset();$("#dAdd").showModal();};
$("#aCancel").onclick=()=>$("#dAdd").close();
$("#dCancel").onclick=()=>$("#dDel").close();
$("#eCancel").onclick=()=>$("#dEdit").close();
$("#bRef").onclick=()=>load();
$("#fAdd").onsubmit=async e=>{e.preventDefault();const b=$("#aOk");b.disabled=true;
  try{const j=await api("/api/add",{name:$("#aName").value.trim(),ip:$("#aIp").value.trim(),note:$("#aNote").value.trim()});
    $("#dAdd").close();load();showCmd(j.cmd);}catch(err){toast(err.message,"bad");}finally{b.disabled=false;}};
$("#fDel").onsubmit=async e=>{e.preventDefault();const b=$("#dOk");b.disabled=true;
  try{await api("/api/del",{name:$("#dWho").textContent,confirm:$("#dName").value.trim()});
    $("#dDel").close();toast("已删除","ok");load();}catch(err){toast(err.message,"bad");}finally{b.disabled=false;}};
$("#fEdit").onsubmit=async e=>{e.preventDefault();const b=$("#eOk");b.disabled=true;
  try{const j=await api("/api/edit",{name:$("#eOld").value,new_name:$("#eName").value.trim(),
      ip:$("#eIp").value.trim(),note:$("#eNote").value.trim()});
    $("#dEdit").close();toast(j.renamed?"已保存（已改名，无需重装）":"已保存","ok");load();}
  catch(err){toast(err.message,"bad");}finally{b.disabled=false;}};
</script>
'''

PAGE_NODES = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>落地节点 · att-tunnel-hub</title><style>{CSS}
.wrap{max-width:1320px;margin:0 auto;padding:20px 18px 44px}
.topbar{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;
padding:16px 18px;margin-bottom:18px;position:relative;overflow:hidden}
.topbar::after{content:"";position:absolute;inset:0 0 auto;height:3px;background:var(--grad);opacity:.95}
.brand{display:flex;gap:13px;align-items:center;min-width:0}
.mark{width:44px;height:44px;border-radius:14px;background:var(--grad);display:flex;align-items:center;
justify-content:center;font-size:22px;box-shadow:var(--shl);flex:none}
h1{font-size:19px;margin:0;letter-spacing:-.01em;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.ver{font-size:11px;font-weight:600;color:var(--pri);background:var(--pri-soft);padding:2px 8px;
border-radius:999px;letter-spacing:0}
.sub{font-size:12.5px;margin-top:3px}
.acts{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.stat{padding:16px 18px;display:flex;flex-direction:column;gap:2px;position:relative;overflow:hidden}
.stat .ico{position:absolute;right:14px;top:11px;font-size:20px;opacity:.45}
.stat .lab{font-size:12.5px;font-weight:600;color:var(--mut);letter-spacing:.02em}
.stat b{font-size:26px;line-height:1.25;font-weight:700;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stat .hint{font-size:12px;color:var(--mut)}
.alert{padding:13px 16px;margin-bottom:16px;border-color:var(--bad);color:var(--bad);background:var(--badb);
display:none;white-space:pre-wrap;border-radius:14px}
.warnbox{padding:13px 16px;margin-bottom:16px;border-color:#fcd34d;color:var(--warn);background:var(--warnb);
display:none;white-space:pre-wrap;font-size:13px;border-radius:14px}
.tblwrap{overflow:auto;padding:2px 0}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:12px 16px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{position:sticky;top:0;background:var(--card);font-size:11.5px;color:var(--mut);font-weight:700;
text-transform:uppercase;letter-spacing:.06em;z-index:1}
tbody tr{transition:background .15s}tbody tr:hover{background:var(--card2)}
tbody tr:last-child td{border-bottom:none}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.fwdcell{font-weight:600}.fwdcell .mono{font-weight:400;margin-top:2px}
.sec{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin:24px 2px 12px}
.sec h3{margin:0;font-size:16px;letter-spacing:-.01em}
.empty{padding:46px 22px;text-align:center;line-height:1.9}
#toasts{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:9px;z-index:20;
max-width:min(400px,92vw)}
.toast{padding:11px 15px;border-radius:12px;color:#fff;background:#111827;box-shadow:0 16px 40px -12px #0006;
font-size:14px}
.toast.ok{background:linear-gradient(135deg,#059669,#10b981)}
.toast.bad{background:linear-gradient(135deg,#b91c1c,#ef4444)}
@media(max-width:760px){.stats{grid-template-columns:repeat(2,1fr)}.wrap{padding:12px 10px 36px}
.topbar{padding:14px}.acts{width:100%}}
</style></head><body><div class="wrap">
<header class="topbar card">
<div class="brand"><div class="mark" aria-hidden="true">🌐</div>
<div style="min-width:0"><h1>落地节点汇总 <span class="ver">v{V}</span></h1>
<div class="sub mut" id="hinfo">加载中…</div></div></div>
<div class="acts"><a class="btn" href="{P}/">← 转发机</a>
<button class="btn" id="bRef" type="button">↻ 刷新</button>
<form method="post" action="{P}/logout" style="margin:0"><input type="hidden" name="csrf" value="{C}"><button class="btn" type="submit">退出</button></form></div></header>
<div class="card alert" id="err" role="alert"></div>
<div class="card warnbox" id="warn"></div>
<div class="stats" id="sum"></div>
<div class="sec"><h3>所有落地节点</h3><span class="mut" style="font-size:12.5px" id="meta" aria-live="polite"></span></div>
<div class="card tblwrap" id="tbl"></div></div>
<div id="toasts" aria-live="polite"></div>
'''
PAGE_NODES += '''
<script>
const P="{P}", C="{C}";
const $=s=>document.querySelector(s);
function toast(m,k){const d=document.createElement("div");d.className="toast "+(k||"");d.textContent=m;
  $("#toasts").appendChild(d);setTimeout(()=>d.remove(),4200);}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function fb(n){n=+n||0;const u=["B","KB","MB","GB","TB","PB"];let i=0;
  while(n>=1024&&i<5){n/=1024;i++}return(i?n.toFixed(n<10?2:n<100?1:0):n)+" "+u[i];}
function row(n){
  const cls=n.online?"on":"off", txt=n.online?"在线":"离线";
  const ip=n.ip?esc(n.ip):'<span class="mut">—</span>';
  const tip=n.probe_err?' title="'+esc(n.probe_err)+'"':'';
  return '<tr><td class="fwdcell">'+esc(n.fwd)+'<div class="mut mono">'+esc(n.fwd_ip)+'</div></td>'
    +'<td>'+esc(n.name)+'</td>'
    +'<td><span class="pill '+cls+'"'+tip+'>'+txt+'</span></td>'
    +'<td class="mono">'+ip+'</td>'
    +'<td class="num">'+esc(n.port)+'</td>'
    +'<td class="mono">'+esc(n.sni||"—")+'</td>'
    +'<td class="num">'+fb(n.total)+'</td>'
    +'<td class="num mut">↑'+fb(n.rate_up)+'/s ↓'+fb(n.rate_down)+'/s</td>'
    +'<td><a class="btn s" href="'+P+'/f/'+encodeURIComponent(n.fwd)+'/">管理</a></td></tr>';
}
async function load(){
  $("#meta").textContent="正在向各转发机取数…";
  try{
    const r=await fetch(P+"/api/nodes",{headers:{"Accept":"application/json"}});
    if(r.status===401){location.href=P+"/";return;}
    const d=await r.json();
    const ns=d.nodes||[], fs=d.forwarders||[];
    const on=ns.filter(n=>n.online).length;
    const total=ns.reduce((s,n)=>s+(+n.total||0),0);
    $("#sum").innerHTML=
      '<div class="stat card"><span class="ico" aria-hidden="true">🛰️</span><span class="lab">转发机</span><b>'+fs.length+'</b><span class="hint">已登记</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">🌐</span><span class="lab">落地节点</span><b>'+ns.length+'</b><span class="hint">全部节点</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">🟢</span><span class="lab">节点在线</span><b>'+on+'</b><span class="hint">'+ns.length+' 个中在线</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">📊</span><span class="lab">累计流量</span><b>'+fb(total)+'</b><span class="hint">全部节点合计</span></div>';
    const okf=fs.filter(f=>!f.error);
    $("#hinfo").innerHTML='<span>已取到 '+okf.length+'/'+fs.length+' 台转发机的节点</span>';
    const bad=fs.filter(f=>f.error);
    if(bad.length){
      $("#warn").textContent="这几台转发机的节点没取到：\\n"
        +bad.map(f=>"  • "+f.name+"（"+f.ip+"）："+f.error).join("\\n");
      $("#warn").style.display="block";
    }else{$("#warn").style.display="none";}
    ns.sort((a,b)=>a.fwd===b.fwd?a.name.localeCompare(b.name):a.fwd.localeCompare(b.fwd));
    $("#tbl").innerHTML=ns.length
      ?'<table><thead><tr><th>转发机</th><th>节点</th><th>状态</th><th>出口 IP</th>'
        +'<th>入口端口</th><th>伪装域名</th><th>累计流量</th><th>当前速率</th><th></th></tr></thead>'
        +'<tbody>'+ns.map(row).join("")+'</tbody></table>'
      :'<div class="empty"><b>还没有落地节点</b><span class="mut">进某台转发机的「管理落地机」添加节点。</span></div>';
    $("#meta").textContent="更新于 "+new Date().toLocaleTimeString();
    $("#err").style.display="none";
  }catch(e){
    $("#err").textContent="读取失败："+e.message;$("#err").style.display="block";
    $("#meta").textContent="";
  }
}
$("#bRef").onclick=()=>load();
load();setInterval(load,30000);
</script>
'''


# ---------------------------------------------------------------- HTTP
class H(http.server.BaseHTTPRequestHandler):
    server_version = 'att-hub'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *a):
        pass

    def peer(self):
        ip = self.client_address[0]
        if TRUST_PROXY and ip in ('127.0.0.1', '::1'):
            xr = self.headers.get('X-Real-IP')
            if xr:
                return xr.strip()
        return ip

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n <= 0 or n > 4 * 1024 * 1024:
            return b''
        return self.rfile.read(n)

    def form(self, raw=None):
        if raw is None:
            raw = self.body()
        ct = (self.headers.get('Content-Type') or '')
        if ct.startswith('application/json'):
            try:
                d = json.loads(raw.decode('utf-8', 'replace'))
                return {k: str(v) for k, v in d.items()} if isinstance(d, dict) else {}
            except ValueError:
                return {}
        return {k: v[0] for k, v in
                urllib.parse.parse_qs(raw.decode('utf-8', 'replace'), keep_blank_values=True).items()}

    def send(self, code, body, ctype='text/html; charset=utf-8', extra=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def jsend(self, code, obj):
        self.send(code, json.dumps(obj, ensure_ascii=False), 'application/json; charset=utf-8')

    def redirect(self, loc, extra=()):
        self.send(303, '', 'text/plain', list(extra) + [('Location', loc)])

    def session(self):
        raw = self.headers.get('Cookie') or ''
        try:
            ck = http.cookies.SimpleCookie(raw)
        except Exception:
            return None, None
        m = ck.get('hub_sid')
        if not m:
            return None, None
        sid = m.value
        with lock:
            s = sessions.get(sid)
            if s and s['exp'] < now():
                sessions.pop(sid, None)
                s = None
        return sid, s

    def same_origin(self):
        """Origin: null + Sec-Fetch-Site: same-origin 也算同源（Referrer-Policy: no-referrer 下
        真实浏览器会这么发）。"""
        sfs = (self.headers.get('Sec-Fetch-Site') or '').lower()
        if sfs in ('same-origin', 'none'):
            return True
        org = self.headers.get('Origin')
        if org in (None, '', 'null'):
            return True
        host = self.headers.get('Host') or ''
        try:
            oh = urllib.parse.urlsplit(org).netloc
        except ValueError:
            return False
        return bool(oh) and oh == host

    def route(self):
        p = urllib.parse.urlsplit(self.path).path
        if p != PREFIX and not p.startswith(PREFIX + '/'):
            return None
        return p[len(PREFIX):] or '/'

    def login_page(self, code, msg=''):
        e = '<p class="err">%s</p>' % msg if msg else ''
        return self.send(code, PAGE_LOGIN.replace('{CSS}', CSS).replace('{P}', PREFIX).replace('{E}', e))

    # ------------------------------------------------------- agent 接入端（无会话，用 token）
    def agent_token(self, f=None):
        auth = self.headers.get('Authorization') or ''
        tok = auth[7:].strip() if auth.lower().startswith('bearer ') else ''
        if not tok and f:
            tok = f.get('token', '')
        return tok

    def do_agent(self, r, raw):
        """/agent/poll 和 /agent/reply：agent 主动外拨进来的唯一两个接口。"""
        f = self.form(raw)
        name, rec = fwd_by_token(self.agent_token(f))
        if not rec:
            time.sleep(0.5)
            return self.jsend(401, {'error': 'bad token'})
        if r == '/agent/poll':
            with lock:
                rec['last_seen'] = now()
                info = {}
                for k in ('web', 'web_path', 'ver', 'ip', 'nodes', 'xray',
                          'rx', 'tx', 'rate_rx', 'rate_tx'):
                    if k in f:
                        info[k] = f[k]
                if info:
                    rec['agent'] = dict(rec.get('agent') or {}, **info)
            safe_save()
            job = bus.take(name, POLL_WAIT)
            if not job:
                return self.jsend(200, {'job': None})
            return self.jsend(200, {'job': {'id': job['id'], **job['req']}})
        if r == '/agent/reply':
            jid = f.get('job', '')
            try:
                code = int(f.get('status') or 502)
            except ValueError:
                code = 502
            bus.answer(jid, {'status': code,
                             'body': f.get('body', ''),
                             'ctype': f.get('ctype', 'text/html; charset=utf-8'),
                             'headers': f.get('headers', '')})
            return self.jsend(200, {'ok': True})
        return self.send(404, 'Not Found', 'text/plain')

    # ------------------------------------------------------- 转发机面板代理
    def do_proxy(self, name, rest, method, raw):
        """把 <根路径>/f/<转发机>/... 转给该转发机本机的 att-tunnel 面板。
        转发机加 / 删落地机的页面就是 att-tunnel 原生页面，所以完全以 att-tunnel 为准。"""
        rec = fwd_get(name)
        if not rec:
            return self.jsend(404, {'error': '转发机 %s 不存在' % name})
        if not fwd_online(rec):
            return self.jsend(503, {'error': '转发机 %s 不在线（agent 未回连）' % name})
        req = {'method': method, 'path': rest or '/',
               'body': raw.decode('utf-8', 'replace') if raw else '',
               'ctype': self.headers.get('Content-Type') or '',
               'csrf': self.headers.get('X-CSRF-Token') or ''}
        job = bus.submit(name, req)
        resp = bus.wait(job, REQ_TIMEOUT)
        if resp is None:
            return self.jsend(504, {'error': '转发机 %s 没有在 %d 秒内应答' % (name, int(REQ_TIMEOUT))})
        base = '%s/f/%s' % (PREFIX, name)
        body = resp.get('body') or ''
        ctype = resp.get('ctype') or 'text/html; charset=utf-8'
        if 'html' in ctype:
            # 把 att-tunnel 面板自己的根路径改成面板机上的代理路径。
            # 必须同时管两种形式：
            #   "<p>/login"（带斜杠，表单 action / 链接）
            #   "<p>"（不带斜杠，如 JS 里的 const P="<p>"）
            # 漏了后者的话，JS 的 fetch(P+"/api/status") 会打到面板机根路径上 404。
            apath = (rec.get('agent') or {}).get('web_path') or ''
            if apath:
                for q in ('"', "'"):
                    body = body.replace(q + apath + '/', q + base + '/')
                    body = body.replace(q + apath + q, q + base + q)
            body = inject_back(body, base, name)
        return self.send(resp.get('status') or 200, body, ctype)

    def do_GET(self):
        r = self.route()
        if r is None:
            return self.send(404, 'Not Found', 'text/plain')
        sid, s = self.session()
        if r == '/':
            if not s:
                return self.login_page(200)
            page = (PAGE_MAIN.replace('{CSS}', CSS).replace('{P}', PREFIX)
                    .replace('{C}', s['csrf']).replace('{V}', VERSION))
            return self.send(200, page)
        if r == '/api/status':
            if not s:
                return self.jsend(401, {'error': 'unauthorized'})
            return self.jsend(200, status_json())
        if r == '/nodes':
            if not s:
                return self.login_page(200)
            page = (PAGE_NODES.replace('{CSS}', CSS).replace('{P}', PREFIX)
                    .replace('{C}', s['csrf']).replace('{V}', VERSION))
            return self.send(200, page)
        if r == '/api/nodes':
            if not s:
                return self.jsend(401, {'error': 'unauthorized'})
            return self.jsend(200, collect_nodes())
        if r.startswith('/f/'):
            parts = r[3:].split('/', 1)
            # 节点订阅：<根路径>/f/<转发机>/sub/<token> 免登录（客户端定时拉取），
            # token 由转发机本机面板校验；这里只放行格式正确的请求。
            if not s:
                rest = parts[1] if len(parts) > 1 else ''
                if (NAME_RE.match(parts[0]) and rest.startswith('sub/')
                        and SUB_RE.match(rest[4:])):
                    return self.do_proxy(parts[0], '/' + rest, 'GET', b'')
                return self.redirect(PREFIX + '/')
            name = parts[0]
            rest = '/' + (parts[1] if len(parts) > 1 else '')
            q = urllib.parse.urlsplit(self.path).query
            if q:
                rest += '?' + q
            return self.do_proxy(name, rest, 'GET', b'')
        return self.send(404, 'Not Found', 'text/plain')

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        r = self.route()
        if r is None:
            return self.send(404, 'Not Found', 'text/plain')
        raw = self.body()
        # agent 接入端：token 鉴权，不走会话/CSRF
        if r in ('/agent/poll', '/agent/reply'):
            return self.do_agent(r, raw)
        ip = self.peer()
        if r == '/login':
            if rate_limited(ip):
                return self.login_page(429, '失败次数过多，请 10 分钟后再试')
            if not self.same_origin():
                return self.login_page(403, '跨站请求已拒绝')
            f = self.form(raw)
            if hmac.compare_digest(f.get('password', '').encode(), PASS.encode()):
                sid = new_session()
                ck = ('hub_sid=%s; Path=%s; HttpOnly; SameSite=Strict; Max-Age=%d%s'
                      % (sid, PREFIX, SESSION_TTL, '; Secure' if COOKIE_SECURE else ''))
                return self.redirect(PREFIX + '/', [('Set-Cookie', ck)])
            note_fail(ip)
            time.sleep(1)
            return self.login_page(401, '密码错误')
        sid, s = self.session()
        if not s:
            return self.jsend(401, {'error': 'unauthorized'})
        if not self.same_origin():
            return self.jsend(403, {'error': '跨站请求已拒绝'})
        # 转发机面板代理：转发机本机的 att-tunnel 面板有自己一套 CSRF，由它自己校验，
        # 所以这里不能拿面板机的 csrf 去卡它；本层只把关会话 + 同源（上面两步已做）。
        if r.startswith('/f/'):
            parts = r[3:].split('/', 1)
            rest = '/' + (parts[1] if len(parts) > 1 else '')
            return self.do_proxy(parts[0], rest, 'POST', raw)
        f = self.form(raw)
        tok = self.headers.get('X-CSRF-Token') or f.get('csrf', '')
        if not hmac.compare_digest(tok.encode(), s['csrf'].encode()):
            return self.jsend(403, {'error': 'CSRF 校验失败，请刷新页面'})
        if r == '/logout':
            with lock:
                sessions.pop(sid, None)
            ck = ('hub_sid=; Path=%s; HttpOnly; SameSite=Strict; Max-Age=0%s'
                  % (PREFIX, '; Secure' if COOKIE_SECURE else ''))
            return self.redirect(PREFIX + '/', [('Set-Cookie', ck)])
        if r == '/api/add':
            return self.do_add(f)
        if r == '/api/edit':
            return self.do_edit(f)
        if r == '/api/cmd':
            rec = fwd_get(f.get('name', ''))
            if not rec:
                return self.jsend(404, {'error': '转发机不存在'})
            return self.jsend(200, {'ok': True, 'cmd': agent_cmd(rec)})
        if r == '/api/del':
            name = f.get('name', '')
            if f.get('confirm') != name:
                return self.jsend(400, {'error': '确认名称不一致'})
            if not fwd_del(name):
                return self.jsend(404, {'error': '转发机不存在'})
            return self.jsend(200, {'ok': True})
        if r == '/api/upgrade':
            return self.do_upgrade(f)
        return self.send(404, 'Not Found', 'text/plain')

    def do_add(self, f):
        name = f.get('name', '').strip()
        ip = f.get('ip', '').strip()
        note = f.get('note', '').strip()[:64]
        if not NAME_RE.match(name):
            return self.jsend(400, {'error': '名称只能用字母/数字/下划线/连字符，最多 32 位'})
        if not IP_RE.match(ip):
            return self.jsend(400, {'error': 'IP 或域名格式不对'})
        if fwd_get(name):
            return self.jsend(409, {'error': '转发机 %s 已存在' % name})
        rec = fwd_add(name, ip, note)
        return self.jsend(200, {'ok': True, 'name': name, 'cmd': agent_cmd(rec)})

    def do_edit(self, f):
        old = f.get('name', '').strip()
        new_name = f.get('new_name', '').strip() or old
        ip = f.get('ip', '').strip()
        note = f.get('note', '').strip()[:64]
        if not NAME_RE.match(new_name):
            return self.jsend(400, {'error': '名称只能用字母/数字/下划线/连字符，最多 32 位'})
        if not IP_RE.match(ip):
            return self.jsend(400, {'error': 'IP 或域名格式不对'})
        rec, err = fwd_edit(old, new_name, ip, note)
        if err:
            return self.jsend(409 if '占用' in err else 404, {'error': err})
        return self.jsend(200, {'ok': True, 'name': new_name, 'renamed': new_name != old})

    def do_upgrade(self, f):
        """快速创建后台任务；页面轮询持久结果，不占用长连接。"""
        name = f.get('name', '').strip()
        rec = fwd_get(name)
        if not rec:
            return self.jsend(404, {'error': '转发机不存在'})
        with lock:
            u = rec.get('upgrade') or {}
            if u.get('state') == 'running':
                return self.jsend(202, {'ok': True, 'upgrade': dict(u)})
            if not fwd_online(rec):
                return self.jsend(503, {'error': '转发机 %s 不在线，无法更新' % name})
            job = bus.submit(name, {'method': 'POST', 'path': '/__upgrade__',
                                   'body': '', 'ctype': '', 'csrf': ''})
            rec['upgrade'] = {'id': job['id'], 'state': 'running', 'started': now(),
                              'message': '更新中，等待转发机完成回执…'}
            u = dict(rec['upgrade'])
        safe_save()
        threading.Thread(target=wait_upgrade, args=(rec, job), daemon=True).start()
        return self.jsend(202, {'ok': True, 'upgrade': u})

class Srv(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def inject_back(html, base, name):
    """在代理过来的 att-tunnel 页面顶部加一条「返回面板」条。"""
    bar = ('<div style="position:sticky;top:0;z-index:99;display:flex;gap:12px;align-items:center;'
           'padding:8px 14px;background:#0f172a;color:#fff;font:14px system-ui">'
           '<a href="%s/" style="color:#93c5fd;text-decoration:none">← 返回面板</a>'
           '<b>转发机 %s</b></div>') % (PREFIX, name)
    i = html.lower().find('<body')
    if i < 0:
        return html
    j = html.find('>', i)
    if j < 0:
        return html
    return html[:j + 1] + bar + html[j + 1:]


def main():
    load_state()
    recover_upgrades()
    with lock:
        state['started'] = now()
    log('att-tunnel-hub 面板 v%s 启动，监听 %s:%d，路径 %s' % (VERSION, LISTEN, PORT, PREFIX))
    Srv((LISTEN, PORT), H).serve_forever()


if __name__ == '__main__':
    main()
