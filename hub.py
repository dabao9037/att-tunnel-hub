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
from html import escape as html_escape

import sshterm

VERSION = 'HUB_VERSION'
ENVF = os.environ.get('HUB_ENV', '/etc/att-hub/hub.env')
STATEF = os.environ.get('HUB_STATE', '/var/lib/att-hub/state.json')
SESSION_TTL = 12 * 3600
POLL_WAIT = 25.0          # agent long-poll 挂起上限
REQ_TIMEOUT = 360.0       # 普通代理请求上限；升级使用独立后台任务
UPGRADE_TIMEOUT = 660.0   # 下载60s + 安装600s（含 apt 装 dnsmasq），仅后台等待
UPGRADE_OK_TTL = 300      # 成功后「✓ 更新成功」保留 5 分钟；之后按钮恢复为「更新」
OFFLINE_AFTER = 45        # 超过这么多秒没 poll 视为离线
NAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
SUB_RE = re.compile(r'^[A-Za-z0-9_-]{20,64}$')     # att-tunnel 面板的订阅 token
IP_RE = re.compile(r'^[A-Za-z0-9.:_-]{3,253}$')
SSH_HOST_RE = re.compile(r'^[A-Za-z0-9._\-\[\]:]{3,253}$')
SSH_USER_RE = re.compile(r'^[A-Za-z0-9._-]{1,32}$')
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')


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
FWD_PORT = int(ENV.get('FWD_PORT', '0') or 0)          # /f/ 独立源监听端口（0=关闭）
FWD_ORIGIN = ENV.get('FWD_ORIGIN', '').rstrip('/')      # 例如 https://att.165789.xyz:8443
ALERT_TOKEN = ENV.get('ALERT_TOKEN', '')                # 邮件轮询器读取告警用
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


def reply_mac(rec, job_id, status, ctype, body):
    # 使用 agent 已持有的专属 token，避免新增密钥分发和旧状态迁移。
    key = str(rec.get('token') or '').encode()
    msg = '%s\n%s\n%s\n%s' % (job_id, int(status), ctype or '', body or '')
    return hmac.new(key, msg.encode('utf-8'), 'sha256').hexdigest()


def reply_verified(rec, job_id, status, ctype, body, mac):
    expected = reply_mac(rec, job_id, status, ctype, body)
    return bool(mac) and hmac.compare_digest(str(mac), expected)


def fwd_online(rec):
    return now() - int(rec.get('last_seen') or 0) <= OFFLINE_AFTER


def add_alert(machine, port, nbytes, action, detail=''):
    rec = {'id': secrets.token_urlsafe(12), 'ts': now(), 'machine': machine,
           'port': int(port), 'bytes': int(nbytes), 'action': action,
           'detail': str(detail)[:200]}
    with lock:
        q = state.setdefault('alerts', [])
        q.append(rec)
        del q[:-200]
    safe_save()
    return rec


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


def upgrade_sequence(names):
    """按顺序逐台更新，一台跑完再下一台，避免 5 台同时重启 att-tunnel。"""
    for name in names:
        with lock:
            rec = state['forwarders'].get(name)
            if not rec or not fwd_online(rec):
                log('全部更新：跳过 %s（离线或已删除）' % name)
                continue
            job = bus.submit(name, {'method': 'POST', 'path': '/__upgrade__',
                                    'body': '', 'ctype': '', 'csrf': ''})
            rec['upgrade'] = {'id': job['id'], 'state': 'running', 'started': now(),
                              'message': '更新中，等待转发机完成回执…'}
        safe_save()
        log('全部更新：开始 %s' % name)
        wait_upgrade(rec, job)
        log('全部更新：%s 结束（%s）' % (name, (rec.get('upgrade') or {}).get('state')))


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
                'ssh': n.get('ssh'),          # SSH 直装出口机的实时进度（来自转发机面板）
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
CSS = ''':root{
  --bg:#f3f4f6;--card:#fff;--card2:#f9fafb;--fg:#111827;--mut:#6b7280;--line:#e5e7eb;
  --pri:#2563eb;--pri2:#1d4ed8;--pri-soft:#eff6ff;--pri-line:#bfdbfe;
  --ok:#059669;--okb:#ecfdf5;--bad:#dc2626;--badb:#fef2f2;--warn:#b45309;--warnb:#fffbeb;
  --grad:linear-gradient(135deg,#2563eb,#4f46e5 55%,#7c3aed);
  --sh:0 1px 2px rgba(15,23,42,.04),0 4px 14px -10px rgba(15,23,42,.16);
  --sh2:0 16px 36px -18px rgba(15,23,42,.28);
  --r:16px;--sidebar:260px;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#0b1120;--card:#111827;--card2:#0f172a;--fg:#f3f4f6;--mut:#9ca3af;--line:#1f2937;
  --pri:#60a5fa;--pri2:#93c5fd;--pri-soft:#1e3a8a33;--pri-line:#1e40af;
  --ok:#34d399;--okb:#064e3b55;--bad:#f87171;--badb:#7f1d1d55;--warn:#fbbf24;--warnb:#78350f55;
  --sh:0 1px 2px #0006,0 10px 28px -16px #000a;--sh2:0 20px 44px -20px #000c;
}}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{font:14px/1.6 ui-sans-serif,system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
background:var(--bg);color:var(--fg);-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:
radial-gradient(900px 520px at 18% -12%,rgba(37,99,235,.08),transparent 62%),
radial-gradient(760px 460px at 102% -8%,rgba(124,58,237,.07),transparent 58%)}
@media(prefers-color-scheme:dark){body::before{background:
radial-gradient(900px 520px at 18% -12%,rgba(37,99,235,.12),transparent 62%),
radial-gradient(760px 460px at 102% -8%,rgba(124,58,237,.10),transparent 58%)}}
button,input,select,textarea{font:inherit;color:inherit}
a{color:inherit}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--line);
background:var(--card);color:var(--fg);padding:9px 14px;border-radius:10px;cursor:pointer;white-space:nowrap;
font-weight:500;text-decoration:none;line-height:1.2;transition:background .15s,border-color .15s,box-shadow .15s,transform .15s}
.btn:hover{background:var(--card2);border-color:#d1d5db;box-shadow:0 4px 12px -8px rgba(15,23,42,.25)}
@media(prefers-color-scheme:dark){.btn:hover{border-color:#374151}}
.btn:active{transform:translateY(1px)}
.btn:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid var(--pri);outline-offset:2px}
.btn.p{background:var(--pri);border-color:var(--pri);color:#fff;box-shadow:0 6px 16px -8px rgba(37,99,235,.65)}
.btn.p:hover{background:var(--pri2);border-color:var(--pri2);filter:none}
.btn.d{color:var(--bad)}
.btn.d:hover{border-color:var(--bad);background:var(--badb)}
.btn.ghost{background:transparent;border-color:transparent;color:var(--mut)}
.btn.ghost:hover{background:var(--card2);color:var(--fg);box-shadow:none}
.btn.s{padding:6px 10px;font-size:12.5px;border-radius:8px}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none;filter:none}
input,select,textarea{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card2);
transition:border-color .15s,box-shadow .15s}
input:focus,select:focus,textarea:focus{border-color:var(--pri);box-shadow:0 0 0 3px var(--pri-soft);outline:none}
label{display:block;font-size:12.5px;font-weight:600;color:var(--mut);margin:12px 0 5px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--sh)}
.mut{color:var(--mut)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.err{color:var(--bad)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border-radius:999px;font-size:11.5px;
font-weight:600;line-height:1.7;white-space:nowrap;border:1px solid transparent}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;flex:none}
.pill.on{color:var(--ok);background:var(--okb);border-color:color-mix(in srgb,var(--ok) 22%,transparent)}
.pill.on::before{animation:pulse 2.2s infinite}
.pill.off{color:var(--bad);background:var(--badb)}
.pill.w{color:var(--warn);background:var(--warnb)}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(5,150,105,.4)}70%{box-shadow:0 0 0 5px rgba(5,150,105,0)}100%{box-shadow:0 0 0 0 rgba(5,150,105,0)}}
@media(prefers-reduced-motion:reduce){.pill.on::before{animation:none}.btn,.fcard{transition:none}}
.app{display:flex;min-height:100vh}
.sidebar{width:var(--sidebar);flex:none;background:var(--card);border-right:1px solid var(--line);
padding:20px 14px 16px;display:flex;flex-direction:column;gap:18px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:11px;padding:2px 8px;text-decoration:none;color:var(--fg)}
.mark{width:42px;height:42px;border-radius:13px;background:var(--grad);display:grid;place-items:center;
font-size:20px;box-shadow:0 8px 18px -10px rgba(37,99,235,.6);flex:none}
.brand-txt{min-width:0}
.brand-txt b{display:block;font-size:15px;letter-spacing:-.01em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.brand-txt span{display:block;font-size:11.5px;color:var(--mut);margin-top:1px}
.nav{display:flex;flex-direction:column;gap:4px}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:10px;color:var(--mut);
text-decoration:none;font-size:14px;font-weight:500;transition:background .15s,color .15s}
.nav-item svg{width:18px;height:18px;flex:none}
.nav-item:hover{background:var(--card2);color:var(--fg)}
.nav-item.active{background:var(--pri-soft);color:var(--pri);font-weight:600}
.nav-count{margin-left:auto;font-size:11px;background:var(--card2);color:var(--mut);padding:1px 7px;
border-radius:999px;border:1px solid var(--line);font-variant-numeric:tabular-nums}
.nav-item.active .nav-count{background:var(--card);color:var(--pri);border-color:var(--pri-line)}
.side-note{margin-top:auto;background:var(--card2);border:1px solid var(--line);border-radius:14px;padding:12px 13px}
.side-note-title{font-size:12.5px;font-weight:600;display:flex;align-items:center;gap:7px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px var(--okb);flex:none}
.side-note p{margin:6px 0 0;font-size:11.5px;color:var(--mut);line-height:1.55}
.side-foot{display:flex;flex-direction:column;gap:8px}
.side-foot .btn{width:100%}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{min-height:72px;display:flex;align-items:center;justify-content:space-between;gap:14px;
padding:12px 28px;background:color-mix(in srgb,var(--card) 88%,transparent);backdrop-filter:blur(10px);
border-bottom:1px solid var(--line);position:sticky;top:0;z-index:10}
.page-head{min-width:0}
.page-head h1{font-size:21px;margin:0;letter-spacing:-.02em;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.ver{font-size:11px;font-weight:600;color:var(--pri);background:var(--pri-soft);padding:2px 8px;
border-radius:999px;letter-spacing:0;border:1px solid var(--pri-line)}
.page-head .sub{margin:3px 0 0;font-size:12.5px;color:var(--mut);overflow:hidden;text-overflow:ellipsis;max-width:min(620px,60vw)}
.acts{display:flex;gap:8px;flex-wrap:wrap;align-items:center;flex:none}
.content{width:100%;max-width:1280px;margin:0 auto;padding:24px 28px 48px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}
.stat{padding:16px 17px;display:grid;grid-template-columns:auto 1fr;gap:0 12px;align-items:center;position:relative;overflow:hidden}
.stat .ico{grid-row:1/4;width:42px;height:42px;border-radius:12px;background:var(--pri-soft);color:var(--pri);
display:grid;place-items:center;font-size:19px;flex:none}
.stat .ico svg{width:21px;height:21px}
.stat:nth-child(2) .ico{background:var(--okb)}
.stat:nth-child(3) .ico{background:#eef2ff}
@media(prefers-color-scheme:dark){.stat:nth-child(3) .ico{background:#312e8133}}
.stat:nth-child(4) .ico{background:#f5f3ff}
@media(prefers-color-scheme:dark){.stat:nth-child(4) .ico{background:#4c1d9533}}
.stat .lab{font-size:12.5px;font-weight:500;color:var(--mut);letter-spacing:.01em}
.stat b{font-size:25px;line-height:1.3;font-weight:700;letter-spacing:-.02em;font-variant-numeric:tabular-nums;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.stat .hint{font-size:11.5px;color:var(--mut);line-height:1.45}
.alert{padding:12px 15px;margin-bottom:16px;border-color:var(--bad);color:var(--bad);background:var(--badb);
display:none;white-space:pre-wrap;border-radius:12px}
.warnbox{padding:12px 15px;margin-bottom:16px;border-color:#fcd34d;color:var(--warn);background:var(--warnb);
display:none;white-space:pre-wrap;font-size:13px;border-radius:12px}
.sec{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;margin:0 0 14px}
.sec h3{font-size:16px;margin:0;letter-spacing:-.01em}
.sec-sub{margin:4px 0 0;font-size:12.5px;color:var(--mut)}
#meta{font-size:12px;color:var(--mut);white-space:nowrap}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(345px,1fr));gap:16px}
.fcard{padding:18px;display:flex;flex-direction:column;transition:box-shadow .2s,transform .2s,border-color .2s}
.fcard:hover{box-shadow:var(--sh2);transform:translateY(-2px);border-color:var(--pri-line)}
.fhead{display:flex;align-items:center;justify-content:space-between;gap:10px}
.fname{display:flex;align-items:center;gap:10px;min-width:0}
.avatar{width:38px;height:38px;border-radius:12px;background:var(--pri-soft);color:var(--pri);display:grid;
place-items:center;font-weight:700;font-size:15px;flex:none;text-transform:uppercase;border:1px solid var(--pri-line)}
.fhead h2{font-size:16px;margin:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;letter-spacing:-.01em}
.fmeta{font-size:12.5px;color:var(--mut);margin:9px 0 0;display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.metrics{display:grid;grid-template-columns:1fr 1fr;gap:12px 14px;margin:15px 0 0;padding:14px 0 0;
border-top:1px solid var(--line)}
.metric{min-width:0}
.metric span{display:block;font-size:11.5px;color:var(--mut);font-weight:500;letter-spacing:.01em}
.metric b{display:block;font-size:14px;font-weight:600;margin-top:2px;font-variant-numeric:tabular-nums;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.metric.wide{grid-column:1/-1}
.metric.wide b{white-space:normal;overflow:visible}
.nact{display:flex;flex-direction:column;gap:9px;margin-top:15px;padding-top:14px;border-top:1px solid var(--line)}
.nact .row{display:flex;gap:7px;flex-wrap:wrap;align-items:center}
.nact .row .grow{flex:1}
.mainbtn .btn{width:100%}
.upmsg{width:100%;font-size:12px;margin-top:9px;color:var(--mut);line-height:1.55}
.empty{padding:52px 22px;text-align:center;line-height:1.9;border-style:dashed;background:var(--card2)}
.empty b{display:block;font-size:16px;margin-bottom:2px}
.tblwrap{overflow:auto;padding:0}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{padding:12px 16px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{position:sticky;top:0;background:var(--card2);font-size:11px;color:var(--mut);font-weight:700;
text-transform:uppercase;letter-spacing:.05em;z-index:1}
tbody tr{transition:background .15s}
tbody tr:hover{background:var(--card2)}
tbody tr:last-child td{border-bottom:none}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.fwdcell{font-weight:600}
.fwdcell .mono{font-weight:400;margin-top:2px;color:var(--mut)}
dialog{border:1px solid var(--line);border-radius:18px;background:var(--card);color:var(--fg);padding:0;
width:min(620px,94vw);box-shadow:0 30px 80px -20px rgba(0,0,0,.45)}
dialog::backdrop{background:rgba(15,23,42,.5);backdrop-filter:blur(4px)}
.dh{padding:18px 22px;border-bottom:1px solid var(--line);font-weight:700;display:flex;align-items:center;gap:8px}
.db{padding:6px 22px 18px}
.df{padding:14px 22px;border-top:1px solid var(--line);display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap}
.copy{display:flex;gap:8px;align-items:flex-start;background:var(--card2);border:1px solid var(--line);
border-radius:10px;padding:10px 12px;margin-top:6px}
.copy .mono{flex:1;max-height:260px;overflow:auto}
#toasts{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:9px;z-index:20;
max-width:min(400px,92vw)}
.toast{padding:11px 15px;border-radius:10px;color:#fff;background:#111827;box-shadow:0 16px 40px -12px rgba(0,0,0,.4);
font-size:13.5px;animation:slideIn .25s ease}
.toast.ok{background:linear-gradient(135deg,#059669,#10b981)}
.toast.bad{background:linear-gradient(135deg,#b91c1c,#ef4444)}
@keyframes slideIn{from{transform:translateX(20px);opacity:0}to{transform:none;opacity:1}}
.login-wrap{min-height:100vh;display:grid;place-items:center;padding:24px}
.lg{width:min(420px,100%);padding:36px 32px 26px;position:relative;overflow:hidden}
.lg::before{content:"";position:absolute;inset:0 0 auto;height:4px;background:var(--grad)}
.lg .mark{width:52px;height:52px;border-radius:16px;font-size:25px;margin-bottom:18px}
.lg h1{font-size:22px;margin:0;letter-spacing:-.02em}
.lg .sub{margin:5px 0 20px;font-size:13px;color:var(--mut)}
.lg .btn{width:100%;margin-top:20px;padding:11px}
.foot{margin:18px 0 0;text-align:center;font-size:11.5px;color:var(--mut)}
@media(max-width:900px){
 .app{display:block}
 .sidebar{position:static;width:auto;height:auto;flex-direction:row;align-items:center;gap:10px;
 padding:10px 14px;border-right:0;border-bottom:1px solid var(--line);overflow-x:auto}
 .brand{padding:0;flex:none}
 .brand-txt b{font-size:14px}
 .nav{flex-direction:row;margin-left:auto;gap:2px}
 .nav-item{padding:8px 10px;font-size:13px;white-space:nowrap}
 .nav-item svg{width:16px;height:16px}
 .nav-count{display:none}
 .side-note{display:none}
 .side-foot{margin-left:4px;flex:none}
 .side-foot .btn{width:auto;padding:7px 9px;font-size:12px}
 .topbar{position:static;min-height:0;padding:14px;flex-wrap:wrap}
 .page-head .sub{max-width:100%}
 .acts{width:100%;display:flex;gap:8px}
 .acts .btn{flex:1;width:auto}
 .content{padding:16px 14px 36px}
 .stats{grid-template-columns:repeat(2,1fr);gap:10px}
 .stat{padding:13px;gap:0 10px}
 .stat .ico{width:36px;height:36px;font-size:17px}
 .stat b{font-size:21px}
 .stat .hint{display:none}
 .grid{grid-template-columns:1fr}
}
@media(max-width:560px){
 .brand-txt{display:none}
 .sec{align-items:flex-start;flex-direction:column;gap:4px}
 #meta{white-space:normal}
 .stats{gap:8px}
 .stat{padding:12px 10px}
 .stat b{font-size:19px}
}
'''

PAGE_LOGIN = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>登录 · att-tunnel-hub</title><style>{CSS}</style></head>
<body><div class="login-wrap"><form class="card lg" method="post" action="{P}/login"><div class="mark" aria-hidden="true">🛰️</div>
<h1>att-tunnel-hub</h1><p class="sub">转发机统一管理面板</p>{E}
<label for="pw">密码</label><input id="pw" type="password" name="password" autocomplete="current-password" required autofocus>
<button class="btn p" type="submit">登 录</button>
<p class="foot">安全登录 · 仅限授权用户</p></form></div></body></html>
'''
PAGE_MAIN = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>转发机 · att-tunnel-hub</title><style>{CSS}</style></head>
<body><div class="app">
<aside class="sidebar">
<a class="brand" href="{P}/"><div class="mark" aria-hidden="true">🛰️</div>
<div class="brand-txt"><b>att-tunnel-hub</b><span>v{V}</span></div></a>
<nav class="nav" aria-label="主导航">
<a class="nav-item active" href="{P}/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg><span>转发机</span><span class="nav-count" id="navFwd">—</span></a>
<a class="nav-item" href="{P}/nodes"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/></svg><span>落地节点</span><span class="nav-count" id="navNodes">—</span></a>
<a class="nav-item" href="{P}/ssh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3"/><path d="M13 15h4"/></svg><span>在线 SSH</span></a>
</nav>
<div class="side-note"><div class="side-note-title"><span class="dot"></span>面板运行中</div>
<p>统一管理转发机与落地节点，业务流量不经过面板机。</p></div>
<div class="side-foot"><form method="post" action="{P}/logout"><input type="hidden" name="csrf" value="{C}"><button class="btn ghost" type="submit">退出登录</button></form></div>
</aside>
<div class="main">
<header class="topbar"><div class="page-head"><h1>转发机</h1>
<p class="sub" id="hinfo">加载中…</p></div>
<div class="acts"><button class="btn" id="bRef" type="button">↻ 刷新</button>
<button class="btn" id="bUpAll" type="button">⇈ 全部更新</button>
<button class="btn p" id="bAdd" type="button">＋ 添加转发机</button></div></header>
<main class="content">
<div class="card alert" id="err" role="alert"></div>
<div class="stats" id="sum"></div>
<div class="sec"><div><h3>全部转发机</h3><p class="sec-sub">查看实时速率、落地节点数量与更新状态</p></div>
<span id="meta" aria-live="polite"></span></div>
<div class="grid" id="list"></div>
</main></div></div>
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
const P="{P}", C="{C}", FO="{FO}";
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
const SI={
fwd:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg>',
on:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
globe:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/></svg>',
chart:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19V5"/><path d="M4 19h16"/><path d="M8 16v-5"/><path d="M12 16V8"/><path d="M16 16v-3"/></svg>'};
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
    ? '<a class="btn p s" href="'+(FO||"")+P+'/f/'+encodeURIComponent(f.name)+'/">管理落地机</a>'
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
    const traffic=fs.reduce((s,f)=>s+(+((f.agent||{}).rx||0))+(+((f.agent||{}).tx||0)),0);
    const onlinePct=fs.length?Math.round(on/fs.length*100):0;
    $("#navFwd").textContent=fs.length;
    $("#navNodes").textContent=nodes;
    $("#sum").innerHTML=
      '<div class="stat card"><span class="ico" aria-hidden="true">'+SI.fwd+'</span><span class="lab">转发机</span><b>'+fs.length+'</b><span class="hint">已登记</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">'+SI.on+'</span><span class="lab">在线</span><b>'+on+'</b><span class="hint">在线率 '+onlinePct+'%</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">'+SI.globe+'</span><span class="lab">落地机（节点）</span><b>'+nodes+'</b><span class="hint">全部转发机合计</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">'+SI.chart+'</span><span class="lab">累计流量</span><b>'+fb(traffic)+'</b><span class="hint">↓ 入站 + ↑ 出站</span></div>';
    $("#hinfo").innerHTML='<span>面板地址 <span class="mono">'+esc(d.hub_url||"未配置")+'</span></span>';
    $("#list").innerHTML=fs.length?fs.map(card).join("")
      :'<div class="card empty"><b>还没有转发机</b><span class="mut">点右上角「＋ 添加转发机」填 IP，把生成的一键代码跑在那台机器上。</span></div>';
    $("#meta").textContent="更新于 "+new Date().toLocaleTimeString('zh-CN',{hour12:false});
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
const bUpAll=$("#bUpAll");
if(bUpAll)bUpAll.onclick=async()=>{
  if(!confirm('确认按顺序更新全部在线转发机？\\n\\n每台约 1-2 分钟，期间该机的落地机会短暂断开，完成后自动重连。'))return;
  bUpAll.disabled=true;bUpAll.textContent='排队中…';
  try{
    const j=await api("/api/upgrade_all",{});
    toast('已排队 '+j.queued.length+' 台：'+j.queued.join('、'),'ok',true);
  }catch(e){toast('全部更新未提交：'+e.message,'bad',true);}
  finally{bUpAll.disabled=false;bUpAll.textContent='⇈ 全部更新';}
};
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
<title>落地节点 · att-tunnel-hub</title><style>{CSS}</style></head>
<body><div class="app">
<aside class="sidebar">
<a class="brand" href="{P}/"><div class="mark" aria-hidden="true">🛰️</div>
<div class="brand-txt"><b>att-tunnel-hub</b><span>v{V}</span></div></a>
<nav class="nav" aria-label="主导航">
<a class="nav-item" href="{P}/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg><span>转发机</span><span class="nav-count" id="navFwd">—</span></a>
<a class="nav-item active" href="{P}/nodes"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/></svg><span>落地节点</span><span class="nav-count" id="navNodes">—</span></a>
<a class="nav-item" href="{P}/ssh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3"/><path d="M13 15h4"/></svg><span>在线 SSH</span></a>
</nav>
<div class="side-note"><div class="side-note-title"><span class="dot"></span>面板运行中</div>
<p>跨转发机汇总所有落地节点，数据来自各机实时上报。</p></div>
<div class="side-foot"><form method="post" action="{P}/logout"><input type="hidden" name="csrf" value="{C}"><button class="btn ghost" type="submit">退出登录</button></form></div>
</aside>
<div class="main">
<header class="topbar"><div class="page-head"><h1>落地节点</h1>
<p class="sub" id="hinfo">加载中…</p></div>
<div class="acts"><button class="btn" id="bRef" type="button">↻ 刷新</button></div></header>
<main class="content">
<div class="card alert" id="err" role="alert"></div>
<div class="card warnbox" id="warn"></div>
<div class="stats" id="sum"></div>
<div class="sec"><div><h3>所有落地节点</h3><p class="sec-sub">按转发机分组，显示出口 IP、入口端口与实时速率</p></div>
<span id="meta" aria-live="polite"></span></div>
<div class="card tblwrap" id="tbl"></div>
</main></div></div>
<div id="toasts" aria-live="polite"></div>
'''
PAGE_NODES += '''
<script>
const P="{P}", C="{C}", FO="{FO}";
const $=s=>document.querySelector(s);
function toast(m,k){const d=document.createElement("div");d.className="toast "+(k||"");d.textContent=m;
  $("#toasts").appendChild(d);setTimeout(()=>d.remove(),4200);}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function fb(n){n=+n||0;const u=["B","KB","MB","GB","TB","PB"];let i=0;
  while(n>=1024&&i<5){n/=1024;i++}return(i?n.toFixed(n<10?2:n<100?1:0):n)+" "+u[i];}
const SI={
fwd:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg>',
on:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
globe:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/></svg>',
chart:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19V5"/><path d="M4 19h16"/><path d="M8 16v-5"/><path d="M12 16V8"/><path d="M16 16v-3"/></svg>'};
function row(n){
  let cls=n.online?"on":"off", txt=n.online?"在线":"离线", tip=n.probe_err?' title="'+esc(n.probe_err)+'"':'';
  if(n.ssh&&!n.ssh.done){cls="w";txt="安装中 "+(+n.ssh.pct||0)+"%";tip=' title="'+esc((n.ssh.state||"")+" · "+(+n.ssh.elapsed||0)+" 秒")+'"';}
  else if(n.ssh&&n.ssh.done&&n.ssh.rc!==0){cls="off";txt="安装失败";tip=' title="'+esc("SSH 直装出口机失败（rc="+n.ssh.rc+"），到转发机面板点「查看链接」看日志")+'"';}
  const ip=n.ip?esc(n.ip):'<span class="mut">—</span>';
  return '<tr><td class="fwdcell">'+esc(n.fwd)+'<div class="mut mono">'+esc(n.fwd_ip)+'</div></td>'
    +'<td>'+esc(n.name)+'</td>'
    +'<td><span class="pill '+cls+'"'+tip+'>'+txt+'</span></td>'
    +'<td class="mono">'+ip+'</td>'
    +'<td class="num">'+esc(n.port)+'</td>'
    +'<td class="mono">'+esc(n.sni||"—")+'</td>'
    +'<td class="num">'+fb(n.total)+'</td>'
    +'<td class="num mut">'+((+n.rate_up||+n.rate_down)?'↑'+fb(n.rate_up)+'/s ↓'+fb(n.rate_down)+'/s':'—')+'</td>'
    +'<td><a class="btn s" href="'+(FO||"")+P+'/f/'+encodeURIComponent(n.fwd)+'/">管理</a></td></tr>';
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
    $("#navFwd").textContent=fs.length;
    $("#navNodes").textContent=ns.length;
    $("#sum").innerHTML=
      '<div class="stat card"><span class="ico" aria-hidden="true">'+SI.fwd+'</span><span class="lab">转发机</span><b>'+fs.length+'</b><span class="hint">已登记</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">'+SI.globe+'</span><span class="lab">落地节点</span><b>'+ns.length+'</b><span class="hint">全部节点</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">'+SI.on+'</span><span class="lab">节点在线</span><b>'+on+'</b><span class="hint">'+ns.length+' 个中在线</span></div>'
     +'<div class="stat card"><span class="ico" aria-hidden="true">'+SI.chart+'</span><span class="lab">累计流量</span><b>'+fb(total)+'</b><span class="hint">全部节点合计</span></div>';
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
    $("#meta").textContent="更新于 "+new Date().toLocaleTimeString('zh-CN',{hour12:false});
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


PAGE_SSH = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark">
<title>在线 SSH · att-tunnel-hub</title><style>{CSS}</style>
<link rel="stylesheet" href="{P}/static/xterm.css">
<style>
.sshform{display:grid;grid-template-columns:minmax(200px,2fr) 90px minmax(120px,1fr);gap:10px}
@media(max-width:760px){.sshform{grid-template-columns:1fr}}
.termscreen{position:fixed;inset:0;z-index:100;background:#0b1020;display:flex;flex-direction:column}
.termscreen[hidden],.textscreen[hidden]{display:none!important}
.termbar{flex:none;display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;background:#0f172a;border-bottom:1px solid #1e293b;color:#e5e7eb;flex-wrap:wrap}
.termtitle{display:flex;align-items:center;gap:10px;min-width:0}
.termtitle b{font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.termtitle span{font-size:12px;color:#94a3b8;white-space:nowrap}
.termacts{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.termbar .btn{background:#1e293b;color:#e5e7eb;border-color:#334155;padding:5px 9px;font-size:12px;border-radius:8px}
.termbar .btn:hover{border-color:#60a5fa}
.termwrap{flex:1;min-height:0;background:#0b1020;padding:6px;overflow:hidden;touch-action:pan-y;overscroll-behavior:contain}
#term{height:100%}#term .xterm{height:100%}
#term .xterm-viewport{overscroll-behavior:contain;touch-action:pan-y;-webkit-overflow-scrolling:touch}
.textscreen{position:fixed;inset:0;z-index:110;background:#0b1020;display:flex;flex-direction:column;color:#e5e7eb}
#selText{flex:1;width:100%;margin:0;padding:12px;border:0;outline:none;background:#0f172a;color:#e5e7eb;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;resize:none;white-space:pre;overflow:auto;-webkit-user-select:text;user-select:text}
body.term-mode{overflow:hidden}
@media(max-width:600px){.termbar{padding:6px 8px}.termbar b{font-size:13px}.termbar .btn{padding:4px 7px;font-size:11px}.termacts{gap:4px}}
</style></head>
<body><div class="app">
<aside class="sidebar">
<a class="brand" href="{P}/"><div class="mark" aria-hidden="true">🛰️</div>
<div class="brand-txt"><b>att-tunnel-hub</b><span>v{V}</span></div></a>
<nav class="nav" aria-label="主导航">
<a class="nav-item" href="{P}/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg><span>转发机</span><span class="nav-count" id="navFwd">—</span></a>
<a class="nav-item" href="{P}/nodes"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/></svg><span>落地节点</span><span class="nav-count" id="navNodes">—</span></a>
<a class="nav-item active" href="{P}/ssh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3"/><path d="M13 15h4"/></svg><span>在线 SSH</span></a>
</nav>
<div class="side-note"><div class="side-note-title"><span class="dot"></span>面板运行中</div>
<p>在浏览器里直接连服务器；凭据只用于本次会话，不保存。</p></div>
<div class="side-foot"><form method="post" action="{P}/logout"><input type="hidden" name="csrf" value="{C}"><button class="btn ghost" type="submit">退出登录</button></form></div>
</aside>
<div class="main">
<header class="topbar"><div class="page-head"><h1>在线 SSH</h1>
<p class="sub">输入 IP / 端口 / 用户名 / 密码，浏览器里直接开会话；不传文件</p></div></header>
<main class="content">
<div class="card" style="padding:18px">
<form id="fSsh" autocomplete="off">
<div style="display:flex;gap:8px;align-items:flex-end;margin-bottom:6px">
<div style="flex:1"><label for="sSaved">已保存的服务器</label><select id="sSaved"><option value="">选择已保存的服务器…</option></select></div>
<button class="btn s d" id="sDel" type="button" style="margin-bottom:1px">删除</button>
</div>
<div class="sshform">
<div><label for="sHost">服务器 IP / 域名</label><input id="sHost" required placeholder="1.2.3.4" autocomplete="off"></div>
<div><label for="sPort">端口</label><input id="sPort" value="22" inputmode="numeric" pattern="[0-9]{1,5}"></div>
<div><label for="sUser">用户名</label><input id="sUser" value="root" autocomplete="off"></div>
</div>
<label for="sPass">密码（勾选“记住”后保存在本浏览器）</label><input id="sPass" type="password" required autocomplete="new-password">
<label style="display:flex;align-items:center;gap:8px;color:var(--mut);font-size:13px;margin-top:8px"><input type="checkbox" id="sRemember" checked style="width:auto"> 记住这台服务器（密码只保存在本浏览器）</label>
<div class="acts" style="margin-top:12px">
<button class="btn p" id="sGo" type="submit">连接</button>
<button class="btn" id="sResume" type="button" hidden>继续上次会话</button>
<span id="sMsg" class="mut" style="font-size:13px;align-self:center"></span>
</div>
</form>
<p class="mut" style="font-size:12.5px;margin:12px 0 0">连接后进入全屏终端：上下滑动只在终端里滚动，不会带动网页；点「选择文本」可以用原生选择/复制。主机指纹首次连接自动接受；服务器不保存密码，勾选「记住」时密码只存在本浏览器 localStorage。</p>
</div>
</main></div></div>
<div id="termScreen" class="termscreen" hidden>
<div class="termbar"><div class="termtitle"><b id="termHost">SSH</b><span id="termMsg">连接中…</span></div>
<div class="termacts">
<button class="btn s" id="qIp" type="button" disabled title="bash <(curl -sL IP.Check.Place)">IP 检测</button>
<button class="btn s" id="qTq" type="button" disabled title="bash <(curl -fsSL https://raw.githubusercontent.com/ibsgss/TcpQuality/main/runTcpQuality.sh)">TQ</button>
<button class="btn s" id="cSel" type="button" disabled>复制选中</button>
<button class="btn s" id="cAll" type="button" disabled>复制全部</button>
<button class="btn s" id="cText" type="button" disabled>选择文本</button>
<button class="btn s" id="sDisc" type="button">断开</button>
</div></div>
<div id="termWrap" class="termwrap"><div id="term"></div></div>
</div>
<div id="textScreen" class="textscreen" hidden>
<div class="termbar"><b>选择文本</b><div class="termacts">
<button class="btn s" id="tAll" type="button">全选</button>
<button class="btn s" id="tCopy" type="button">复制选中</button>
<button class="btn s" id="tClose" type="button">关闭</button>
</div></div>
<textarea id="selText" readonly spellcheck="false"></textarea>
</div>
<div id="toasts" aria-live="polite"></div>
<script src="{P}/static/xterm.js"></script>
<script src="{P}/static/addon-fit.js"></script>
<script src="{P}/static/addon-webgl.js"></script>
<script>
const P="{P}",C="{C}";
const $=s=>document.getElementById(s);
function msg(t,k){const e=$("sMsg");e.textContent=t;e.className=(k==="bad")?"err":"mut";}
function tmsg(t,k){const e=$("termMsg");e.textContent=t;e.className=(k==="bad")?"err":"mut";}
async function post(u,b){const r=await fetch(P+u,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded","X-CSRF-Token":C},body:new URLSearchParams(b||{})});
if(r.status===401){location.href=P+"/";throw new Error("登录已过期")}let j={};try{j=await r.json()}catch(e){}
if(!r.ok||!j.ok)throw new Error(j.error||("HTTP "+r.status));return j}
function fallbackCopy(t){const a=document.createElement("textarea");a.value=t;document.body.appendChild(a);a.select();try{document.execCommand("copy");tmsg("已复制 "+t.length+" 字符")}catch(e){tmsg("复制失败，请手动选择","bad")}a.remove()}
function copyText(t){if(!t){tmsg("没有可复制的内容","bad");return}
 if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(()=>tmsg("已复制 "+t.length+" 字符"),()=>fallbackCopy(t))}else{fallbackCopy(t)}}
function allText(){if(!term)return "";const b=term.buffer.active;const a=[];for(let i=0;i<b.length;i++){const l=b.getLine(i);if(l)a.push(l.translateToString(true))}return a.join("\n").replace(/\s+$/,"")}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
const SKEY="ipcare-ssh-saved",LKEY="ipcare-ssh-last",RKEY="ipcare-ssh-resume";
function loadSaved(){try{return JSON.parse(localStorage.getItem(SKEY)||"[]")}catch(e){return []}}
function storeSaved(a){try{localStorage.setItem(SKEY,JSON.stringify(a))}catch(e){}}
function renderSaved(){const a=loadSaved(),sel=$("sSaved");sel.innerHTML='<option value="">选择已保存的服务器…</option>'+a.map((x,i)=>'<option value="'+i+'">'+esc(x.name||x.host)+' ('+esc(x.user)+'@'+esc(x.host)+':'+esc(x.port)+')</option>').join("");const last=localStorage.getItem(LKEY)||"";const idx=a.findIndex(x=>x.host+"|"+x.port+"|"+x.user===last);if(idx>=0)sel.value=String(idx)}
function fillRecord(x){if(!x)return;$("sHost").value=x.host||"";$("sPort").value=x.port||"22";$("sUser").value=x.user||"root";$("sPass").value=x.password||"";lastHost=x.host||"";lastPort=String(x.port||"22");lastUser=x.user||"root";lastPass=x.password||""}
function saveRecord(rec){const a=loadSaved(),key=rec.host+"|"+rec.port+"|"+rec.user;const i=a.findIndex(x=>x.host+"|"+x.port+"|"+x.user===key);if(i>=0)a[i]=rec;else a.push(rec);storeSaved(a);localStorage.setItem(LKEY,key);renderSaved();const j=a.findIndex(x=>x.host+"|"+x.port+"|"+x.user===key);if(j>=0)$("sSaved").value=String(j)}
function deleteRecord(){const a=loadSaved(),v=$("sSaved").value;if(v===""||!a[v]){msg("先选择一个已保存的服务器","bad");return}if(!confirm("删除记录 "+a[v].host+"？"))return;a.splice(v,1);storeSaved(a);renderSaved();$("sSaved").value="";msg("已删除")}
let ws=null,term=null,fit=null,ka=null;
let sid=null,received=0,stopped=false,retry=0,retryTimer=null,reconnectTries=0,connecting=false,hiddenAt=0;
let lastHost="",lastPort="22",lastUser="root",lastPass="";
function startKA(){stopKA();ka=setInterval(()=>{if(ws&&ws.readyState===1){try{ws.send(JSON.stringify({t:"p"}))}catch(e){}}},20000)}
function stopKA(){if(ka){clearInterval(ka);ka=null}}
function quick(on){["qIp","qTq"].forEach(id=>{const b=$(id);if(b)b.disabled=!on})}
function sendCmd(cmd){if(ws&&ws.readyState===1){ws.send(JSON.stringify({t:"i",d:cmd+"\n"}));term.focus()}}
function initTerm(){
 if(term)return;
 term=new Terminal({cursorBlink:true,fontSize:14,scrollback:2000,fontFamily:'ui-monospace,SFMono-Regular,Menlo,Consolas,monospace',theme:{background:'#0b1020',foreground:'#e5e7eb',cursor:'#93c5fd',selectionBackground:'#334155'},scrollback:5000});
 fit=new FitAddon.FitAddon();term.loadAddon(fit);term.open($("term"));
 try{const c=document.createElement("canvas");if(window.WebglAddon&&c.getContext("webgl2")){const wg=new WebglAddon.WebglAddon();term.loadAddon(wg);wg.onContextLoss(()=>{try{wg.dispose()}catch(e){}})}}catch(e){}
 const vp=term.element&&term.element.querySelector(".xterm-viewport");
 if(vp){const stopTouch=e=>e.stopPropagation();vp.addEventListener("touchstart",stopTouch,{passive:true});vp.addEventListener("touchmove",stopTouch,{passive:true});vp.addEventListener("touchend",()=>{try{term.focus()}catch(e){}},{passive:true})}
 term.onData(d=>{if(ws&&ws.readyState===1)ws.send(JSON.stringify({t:"i",d}))});
 term.onResize(({cols,rows})=>{if(ws&&ws.readyState===1)ws.send(JSON.stringify({t:"r",cols,rows}))});
 term.onSelectionChange(()=>{if($("cSel"))$("cSel").disabled=!term.hasSelection()});
 term.attachCustomKeyEventHandler(e=>{if(e.type==="keydown"&&(e.ctrlKey||e.metaKey)&&(e.key==="c"||e.key==="C")&&term.hasSelection()){copyText(term.getSelection());return false}return true});
 window.addEventListener("resize",()=>{if(term){try{fit.fit()}catch(e){}}});
}
function closeTerm(){$("textScreen").hidden=true;$("termScreen").hidden=true;document.body.classList.remove("term-mode");$("sGo").disabled=false;$("sGo").textContent="连接";$("sDisc").textContent="断开";msg("已断开");connecting=false}
function saveResume(){if(!sid)return;try{sessionStorage.setItem(RKEY,JSON.stringify({id:sid,host:lastHost,user:lastUser,port:lastPort}))}catch(e){}}
function loadResume(){try{return JSON.parse(sessionStorage.getItem(RKEY)||"null")}catch(e){return null}}
function scheduleReconnect(){if(stopped||!sid)return;clearTimeout(retryTimer);const d=Math.min(1000*Math.pow(2,Math.min(retry,4)),15000);retry++;retryTimer=setTimeout(()=>{if(!stopped&&sid)openSocket(true)},d)}
function reconnectNew(){if(stopped)return;if(!lastPass){tmsg("会话已过期，请重新连接","bad");$("sDisc").textContent="返回";stopped=true;return}tmsg("旧会话已过期，正在重新连接…");post("/api/ssh/connect",{host:lastHost,port:lastPort,user:lastUser,password:lastPass}).then(j=>{if(stopped)return;sid=j.id;received=0;reconnectTries=0;retry=0;term.reset();term.write("\r\n\x1b[33m[旧会话已过期，已重新连接]\x1b[0m\r\n");openSocket(false)}).catch(e=>{tmsg("重新连接失败："+e.message,"bad");$("sDisc").textContent="返回";stopped=true})}
function openSocket(resume){
 if(!sid||stopped)return;
 if(ws){try{ws.onclose=null;ws.close()}catch(e){}ws=null}
 const proto=(location.protocol==="https:")?"wss":"ws";
 const url=proto+"://"+location.host+P+"/ssh/ws?id="+encodeURIComponent(sid)+"&offset="+(resume?received:0)+"&cols="+term.cols+"&rows="+term.rows;
 const sock=new WebSocket(url);ws=sock;sock.binaryType="arraybuffer";
 sock.onopen=()=>{if(ws!==sock)return;retry=0;reconnectTries=0;clearTimeout(retryTimer);$("sDisc").textContent="断开";quick(true);$("cAll").disabled=false;$("cText").disabled=false;$("cSel").disabled=true;tmsg(resume?"已重新连接（同一个会话）":("已连接 "+lastUser+"@"+lastHost));fit.fit();startKA();sock.send(JSON.stringify({t:"r",cols:term.cols,rows:term.rows}));term.focus();saveResume()};
 sock.onmessage=e=>{if(ws!==sock)return;if(typeof e.data==="string"){term.write(e.data)}else{const b=new Uint8Array(e.data);received+=b.length;term.write(b)}};
 sock.onerror=()=>{};
 sock.onclose=()=>{if(ws!==sock)return;ws=null;stopKA();quick(false);if(stopped)return;if(!sid){tmsg("已断开","bad");return}reconnectTries++;if(reconnectTries>=4&&lastPass){reconnectNew();return}tmsg("连接中断，正在重连…","bad");scheduleReconnect()};
}
$("fSsh").onsubmit=async ev=>{
 ev.preventDefault();
 if(ws||connecting)return;
 const host=$("sHost").value.trim(),port=$("sPort").value.trim()||"22",user=$("sUser").value.trim()||"root",pass=$("sPass").value;
 if(!host||!pass){msg("请填 IP 和密码","bad");return}
 connecting=true;$("sGo").disabled=true;$("sGo").textContent="连接中…";msg("正在建立 SSH 会话…");
 stopped=false;clearTimeout(retryTimer);retry=0;reconnectTries=0;
 lastHost=host;lastPort=port;lastUser=user;lastPass=pass;
 try{
  const j=await post("/api/ssh/connect",{host,port,user,password:pass});
  sid=j.id;received=0;
  $("termHost").textContent=user+"@"+host;$("termScreen").hidden=false;document.body.classList.add("term-mode");
  initTerm();term.reset();
  await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));
  fit.fit();openSocket(false);saveResume();
  if($("sRemember").checked)saveRecord({name:host,host:host,port:port,user:user,password:pass});else $("sPass").value="";
 }catch(x){msg("连接失败："+x.message,"bad");$("termScreen").hidden=true;document.body.classList.remove("term-mode");$("sGo").disabled=false;$("sGo").textContent="连接";connecting=false}
};
$("sSaved").onchange=()=>{const a=loadSaved(),v=$("sSaved").value;if(v!=="")fillRecord(a[+v])};
$("sDel").onclick=deleteRecord;
$("sResume").onclick=()=>{const r=loadResume();if(!r)return;sid=r.id;received=0;stopped=false;reconnectTries=0;retry=0;lastHost=r.host||"";lastPort=r.port||"22";lastUser=r.user||"root";const rec=loadSaved().find(x=>x.host===lastHost&&String(x.port)===String(lastPort)&&x.user===lastUser);lastPass=rec?rec.password||"":"";$("termHost").textContent=lastUser+"@"+lastHost;$("sHost").value=lastHost;$("sPort").value=lastPort;$("sUser").value=lastUser;$("termScreen").hidden=false;document.body.classList.add("term-mode");initTerm();term.reset();requestAnimationFrame(()=>requestAnimationFrame(()=>{fit.fit();openSocket(true)}))};
$("sDisc").onclick=()=>{stopped=true;clearTimeout(retryTimer);stopKA();if(ws){try{ws.send(JSON.stringify({t:"bye"}))}catch(e){};try{ws.close()}catch(e){};ws=null}sid=null;received=0;sessionStorage.removeItem(RKEY);$("sResume").hidden=true;closeTerm()};
$("cSel").onclick=()=>copyText(term&&term.getSelection());
$("cAll").onclick=()=>copyText(allText());
$("cText").onclick=()=>{$("selText").value=allText();$("textScreen").hidden=false;setTimeout(()=>{const a=$("selText");a.focus();a.scrollTop=a.scrollHeight},50)};
$("tAll").onclick=()=>{const a=$("selText");a.focus();a.select()};
$("tCopy").onclick=()=>{const a=$("selText");const s=a.value.substring(a.selectionStart,a.selectionEnd);copyText(s||a.value)};
$("tClose").onclick=()=>{$("textScreen").hidden=true;if(term)term.focus()};
$("qIp").onclick=()=>sendCmd("bash <(curl -sL IP.Check.Place)");
$("qTq").onclick=()=>sendCmd("bash <(curl -fsSL https://raw.githubusercontent.com/ibsgss/TcpQuality/main/runTcpQuality.sh)");
document.addEventListener("visibilitychange",()=>{if(document.hidden){hiddenAt=Date.now();saveResume();return}if(stopped||!sid)return;if(hiddenAt&&Date.now()-hiddenAt>8000){try{ws&&ws.close()}catch(e){}ws=null;retry=0;openSocket(true);return}if(!ws||ws.readyState!==1){retry=0;clearTimeout(retryTimer);openSocket(true)}else{try{ws.send(JSON.stringify({t:"p"}))}catch(e){};try{fit.fit()}catch(e){};term.focus()}});
window.addEventListener("online",()=>{if(!stopped&&sid&&(!ws||ws.readyState!==1)){retry=0;openSocket(true)}});
window.addEventListener("beforeunload",()=>{saveResume();stopKA();if(ws){try{ws.send(JSON.stringify({t:"unload"}))}catch(e){};ws.close()}});
setInterval(()=>{if(ws&&ws.readyState===1)saveResume()},5000);
renderSaved();
const __saved=loadSaved();
if(__saved.length){const v=$("sSaved").value;fillRecord(v!==""?__saved[+v]:__saved[0])}
const __resume=loadResume();if(__resume){$("sResume").hidden=false;msg("有上次未结束的会话，可点「继续上次会话」")}

</script></body></html>
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
            route = self.route() or ''
            if 'html' in (ctype or '').lower() and route.startswith('/f/'):
                # 代理的是转发机本机的 att-tunnel 面板，它必须跑自己的内联脚本；
                # 这里禁止外部加载/外联，真正的同源隔离需要独立域名（见部署说明）。
                policy = ("default-src 'self' data:; script-src 'self' 'unsafe-inline'; "
                          "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                          "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                          "form-action 'self'; frame-ancestors 'none'")
            elif 'html' in (ctype or '').lower():
                nonce = secrets.token_urlsafe(18)
                host = self.headers.get('Host') or ''
                ws = (' ws://%s wss://%s' % (host, host)
                      if re.fullmatch(r'[A-Za-z0-9.:\[\]-]+', host) else '')
                body = re.sub(r'<script(?=[\s>])', '<script nonce="%s"' % nonce, body)
                policy = (
                    "default-src 'none'; script-src 'self' 'nonce-%s'; "
                    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                    "font-src 'self' data:; connect-src 'self'%s; "
                    "object-src 'none'; base-uri 'none'; form-action 'self'; "
                    "frame-ancestors 'none'" % (nonce, ws))
            else:
                policy = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            extra = list(extra) + [('Content-Security-Policy', policy)]
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def jsend(self, code, obj):
        self.send(code, json.dumps(obj, ensure_ascii=False), 'application/json; charset=utf-8')

    def send_static(self, r):
        name = r[len('/static/'):]
        if name not in ('xterm.js', 'xterm.css', 'addon-fit.js', 'addon-webgl.js'):
            return self.send(404, 'Not Found', 'text/plain')
        path = os.path.join(STATIC_DIR, name)
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except OSError:
            return self.send(404, 'Not Found', 'text/plain')
        ctype = ('text/css; charset=utf-8' if name.endswith('.css')
                 else 'application/javascript; charset=utf-8')
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'public, max-age=86400')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

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

    def alert_auth(self):
        tok = self.headers.get('X-Alert-Token') or ''
        return bool(ALERT_TOKEN) and hmac.compare_digest(tok.encode(), ALERT_TOKEN.encode())

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
        tok = self.agent_token()
        if tok:
            # 带 Bearer 时先验身份再解析请求体；老 agent 没有这个头，退回表单 token。
            name, rec = fwd_by_token(tok)
            f = self.form(raw) if rec else None
        else:
            f = self.form(raw)
            name, rec = fwd_by_token(f.get('token', ''))
        if not rec:
            time.sleep(0.5)
            return self.jsend(401, {'error': 'bad token'})
        if r == '/agent/quota':
            try:
                port = int(f.get('port') or 0)
                nbytes = int(f.get('bytes') or 0)
            except ValueError:
                return self.jsend(400, {'error': 'bad port/bytes'})
            action = (f.get('action') or 'block')[:32]
            rec2 = add_alert(name, port, nbytes, action, f.get('detail', ''))
            log('配额告警：%s 端口 %s 用量 %s 动作 %s' % (name, port, nbytes, action))
            return self.jsend(200, {'ok': True, 'id': rec2['id']})
        if r == '/agent/poll':
            with lock:
                rec['last_seen'] = now()
                info = {}
                for k in ('web', 'web_path', 'ver', 'ip', 'nodes', 'xray',
                          'rx', 'tx', 'rate_rx', 'rate_tx', 'guard', 'quota'):
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
            body = f.get('body', '')
            ctype = f.get('ctype', 'text/plain; charset=utf-8')
            if not reply_verified(rec, jid, code, ctype, body, f.get('mac')):
                return self.jsend(403, {'error': 'invalid reply signature'})
            with bus.cv:
                job = bus.jobs.get(jid)
                if not job or job.get('fwd') != name:
                    return self.jsend(404, {'error': 'job not found'})
            bus.answer(jid, {'status': code, 'body': body, 'ctype': ctype,
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
        if FWD_ORIGIN and not getattr(self, 'ISOLATED', False) and r.startswith('/f/'):
            # 主源不再承载代理 HTML；统一跳到独立源，避免同源脚本执行
            q = urllib.parse.urlsplit(self.path).query
            return self.redirect(FWD_ORIGIN + PREFIX + r + (('?' + q) if q else ''))
        if r.startswith('/static/'):
            return self.send_static(r)
        if r == '/alerts/pending':
            if not self.alert_auth():
                return self.jsend(403, {'error': 'forbidden'})
            with lock:
                q = list(state.get('alerts') or [])
            return self.jsend(200, {'alerts': q})
        sid, s = self.session()
        if r == '/':
            if not s:
                return self.login_page(200)
            page = (PAGE_MAIN.replace('{CSS}', CSS).replace('{P}', PREFIX)
                    .replace('{C}', s['csrf']).replace('{V}', VERSION)
                    .replace('{FO}', FWD_ORIGIN))
            return self.send(200, page)
        if r == '/api/status':
            if not s:
                return self.jsend(401, {'error': 'unauthorized'})
            return self.jsend(200, status_json())
        if r == '/nodes':
            if not s:
                return self.login_page(200)
            page = (PAGE_NODES.replace('{CSS}', CSS).replace('{P}', PREFIX)
                    .replace('{C}', s['csrf']).replace('{V}', VERSION)
                    .replace('{FO}', FWD_ORIGIN))
            return self.send(200, page)
        if r == '/ssh':
            if not s:
                return self.login_page(200)
            page = (PAGE_SSH.replace('{CSS}', CSS).replace('{P}', PREFIX)
                    .replace('{C}', s['csrf']).replace('{V}', VERSION))
            return self.send(200, page)
        if r == '/ssh/ws':
            if not s:
                return self.send(403, '请先登录', 'text/plain; charset=utf-8')
            return sshterm.handle_ws(self)
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
        if r in ('/agent/poll', '/agent/reply', '/agent/quota'):
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
        if r == '/alerts/ack':
            if not self.alert_auth():
                return self.jsend(403, {'error': 'forbidden'})
            f = self.form(raw)
            ids = {x for x in (f.get('ids') or '').split(',') if x}
            with lock:
                state['alerts'] = [a for a in (state.get('alerts') or [])
                                   if a.get('id') not in ids]
            safe_save()
            return self.jsend(200, {'ok': True, 'left': len(state.get('alerts') or [])})
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
        if r == '/api/ssh/connect':
            return self.do_ssh_connect(f)
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
        if r == '/api/upgrade_all':
            return self.do_upgrade_all(f)
        return self.send(404, 'Not Found', 'text/plain')

    def do_ssh_connect(self, f):
        host = (f.get('host') or '').strip()
        port = (f.get('port') or '22').strip()
        user = (f.get('user') or 'root').strip()
        pw = f.get('password') or ''
        if not SSH_HOST_RE.match(host):
            return self.jsend(400, {'error': '服务器 IP / 域名格式不对'})
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            return self.jsend(400, {'error': '端口必须是 1-65535'})
        if not SSH_USER_RE.match(user):
            return self.jsend(400, {'error': 'SSH 用户名格式不对'})
        if not pw:
            return self.jsend(400, {'error': '请填 SSH 密码'})
        if '\n' in pw or '\r' in pw:
            return self.jsend(400, {'error': '密码里不能有换行'})
        sid = sshterm.new_session(host, int(port), user, pw)
        return self.jsend(200, {'ok': True, 'id': sid})

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

    def do_upgrade_all(self, f):
        """把所有在线且不在更新中的转发机排进顺序更新队列。"""
        with lock:
            targets = [name for name, rec in state['forwarders'].items()
                       if fwd_online(rec) and (rec.get('upgrade') or {}).get('state') != 'running']
        if not targets:
            return self.jsend(409, {'error': '没有可更新的转发机（全部离线或正在更新）'})
        threading.Thread(target=upgrade_sequence, args=(targets,), daemon=True).start()
        return self.jsend(202, {'ok': True, 'queued': targets})

class Srv(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def inject_back(html, base, name):
    """在代理过来的 att-tunnel 页面顶部加一条「返回面板」条。"""
    bar = ('<div style="position:sticky;top:0;z-index:99;display:flex;gap:12px;align-items:center;'
           'padding:8px 14px;background:#0f172a;color:#fff;font:14px system-ui">'
           '<a href="%s/" style="color:#93c5fd;text-decoration:none">← 返回面板</a>'
           '<b>转发机 %s</b></div>') % (HUB_URL, html_escape(name))
    i = html.lower().find('<body')
    if i < 0:
        return html
    j = html.find('>', i)
    if j < 0:
        return html
    return html[:j + 1] + bar + html[j + 1:]


class HF(H):
    """独立源监听：只服务 /f/ 代理路径，其余一律 404。"""

    ISOLATED = True

    def route(self):
        r = super().route()
        return r if r and r.startswith('/f/') else None


def main():
    load_state()
    recover_upgrades()
    with lock:
        state['started'] = now()
    log('att-tunnel-hub 面板 v%s 启动，监听 %s:%d，路径 %s' % (VERSION, LISTEN, PORT, PREFIX))
    if FWD_PORT:
        fwd = Srv(('127.0.0.1', FWD_PORT), HF)
        threading.Thread(target=fwd.serve_forever, daemon=True).start()
        log('代理独立源监听 127.0.0.1:%d，外部入口 %s' % (FWD_PORT, FWD_ORIGIN or '(未配置)'))
    Srv((LISTEN, PORT), H).serve_forever()


if __name__ == '__main__':
    main()
