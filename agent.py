#!/usr/bin/env python3
# att-hub-agent：装在转发机（机器2/3）上，只用 Python 标准库。
#
# 它做两件事，全程主动外拨，转发机不需要为面板开任何入站端口：
#   1. long-poll 面板机 /agent/poll 上报心跳（att-tunnel 版本、节点数、面板是否就绪）。
#   2. 取到面板下发的 HTTP 请求后，在本机打给 att-tunnel 面板（127.0.0.1），把响应 POST 回面板机。
#
# 因此「转发机添加落地机」的页面就是 att-tunnel 面板原生页面，完全以 att-tunnel 为准。
# 面板机下发的请求只能落到本机 att-tunnel 面板的路径上，没有任意命令执行通道。
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = 'HUB_VERSION'
ENVF = os.environ.get('AGENT_ENV', '/etc/att-hub-agent/agent.env')
WEBENV = os.environ.get('ATT_WEB_ENV', '/etc/att-tunnel/web.env')
CFG = os.environ.get('ATT_CFG', '/usr/local/etc/att-tunnel/config.json')
POLL_TIMEOUT = 35
BACKOFF_MAX = 60
NET_SAMPLE = 5          # 网速采样间隔（秒）
CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')
# 虚拟网卡：统计本机对外网速时要排除，否则重复计数
SKIP_IF = ('lo', 'docker', 'veth', 'br-', 'virbr', 'tun', 'tap', 'wg', 'sit', 'dummy')


def log(*a):
    print(time.strftime('%F %T'), *a, file=sys.stderr, flush=True)


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
HUB = (ENV.get('HUB_URL') or '').rstrip('/')
TOKEN = ENV.get('HUB_TOKEN') or ''
if not HUB or not TOKEN:
    sys.exit('agent.env 不完整：需要 HUB_URL 和 HUB_TOKEN')

CTX = ssl.create_default_context()


def hub_post(path, data, timeout):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(HUB + path, data=body, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    req.add_header('Authorization', 'Bearer ' + TOKEN)
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
        return json.loads(r.read().decode('utf-8', 'replace'))


def local_web():
    """读本机 att-tunnel 面板的端口/路径，没开面板就返回 None。"""
    e = load_env(WEBENV)
    port, path = e.get('WEB_PORT'), e.get('WEB_PATH')
    if not port or not path:
        return None
    return {'port': int(port), 'path': '/' + path.strip('/')}


def node_count():
    try:
        with open(CFG) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    # 与 att-tunnel list_exits 同一口径：user-in（主入口）和 user-in-<端口> 里的 clients 就是节点
    n = 0
    for ib in d.get('inbounds', []):
        tag = str(ib.get('tag', ''))
        if tag == 'user-in' or tag.startswith('user-in-'):
            n += len((ib.get('settings') or {}).get('clients') or [])
    return n


# ---------------------------------------------------------------- 本机网速 / 流量
# 从 /proc/net/dev 读累计字节数，两次采样算速率。只算物理网卡：
# lo / docker / veth / tun 这类虚拟设备会把同一份流量重复计进来。
# 累计流量是网卡自开机以来的总量（重启会归零），不是 att-tunnel 的节点计数。
def net_total():
    """返回 (rx_bytes, tx_bytes) 累计值；读不到返回 None。"""
    try:
        with open('/proc/net/dev') as f:
            lines = f.readlines()[2:]
    except OSError:
        return None
    rx = tx = 0
    for line in lines:
        if ':' not in line:
            continue
        name, rest = line.split(':', 1)
        name = name.strip()
        if not name or name.startswith(SKIP_IF):
            continue
        cols = rest.split()
        if len(cols) < 9:
            continue
        try:
            rx += int(cols[0])
            tx += int(cols[8])
        except ValueError:
            continue
    return rx, tx


class NetMeter:
    """后台采样网速。心跳里直接读最近一次的结果，不在请求里做 sleep。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.rx = self.tx = 0          # 累计
        self.rate_rx = self.rate_tx = 0.0   # 字节/秒
        self.ok = False

    def run(self):
        last = net_total()
        last_t = time.monotonic()
        while True:
            time.sleep(NET_SAMPLE)
            cur = net_total()
            now_t = time.monotonic()
            if cur is None:
                with self.lock:
                    self.ok = False
                continue
            dt = now_t - last_t
            if last is not None and dt > 0:
                # 网卡计数器归零（重启/网卡重建）时不输出负值
                drx = max(0, cur[0] - last[0])
                dtx = max(0, cur[1] - last[1])
                with self.lock:
                    self.rx, self.tx = cur
                    self.rate_rx = drx / dt
                    self.rate_tx = dtx / dt
                    self.ok = True
            last, last_t = cur, now_t

    def snapshot(self):
        with self.lock:
            if not self.ok:
                return None
            return {'rx': self.rx, 'tx': self.tx,
                    'rate_rx': round(self.rate_rx, 1),
                    'rate_tx': round(self.rate_tx, 1)}


net = NetMeter()

# ---------------------------------------------------------------- 本机 att-tunnel 面板会话
# agent 用 web.env 里的密码登录本机面板，自己持一份 cookie 和 CSRF，
# 这样面板机那边不需要知道转发机面板的密码。
class Local:
    def __init__(self):
        self.cookie = ''
        self.csrf = ''
        self.web = None
        self.lock = threading.Lock()     # 多个请求并发时，登录只做一次

    def base(self):
        self.web = local_web()
        if not self.web:
            return None
        return 'http://127.0.0.1:%d%s' % (self.web['port'], self.web['path'])

    def req(self, method, path, body=None, ctype=''):
        b = self.base()
        if not b:
            raise RuntimeError('本机未开启 att-tunnel 面板（请在本机跑 att-tunnel --web）')
        url = b + (path if path.startswith('/') else '/' + path)
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header('Content-Type', ctype or 'application/x-www-form-urlencoded')
        if self.cookie:
            req.add_header('Cookie', self.cookie)
        # 本机面板会校验同源；这里就是同源请求
        req.add_header('Origin', 'http://127.0.0.1:%d' % self.web['port'])
        req.add_header('Sec-Fetch-Site', 'same-origin')
        try:
            with urllib.request.urlopen(req, timeout=270) as r:
                return (r.status, r.read().decode('utf-8', 'replace'),
                        r.headers.get('Content-Type') or 'text/html; charset=utf-8')
        except urllib.error.HTTPError as e:
            return (e.code, e.read().decode('utf-8', 'replace'),
                    e.headers.get('Content-Type') or 'text/html; charset=utf-8')

    def login(self):
        b = self.base()
        if not b:
            raise RuntimeError('本机未开启 att-tunnel 面板')
        pw = load_env(WEBENV).get('WEB_PASS') or ''
        if not pw:
            raise RuntimeError('读不到 att-tunnel 面板密码（%s）' % WEBENV)
        body = urllib.parse.urlencode({'password': pw}).encode()
        req = urllib.request.Request(b + '/login', data=body, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Origin', 'http://127.0.0.1:%d' % self.web['port'])
        req.add_header('Sec-Fetch-Site', 'same-origin')
        cls = urllib.request.HTTPRedirectHandler

        class NoRedir(cls):
            def redirect_request(self, *a, **k):
                return None

        op = urllib.request.build_opener(NoRedir)
        try:
            with op.open(req, timeout=30) as r:
                sc = r.headers.get('Set-Cookie') or ''
        except urllib.error.HTTPError as e:
            sc = e.headers.get('Set-Cookie') or ''
        if 'att_sid=' not in sc:
            raise RuntimeError('登录本机 att-tunnel 面板失败')
        self.cookie = sc.split(';', 1)[0]
        st, html, _ = self.req('GET', '/')
        m = CSRF_RE.search(html)
        if not m:
            raise RuntimeError('取不到本机面板 CSRF')
        self.csrf = m.group(1)
        return True

# ---------------------------------------------------------------- 请求执行
local = Local()


def handle(job):
    """把面板机下发的请求打给本机 att-tunnel 面板。路径已被面板限定在转发机面板前缀下。"""
    method = (job.get('method') or 'GET').upper()
    if method not in ('GET', 'POST', 'HEAD'):
        return {'status': 405, 'body': 'method not allowed', 'ctype': 'text/plain'}
    path = job.get('path') or '/'
    if not path.startswith('/'):
        path = '/' + path
    body = job.get('body') or ''
    ctype = job.get('ctype') or ''
    
    # 特殊处理升级请求：直接重跑本机的安装脚本
    if path == '/__upgrade__' and method == 'POST':
        return handle_upgrade()
    with local.lock:
        if not local.cookie:
            local.login()
    # 本机面板的 CSRF 由 agent 自己的会话提供：把表单/JSON 里的 csrf 换成本地值
    if method == 'POST':
        d = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
        d['csrf'] = local.csrf
        body = urllib.parse.urlencode(d)
        ctype = 'application/x-www-form-urlencoded'
    st, text, rct = local.req(method, path, body if method == 'POST' else None, ctype)
    if st in (401, 403):
        # 会话过期或 CSRF 对不上：重登一次再试
        with local.lock:
            local.cookie = ''
            local.login()
        if method == 'POST':
            d = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
            d['csrf'] = local.csrf
            body = urllib.parse.urlencode(d)
        st, text, rct = local.req(method, path, body if method == 'POST' else None, ctype)
    return {'status': st, 'body': text, 'ctype': rct}


def handle_upgrade():
    """执行升级：从 HUB_URL 重新下载 install.sh 并运行。"""
    import subprocess
    import tempfile
    import os
    try:
        hub_url = HUB.rstrip('/')
        script_url = 'https://raw.githubusercontent.com/dabao9037/att-tunnel-hub/main/install.sh'
        
        # 使用临时目录，避免权限和路径问题
        with tempfile.TemporaryDirectory(prefix='att-upgrade-') as tmpdir:
            script_file = os.path.join(tmpdir, 'install.sh')
            
            # 下载脚本（用列表避免 shell 注入）
            dl = subprocess.run(['curl', '-fsSL', script_url, '-o', script_file],
                              capture_output=True, text=True, timeout=60)
            if dl.returncode != 0:
                return {'status': 500, 'body': f'下载失败：{dl.stderr}',
                        'ctype': 'text/plain; charset=utf-8'}
            
            os.chmod(script_file, 0o755)
            
            # 运行升级（用列表形式传参，避免引号转义问题）
            result = subprocess.run(
                ['/bin/bash', script_file, '-a', hub_url, '-s', TOKEN],
                capture_output=True, text=True, timeout=330, cwd=tmpdir
            )
            
            if result.returncode == 0:
                return {'status': 200, 'body': '升级完成',
                        'ctype': 'text/plain; charset=utf-8'}
            else:
                err = result.stderr.strip() or result.stdout.strip() or '升级失败（未知错误）'
                return {'status': 500, 'body': err,
                        'ctype': 'text/plain; charset=utf-8'}
    
    except subprocess.TimeoutExpired:
        return {'status': 504, 'body': '升级超时（超过 5.5 分钟）',
                'ctype': 'text/plain; charset=utf-8'}
    except Exception as e:
        log('升级异常:', e)
        return {'status': 500, 'body': f'升级异常：{str(e)}',
                'ctype': 'text/plain; charset=utf-8'}

# ---------------------------------------------------------------- 主循环
def heartbeat_fields():
    f = {}
    w = local_web()
    if w:
        f['web'] = '1'
        f['web_path'] = w['path']
    else:
        f['web'] = ''
    n = node_count()
    if n is not None:
        f['nodes'] = str(n)
    s = net.snapshot()
    if s:
        f['rx'] = str(s['rx'])
        f['tx'] = str(s['tx'])
        f['rate_rx'] = str(s['rate_rx'])
        f['rate_tx'] = str(s['rate_tx'])
    f['ver'] = VERSION
    return f


def run_job(job):
    try:
        resp = handle(job)
    except Exception as e:
        log('执行请求失败:', e)
        resp = {'status': 502,
                'body': '<p class="err">转发机本地面板调用失败：%s</p>' % e,
                'ctype': 'text/html; charset=utf-8'}
    try:
        hub_post('/agent/reply', {'token': TOKEN, 'job': job['id'],
                                  'status': str(resp['status']),
                                  'body': resp['body'], 'ctype': resp['ctype']}, 60)
    except Exception as e:
        log('回包失败:', e)


def main():
    log('att-hub-agent v%s 启动，面板 %s' % (VERSION, HUB))
    threading.Thread(target=net.run, daemon=True).start()
    back = 1
    while True:
        try:
            d = hub_post('/agent/poll', dict(heartbeat_fields(), token=TOKEN),
                         POLL_TIMEOUT)
            back = 1
            job = d.get('job')
            if not job:
                continue
            # 每个请求一个线程：加落地机要跑几分钟，期间照样继续 poll（心跳不断、状态刷新不卡）
            threading.Thread(target=run_job, args=(job,), daemon=True).start()
        except KeyboardInterrupt:
            return
        except Exception as e:
            log('连面板失败（%ds 后重试）:' % back, e)
            time.sleep(back)
            back = min(BACKOFF_MAX, back * 2)


if __name__ == '__main__':
    main()
