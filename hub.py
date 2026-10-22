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
REQ_TIMEOUT = 280.0       # 代理请求等 agent 回包的上限（att-tunnel 加节点脚本最长 240s）
OFFLINE_AFTER = 45        # 超过这么多秒没 poll 视为离线
NAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
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
        })
    return {
        'version': VERSION,
        'started': state.get('started') or 0,
        'now': now(),
        'hub_url': HUB_URL,
        'forwarders': out,
    }

# ---------------------------------------------------------------- 一键代码
def agent_cmd(rec):
    """转发机（机器2/3）跟的一键代码：装 att-tunnel A 端 + agent。"""
    url = RAW_URL or 'https://raw.githubusercontent.com/dabao9037/att-tunnel-hub/main/install.sh'
    hub = HUB_URL or '(面板外网地址未配置)'
    return ('bash <(curl -fsSL %s) --forwarder %s %s'
            % (url, hub, rec['token']))


def status_line(rec):
    if not rec.get('last_seen'):
        return '待安装'
    return '在线' if fwd_online(rec) else '离线'

# ---------------------------------------------------------------- 页面（样式与 att-tunnel 面板同源）
CSS = '''
:root{--bg:#f3f5f9;--card:#fff;--fg:#0f172a;--mut:#64748b;--line:#e2e8f0;--pri:#2563eb;--pri2:#1d4ed8;
--ok:#16a34a;--okb:#dcfce7;--bad:#dc2626;--badb:#fee2e2;--warn:#b45309;--warnb:#fef3c7;--sh:0 1px 3px #0f172a14,0 4px 16px #0f172a0d}
@media(prefers-color-scheme:dark){:root{--bg:#0b1020;--card:#141b2d;--fg:#e2e8f0;--mut:#94a3b8;--line:#243049;
--pri:#3b82f6;--pri2:#60a5fa;--ok:#4ade80;--okb:#14532d66;--bad:#f87171;--badb:#7f1d1d66;--warn:#fbbf24;--warnb:#78350f66;--sh:0 1px 3px #0006}}
*{box-sizing:border-box}html,body{margin:0}body{font:15px/1.5 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--fg)}
button,input,select{font:inherit;color:inherit}
.btn{border:1px solid var(--line);background:var(--card);padding:8px 14px;border-radius:10px;cursor:pointer;white-space:nowrap}
.btn:hover{border-color:var(--pri)}.btn:focus-visible,input:focus-visible{outline:2px solid var(--pri);outline-offset:2px}
.btn.p{background:var(--pri);border-color:var(--pri);color:#fff}.btn.p:hover{background:var(--pri2)}
.btn.d{color:var(--bad)}.btn.d:hover{border-color:var(--bad)}.btn.s{padding:5px 10px;font-size:13px}
.btn:disabled{opacity:.55;cursor:not-allowed}
input,select{width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:10px;background:var(--bg)}
label{display:block;font-size:13px;color:var(--mut);margin:10px 0 4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:var(--sh)}
.mut{color:var(--mut)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;word-break:break-all}
.err{color:var(--bad)}
'''

PAGE_LOGIN = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>att-tunnel-hub 登录</title><style>{CSS}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
form{width:min(360px,100%);padding:28px}h1{font-size:20px;margin:0 0 4px}.logo{font-size:28px}
.btn{width:100%;margin-top:16px;padding:11px}</style></head>
<body><form class="card" method="post" action="{P}/login"><div class="logo" aria-hidden="true">🛰️</div>
<h1>att-tunnel-hub</h1><p class="mut" style="margin:0 0 8px">转发机统一管理面板</p>{E}
<label for="pw">密码</label><input id="pw" type="password" name="password" autocomplete="current-password" required autofocus>
<button class="btn p" type="submit">登录</button></form></body></html>'''
PAGE_MAIN = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>att-tunnel-hub 面板</title><style>{CSS}
.wrap{max-width:1180px;margin:0 auto;padding:16px}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;padding:16px 20px;margin-bottom:16px}
header h1{font-size:19px;margin:0}.hinfo{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:13px}
.acts{display:flex;gap:8px;flex-wrap:wrap}
.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}
.pill::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}
.pill.on{color:var(--ok);background:var(--okb)}.pill.off{color:var(--bad);background:var(--badb)}.pill.w{color:var(--warn);background:var(--warnb)}
.sum{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px}
.sum .card{padding:14px 16px}.sum b{display:block;font-size:24px;font-weight:700;margin-top:2px}
.alert{padding:12px 16px;margin-bottom:16px;border-color:var(--bad);color:var(--bad);background:var(--badb);display:none;white-space:pre-wrap}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}
.node{padding:16px}.node h2{font-size:17px;margin:0;display:flex;align-items:center;justify-content:space-between;gap:8px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;margin:12px 0;font-size:14px}.kv dt{color:var(--mut)}.kv dd{margin:0;word-break:break-all}
.nact{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.sec{display:flex;align-items:center;justify-content:space-between;margin:20px 0 10px}.sec h3{margin:0;font-size:16px}
.empty{padding:30px;text-align:center}
dialog{border:1px solid var(--line);border-radius:16px;background:var(--card);color:var(--fg);padding:0;width:min(600px,94vw);box-shadow:var(--sh)}
dialog::backdrop{background:#0008}.dh{padding:16px 20px;border-bottom:1px solid var(--line);font-weight:700}
.db{padding:4px 20px 16px}.df{padding:12px 20px;border-top:1px solid var(--line);display:flex;gap:8px;justify-content:flex-end}
.copy{display:flex;gap:6px;align-items:flex-start;background:var(--bg);border-radius:10px;padding:8px 10px;margin-top:4px}.copy .mono{flex:1}
#toasts{position:fixed;right:16px;bottom:16px;display:flex;flex-direction:column;gap:8px;z-index:9;max-width:min(380px,90vw)}
.toast{padding:10px 14px;border-radius:12px;color:#fff;background:#0f172a;box-shadow:var(--sh);font-size:14px}
.toast.ok{background:#15803d}.toast.bad{background:#b91c1c}
@media(max-width:760px){.sum{grid-template-columns:1fr}.wrap{padding:10px}header{padding:14px}}
</style></head><body><div class="wrap">
<header class="card"><div><h1>🛰️ att-tunnel-hub <span class="mut" style="font-size:13px;font-weight:400">v{V}</span></h1>
<div class="hinfo mut" id="hinfo">加载中…</div></div>
<div class="acts"><button class="btn p" id="bAdd" type="button">＋ 添加转发机</button>
<button class="btn" id="bRef" type="button">刷新</button>
<form method="post" action="{P}/logout" style="margin:0"><input type="hidden" name="csrf" value="{C}"><button class="btn" type="submit">退出</button></form></div></header>
<div class="card alert" id="err" role="alert"></div>
<div class="sum" id="sum"></div>
<div class="sec"><h3>转发机</h3><span class="mut" style="font-size:13px" id="meta" aria-live="polite"></span></div>
<div class="grid" id="list"></div></div>
<div id="toasts" aria-live="polite"></div>
'''
PAGE_MAIN += '''
<dialog id="dAdd" aria-labelledby="dAddH"><form id="fAdd" method="dialog"><div class="dh" id="dAddH">添加转发机</div><div class="db">
<p class="mut" style="font-size:13px">填转发机的公网 IP，面板会生成该机专属的一键代码。把代码贴到那台机器跑完，它会自动回连本面板。</p>
<label for="aName">名称</label><input id="aName" name="name" required placeholder="如 fwd2" pattern="[A-Za-z0-9_-]{1,32}">
<label for="aIp">公网 IP 或域名</label><input id="aIp" name="ip" required placeholder="如 1.2.3.4">
<label for="aNote">备注（可空）</label><input id="aNote" name="note" placeholder="如 香港入口">
</div><div class="df"><button class="btn" type="button" id="aCancel">取消</button>
<button class="btn p" id="aOk" type="submit">生成一键代码</button></div></form></dialog>

<dialog id="dCmd" aria-labelledby="dCmdH"><div class="dh" id="dCmdH">一键安装代码</div><div class="db">
<p class="mut" style="font-size:13px">在这台转发机上用 root 跑下面这条命令。它会装好 att-tunnel 入口端和上报 agent，装完这里会变成「在线」。<br>代码里带着该机的专属 token，请当密码保管。</p>
<div class="copy"><code class="mono" id="cmdText"></code><button class="btn s" type="button" id="cmdCopy">复制</button></div>
</div><div class="df"><button class="btn p" type="button" id="cmdClose">知道了</button></div></dialog>

<dialog id="dDel" aria-labelledby="dDelH"><form id="fDel" method="dialog"><div class="dh" id="dDelH">删除转发机</div><div class="db">
<p>仅从面板里移除记录，<b>不会</b>去动那台机器上的 att-tunnel。如要彻底卸载，在那台机上跑 <code class="mono">att-tunnel</code> 菜单里的卸载。</p>
<label for="dName">输入名称确认：<b id="dWho"></b></label><input id="dName" name="confirm" required autocomplete="off">
</div><div class="df"><button class="btn" type="button" id="dCancel">取消</button>
<button class="btn d" id="dOk" type="submit">确认删除</button></div></form></dialog>
'''
PAGE_MAIN += '''
<script>
const P="{P}", C="{C}";
const $=s=>document.querySelector(s);
function toast(m,k){const d=document.createElement("div");d.className="toast "+(k||"");d.textContent=m;
  $("#toasts").appendChild(d);setTimeout(()=>d.remove(),4200);}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function ago(t){if(!t)return "从未";const s=Math.max(0,Math.floor(Date.now()/1000)-t);
  if(s<60)return s+" 秒前";if(s<3600)return Math.floor(s/60)+" 分钟前";
  if(s<86400)return Math.floor(s/3600)+" 小时前";return Math.floor(s/86400)+" 天前";}
async function api(path,data){
  const r=await fetch(P+path,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded","X-CSRF-Token":C},
    body:new URLSearchParams(Object.assign({csrf:C},data||{}))});
  let j={};try{j=await r.json();}catch(e){}
  if(!r.ok)throw new Error(j.error||("HTTP "+r.status));
  return j;}
function showCmd(cmd){$("#cmdText").textContent=cmd;$("#dCmd").showModal();}
function card(f){
  const cls=f.online?"on":(f.last_seen?"off":"w");
  const txt=f.online?"在线":(f.last_seen?"离线":"待安装");
  const a=f.agent||{};
  const manage=f.online&&f.paneled
    ? '<a class="btn p s" href="'+P+'/f/'+encodeURIComponent(f.name)+'/">管理落地机</a>'
    : '<button class="btn s" type="button" disabled title="转发机在线后可用">管理落地机</button>';
  return '<div class="card node"><h2>'+esc(f.name)+'<span class="pill '+cls+'">'+txt+'</span></h2>'
    +'<dl class="kv"><dt>IP</dt><dd class="mono">'+esc(f.ip)+'</dd>'
    +(f.note?'<dt>备注</dt><dd>'+esc(f.note)+'</dd>':'')
    +'<dt>落地机</dt><dd>'+(a.nodes!==undefined?esc(a.nodes)+' 个':'—')+'</dd>'
    +'<dt>最后上报</dt><dd>'+ago(f.last_seen)+'</dd>'
    +(a.ver?'<dt>版本</dt><dd>att-tunnel '+esc(a.ver)+'</dd>':'')+'</dl>'
    +'<div class="nact">'+manage
    +'<button class="btn s" type="button" data-cmd="'+esc(f.name)+'">一键代码</button>'
    +'<button class="btn d s" type="button" data-del="'+esc(f.name)+'">删除</button></div></div>';
}
async function load(){
  try{
    const r=await fetch(P+"/api/status",{headers:{"Accept":"application/json"}});
    if(r.status===401){location.href=P+"/";return;}
    const d=await r.json();
    const fs=d.forwarders||[], on=fs.filter(f=>f.online).length;
    const nodes=fs.reduce((s,f)=>s+(parseInt((f.agent||{}).nodes,10)||0),0);
    $("#sum").innerHTML=
      '<div class="card"><span class="mut">转发机</span><b>'+fs.length+'</b></div>'
     +'<div class="card"><span class="mut">在线</span><b>'+on+'</b></div>'
     +'<div class="card"><span class="mut">落地机（节点）</span><b>'+nodes+'</b></div>';
    $("#hinfo").innerHTML='<span>面板地址 <span class="mono">'+esc(d.hub_url||"未配置")+'</span></span>';
    $("#list").innerHTML=fs.length?fs.map(card).join("")
      :'<div class="card empty mut">还没有转发机。点「＋ 添加转发机」填 IP，把生成的一键代码跑在那台机器上。</div>';
    $("#meta").textContent="更新于 "+new Date().toLocaleTimeString();
    $("#err").style.display="none";
    $("#list").querySelectorAll("[data-cmd]").forEach(b=>b.onclick=async()=>{
      try{const j=await api("/api/cmd",{name:b.dataset.cmd});showCmd(j.cmd);}catch(e){toast(e.message,"bad");}});
    $("#list").querySelectorAll("[data-del]").forEach(b=>b.onclick=()=>{
      $("#dWho").textContent=b.dataset.del;$("#dName").value="";$("#dDel").showModal();});
  }catch(e){$("#err").textContent="读取状态失败："+e.message;$("#err").style.display="block";}
}
load();setInterval(load,10000);
$("#cmdCopy").onclick=async()=>{try{await navigator.clipboard.writeText($("#cmdText").textContent);toast("已复制","ok");}
  catch(e){toast("复制失败，请手动选中","bad");}};
$("#cmdClose").onclick=()=>$("#dCmd").close();
$("#bAdd").onclick=()=>{$("#fAdd").reset();$("#dAdd").showModal();};
$("#aCancel").onclick=()=>$("#dAdd").close();
$("#dCancel").onclick=()=>$("#dDel").close();
$("#bRef").onclick=()=>load();
$("#fAdd").onsubmit=async e=>{e.preventDefault();const b=$("#aOk");b.disabled=true;
  try{const j=await api("/api/add",{name:$("#aName").value.trim(),ip:$("#aIp").value.trim(),note:$("#aNote").value.trim()});
    $("#dAdd").close();load();showCmd(j.cmd);}catch(err){toast(err.message,"bad");}finally{b.disabled=false;}};
$("#fDel").onsubmit=async e=>{e.preventDefault();const b=$("#dOk");b.disabled=true;
  try{await api("/api/del",{name:$("#dWho").textContent,confirm:$("#dName").value.trim()});
    $("#dDel").close();toast("已删除","ok");load();}catch(err){toast(err.message,"bad");}finally{b.disabled=false;}};
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
                for k in ('web', 'web_path', 'ver', 'ip', 'nodes', 'xray'):
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
        if r.startswith('/f/'):
            if not s:
                return self.redirect(PREFIX + '/')
            parts = r[3:].split('/', 1)
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
    with lock:
        state['started'] = now()
    log('att-tunnel-hub 面板 v%s 启动，监听 %s:%d，路径 %s' % (VERSION, LISTEN, PORT, PREFIX))
    Srv((LISTEN, PORT), H).serve_forever()


if __name__ == '__main__':
    main()
