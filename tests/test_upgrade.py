"""Regression checks without touching production forwarders or services."""
import os
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / 'hub.py').read_text()
# Evaluate only page literals; no production configuration or state loaded.
parts = re.findall(r"PAGE_MAIN (?:\+)?= ('''[\s\S]*?''')", src)
page = ''.join(eval(p) for p in parts)
js = re.search(r'<script>([\s\S]*?)</script>', page).group(1)
with tempfile.TemporaryDirectory() as tmp:
    p = pathlib.Path(tmp)
    (p / 'page.js').write_text(js)
    subprocess.run(['node', '--check', str(p / 'page.js')], check=True)
    test = '''
const vm=require('vm'),fs=require('fs');
const elements=new Map();
function el(s){if(!elements.has(s))elements.set(s,{style:{},querySelectorAll(){return []}});return elements.get(s)}
const ctx={document:{querySelector:el},setInterval(){},setTimeout(){},location:{},fetch:async()=>({status:200,json:async()=>({forwarders:[{name:'test',online:true,agent:{}}]})})};
vm.createContext(ctx);vm.runInContext(fs.readFileSync(process.argv[2],'utf8'),ctx);
(async()=>{
for(const [state,label] of [['running','更新中…'],['ok','✓ 更新成功'],['error','更新失败，重试'],['unknown','结果未确认']]){
vm.runInContext("UPGRADES.set('test',{state:'"+state+"'})",ctx);
await vm.runInContext('load()',ctx);await vm.runInContext('load()',ctx);
if(!el('#list').innerHTML.includes(label))throw Error('refresh lost '+state);
if(state==='running'&&!el('#list').innerHTML.includes(' disabled'))throw Error('duplicate update enabled');
}
vm.runInContext("SUBMITTING.add('test');UPGRADES.set('test',{state:'running'})",ctx);
ctx.fetch=async()=>({status:200,json:async()=>({forwarders:[{name:'test',online:true,agent:{},upgrade:{id:'old',state:'ok'}}]})});
await vm.runInContext('load()',ctx);
if(!el('#list').innerHTML.includes(' disabled')||!el('#list').innerHTML.includes('更新中…'))throw Error('stale success overwrote pending submission');
console.log('PASS: rendered JS syntax; repeated refresh preserves running/success/error/unknown; stale success cannot overwrite submission');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
    (p / 'dom.js').write_text(test)
    subprocess.run(['node', str(p / 'dom.js'), str(p / 'page.js')], check=True)
    # Execute the real restart block with mocked systemctl/systemd-run/sleep.
    sh = (ROOT / 'install.sh').read_text()
    block = sh[sh.index('  local agent_invocation'):sh.index('\n  echo\n  ok "转发机安装完成')]
    for invocation, expected in [('same', 'timer'), ('different', 'restart')]:
        script = '''set -eu
ok(){ :; }; die(){ exit 1; }; sleep(){ :; }
systemctl(){ case "$1" in show) echo same;; restart) echo restart;; is-active) :;; esac; }
systemd-run(){ echo timer; }
f(){
''' + block + '\n}; f\n'
        result = subprocess.run(['bash', '-c', script], env=dict(os.environ, INVOCATION_ID=invocation), capture_output=True, text=True, check=True)
        assert result.stdout.strip() == expected, result.stdout
    failure_script = script.replace('systemd-run(){ echo timer; }', 'systemd-run(){ return 1; }')
    failed = subprocess.run(['bash', '-c', failure_script], env=dict(os.environ, INVOCATION_ID='same'), capture_output=True)
    assert failed.returncode != 0, 'failed restart scheduling reported success'
    print('PASS: agent-origin upgrade schedules restart; manual upgrade restarts synchronously; timer failure fails upgrade')

# Actual hub HTTP + simulated legacy agent: no production state or upgrade touched.
import importlib.util
import http.cookiejar
import json
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
with tempfile.TemporaryDirectory() as tmp:
    p = pathlib.Path(tmp)
    (p / 'hub.env').write_text('WEB_PORT=1\nWEB_PATH=test\nWEB_PASS=testpass123\n')
    old_env = {k: os.environ.get(k) for k in ('HUB_ENV', 'HUB_STATE')}
    os.environ.update(HUB_ENV=str(p / 'hub.env'), HUB_STATE=str(p / 'state.json'))
    spec = importlib.util.spec_from_file_location('hub_test', ROOT / 'hub.py')
    hub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hub)
    hub.UPGRADE_TIMEOUT = .3
    hub.fwd_add('test', '127.0.0.1', '')
    rec = hub.fwd_get('test')
    rec['last_seen'] = hub.now()
    server = hub.Srv(('127.0.0.1', 0), hub.H)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = 'http://127.0.0.1:%d/test' % server.server_port
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def post(path, data):
        return client.open(base + path, urllib.parse.urlencode(data).encode(), timeout=3)
    try:
        try:
            post('/api/upgrade', {'name': 'test'})
            raise AssertionError('unauthenticated upgrade accepted')
        except urllib.error.HTTPError as e:
            assert e.code == 401
        page = post('/login', {'password': 'testpass123'}).read().decode()
        csrf = re.search(r'const P="[^"]+", C="([^"]+)"', page).group(1)
        for status, expected in [(200, 'ok'), (500, 'error'), (None, 'unknown')]:
            start = time.monotonic()
            r = post('/api/upgrade', {'name': 'test', 'csrf': csrf})
            result = json.load(r)
            assert r.status == 202 and time.monotonic()-start < .2
            assert result['upgrade']['state'] == 'running'
            duplicate = json.load(post('/api/upgrade', {'name': 'test', 'csrf': csrf}))
            assert duplicate['upgrade']['id'] == result['upgrade']['id']
            job = hub.bus.take('test', .1)
            assert job['req']['path'] == '/__upgrade__'
            if status is not None:
                reply = json.load(post('/agent/reply', {'token': rec['token'], 'job': job['id'], 'status': status, 'body': 'sensitive-test-output'}))
                assert reply['ok']
            end = time.monotonic() + 2
            while rec['upgrade']['state'] == 'running' and time.monotonic() < end:
                time.sleep(.01)
            assert rec['upgrade']['state'] == expected, rec['upgrade']
            hub.save_state()
            hub.load_state()
            rec = hub.fwd_get('test')
            assert rec['upgrade']['state'] == expected
            public = json.load(client.open(base + '/api/status'))
            assert public['forwarders'][0]['upgrade']['state'] == expected
            assert 'sensitive-test-output' not in json.dumps(public)
            assert 'sensitive-test-output' not in (p / 'state.json').read_text()
        rec['upgrade'] = {'id': 'restart-test', 'state': 'running'}
        hub.recover_upgrades()
        assert rec['upgrade']['state'] == 'unknown'
        print('PASS: HTTP 202 immediate; duplicate coalescing; authenticated agent success/failure/timeout; persisted status; restart recovery; output not leaked')
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        for k, v in old_env.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v
