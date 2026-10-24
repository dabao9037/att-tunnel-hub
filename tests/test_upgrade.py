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
for(const [state,label] of [['running','更新中…'],['ok','✓ 更新成功'],['error','更新失败，重试']]){
vm.runInContext("UPGRADES.set('test',{state:'"+state+"'})",ctx);
await vm.runInContext('load()',ctx);await vm.runInContext('load()',ctx);
if(!el('#list').innerHTML.includes(label))throw Error('refresh lost '+state);
if(state==='running'&&!el('#list').innerHTML.includes(' disabled'))throw Error('duplicate update enabled');
}
console.log('PASS: rendered JS syntax; repeated refresh preserves running/success/error');
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
    print('PASS: agent-origin upgrade schedules restart; manual upgrade still restarts synchronously')
