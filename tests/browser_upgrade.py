"""Optional regression: requires Playwright + Chromium; uses isolated state only.

页面在真实 CSP 下加载（nonce 生效），所以等待一律走 Python 轮询/定位器，
不用 page.wait_for_function 的字符串形式——那会触发页面 eval，被 CSP 正确拦截。
"""
import os, sys, pathlib, tempfile, importlib.util, threading, urllib.parse, urllib.request, json, time, hmac
from playwright.sync_api import sync_playwright
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
with tempfile.TemporaryDirectory() as tmp:
 p=pathlib.Path(tmp);(p/'env').write_text('WEB_PORT=1\nWEB_PATH=test\nWEB_PASS=testpass123\n')
 os.environ.update(HUB_ENV=str(p/'env'),HUB_STATE=str(p/'state'))
 spec=importlib.util.spec_from_file_location('hub_browser',ROOT/'hub.py');hub=importlib.util.module_from_spec(spec);spec.loader.exec_module(hub)
 hub.UPGRADE_TIMEOUT=2
 rec=hub.fwd_add('test','127.0.0.1','');rec['last_seen']=hub.now()
 srv=hub.Srv(('127.0.0.1',0),hub.H);threading.Thread(target=srv.serve_forever,daemon=True).start();base='http://127.0.0.1:%d/test'%srv.server_port
 def wait(pred,msg='timeout',timeout=8):
  end=time.time()+timeout
  while time.time()<end:
   try:
    if pred():return
   except Exception:pass
   time.sleep(.05)
  raise AssertionError(msg)
 try:
  with sync_playwright() as pw:
   browser=pw.chromium.launch(args=['--no-sandbox']);ctx=browser.new_context(viewport={'width':390,'height':844},is_mobile=True,user_agent='Mozilla/5.0 (Linux; Android 16; V2520A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.178 Mobile Safari/537.36 VivoBrowser/31.1.3.1')
   page=ctx.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)));page.on('dialog',lambda d:d.accept())
   page.goto(base+'/');page.locator('input[name="password"]').fill('testpass123');page.locator('button[type="submit"]').click();page.wait_for_selector('[data-upgrade="test"]')
   def reply(code):
    job=hub.bus.take('test',.3);assert job
    body,ctype='simulated installer result','text/plain; charset=utf-8'
    msg='%s\n%s\n%s\n%s'%(job['id'],code,ctype,body)
    mac=hmac.new(rec['token'].encode(),msg.encode(),'sha256').hexdigest()
    data=urllib.parse.urlencode({'token':rec['token'],'job':job['id'],'status':code,'body':body,'ctype':ctype,'mac':mac}).encode()
    assert json.load(urllib.request.urlopen(base+'/agent/reply',data))['ok']
   b=page.locator('[data-upgrade="test"]');b.click();wait(lambda:b.is_disabled(),'click did not disable')
   page.reload();b=page.locator('[data-upgrade="test"]');wait(lambda:b.is_disabled(),'reload lost running state')
   reply(200)
   page.evaluate('load()');wait(lambda:'更新成功' in b.inner_text(),'success not shown')
   page.reload();b=page.locator('[data-upgrade="test"]');wait(lambda:'更新成功' in b.inner_text(),'success not persisted')
   page.evaluate('load()');page.evaluate('load()');assert '更新成功' in b.inner_text()
   # Hold a second submission before it reaches the hub: polling the previous
   # success must not re-enable a newly rendered button during this window.
   pending=[]
   page.route('**/api/upgrade',lambda route:pending.append(route))
   b.click();wait(lambda:b.is_disabled(),'second click did not disable')
   page.evaluate('load()');assert b.is_disabled() and '更新中' in b.inner_text()
   assert len(pending)==1
   pending[0].continue_();page.unroute('**/api/upgrade')
   wait(lambda:page.evaluate('SUBMITTING.size===0'),'submission flag stuck')
   reply(500);page.evaluate('load()');wait(lambda:'更新失败' in b.inner_text(),'failure not shown')
   b.click();wait(lambda:b.is_disabled(),'third click did not disable');time.sleep(2.2);page.evaluate('load()');wait(lambda:'结果未确认' in b.inner_text(),'unknown not shown')
   page.reload();b=page.locator('[data-upgrade="test"]');wait(lambda:'结果未确认' in b.inner_text(),'unknown not persisted')
   assert not errors,errors
   print('PASS: mobile Chromium under real nonce CSP; click/reload/refresh; success/failure/unknown; no JS errors')
   browser.close()
 finally:srv.shutdown();srv.server_close()
