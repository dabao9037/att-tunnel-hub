"""Optional regression: requires Playwright + Chromium; uses isolated state only."""
import os, sys, pathlib, tempfile, importlib.util, threading, urllib.parse, urllib.request, json, time
from playwright.sync_api import sync_playwright
ROOT=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as tmp:
 p=pathlib.Path(tmp);(p/'env').write_text('WEB_PORT=1\nWEB_PATH=test\nWEB_PASS=testpass123\n')
 os.environ.update(HUB_ENV=str(p/'env'),HUB_STATE=str(p/'state'))
 spec=importlib.util.spec_from_file_location('hub_browser',ROOT/'hub.py');hub=importlib.util.module_from_spec(spec);spec.loader.exec_module(hub)
 hub.UPGRADE_TIMEOUT=2
 rec=hub.fwd_add('test','127.0.0.1','');rec['last_seen']=hub.now()
 srv=hub.Srv(('127.0.0.1',0),hub.H);threading.Thread(target=srv.serve_forever,daemon=True).start();base='http://127.0.0.1:%d/test'%srv.server_port
 try:
  with sync_playwright() as pw:
   browser=pw.chromium.launch(args=['--no-sandbox']);ctx=browser.new_context(viewport={'width':390,'height':844},is_mobile=True,user_agent='Mozilla/5.0 (Linux; Android 16; V2520A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.178 Mobile Safari/537.36 VivoBrowser/31.1.3.1')
   page=ctx.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)));page.on('dialog',lambda d:d.accept())
   page.goto(base+'/');page.locator('input[name="password"]').fill('testpass123');page.locator('button[type="submit"]').click();page.wait_for_selector('[data-upgrade="test"]')
   def reply(code):
    job=hub.bus.take('test',.3);assert job
    data=urllib.parse.urlencode({'token':rec['token'],'job':job['id'],'status':code,'body':'simulated installer result'}).encode()
    assert json.load(urllib.request.urlopen(base+'/agent/reply',data))['ok']
   b=page.locator('[data-upgrade="test"]');b.click();page.wait_for_function("document.querySelector('[data-upgrade]').disabled")
   page.reload();page.wait_for_function("document.querySelector('[data-upgrade]')?.disabled")
   reply(200)
   page.evaluate('load()');page.wait_for_function("document.querySelector('[data-upgrade]').textContent.includes('更新成功')")
   page.reload();page.wait_for_function("document.querySelector('[data-upgrade]')?.textContent.includes('更新成功')")
   page.evaluate('load()');page.evaluate('load()');assert '更新成功' in b.inner_text()
   # Hold a second submission before it reaches the hub: polling the previous
   # success must not re-enable a newly rendered button during this window.
   pending=[]
   page.route('**/api/upgrade',lambda route:pending.append(route))
   b.click();page.wait_for_function("document.querySelector('[data-upgrade]').disabled")
   page.evaluate('load()');assert b.is_disabled() and '更新中' in b.inner_text()
   assert len(pending)==1
   pending[0].continue_();page.unroute('**/api/upgrade')
   page.wait_for_function('SUBMITTING.size===0');reply(500);page.evaluate('load()');page.wait_for_function("document.querySelector('[data-upgrade]').textContent.includes('更新失败')")
   b.click();page.wait_for_function("document.querySelector('[data-upgrade]').disabled");time.sleep(2.2);page.evaluate('load()');page.wait_for_function("document.querySelector('[data-upgrade]').textContent.includes('结果未确认')")
   page.reload();page.wait_for_function("document.querySelector('[data-upgrade]')?.textContent.includes('结果未确认')")
   assert not errors,errors
   print('PASS: mobile Chromium actual HTTP clicks; reload during upgrade; success persists across reload/repeated refresh; stale-success submission race; failure; unknown persists across reload; no JS errors')
   browser.close()
 finally:srv.shutdown();srv.server_close()
