"""端到端验证：真实 agent.py 回包必须带 HMAC 且被 hub 接受。

本地起一个 hub 实例和一个假 att-tunnel 面板；agent 用临时 agent.env 连接。
不触碰生产 state、转发机或服务。
"""
import http.cookiejar
import http.server
import importlib.util
import json
import os
import pathlib
import re
import sys
import tempfile
import threading
import time
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

seen_origin = []


class Panel(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype='text/html; charset=utf-8', extra=()):
        b = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        seen_origin.append(self.headers.get('Origin'))
        n = int(self.headers.get('Content-Length') or 0)
        self.rfile.read(n)
        if self.path.endswith('/login'):
            return self.send(303, '', 'text/plain', [('Set-Cookie', 'att_sid=test; Path=/panel')])
        self.send(404, 'no', 'text/plain')

    def do_GET(self):
        seen_origin.append(self.headers.get('Origin'))
        if self.path.endswith('/api/status'):
            return self.send(200, json.dumps({'nodes': [{'name': 'n1', 'up': 1, 'down': 2}]}),
                             'application/json; charset=utf-8')
        return self.send(200, '<input name="csrf" value="tok123"><script>const C="tok123";</script>')


with tempfile.TemporaryDirectory() as tmp:
    p = pathlib.Path(tmp)
    (p / 'hub.env').write_text('WEB_PORT=1\nWEB_PATH=test\nWEB_PASS=testpass123\n')
    os.environ['HUB_ENV'] = str(p / 'hub.env')
    os.environ['HUB_STATE'] = str(p / 'state.json')
    spec = importlib.util.spec_from_file_location('hub_e2e', ROOT / 'hub.py')
    hub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hub)
    rec = hub.fwd_add('local', '127.0.0.1', '')
    hub_server = hub.Srv(('127.0.0.1', 0), hub.H)
    threading.Thread(target=hub_server.serve_forever, daemon=True).start()

    panel = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Panel)
    threading.Thread(target=panel.serve_forever, daemon=True).start()
    panel_port = panel.server_port
    (p / 'web.env').write_text('WEB_PORT=%d\nWEB_PATH=panel\nWEB_PASS=testpass123\n' % panel_port)
    (p / 'config.json').write_text(json.dumps({'inbounds': [{'tag': 'user-in', 'settings': {'clients': [{}]}}]}))
    (p / 'agent.env').write_text(
        'HUB_URL=http://127.0.0.1:%d/test\nHUB_TOKEN=%s\n' % (hub_server.server_port, rec['token']))
    os.environ.update(AGENT_ENV=str(p / 'agent.env'), ATT_WEB_ENV=str(p / 'web.env'),
                      ATT_CFG=str(p / 'config.json'))
    spec = importlib.util.spec_from_file_location('agent_e2e', ROOT / 'agent.py')
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    threading.Thread(target=agent.main, daemon=True).start()

    try:
        job = hub.bus.submit('local', {'method': 'GET', 'path': '/api/status', 'body': '', 'ctype': ''})
        resp = hub.bus.wait(job, 20)
        assert resp is not None, 'agent 回包未通过 hub 的 HMAC/归属校验'
        assert resp['status'] == 200, resp
        assert 'n1' in resp['body'], resp
        assert seen_origin and seen_origin[0] == 'http://127.0.0.1:%d' % panel_port, seen_origin
        print('PASS: real agent signs reply with per-forwarder token; hub accepts and proxies JSON')
    finally:
        hub_server.shutdown()
        hub_server.server_close()
        panel.shutdown()
        panel.server_close()
