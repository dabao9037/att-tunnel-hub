"""验证 /f/ 独立源跳转与配额告警接口（本地临时实例，不碰生产）。"""
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
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory() as tmp:
    p = pathlib.Path(tmp)
    (p / 'hub.env').write_text(
        'WEB_PORT=1\nWEB_PATH=test\nWEB_PASS=testpass123\n'
        'FWD_ORIGIN=https://att.example:8443\nALERT_TOKEN=alerttok\n')
    os.environ['HUB_ENV'] = str(p / 'hub.env')
    os.environ['HUB_STATE'] = str(p / 'state.json')
    spec = importlib.util.spec_from_file_location('hub_origin', ROOT / 'hub.py')
    hub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hub)
    rec = hub.fwd_add('test', '127.0.0.1', '')

    srv = hub.Srv(('127.0.0.1', 0), hub.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = 'http://127.0.0.1:%d/test' % srv.server_port

    class N(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    op = urllib.request.build_opener(N)
    try:
        try:
            op.open(base + '/f/abc/sub/x')
            raise AssertionError('no redirect')
        except urllib.error.HTTPError as e:
            r = e
        assert r.code == 303 and r.headers['Location'] == \
            'https://att.example:8443/test/f/abc/sub/x', r.headers['Location']
        print('PASS: main origin redirects /f/ to isolated origin')

        fwd = hub.Srv(('127.0.0.1', 0), hub.HF)
        threading.Thread(target=fwd.serve_forever, daemon=True).start()
        fbase = 'http://127.0.0.1:%d/test' % fwd.server_port
        try:
            op.open(fbase + '/api/status')
            raise AssertionError('HF exposed /api/status')
        except urllib.error.HTTPError as e:
            assert e.code == 404
        try:
            op.open(fbase + '/f/abc/')
            raise AssertionError('HF served /f/ without session')
        except urllib.error.HTTPError as e:
            assert e.code == 303
        print('PASS: isolated listener only serves /f/ and still requires session')

        data = urllib.parse.urlencode({'token': rec['token'], 'port': '443',
                                       'bytes': str(60 << 30), 'action': 'block',
                                       'detail': 'test'}).encode()
        req = urllib.request.Request(base + '/agent/quota', data=data,
                                     headers={'Authorization': 'Bearer ' + rec['token'],
                                              'Content-Type': 'application/x-www-form-urlencoded'})
        assert json.load(urllib.request.urlopen(req))['ok']
        req = urllib.request.Request(base + '/alerts/pending', headers={'X-Alert-Token': 'alerttok'})
        alerts = json.load(urllib.request.urlopen(req))['alerts']
        assert len(alerts) == 1 and alerts[0]['machine'] == 'test' and alerts[0]['port'] == 443
        try:
            urllib.request.urlopen(base + '/alerts/pending')
            raise AssertionError('alerts readable without token')
        except urllib.error.HTTPError as e:
            assert e.code == 403
        ack = urllib.parse.urlencode({'ids': alerts[0]['id']}).encode()
        req = urllib.request.Request(base + '/alerts/ack', data=ack,
                                     headers={'X-Alert-Token': 'alerttok',
                                              'Content-Type': 'application/x-www-form-urlencoded'})
        assert json.load(urllib.request.urlopen(req))['left'] == 0
        print('PASS: quota alert requires agent token; read/ack requires alert token')
    finally:
        srv.shutdown()
        srv.server_close()
