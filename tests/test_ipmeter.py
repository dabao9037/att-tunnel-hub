"""ipmeter 解析与阈值测试：用 fixture 模拟 conntrack 输出，不碰真实网络。"""
import importlib.util
import json
import os
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCAL = '68.164.22.163'


def line(src, dst, sport, dport, b1, b2):
    return ('ipv4 2 tcp 6 100 ESTABLISHED src=%s dst=%s sport=%s dport=%s packets=1 bytes=%d '
            'src=%s dst=%s sport=%s dport=%s packets=1 bytes=%d [ASSURED] mark=0 use=1\n'
            % (src, dst, sport, dport, b1, dst, src, dport, sport, b2))


with tempfile.TemporaryDirectory() as tmp:
    p = pathlib.Path(tmp)
    fixture = p / 'ct'
    fixture.write_text(line('1.2.3.4', LOCAL, 1234, 443, 1000, 500)
                       + line(LOCAL, '8.8.8.8', 5555, 53, 200, 100))
    (p / 'ipmeter.env').write_text('HUB_URL=http://127.0.0.1:1/test\nHUB_TOKEN=x\nIP_THRESHOLD=1K\n')
    os.environ.update(ATT_IPMETER_ENV=str(p / 'ipmeter.env'),
                      ATT_IPMETER_STATE=str(p / 'state.json'),
                      ATT_CONNTRACK_FILE=str(fixture))
    spec = importlib.util.spec_from_file_location('ipmeter_test', ROOT / 'ipmeter.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.ensure_tracking = lambda: None
    got = []
    m.alert = lambda env, ip, nbytes, detail: got.append((ip, nbytes)) or True

    assert m.main(now=1000) == 0
    assert got == [], 'first sample must only build baseline'
    fixture.write_text(line('1.2.3.4', LOCAL, 1234, 443, 3000, 1500)
                       + line(LOCAL, '8.8.8.8', 5555, 53, 200, 100))
    assert m.main(now=1060) == 0
    assert got and got[0][0] == '1.2.3.4' and got[0][1] >= 1024, got
    st = json.loads((p / 'state.json').read_text())
    assert st['ips']['1.2.3.4']['last_alert'] == 1060
    # 同一 IP 一小时内不重复发
    fixture.write_text(line('1.2.3.4', LOCAL, 1234, 443, 6000, 3000))
    m.main(now=1100)
    assert len(got) == 1, got
    print('PASS: ipmeter parses conntrack, ignores baseline, alerts once per IP/hour')
