#!/usr/bin/env python3
"""单 IP 滚动一小时全端口流量告警：所有经过本机的连接，按对端 IP 汇总上下行。

只发邮件，不封 IP/端口。依赖 nf_conntrack_acct=1 读取每条连接的字节数。
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

ENVF = os.environ.get('ATT_IPMETER_ENV', '/etc/att-quota/ipmeter.env')
STATE = os.environ.get('ATT_IPMETER_STATE', '/var/lib/att-quota/ip-state.json')
CONNTRACK_FILE = os.environ.get('ATT_CONNTRACK_FILE', '')
CONNTRACK_CMD = os.environ.get('ATT_CONNTRACK_CMD', 'conntrack -L -o extended')
WINDOW = 3600
IPRE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})$')


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


def size(s):
    s = str(s).strip().upper()
    mult = 1
    if s.endswith(('K', 'M', 'G', 'T')):
        mult = {'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30, 'T': 1 << 40}[s[-1]]
        s = s[:-1]
    return int(float(s) * mult)


def local_ips():
    ips = set()
    try:
        out = subprocess.run(['ip', '-o', '-4', 'addr', 'show'], capture_output=True, text=True).stdout
        for m in re.finditer(r'inet (\d{1,3}(?:\.\d{1,3}){3})/', out):
            ips.add(m.group(1))
    except OSError:
        pass
    return ips


def parse_line(line, locals_):
    """返回 (key, remote_ip, total_bytes)；无法解析返回 None。"""
    if 'bytes=' not in line:
        return None
    m = re.search(r'\bsrc=(\d{1,3}(?:\.\d{1,3}){3})\s+dst=(\d{1,3}(?:\.\d{1,3}){3})'
                  r'\s+sport=(\d+)\s+dport=(\d+)', line)
    if not m:
        return None
    src, dst, sport, dport = m.groups()
    toks = line.split()
    proto = next((t for t in toks[:4] if t in ('tcp', 'udp', 'icmp')), '?')
    total = sum(int(x) for x in re.findall(r'\bbytes=(\d+)', line))
    if total <= 0:
        return None
    remote = dst if src in locals_ else src
    if not IPRE.match(remote) or remote.startswith('127.') or remote in locals_:
        return None
    key = '%s|%s|%s|%s|%s' % (proto, src, sport, dst, dport)
    return key, remote, total


def ensure_tracking():
    """没有 conntrack 规则的机器上，加一条 raw 匹配触发连接跟踪（幂等）。"""
    spec = ['-t', 'raw', '-C', 'PREROUTING', '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'RETURN']
    try:
        if subprocess.run(['iptables'] + spec, capture_output=True).returncode != 0:
            subprocess.run(['iptables', '-t', 'raw', '-I', 'PREROUTING', '1',
                            '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'RETURN'],
                           capture_output=True)
    except OSError:
        pass


def read_entries(locals_):
    out = {}
    if CONNTRACK_FILE:
        try:
            with open(CONNTRACK_FILE) as f:
                lines = f.readlines()
        except OSError:
            lines = []
    else:
        try:
            lines = subprocess.run(CONNTRACK_CMD.split(), capture_output=True, text=True).stdout.splitlines()
        except OSError:
            lines = []
    for line in lines:
        r = parse_line(line, locals_)
        if r:
            key, remote, total = r
            out[key] = (remote, total)
    return out


def load_state():
    try:
        with open(STATE) as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get('ips'), dict):
            return d
    except (OSError, ValueError):
        pass
    return {'ips': {}, 'seen': {}}


def save_state(d):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(d, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE)


def alert(env, ip, nbytes, detail):
    data = urllib.parse.urlencode({
        'token': env.get('HUB_TOKEN', ''),
        'port': '0',
        'ip': ip,
        'bytes': nbytes,
        'action': 'ip_hour',
        'detail': detail,
    }).encode()
    req = urllib.request.Request((env.get('HUB_URL') or '').rstrip('/') + '/agent/quota', data=data)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    req.add_header('Authorization', 'Bearer ' + env.get('HUB_TOKEN', ''))
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status == 200
    except Exception as e:  # noqa: BLE001
        log('告警发送失败：', e)
        return False


def main(now=None):
    now = int(now or time.time())
    env = load_env(ENVF)
    if not env.get('HUB_URL') or not env.get('HUB_TOKEN'):
        log('ipmeter.env 不完整')
        return 2
    threshold = size(env.get('IP_THRESHOLD', '20G'))
    ensure_tracking()
    locals_ = local_ips()
    entries = read_entries(locals_)
    st = load_state()
    seen = st.get('seen') or {}
    cur_keys = set()
    for key, (remote, total) in entries.items():
        cur_keys.add(key)
        prev = seen.get(key)
        if prev:
            delta = total - int(prev[0])
        else:
            delta = 0  # 首次只建基线，避免把安装前的历史流量算进来
        if delta > 0:
            rec = st['ips'].setdefault(remote, {'buckets': [], 'last_alert': 0})
            rec['buckets'].append([now, delta])
        seen[key] = [total, now]
    # 清理 1 小时前的窗口与 2 分钟没再出现的连接快照
    for ip in list(st['ips']):
        rec = st['ips'][ip]
        rec['buckets'] = [b for b in rec['buckets'] if b[0] >= now - WINDOW]
        if not rec['buckets']:
            st['ips'].pop(ip, None)
    for key in list(seen):
        if key not in cur_keys and now - int(seen[key][1]) > 120:
            seen.pop(key, None)
    st['seen'] = seen

    changed = False
    for ip, rec in st['ips'].items():
        total = sum(int(b[1]) for b in rec['buckets'])
        last = int(rec.get('last_alert') or 0)
        if total >= threshold and (last == 0 or now - last >= WINDOW):
            detail = '单 IP 滚动 1 小时全端口流量 %d 字节（%s）' % (total, ip)
            if alert(env, ip, total, detail):
                rec['last_alert'] = now
                changed = True
                log('IP %s 一小时内 %d 字节，已发告警' % (ip, total))
    if changed:
        save_state(st)
    elif entries:
        save_state(st)
    if '--status' in sys.argv:
        print(json.dumps(st, ensure_ascii=False, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
