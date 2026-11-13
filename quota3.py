#!/usr/bin/env python3
"""转发机端口日流量限额：超过阈值封端口，并把告警交给 hub（邮件由母鸡轮询发送）。

只用标准库；用专用 iptables 链计数/封停，不依赖 xt_comment 内核模块。
按北京时间 00:00 重置；只管理 att-tunnel 自己的端口，不碰 gost。
"""
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from zoneinfo import ZoneInfo

ENVF = os.environ.get('ATT_QUOTA_ENV', '/etc/att-quota/quota.env')
STATE = os.environ.get('ATT_QUOTA_STATE', '/var/lib/att-quota/state.json')
TZ = ZoneInfo('Asia/Shanghai')
CH_IN, CH_OUT = 'ATTQ_IN', 'ATTQ_OUT'
IPT = 'iptables'


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


def run(*args, check=False):
    try:
        r = subprocess.run(args, capture_output=True, text=True)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, '', 'not found')
    if check and r.returncode != 0:
        raise RuntimeError('%s: %s' % (' '.join(args), (r.stderr or r.stdout).strip()))
    return r


def ssh_ports():
    ports = {'22'}
    try:
        out = run('sshd', '-T').stdout
        for line in out.splitlines():
            if line.startswith('port '):
                ports.add(line.split()[1])
    except OSError:
        pass
    return ports


def discover_ports():
    """所有对外监听端口（TCP+UDP），排除回环和 SSH。"""
    ssh = ssh_ports()
    found = []
    for proto, flag in (('tcp', '-ltn'), ('udp', '-lun')):
        out = run('ss', flag).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            host, _, port = local.rpartition(':')
            if not port.isdigit() or int(port) <= 0:
                continue
            if host in ('127.0.0.1', '[::1]', '::1') or host.startswith('127.'):
                continue
            if port in ssh:
                continue
            found.append((proto, int(port)))
    return sorted(set(found))


def pick_ipt():
    global IPT
    for c in ('iptables', 'iptables-nft', 'iptables-legacy'):
        if run('sh', '-c', 'command -v %s' % c).returncode != 0:
            continue
        if run(c, '-L', 'INPUT', '-n').returncode == 0:
            IPT = c
            return IPT
    raise RuntimeError('没有可用的 iptables（iptables / iptables-nft / iptables-legacy）')


def ipt(*args):
    return run(IPT, *args)


def ensure_chain(name, hook):
    if ipt('-N', name).returncode not in (0, 1):
        pass
    # 挂到 INPUT/OUTPUT 顶部，幂等
    if ipt('-C', hook, '-j', name).returncode != 0:
        ipt('-I', hook, '1', '-j', name)


def setup_chains():
    ensure_chain(CH_IN, 'INPUT')
    ensure_chain(CH_OUT, 'OUTPUT')


def flush_chains():
    ipt('-F', CH_IN)
    ipt('-F', CH_OUT)


def cleanup_legacy():
    """删除上一版基于 -m comment 的规则，避免重复计数/重复封停。"""
    out = run(IPT + '-save', '-c').stdout
    for line in out.splitlines():
        if 'attq:' not in line and 'attqb:' not in line:
            continue
        spec = line.split('] ', 1)[-1]
        if spec.startswith('-A '):
            ipt('-D', *shlex.split(spec[3:]))


def count_spec(proto, port, direction):
    key = '--dport' if direction == 'in' else '--sport'
    return [CH_IN if direction == 'in' else CH_OUT, '-p', proto, key, str(port)]


def block_specs(proto, port):
    rej = ['-j', 'REJECT', '--reject-with', 'tcp-reset'] if proto == 'tcp' else ['-j', 'DROP']
    return [
        [CH_IN, '-p', proto, '--dport', str(port)] + rej,
        [CH_OUT, '-p', proto, '--sport', str(port)] + rej,
    ]


def rule_exists(spec):
    return ipt('-C', *spec).returncode == 0


def add_rule(spec):
    if not rule_exists(spec):
        r = ipt('-I', *spec)
        if r.returncode != 0:
            raise RuntimeError('%s %s: %s' % (IPT, ' '.join(spec), r.stderr.strip()))


def del_rule(spec):
    while rule_exists(spec):
        if ipt('-D', *spec).returncode != 0:
            break


def counters(proto, port):
    save = IPT + '-save'
    total = 0
    for line in run(save, '-c').stdout.splitlines():
        if not line.startswith('['):
            continue
        if ('-A %s ' % CH_IN) in line and ('--dport %s' % port) in line:
            total += int(line[line.index(':') + 1:line.index(']')])
        elif ('-A %s ' % CH_OUT) in line and ('--sport %s' % port) in line:
            total += int(line[line.index(':') + 1:line.index(']')])
    return total


def kill_conns(proto, port):
    if proto != 'tcp':
        return
    if run('conntrack', '-D', '-p', 'tcp', '--dport', str(port)).returncode == 0:
        return
    run('ss', '-K', 'dport', '=', ':%d' % port)


def load_state():
    try:
        with open(STATE) as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get('ports'), dict):
            return d
    except (OSError, ValueError):
        pass
    return {'day': '', 'ports': {}}


def save_state(d):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(d, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE)


def alert(env, port, nbytes, action, detail):
    data = urllib.parse.urlencode({
        'token': env.get('HUB_TOKEN', ''),
        'port': port,
        'bytes': nbytes,
        'action': action,
        'detail': detail,
    }).encode()
    req = urllib.request.Request((env.get('HUB_URL') or '').rstrip('/') + '/agent/quota', data=data)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    req.add_header('Authorization', 'Bearer ' + env.get('HUB_TOKEN', ''))
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status == 200
    except Exception as e:  # noqa: BLE001 - 告警失败不能影响封停
        log('告警发送失败：', e)
        return False


def main():
    env = load_env(ENVF)
    pick_ipt()
    if not env.get('HUB_URL') or not env.get('HUB_TOKEN'):
        log('quota.env 不完整')
        return 2
    threshold = size(env.get('THRESHOLD', '50G'))
    ports = []
    for item in (env.get('PORTS') or '').split():
        proto, _, port = item.partition(':')
        if proto in ('tcp', 'udp') and port.isdigit():
            ports.append((proto, int(port)))
    ports = sorted(set(ports))
    if not ports:
        ports = discover_ports()
    if not ports:
        log('没有可监控端口')
        return 2

    setup_chains()
    cleanup_legacy()
    try:
        os.remove('/var/lib/att-quota/error.log')
    except OSError:
        pass

    if '--reset' in sys.argv:
        for proto, port in ports:
            for spec in block_specs(proto, port):
                del_rule(spec)
        flush_chains()
        save_state({'day': '', 'ports': {}})
        print('已解除限额规则并清零')
        return 0

    today = datetime.now(TZ).strftime('%Y-%m-%d')
    st = load_state()
    if st.get('day') != today:
        flush_chains()
        st = {'day': today, 'ports': {}}
        save_state(st)

    changed = False
    for proto, port in ports:
        key = '%s:%d' % (proto, port)
        rec = st['ports'].setdefault(key, {'bytes': 0, 'blocked': False, 'alerted': False})
        for direction in ('in', 'out'):
            add_rule(count_spec(proto, port, direction))
        n = counters(proto, port)
        if n > rec.get('bytes', 0):
            rec['bytes'] = n
            changed = True
        if rec['bytes'] >= threshold and not rec.get('blocked'):
            for spec in block_specs(proto, port):
                add_rule(spec)
            kill_conns(proto, port)
            rec['blocked'] = True
            rec['alerted'] = False
            changed = True
            log('端口 %s/%s 当日 %d 字节，超过阈值，已封停' % (proto, port, rec['bytes']))
        if rec.get('blocked') and not rec.get('alerted'):
            if alert(env, port, rec['bytes'], 'block',
                     '端口 %s/%s 日流量 %d 字节，已封停至次日 00:00' % (proto, port, rec['bytes'])):
                rec['alerted'] = True
                changed = True
    if changed:
        save_state(st)
    if '--status' in sys.argv:
        print(json.dumps(st, ensure_ascii=False, indent=1))
    return 0


def _logerr():
    try:
        import traceback
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        with open('/var/lib/att-quota/error.log', 'w') as f:
            f.write(traceback.format_exc().strip().splitlines()[-1][:300] + '\n')
    except OSError:
        pass


if __name__ == '__main__':
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        _logerr()
        raise
