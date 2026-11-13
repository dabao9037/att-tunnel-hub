#!/usr/bin/env python3
"""转发机端口日流量限额：超过阈值封端口，并把告警交给 hub（邮件由母鸡轮询发送）。

只用标准库；计数/封停走 iptables 注释规则，按北京时间 00:00 重置。
不碰 gost 或其他项目端口，只管理 att-tunnel 自己的入口/反代/WG 端口。
"""
import json
import os
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


IPT = 'iptables'


def pick_ipt():
    global IPT
    for c in ('iptables', 'iptables-nft', 'iptables-legacy'):
        if run('sh', '-c', 'command -v %s' % c).returncode != 0:
            continue
        if run(c, '-L', 'INPUT', '-n').returncode == 0:
            IPT = c
            log('使用 %s' % c)
            return IPT
    raise RuntimeError('没有可用的 iptables（iptables / iptables-nft / iptables-legacy）')


def ipt(*args):
    return run(IPT, *args)


def rule_exists(spec):
    return ipt('-C', *spec).returncode == 0


def add_rule(spec):
    if not rule_exists(spec):
        r = ipt('-I', *spec)
        if r.returncode != 0:
            raise RuntimeError('iptables -I %s: %s' % (' '.join(spec), r.stderr.strip()))


def del_rule(spec):
    while rule_exists(spec):
        if ipt('-D', *spec).returncode != 0:
            break


def count_spec(proto, port, direction):
    key = '--dport' if direction == 'in' else '--sport'
    return ['INPUT' if direction == 'in' else 'OUTPUT', '-p', proto, key, str(port),
            '-m', 'comment', '--comment', 'attq:%s:%s' % (proto, port)]


def block_specs(proto, port):
    rej = ['-j', 'REJECT', '--reject-with', 'tcp-reset'] if proto == 'tcp' else ['-j', 'DROP']
    c = 'attqb:%s:%s' % (proto, port)
    return [
        ['INPUT', '-p', proto, '--dport', str(port), '-m', 'comment', '--comment', c] + rej,
        ['OUTPUT', '-p', proto, '--sport', str(port), '-m', 'comment', '--comment', c] + rej,
    ]


def counters(proto, port):
    """返回该端口入+出累计字节数（iptables -c 计数器）。"""
    total = 0
    save = (IPT.replace('iptables', 'iptables-save') if IPT == 'iptables'
            else IPT + '-save')
    out = run(save, '-c').stdout
    tag = 'attq:%s:%s' % (proto, port)
    for line in out.splitlines():
        if tag not in line or not line.startswith('['):
            continue
        try:
            # iptables-save -c 的格式是 [packets:bytes]
            total += int(line[line.index(':') + 1:line.index(']')])
        except (ValueError, IndexError):
            pass
    return total


def kill_conns(proto, port):
    if proto != 'tcp':
        return
    if run('conntrack', '-D', '-p', 'tcp', '--dport', str(port)).returncode == 0:
        return
    # 没有 conntrack-tools 时退回 ss -K
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
    if not ports:
        for p in (env.get('USER_PORT'), env.get('REVERSE_PORT')):
            if p and p.isdigit():
                ports.append(('tcp', int(p)))
        wg = env.get('WG_PORT')
        if wg and wg.isdigit():
            ports.append(('udp', int(wg)))
    ports = sorted(set(ports))
    if not ports:
        log('没有可监控端口')
        return 2

    if '--reset' in sys.argv:
        for proto, port in ports:
            for spec in block_specs(proto, port):
                del_rule(spec)
            for direction in ('in', 'out'):
                del_rule(count_spec(proto, port, direction))
        save_state({'day': '', 'ports': {}})
        print('已解除限额规则并清零')
        return 0

    today = datetime.now(TZ).strftime('%Y-%m-%d')
    st = load_state()
    if st.get('day') != today:
        # 新的一天：解封、清零计数
        for key, rec in (st.get('ports') or {}).items():
            try:
                proto, port = key.split(':', 1)
                for spec in block_specs(proto, int(port)):
                    del_rule(spec)
            except Exception as e:  # noqa: BLE001
                log('昨日解封失败', key, e)
        for proto, port in ports:
            for direction in ('in', 'out'):
                spec = count_spec(proto, port, direction)
                del_rule(spec)
                add_rule(spec)
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
