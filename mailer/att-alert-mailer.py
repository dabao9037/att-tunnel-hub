#!/usr/bin/env python3
"""母鸡上的告警邮件发送器：轮询 hub 的待发告警，用本机 SMTP 发信后回执。"""
import json
import os
import smtplib
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from zoneinfo import ZoneInfo

ENVF = os.environ.get('ATT_ALERT_ENV', '/etc/att-alert/mailer.env')
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


def human(n):
    n = float(n or 0)
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or u == 'TB':
            return '%.2f %s' % (n, u)
        n /= 1024


def fetch(env):
    req = urllib.request.Request(env['HUB_ALERTS_URL'], headers={'X-Alert-Token': env['ALERT_TOKEN']})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode()).get('alerts') or []


def ack(env, ids):
    data = urllib.parse.urlencode({'ids': ','.join(ids)}).encode()
    req = urllib.request.Request(env['HUB_ALERT_ACK_URL'], data=data,
                                 headers={'X-Alert-Token': env['ALERT_TOKEN'],
                                          'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status == 200


def send(env, a):
    when = datetime.fromtimestamp(int(a.get('ts') or 0), TZ).strftime('%Y-%m-%d %H:%M:%S')
    msg = EmailMessage()
    if a.get('action') == 'ip_hour':
        msg['Subject'] = '[att-quota] %s 单 IP 一小时超 20GB：%s' % (
            a.get('machine'), a.get('ip') or '?')
    else:
        msg['Subject'] = '[att-quota] %s 端口 %s 已封停' % (a.get('machine'), a.get('port'))
    msg['From'] = env.get('MAIL_FROM') or env['SMTP_USER']
    msg['To'] = env['MAIL_TO']
    msg.set_content(
        '转发机：%s\n端口：%s\nIP：%s\n滚动一小时累计：%s（%s 字节）\n动作：%s\n时间：%s（北京时间）\n\n%s\n\n'
        '本条只告警，不封 IP/端口。\n'
        % (a.get('machine'), a.get('port'), a.get('ip') or '-',
           human(a.get('bytes')), a.get('bytes'),
           a.get('action'), when, a.get('detail') or ''))
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(env['SMTP_HOST'], int(env.get('SMTP_PORT') or 465),
                          timeout=25, context=ctx) as s:
        s.login(env['SMTP_USER'], env['SMTP_PASS'])
        s.send_message(msg)


def main():
    env = load_env(ENVF)
    need = ('HUB_ALERTS_URL', 'HUB_ALERT_ACK_URL', 'ALERT_TOKEN', 'SMTP_HOST',
            'SMTP_USER', 'SMTP_PASS', 'MAIL_TO')
    missing = [k for k in need if not env.get(k)]
    if missing:
        log('mailer.env 缺少', ','.join(missing))
        return 2
    try:
        alerts = fetch(env)
    except Exception as e:  # noqa: BLE001
        log('拉取告警失败：', e)
        return 1
    if not alerts:
        return 0
    done = []
    for a in alerts:
        if a.get('action') not in ('block', 'test', 'ip_hour'):
            done.append(a['id'])
            continue
        try:
            send(env, a)
            done.append(a['id'])
            log('已发送告警', a.get('machine'), a.get('port'))
        except Exception as e:  # noqa: BLE001
            log('发送失败，保留待重试：', a.get('id'), e)
            break
    if done:
        try:
            ack(env, done)
        except Exception as e:  # noqa: BLE001
            log('回执失败：', e)
    return 0


if __name__ == '__main__':
    sys.exit(main())
