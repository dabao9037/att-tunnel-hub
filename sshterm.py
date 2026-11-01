#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal WebSocket-backed SSH terminal for att-tunnel-hub.

No third-party packages: stdlib WebSocket framing + system ssh/sshpass + pty.
Passwords live only in a short-lived in-memory map and a 0600 temp file.
"""
import base64
import fcntl
import hashlib
import json
import os
import pty
import secrets
import shutil
import signal
import struct
import tempfile
import termios
import threading
import urllib.parse
import time

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
PENDING_TTL = 120
_LOCK = threading.Lock()
_PENDING = {}


def new_session(host, port, user, password):
    """Create a one-time ticket for the WebSocket; credentials stay in memory."""
    sid = secrets.token_urlsafe(18)
    now = time.time()
    with _LOCK:
        for k in [k for k, v in _PENDING.items() if v['exp'] < now]:
            _PENDING.pop(k, None)
        _PENDING[sid] = {'host': host, 'port': int(port), 'user': user,
                         'password': password, 'exp': now + PENDING_TTL}
    return sid


def pop_session(sid):
    with _LOCK:
        d = _PENDING.pop(sid, None)
    if not d or d['exp'] < time.time():
        return None
    return d


# ---------------------------------------------------------------- WebSocket
def _read_exact(f, n):
    b = f.read(n)
    if len(b) < n:
        raise EOFError
    return b


def _read_frame(f):
    h = _read_exact(f, 2)
    b1, b2 = h[0], h[1]
    fin = bool(b1 & 0x80)
    op = b1 & 0x0F
    masked = bool(b2 & 0x80)
    ln = b2 & 0x7F
    if ln == 126:
        ln = struct.unpack('!H', _read_exact(f, 2))[0]
    elif ln == 127:
        ln = struct.unpack('!Q', _read_exact(f, 8))[0]
    mask = _read_exact(f, 4) if masked else b''
    data = _read_exact(f, ln) if ln else b''
    if masked:
        data = bytes(c ^ mask[i % 4] for i, c in enumerate(data))
    return fin, op, data


def _send_frame(sock, wlock, op, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    hdr = bytearray([0x80 | op])
    n = len(data)
    if n < 126:
        hdr.append(n)
    elif n < 65536:
        hdr.append(126)
        hdr += struct.pack('!H', n)
    else:
        hdr.append(127)
        hdr += struct.pack('!Q', n)
    with wlock:
        sock.sendall(bytes(hdr) + data)


def _winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ,
                    struct.pack('HHHH', max(5, int(rows)), max(20, int(cols)), 0, 0))
    except Exception:
        pass


def _which(name):
    for d in ('/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return ''


def handle_ws(handler):
    """Hijack the HTTP connection and bridge a PTY running ssh."""
    try:
        q = {k: v[0] for k, v in
             urllib.parse.parse_qs(urllib.parse.urlsplit(handler.path).query).items()}
    except Exception:
        q = {}
    sess = pop_session(q.get('id', ''))
    if not sess:
        return handler.send(403, 'SSH 会话不存在或已过期，请重新连接', 'text/plain; charset=utf-8')
    key = handler.headers.get('Sec-WebSocket-Key') or ''
    if not key or (handler.headers.get('Upgrade') or '').lower() != 'websocket':
        return handler.send(400, 'websocket only', 'text/plain')
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    handler.send_response(101, 'Switching Protocols')
    handler.send_header('Upgrade', 'websocket')
    handler.send_header('Connection', 'Upgrade')
    handler.send_header('Sec-WebSocket-Accept', accept)
    handler.end_headers()
    handler.close_connection = True

    ssh = _which('ssh')
    sshpass = _which('sshpass')
    conn = handler.connection
    wlock = threading.Lock()

    def say(text):
        try:
            _send_frame(conn, wlock, 0x1, text)
        except Exception:
            pass

    if not ssh or not sshpass:
        say('\r\n\x1b[31m[面板机缺少 ssh 或 sshpass，无法建立 SSH 连接]\x1b[0m\r\n')
        try:
            _send_frame(conn, wlock, 0x8, b'')
        except Exception:
            pass
        return

    rows = q.get('rows', '24')
    cols = q.get('cols', '80')
    try:
        rows, cols = int(rows), int(cols)
    except ValueError:
        rows, cols = 24, 80

    tmpdir = tempfile.mkdtemp(prefix='att-ssh-')
    pwfile = os.path.join(tmpdir, 'pw')
    known = os.path.join(tmpdir, 'known_hosts')
    try:
        with open(pwfile, 'w') as f:
            f.write(sess['password'])
        os.chmod(pwfile, 0o600)
        env = dict(os.environ, TERM='xterm-256color', LANG='C.UTF-8', LC_ALL='C.UTF-8')
        args = [sshpass, '-f', pwfile, ssh, '-tt',
                '-p', str(sess['port']),
                '-o', 'StrictHostKeyChecking=accept-new',
                '-o', 'UserKnownHostsFile=' + known,
                '-o', 'ConnectTimeout=15',
                '-o', 'ServerAliveInterval=30',
                '-o', 'ServerAliveCountMax=4',
                '-o', 'NumberOfPasswordPrompts=1',
                '-o', 'PubkeyAuthentication=no',
                '-o', 'PreferredAuthentications=password,keyboard-interactive',
                '-o', 'LogLevel=ERROR',
                '%s@%s' % (sess['user'], sess['host'])]
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.closerange(3, 256)
                os.execvpe(sshpass, args, env)
            except Exception:
                os._exit(127)
        _winsize(fd, rows, cols)

        stop = threading.Event()

        def reader():
            while not stop.is_set():
                try:
                    data = os.read(fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                try:
                    _send_frame(conn, wlock, 0x2, data)
                except Exception:
                    break
            try:
                _send_frame(conn, wlock, 0x8, b'')
            except Exception:
                pass

        th = threading.Thread(target=reader, daemon=True)
        th.start()

        def pinger():
            while not stop.is_set():
                if stop.wait(25):
                    break
                try:
                    _send_frame(conn, wlock, 0x9, b'')
                except Exception:
                    break

        ping_th = threading.Thread(target=pinger, daemon=True)
        ping_th.start()

        try:
            pending_op = None
            pending = b''
            while True:
                fin, op, data = _read_frame(handler.rfile)
                if op == 0x8:
                    break
                if op == 0x9:
                    _send_frame(conn, wlock, 0xA, data)
                    continue
                if op == 0xA:
                    continue
                if op in (0x1, 0x2):
                    if not fin:
                        pending_op = op
                        pending += data
                        continue
                    if pending_op is not None:
                        data = pending + data
                        pending_op = None
                        pending = b''
                    try:
                        msg = json.loads(data.decode('utf-8', 'replace'))
                    except ValueError:
                        continue
                    t = msg.get('t')
                    if t == 'p':
                        continue
                    if t == 'i':
                        d = msg.get('d') or ''
                        if d:
                            n = os.write(fd, d.encode('utf-8', 'replace'))
                    elif t == 'r':
                        _winsize(fd, msg.get('rows') or rows, msg.get('cols') or cols)
        except (EOFError, ConnectionResetError, OSError, ValueError):
            pass
        finally:
            stop.set()
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
            for t in (th, ping_th):
                try:
                    t.join(timeout=2)
                except Exception:
                    pass
    except Exception as e:
        try:
            say('\r\n\x1b[31m[SSH 连接失败：%s]\x1b[0m\r\n' % str(e)[:200])
        except Exception:
            pass
    finally:
        for p in (pwfile, known):
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass
