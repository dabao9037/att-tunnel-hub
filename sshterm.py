#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WebSocket-backed SSH terminal for att-tunnel-hub.

The SSH PTY is kept on the panel machine for a grace period after the browser
WebSocket drops (background tab, phone lock, network change). A page can
reattach to the same shell with `?id=<session>&offset=<bytes already received>`
and the server replays the missed output. No third-party packages.

Passwords stay in memory only (and a 0600 temp file used by sshpass); they are
removed when the session is closed.
"""
import base64
import fcntl
import hashlib
import json
import os
import pty
import secrets
import signal
import struct
import tempfile
import termios
import threading
import time
import urllib.parse

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
PENDING_TTL = 120          # an unspawned session must be attached within this
DETACH_TTL = 600           # keep a detached SSH shell for 10 minutes
CLOSED_TTL = 60
MAX_BUF = 4 * 1024 * 1024
MAX_SESSIONS = 30
_LOCK = threading.RLock()
_SESSIONS = {}


# ---------------------------------------------------------------- frame helpers
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


# ---------------------------------------------------------------- session
class Session:
    def __init__(self, sid, host, port, user, password):
        self.id = sid
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.lock = threading.RLock()
        self.conn = None
        self.wlock = None
        self.fd = None
        self.pid = None
        self.tmpdir = ''
        self.buf = bytearray()
        self.dropped = 0
        self.spawned = False
        self.closed = False
        self.created = time.time()
        self.detached = time.time()
        self.rows = 24
        self.cols = 80

    def total(self):
        with self.lock:
            return self.dropped + len(self.buf)

    def append(self, data):
        if not data:
            return
        if isinstance(data, str):
            data = data.encode('utf-8', 'replace')
        with self.lock:
            self.buf += data
            if len(self.buf) > MAX_BUF:
                drop = len(self.buf) - MAX_BUF
                del self.buf[:drop]
                self.dropped += drop
            conn, wl = self.conn, self.wlock
        if conn is not None:
            try:
                _send_frame(conn, wl, 0x2, data)
            except Exception:
                self.detach()

    def attach(self, conn, wlock, offset):
        old, old_wl = None, None
        with self.lock:
            old, old_wl = self.conn, self.wlock
            self.conn, self.wlock = conn, wlock
            total = self.dropped + len(self.buf)
            start = offset if 0 <= offset <= total else 0
            pos = max(0, start - self.dropped)
            data = bytes(self.buf[pos:])
            if data:
                try:
                    _send_frame(conn, wlock, 0x2, data)
                except Exception:
                    self.conn = None
                    self.wlock = None
        if old is not None and old is not conn:
            try:
                _send_frame(old, old_wl, 0x8, b'')
            except Exception:
                pass

    def detach(self, conn=None):
        with self.lock:
            if conn is not None and self.conn is not conn:
                return
            self.conn = None
            self.wlock = None
            self.detached = time.time()

    def spawn(self, rows, cols):
        with self.lock:
            if self.spawned:
                self._resize(rows, cols)
                return True
            self.spawned = True
            self.rows, self.cols = rows, cols
        ssh = _which('ssh')
        sshpass = _which('sshpass')
        if not ssh or not sshpass:
            self.append('\r\n\x1b[31m[面板机缺少 ssh 或 sshpass，无法建立 SSH 连接]\x1b[0m\r\n')
            self.closed = True
            return False
        try:
            self.tmpdir = tempfile.mkdtemp(prefix='att-ssh-')
            pwfile = os.path.join(self.tmpdir, 'pw')
            known = os.path.join(self.tmpdir, 'known_hosts')
            with open(pwfile, 'w') as f:
                f.write(self.password)
            os.chmod(pwfile, 0o600)
            env = dict(os.environ, TERM='xterm-256color', LANG='C.UTF-8', LC_ALL='C.UTF-8')
            args = [sshpass, '-f', pwfile, ssh, '-tt',
                    '-p', str(self.port),
                    '-o', 'StrictHostKeyChecking=accept-new',
                    '-o', 'UserKnownHostsFile=' + known,
                    '-o', 'ConnectTimeout=15',
                    '-o', 'ServerAliveInterval=30',
                    '-o', 'ServerAliveCountMax=4',
                    '-o', 'NumberOfPasswordPrompts=1',
                    '-o', 'PubkeyAuthentication=no',
                    '-o', 'PreferredAuthentications=password,keyboard-interactive',
                    '-o', 'LogLevel=ERROR',
                    '%s@%s' % (self.user, self.host)]
            pid, fd = pty.fork()
            if pid == 0:
                try:
                    os.closerange(3, 256)
                    os.execvpe(sshpass, args, env)
                except Exception:
                    os._exit(127)
            with self.lock:
                self.pid, self.fd = pid, fd
            _winsize(fd, rows, cols)
            threading.Thread(target=self._reader, daemon=True).start()
            return True
        except Exception as e:
            self.append('\r\n\x1b[31m[SSH 连接失败：%s]\x1b[0m\r\n' % str(e)[:200])
            self.closed = True
            return False

    def _resize(self, rows, cols):
        with self.lock:
            fd = self.fd
        if fd is not None:
            _winsize(fd, rows, cols)

    def _reader(self):
        fd = self.fd
        while True:
            try:
                data = os.read(fd, 8192)
            except OSError:
                break
            if not data:
                break
            self.append(data)
        with self.lock:
            self.closed = True
            conn, wl = self.conn, self.wlock
        self.append('\r\n\x1b[33m[SSH 会话已结束]\x1b[0m\r\n')
        if conn is not None:
            try:
                _send_frame(conn, wl, 0x8, b'')
            except Exception:
                pass

    def write(self, data):
        with self.lock:
            fd = self.fd
            closed = self.closed
        if fd is not None and not closed and data:
            try:
                os.write(fd, data)
            except OSError:
                pass

    def close(self):
        with self.lock:
            if self.closed and self.fd is None and self.pid is None:
                pass
            self.closed = True
            fd, pid = self.fd, self.pid
            self.fd = self.pid = None
            conn, wl = self.conn, self.wlock
            self.conn = self.wlock = None
            tmpdir = self.tmpdir
            self.tmpdir = ''
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
        if conn is not None:
            try:
                _send_frame(conn, wl, 0x8, b'')
            except Exception:
                pass
        if tmpdir:
            for name in ('pw', 'known_hosts'):
                try:
                    os.remove(os.path.join(tmpdir, name))
                except OSError:
                    pass
            try:
                os.rmdir(tmpdir)
            except OSError:
                pass
        with _LOCK:
            _SESSIONS.pop(self.id, None)


def _reap():
    while True:
        time.sleep(30)
        now = time.time()
        for s in list(_SESSIONS.values()):
            with s.lock:
                attached = s.conn is not None
                spawned = s.spawned
                closed = s.closed
                detached = s.detached
                created = s.created
            try:
                if not spawned and now - created > PENDING_TTL:
                    s.close()
                elif spawned and not attached and now - detached > DETACH_TTL:
                    s.close()
                elif closed and not attached and now - detached > CLOSED_TTL:
                    s.close()
            except Exception:
                pass


threading.Thread(target=_reap, daemon=True).start()


def new_session(host, port, user, password):
    sid = secrets.token_urlsafe(18)
    s = Session(sid, host, port, user, password)
    with _LOCK:
        if len(_SESSIONS) >= MAX_SESSIONS:
            # evict the oldest detached/closed session first
            candidates = []
            for x in _SESSIONS.values():
                with x.lock:
                    if x.conn is None:
                        candidates.append((x.detached, x))
            candidates.sort(key=lambda z: z[0])
            for _, x in candidates[:max(1, len(candidates))]:
                x.close()
                if len(_SESSIONS) < MAX_SESSIONS:
                    break
        _SESSIONS[sid] = s
    return sid


def get_session(sid):
    with _LOCK:
        return _SESSIONS.get(sid)


def handle_ws(handler):
    try:
        q = {k: v[0] for k, v in
             urllib.parse.parse_qs(urllib.parse.urlsplit(handler.path).query).items()}
    except Exception:
        q = {}
    sess = get_session(q.get('id', ''))
    if not sess:
        return handler.send(410, 'SSH 会话不存在或已过期，请重新连接', 'text/plain; charset=utf-8')
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

    rows = q.get('rows', '24')
    cols = q.get('cols', '80')
    try:
        rows, cols = int(rows), int(cols)
    except ValueError:
        rows, cols = 24, 80
    try:
        offset = int(q.get('offset', '0'))
    except ValueError:
        offset = 0

    conn = handler.connection
    wlock = threading.Lock()
    if not sess.spawn(rows, cols):
        try:
            _send_frame(conn, wlock, 0x8, b'')
        except Exception:
            pass
        return
    sess.attach(conn, wlock, offset)

    stop = threading.Event()

    def pinger():
        while not stop.wait(25):
            with sess.lock:
                if sess.conn is not conn:
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
                if t == 'bye':
                    sess.close()
                    break
                if t == 'i':
                    sess.write((msg.get('d') or '').encode('utf-8', 'replace'))
                elif t == 'r':
                    sess._resize(msg.get('rows') or rows, msg.get('cols') or cols)
    except (EOFError, ConnectionResetError, OSError, ValueError):
        pass
    finally:
        stop.set()
        sess.detach(conn)
        try:
            ping_th.join(timeout=2)
        except Exception:
            pass
