"""quota 端口发现：所有对外监听端口，排除回环与 SSH。"""
import importlib.util
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('quota_t', ROOT / 'quota.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

TCP = '''State Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*
LISTEN 0 4096 [::]:443 [::]:*
LISTEN 0 511 127.0.0.1:6379 0.0.0.0:*
LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 128 0.0.0.0:1000 0.0.0.0:*
LISTEN 0 128 0.0.0.0:34302 0.0.0.0:*
'''
UDP = '''State Recv-Q Send-Q Local Address:Port Peer Address:Port
UNCONN 0 0 0.0.0.0:29851 0.0.0.0:*
UNCONN 0 0 127.0.0.53:53 0.0.0.0:*
'''


def fake(*args, **kw):
    if args[:2] == ('sshd', '-T'):
        return subprocess.CompletedProcess(args, 0, 'port 22\n', '')
    if '-ltn' in args:
        return subprocess.CompletedProcess(args, 0, TCP, '')
    if '-lun' in args:
        return subprocess.CompletedProcess(args, 0, UDP, '')
    return subprocess.CompletedProcess(args, 1, '', '')


m.run = fake
ports = m.discover_ports()
assert ('tcp', 443) in ports and ('tcp', 1000) in ports and ('tcp', 34302) in ports
assert ('udp', 29851) in ports
for bad in (('tcp', 22), ('tcp', 6379), ('udp', 53)):
    assert bad not in ports, ports
print('PASS: discovers all public listening ports, excludes loopback and SSH')
