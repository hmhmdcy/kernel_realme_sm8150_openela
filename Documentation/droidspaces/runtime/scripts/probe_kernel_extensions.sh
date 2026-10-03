#!/bin/sh
# Isolated, opt-in functional probes. A return code of 77 means unavailable.
set -eu
test -f /etc/droidspaces
mode=${1:?usage: probe_kernel_extensions.sh qemu|binfmt|bbr|nft|checkpoint|io|wireguard|lxc}
python3 - "$mode" <<'PY'
import json, os, shutil, socket, struct, subprocess, sys, tempfile, time, uuid
from pathlib import Path

mode = sys.argv[1]

def run(argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=40, **kwargs)
    if result.returncode:
        print(json.dumps({'failed_command': argv, 'returncode': result.returncode,
                          'stdout': result.stdout, 'stderr': result.stderr}), flush=True)
        result.check_returncode()
    return result.stdout.strip()

def unavailable(reason):
    print(json.dumps({'probe': mode, 'status': 'unavailable', 'reason': reason}))
    raise SystemExit(77)

def require(*tools):
    absent = [name for name in tools if not shutil.which(name)]
    if absent:
        unavailable('Missing userspace tools: ' + ', '.join(absent))

if mode in ('qemu', 'binfmt'):
    require('qemu-x86_64-static')
    if mode == 'binfmt' and 'binfmt_misc' not in Path('/proc/filesystems').read_text():
        unavailable('Running kernel has no binfmt_misc')
    with tempfile.TemporaryDirectory(prefix='rmx1931-qemu-') as temporary:
        base = Path(temporary)
        message = b'RMX1931_X86_64_PASS\n'
        # A minimal x86_64 ELF with write(1, message) and exit(0); no libc.
        code = (b'\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35' +
                struct.pack('<i', 16) + b'\xba' + struct.pack('<I', len(message)) +
                b'\x0f\x05\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05')
        ident = b'\x7fELF\x02\x01\x01' + b'\0' * 9
        size = 120 + len(code) + len(message)
        blob = (struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0) +
                struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, size, size, 0x1000) + code + message)
        binary = base / 'probe-x86_64'
        binary.write_bytes(blob)
        binary.chmod(0o700)
        assert run(['qemu-x86_64-static', str(binary)]) == message.decode().strip()
        if mode == 'binfmt':
            mount = base / 'binfmt'
            mount.mkdir()
            name = 'rmx1931-probe-' + uuid.uuid4().hex
            registered = False
            run(['mount', '-t', 'binfmt_misc', 'none', str(mount)])
            try:
                assert (mount / 'status').read_text().strip() == 'enabled', 'Global binfmt is disabled; refusing to enable it'
                magic = ''.join('\\x%02x' % byte for byte in blob[:20])
                (mount / 'register').write_text(':' + name + ':M::' + magic + '::/usr/bin/qemu-x86_64-static:F\n')
                registered = True
                assert run([str(binary)]) == message.decode().strip()
                assert run(['/bin/echo', 'NATIVE_ARM64_PASS']) == 'NATIVE_ARM64_PASS'
            finally:
                if registered:
                    (mount / name).write_text('-1\n')
                    assert not (mount / name).exists()
                run(['umount', str(mount)])
        print(json.dumps({'probe': mode, 'status': 'passed', 'architecture': 'x86_64',
                          'explicit_qemu': True, 'automatic_dispatch': mode == 'binfmt',
                          'registration_removed': mode == 'binfmt'}))
elif mode == 'bbr':
    require('unshare', 'tc', 'ip')
    # This 4.14 tree exposes the congestion-control sysctls only in init_net.
    # Read the actual per-socket default in the guest; require explicit BBR below.
    def default_algorithm():
        with socket.socket() as probe:
            return probe.getsockopt(socket.IPPROTO_TCP, 13, 16).rstrip(b'\0').decode()
    before = default_algorithm()
    assert before == 'cubic', before
    code = r'''
import socket, subprocess, threading, json
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
subprocess.run(['tc', 'qdisc', 'replace', 'dev', 'lo', 'root', 'fq'], check=True)
server = socket.socket()
server.bind(('127.0.0.1', 0)); server.listen(1)
total = [0]
def receive():
    peer, _ = server.accept()
    peer.settimeout(10)
    while True:
        data = peer.recv(65536)
        if not data: break
        total[0] += len(data)
    peer.close()
thread = threading.Thread(target=receive); thread.start()
client = socket.socket(); client.settimeout(10)
client.setsockopt(socket.IPPROTO_TCP, 13, b'bbr')
assert client.getsockopt(socket.IPPROTO_TCP, 13, 16).rstrip(b'\0') == b'bbr'
client.connect(server.getsockname()); client.sendall(b'x' * 1048576); client.close()
thread.join(15); assert not thread.is_alive() and total[0] == 1048576
server.close()
qdisc = subprocess.check_output(['tc', 'qdisc', 'show', 'dev', 'lo'], text=True)
assert 'qdisc fq ' in qdisc
print(json.dumps({'bytes_received': total[0], 'socket_algorithm': 'bbr', 'qdisc': qdisc.strip()}))
'''
    result = json.loads(run(['unshare', '--net', '--', 'python3', '-c', code]))
    assert default_algorithm() == before
    print(json.dumps({'probe': mode, 'status': 'passed', 'guest_default_preserved': before, **result}))
elif mode == 'nft':
    require('nft', 'unshare', 'nsenter', 'ip')
    # All hooks and NAT traffic live inside a disposable router namespace.
    code = r"""
import subprocess, time, json, select, socket, sys
from pathlib import Path
def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=15).stdout.strip()
children = []
server = None
def line(process):
    assert select.select([process.stdout], [], [], 10)[0], 'Server readiness timeout'
    value = process.stdout.readline().decode().strip()
    assert value, 'Server exited: ' + process.stderr.read().decode()
    return value
try:
    current = Path('/proc/self/ns/net').stat().st_ino
    for name in ['src', 'dst']:
        p = subprocess.Popen(['unshare', '--net', '--', 'sleep', '90'])
        children.append(p)
        for attempt in range(100):
            if Path('/proc/%s/ns/net' % p.pid).stat().st_ino != current: break
            time.sleep(.02)
        else: raise RuntimeError('Child network namespace was not created')
    src, dst = [p.pid for p in children]
    def ns(pid, argv): return ['nsenter', '-t', str(pid), '-n', '--'] + argv
    for n, pid, ipv4, ipv6 in [('s', src, '192.0.2', 'fd00:1931:1'), ('d', dst, '198.51.100', 'fd00:1931:2')]:
        router, endpoint = 'rmx-' + n + 'r', 'rmx-' + n
        run(['ip', 'link', 'add', router, 'type', 'veth', 'peer', 'name', endpoint])
        run(['ip', 'link', 'set', endpoint, 'netns', str(pid)])
        run(['ip', 'addr', 'add', ipv4 + '.1/24', 'dev', router])
        run(['ip', '-6', 'addr', 'add', ipv6 + '::1/64', 'dev', router, 'nodad'])
        run(['ip', 'link', 'set', router, 'up'])
        run(ns(pid, ['ip', 'addr', 'add', ipv4 + '.2/24', 'dev', endpoint]))
        run(ns(pid, ['ip', '-6', 'addr', 'add', ipv6 + '::2/64', 'dev', endpoint, 'nodad']))
        run(ns(pid, ['ip', 'link', 'set', endpoint, 'up']))
        run(ns(pid, ['ip', 'link', 'set', 'lo', 'up']))
    run(ns(src, ['ip', 'route', 'add', 'default', 'via', '192.0.2.1']))
    run(ns(src, ['ip', '-6', 'route', 'add', 'default', 'via', 'fd00:1931:1::1']))
    Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
    Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1\n')
    for family in ['inet', 'ip', 'ip6', 'arp', 'bridge', 'netdev']:
        run(['nft', 'add', 'table', family, 'rmx1931_probe'])
    rules = '''
add chain inet rmx1931_probe forward { type filter hook forward priority 0; policy drop; }
add rule inet rmx1931_probe forward ct state established,related counter accept
add rule inet rmx1931_probe forward tcp dport 4242 ct state new counter accept
add chain inet rmx1931_probe prerouting { type filter hook prerouting priority -150; }
add rule inet rmx1931_probe prerouting udp dport 4343 socket transparent 1 counter accept
add rule inet rmx1931_probe prerouting udp dport 4344 socket transparent 0 counter drop
add chain ip rmx1931_probe prerouting { type nat hook prerouting priority -100; }
add chain ip rmx1931_probe postrouting { type nat hook postrouting priority 100; }
add rule ip rmx1931_probe postrouting oifname "rmx-dr" ip saddr 192.0.2.0/24 counter masquerade
add chain ip6 rmx1931_probe prerouting { type nat hook prerouting priority -100; }
add chain ip6 rmx1931_probe postrouting { type nat hook postrouting priority 100; }
add rule ip6 rmx1931_probe postrouting oifname "rmx-dr" ip6 saddr fd00:1931:1::/64 counter masquerade
'''
    subprocess.run(['nft', '-f', '-'], input=rules, check=True, text=True, timeout=10)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as transparent:
        transparent.setsockopt(socket.SOL_IP, 19, 1)
        transparent.settimeout(5); transparent.bind(('192.0.2.1', 4343))
        client_code = 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(8); s.sendto(b"SOCKET_PROBE",("192.0.2.1",4343)); assert s.recv(128)==b"SOCKET_OK"; s.close()'
        socket_client = subprocess.Popen(ns(src, ['python3', '-c', client_code]), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        data, peer = transparent.recvfrom(128); assert data == b'SOCKET_PROBE'
        transparent.sendto(b'SOCKET_OK', peer)
        _, errors = socket_client.communicate(timeout=10); assert socket_client.returncode == 0, errors
    run(ns(src, ['python3', '-c', 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"NO_SOCKET",("192.0.2.1",4344)); s.close()']))
    server_code = '''
import socket, json
for family, address in [(socket.AF_INET, '198.51.100.2'), (socket.AF_INET6, 'fd00:1931:2::2')]:
    with socket.socket(family) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(10); listener.bind((address, 4242)); listener.listen(1)
        print('READY', flush=True)
        peer, remote = listener.accept()
        with peer:
            peer.settimeout(5); assert peer.recv(128) == b'RMX1931_NAT_PROBE'; peer.sendall(b'OK')
        print(json.dumps({'peer': remote[0]}), flush=True)
'''
    server = subprocess.Popen(ns(dst, ['python3', '-c', server_code]), stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    peers = []
    for family, address, expected in [('AF_INET', '198.51.100.2', '198.51.100.1'), ('AF_INET6', 'fd00:1931:2::2', 'fd00:1931:2::1')]:
        assert line(server) == 'READY'
        client_code = 'import socket; s=socket.socket(socket.%s); s.settimeout(8); s.connect((%r,4242)); s.sendall(b"RMX1931_NAT_PROBE"); assert s.recv(128)==b"OK"; s.close()' % (family, address)
        run(ns(src, ['python3', '-c', client_code]))
        peer = json.loads(line(server))['peer']; assert peer == expected, (peer, expected); peers.append(peer)
    assert server.wait(timeout=10) == 0
    ruleset = json.loads(run(['nft', '-j', 'list', 'ruleset']))
    counts = {family: 0 for family in ['ip', 'ip6']}
    socket_counts = {}
    for item in ruleset['nftables']:
        rule = item.get('rule', {})
        if rule.get('chain') == 'postrouting' and rule.get('family') in counts:
            counts[rule['family']] += sum(expr.get('counter', {}).get('packets', 0) for expr in rule['expr'])
        if rule.get('chain') == 'prerouting' and rule.get('family') == 'inet':
            for expression in rule['expr']:
                match = expression.get('match', {})
                if isinstance(match.get('left'), dict) and 'socket' in match['left']:
                    socket_counts[int(match['right'])] = sum(expr.get('counter', {}).get('packets', 0) for expr in rule['expr'])
    assert all(count > 0 for count in counts.values()), counts
    assert socket_counts.get(1, 0) > 0 and socket_counts.get(0) == 0, socket_counts
    print(json.dumps({'families': ['inet','ip','ip6','arp','bridge','netdev'], 'nat_observed_peers': peers, 'nat_packet_counters': counts, 'socket_counters': socket_counts}))
finally:
    if server and server.poll() is None: server.terminate(); server.wait(timeout=5)
    for p in children:
        if p.poll() is None: p.terminate(); p.wait(timeout=5)
"""
    result = json.loads(run(['unshare', '--net', '--', 'python3', '-c', code]))
    print(json.dumps({'probe': mode, 'status': 'passed', 'scope': 'disposable netns only', **result}))
elif mode == 'checkpoint':
    require('criu')
    if not Path('/proc/self/task/%s/children' % os.getpid()).exists():
        unavailable('Running kernel lacks checkpoint/restore children interface')
    with tempfile.TemporaryDirectory(prefix='rmx1931-criu-') as temporary:
        directory = Path(temporary)
        original = subprocess.Popen(['sleep', '90'], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        restored = None
        try:
            run(['criu', 'check', '-v4', '-o', str(directory / 'check.log')])
            run(['criu', 'dump', '-t', str(original.pid), '-D', temporary, '--shell-job', '--leave-running', '-o', 'dump.log'])
            assert original.poll() is None
            # Stop only this fixture, then restore it from its checkpoint.
            original.terminate(); original.wait(timeout=5)
            pidfile = directory / 'restored.pid'
            run(['criu', 'restore', '-D', temporary, '--shell-job', '--restore-detached', '--pidfile', str(pidfile), '-o', 'restore.log'])
            restored = int(pidfile.read_text())
            assert restored > 1 and Path('/proc/%s/comm' % restored).read_text().strip() == 'sleep'
            print(json.dumps({'probe': mode, 'status': 'passed', 'scope': 'single sleep process', 'container_checkpoint_verified': False}))
        except Exception:
            # Keep diagnostics outside the temporary image directory.
            output = Path('/tmp/rmx1931-tests/criu-diagnostics-' + uuid.uuid4().hex)
            output.mkdir(parents=True)
            for name in ['check.log', 'dump.log', 'restore.log']:
                if (directory / name).exists():
                    shutil.copy2(directory / name, output / name)
                    print((directory / name).read_text(errors='replace')[-10000:], flush=True)
            print(json.dumps({'probe': mode, 'status': 'failed', 'diagnostics': str(output)}))
            raise
        finally:
            if original.poll() is None: original.terminate(); original.wait(timeout=5)
            if restored and Path('/proc/%s/comm' % restored).exists():
                assert Path('/proc/%s/comm' % restored).read_text().strip() == 'sleep'
                os.kill(restored, 15)
elif mode == 'io':
    # Android currently owns blkio in v1. Do not unbind/migrate it to make a test pass.
    controllers = Path('/sys/fs/cgroup/cgroup.controllers').read_text().split()
    source = run(['findmnt', '-n', '-o', 'SOURCE,FSTYPE', '/'])
    print(json.dumps({'probe': mode, 'guest_v2_controllers': controllers, 'rootfs': source,
                      'io_max_available': 'io' in controllers, 'enforcement_verified': False}))
    unavailable('I/O enforcement requires a separately delegated controller and verified loop/backing-device accounting')
elif mode == 'wireguard':
    require('unshare', 'ip', 'wg', 'nsenter', 'ping')
    code = r'''
import subprocess, tempfile, time, json
from pathlib import Path
def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=15, **kwargs).stdout.strip()
children = []
try:
    original = Path('/proc/self/ns/net').stat().st_ino
    for index in range(2):
        child = subprocess.Popen(['unshare', '--net', '--', 'sleep', '90']); children.append(child)
        for attempt in range(100):
            if Path('/proc/%s/ns/net' % child.pid).stat().st_ino != original: break
            time.sleep(.02)
        else: raise RuntimeError('WireGuard child namespace was not created')
    def ns(index, argv): return ['nsenter', '-t', str(children[index].pid), '-n', '--'] + argv
    run(['ip', 'link', 'add', 'rmx-wga', 'type', 'veth', 'peer', 'name', 'rmx-wgb'])
    keys = []
    with tempfile.TemporaryDirectory(prefix='rmx1931-wg-') as temporary:
        for index in range(2):
            key = run(['wg', 'genkey']); public = run(['wg', 'pubkey'], input=key + '\n')
            target = Path(temporary) / ('key-%s' % index)
            target.write_text(key + '\n'); target.chmod(0o600); keys.append((target, public))
        for index, name in enumerate(['rmx-wga', 'rmx-wgb']):
            run(['ip', 'link', 'set', name, 'netns', str(children[index].pid)])
            run(ns(index, ['ip', 'addr', 'add', '192.0.2.%s/24' % (index + 1), 'dev', name]))
            run(ns(index, ['ip', 'link', 'set', name, 'up']))
            run(ns(index, ['ip', 'link', 'set', 'lo', 'up']))
            run(ns(index, ['ip', 'link', 'add', 'wg0', 'type', 'wireguard']))
            run(ns(index, ['ip', 'addr', 'add', '10.193.1.%s/24' % (index + 1), 'dev', 'wg0']))
            other = 1 - index
            run(ns(index, ['wg', 'set', 'wg0', 'private-key', str(keys[index][0]), 'listen-port', '51820',
                           'peer', keys[other][1], 'allowed-ips', '10.193.1.%s/32' % (other + 1),
                           'endpoint', '192.0.2.%s:51820' % (other + 1)]))
            run(ns(index, ['ip', 'link', 'set', 'wg0', 'up']))
        ping = run(ns(0, ['ping', '-I', 'wg0', '-c', '3', '-W', '3', '10.193.1.2']))
        assert '0% packet loss' in ping, ping
        handshakes, transfer = [], []
        for index in range(2):
            handshake = run(ns(index, ['wg', 'show', 'wg0', 'latest-handshakes'])).split()
            assert len(handshake) == 2 and int(handshake[1]) > 0
            stats = run(ns(index, ['wg', 'show', 'wg0', 'transfer'])).split()
            assert len(stats) == 3 and int(stats[1]) > 0 and int(stats[2]) > 0
            handshakes.append(True); transfer.append({'rx': int(stats[1]), 'tx': int(stats[2])})
        print(json.dumps({'peer_handshakes': handshakes, 'tunnel_ping_packets': 3, 'packet_loss_percent': 0, 'transfer_bytes': transfer}))
finally:
    for child in children:
        if child.poll() is None: child.terminate(); child.wait(timeout=5)
'''
    result = json.loads(run(['unshare', '--net', '--', 'python3', '-c', code]))
    print(json.dumps({'probe': mode, 'status': 'passed', 'scope': 'disposable namespaces and ephemeral keys', **result}))
elif mode == 'lxc':
    require('lxc-checkconfig')
    print(run(['lxc-checkconfig']))
    print(json.dumps({'probe': mode, 'status': 'diagnostic-only', 'container_launch_verified': False}))
else:
    raise SystemExit('Unknown mode')
PY
