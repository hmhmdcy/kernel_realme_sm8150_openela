#!/usr/bin/python3
"""Persistent, pre-execution OCI policies for the isolated RMX1931 guest.

CPU uses native V2 when available, with legacy V1 fallback. Memory, pids and IO are native V2
resources supplied to the real OCI runtime. No post-start polling applies limits.
"""
import argparse
import decimal
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import sys
import tempfile
import time

ANNOTATION = 'io.rmx1931.resource-policy'
REGISTRY = Path('/etc/rmx1931/resource-policies.json')
STATE = Path('/var/lib/rmx1931-policy/containers')
RUN = Path('/run/rmx1931-policy')
SOCKET = RUN / 'control.sock'
CPU_PREFIX = 'rmx1931-policy-'
NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}')
CID = re.compile(r'[0-9a-f]{64}')
STORAGE = {0: Path('/var/lib/containers/storage'),
           1000: Path('/home/podmantest/.local/share/containers/storage')}
MAX_JSON = 2 * 1024 * 1024


class PolicyError(RuntimeError):
    pass


def bounded_integer(value, low, high, field):
    if type(value) is not int or not low <= value <= high:
        raise PolicyError('Invalid ' + field)
    return value


def validate_registry(data):
    if type(data) is not dict or set(data) != {'version', 'profiles'} or type(data['version']) is not int or data['version'] != 1:
        raise PolicyError('Unsupported policy registry')
    if type(data['profiles']) is not dict or len(data['profiles']) > 128:
        raise PolicyError('Invalid profiles')
    for name, profile in data['profiles'].items():
        if not NAME.fullmatch(name) or type(profile) is not dict:
            raise PolicyError('Invalid profile name')
        fields = {'uid', 'cpu_quota_us', 'memory_bytes', 'pids', 'read_bps', 'write_bps', 'oom_group'}
        if set(profile) not in (fields, fields | {'memory_high_bytes'}) or type(profile['uid']) is not int or profile['uid'] not in STORAGE:
            raise PolicyError('Invalid profile fields/owner')
        bounded_integer(profile['cpu_quota_us'], 1000, 800000, 'CPU quota')
        bounded_integer(profile['memory_bytes'], 16 * 1024**2, 8 * 1024**3, 'memory limit')
        if 'memory_high_bytes' in profile:
            bounded_integer(profile['memory_high_bytes'], 16 * 1024**2,
                            profile['memory_bytes'] - 1, 'memory high threshold')
        bounded_integer(profile['pids'], 8, 4096, 'pids limit')
        for field in ('read_bps', 'write_bps'):
            bounded_integer(profile[field], 65536, 1024**3, field)
        if type(profile['oom_group']) is not bool:
            raise PolicyError('Invalid oom_group')
    return data


def visible_root_uid(mapping, overflow):
    for line in mapping.splitlines():
        inner, outer, length = map(int, line.split())
        if outer <= 0 < outer + length:
            return inner - outer
    return overflow


def trusted_json(path, missing=None, client=False):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        if missing is not None:
            return missing
        raise
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        root_uid = visible_root_uid(Path('/proc/self/uid_map').read_text(),
                                    int(Path('/proc/sys/kernel/overflowuid').read_text())) if client else 0
        if not stat.S_ISREG(info.st_mode) or info.st_uid != root_uid or info.st_mode & 0o022:
            raise PolicyError('Policy/state must be a root-owned regular file: ' + str(path))
        content = stream.read(MAX_JSON + 1)
        if len(content) > MAX_JSON:
            raise PolicyError('Policy/state too large')
        return json.loads(content)


def registry(client=False):
    return validate_registry(trusted_json(REGISTRY, client=client))


def profile_references(name):
    references = []
    for path in STATE.glob('*.json'):
        record = trusted_json(path)
        if record['profile'] == name and expected_config(record['uid'], record['cid']).exists():
            references.append(record['cid'])
    return references


def atomic_json(path, data, mode=0o644):
    content = (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()
    fd, temporary = tempfile.mkstemp(prefix='.policy-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def expected_config(uid, cid):
    if uid not in STORAGE or not CID.fullmatch(cid):
        raise PolicyError('Invalid OCI owner/container identity')
    return STORAGE[uid] / 'overlay-containers' / cid / 'userdata' / 'config.json'


def directory_fd(path):
    """Walk from / with no symlink traversal, and retain the actual directory."""
    if not path.is_absolute() or '..' in path.parts:
        raise PolicyError('Invalid bundle path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_config(uid, cid, bundle=None):
    path = expected_config(uid, cid)
    if bundle is not None and Path(bundle) != path.parent:
        raise PolicyError('OCI bundle does not match caller-owned Podman storage')
    parent = directory_fd(path.parent)
    try:
        fd = os.open('config.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1:
                raise PolicyError('OCI configuration owner/type changed')
            content = stream.read(MAX_JSON + 1)
            if len(content) > MAX_JSON:
                raise PolicyError('OCI configuration too large')
            config = json.loads(content)
        if config.get('annotations', {}).get('io.container.manager') != 'libpod':
            raise PolicyError('Only Podman OCI bundles are supported')
        if not str(config.get('linux', {}).get('cgroupsPath', '')).endswith(':libpod:' + cid):
            raise PolicyError('OCI cgroup identity mismatch')
        return parent, info, config
    except BaseException:
        os.close(parent)
        raise


def write_config(parent, original, uid, config):
    """Publish only inside the already opened, verified userdata directory."""
    current = os.stat('config.json', dir_fd=parent, follow_symlinks=False)
    if (current.st_dev, current.st_ino, current.st_mtime_ns) != (original.st_dev, original.st_ino, original.st_mtime_ns):
        raise PolicyError('OCI configuration changed while applying policy')
    temporary = '.rmx1931-policy-' + os.urandom(12).hex()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        os.fchown(fd, uid, original.st_gid)
        os.fchmod(fd, stat.S_IMODE(original.st_mode))
        with os.fdopen(fd, 'wb') as stream:
            stream.write((json.dumps(config) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, 'config.json', src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def apply_resources(config, profile, device, cpu_backend='v1'):
    if cpu_backend not in ('v1', 'v2'):
        raise PolicyError('Unknown CPU backend')
    major, minor = device
    resources = config['linux'].setdefault('resources', {})
    resources.setdefault('memory', {}).update(limit=profile['memory_bytes'], swap=profile['memory_bytes'] * 2)
    resources['pids'] = {'limit': profile['pids']}
    block = resources.setdefault('blockIO', {})
    # Preserve unrelated device rules. Replace only this guest rootfs device.
    for field, rate in [('throttleReadBpsDevice', profile['read_bps']), ('throttleWriteBpsDevice', profile['write_bps'])]:
        rules = [item for item in block.get(field, []) if (item.get('major'), item.get('minor')) != device]
        rules.append({'major': major, 'minor': minor, 'rate': rate})
        block[field] = rules
    resources.setdefault('unified', {})['memory.oom.group'] = '1' if profile['oom_group'] else '0'
    if 'memory_high_bytes' in profile:
        resources['unified']['memory.high'] = str(profile['memory_high_bytes'])
    if cpu_backend == 'v2':
        resources.setdefault('cpu', {}).update(quota=profile['cpu_quota_us'], period=100000)
        # A caller's raw knob must not override the annotated policy quota.
        resources['unified'].pop('cpu.max', None)
    return config


def send_request(request, timeout=8):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(SOCKET))
        sock.sendall(json.dumps(request).encode() + b'\n')
        data = bytearray()
        while b'\n' not in data:
            chunk = sock.recv(65536)
            if not chunk or len(data) + len(chunk) > MAX_JSON:
                raise PolicyError('Incomplete/oversized policy response')
            data.extend(chunk)
        response = json.loads(bytes(data).split(b'\n', 1)[0])
        if not response.get('ok'):
            raise PolicyError(response.get('error', 'Policy service rejected request'))
        return response


def parse_runtime(argv):
    ids = [item for item in argv if CID.fullmatch(item)]
    if not ids:
        return None
    if len(set(ids)) != 1:
        raise PolicyError('Ambiguous OCI container identity')
    action = next((item for item in argv if item in {'create', 'run', 'start', 'exec', 'delete'}), None)
    if action is None:
        return None
    bundle = None
    for index, item in enumerate(argv):
        if item in ('--bundle', '-b'):
            if index + 1 == len(argv):
                raise PolicyError('Missing OCI bundle')
            bundle = str(Path(argv[index + 1]).absolute())
        elif item.startswith('--bundle='):
            bundle = str(Path(item.split('=', 1)[1]).absolute())
    if action in {'create', 'run'} and bundle is None:
        bundle = os.getcwd()
    return {'action': action, 'cid': ids[0], 'bundle': bundle}


def runtime_entry(argv):
    request = parse_runtime(argv)
    if request is None:
        return False
    # Validate even when the server is unavailable; malformed policies must not
    # silently disable protection. No profile annotation means ordinary Podman.
    registry(client=True)
    try:
        return send_request(request)['managed']
    except (OSError, TimeoutError) as error:
        cid = request['cid']
        state = trusted_json(STATE / (cid + '.json'), missing={}, client=True)
        managed = bool(state.get('profile'))
        if request['bundle'] is not None:
            path = Path(request['bundle']) / 'config.json'
            # Read only the caller's current OCI config for an outage decision.
            with path.open('rb') as stream:
                content = stream.read(MAX_JSON + 1)
            if len(content) > MAX_JSON:
                raise PolicyError('OCI configuration too large')
            managed = managed or ANNOTATION in json.loads(content).get('annotations', {})
        if managed and request['action'] in {'create', 'run', 'start', 'exec'}:
            raise PolicyError('Managed container refused: policy service unavailable: ' + str(error)) from error
        return False


class Server:
    def __init__(self, cpu_root):
        self.cpu_root = cpu_root
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.pidns = os.readlink('/proc/self/ns/pid')
        dev = Path('/').stat().st_dev
        self.device = (os.major(dev), os.minor(dev))
        if self.device[0] != 7:
            raise PolicyError('Policy IO device must be this guest rootfs loop device')
        self.cpu_backend = 'v2' if 'cpu' in Path('/sys/fs/cgroup/cgroup.controllers').read_text().split() else 'v1'
        if self.cpu_backend == 'v1' and not (cpu_root / 'cpu.cfs_quota_us').is_file():
            raise PolicyError('Neither native V2 CPU nor private V1 CPU is available')
        self.stopped = False

    def collect_empty(self):
        for path in STATE.glob('*.json'):
            cid = path.stem
            if not CID.fullmatch(cid):
                raise PolicyError('Unexpected policy state filename')
            state = trusted_json(path)
            uid = state['uid']
            group = self.cpu_root / (CPU_PREFIX + cid) if state.get('cpu_backend', 'v1') == 'v1' else None
            if group is not None and group.exists() and not (group / 'cgroup.procs').read_text().strip():
                try:
                    group.rmdir()
                except OSError as error:
                    if error.errno not in (errno.EBUSY, errno.ENOTEMPTY):
                        raise
            if not expected_config(uid, cid).exists() and (group is None or not group.exists()):
                path.unlink()

    def handle(self, request, pid, uid):
        if uid not in STORAGE or pid <= 1 or os.readlink('/proc/' + str(pid) + '/ns/pid') != self.pidns:
            raise PolicyError('Unauthorized caller/guest PID namespace')
        action = request.get('action')
        if action == 'ping':
            return {'ok': True, 'pid': os.getpid(), 'boot_id': self.boot, 'pid_namespace': self.pidns,
                    'device': self.device, 'cpu_backend': self.cpu_backend,
                    'cpu_interface': 'V2 cpu.max via OCI' if self.cpu_backend == 'v2' else 'V1 cpu.cfs_quota_us',
                    'managed': False}
        if action == 'status':
            return {'ok': True, 'containers': [trusted_json(path) for path in STATE.glob('*.json')
                                               if trusted_json(path)['uid'] == uid]}
        if action not in {'create', 'run', 'start', 'exec', 'delete'}:
            raise PolicyError('Unsupported OCI operation')
        cid = request.get('cid', '')
        bundle = request.get('bundle')
        parent, info, config = open_config(uid, cid, bundle)
        try:
            name = config.get('annotations', {}).get(ANNOTATION)
            if name is None:
                return {'ok': True, 'managed': False}
            if action == 'delete':
                # A failed admission must still be removable. Cleanup validates
                # the caller/bundle identity but does not apply a missing policy.
                return {'ok': True, 'managed': True}
            profiles = registry()['profiles']
            if type(name) is not str or name not in profiles or profiles[name]['uid'] != uid:
                raise PolicyError('Unknown policy or policy belongs to a different user: ' + str(name))
            profile = profiles[name]
            if action in {'create', 'run'}:
                apply_resources(config, profile, self.device, self.cpu_backend)
                write_config(parent, info, uid, config)
            # SO_PEERCRED chooses the requesting process; no client-supplied PID.
            # Keep a pidfd open across placement to bind this live peer identity.
            peer_fd = os.pidfd_open(pid)
            try:
                if self.cpu_backend == 'v1':
                    group = self.cpu_root / (CPU_PREFIX + cid)
                    if not group.exists():
                        group.mkdir(mode=0o700)
                    (group / 'cpu.cfs_period_us').write_text('100000\n')
                    (group / 'cpu.cfs_quota_us').write_text(str(profile['cpu_quota_us']) + '\n')
                    (group / 'cgroup.procs').write_text(str(pid) + '\n')
                else:
                    require_native_cpu_peer(Path('/proc/' + str(pid) + '/cgroup').read_text())
            finally:
                os.close(peer_fd)
            row = {'cid': cid, 'uid': uid, 'profile': name, 'limits': profile, 'boot_id': self.boot,
                   'guest_pid_namespace': self.pidns, 'io_device': list(self.device),
                   'cpu_backend': self.cpu_backend,
                   'cpu_group': '/' + CPU_PREFIX + cid if self.cpu_backend == 'v1' else config['linux']['cgroupsPath'],
                   'cpu_group_format': 'V1 absolute path' if self.cpu_backend == 'v1' else 'OCI systemd cgroupsPath',
                   'cpu_applied_before_runtime': self.cpu_backend == 'v1',
                   'cpu_resources_in_oci': self.cpu_backend == 'v2', 'last_operation': action,
                   'applied_before_runtime': True, 'observed_at': time.time()}
            atomic_json(STATE / (cid + '.json'), row)
            print(json.dumps({'event': 'policy-applied', **row}), flush=True)
            return {'ok': True, 'managed': True, **row}
        finally:
            os.close(parent)

    def serve(self, ready_fd=None):
        registry()
        self.collect_empty()
        if SOCKET.exists():
            raise PolicyError('Existing policy socket: inspect the previous server before restarting')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(SOCKET))
            os.chmod(SOCKET, 0o666)
            server.listen(16)
            server.settimeout(1)
            atomic_json(RUN / 'server.json', self.handle({'action': 'ping'}, os.getpid(), 0))
            if ready_fd is not None:
                os.write(ready_fd, b'1')
                os.close(ready_fd)
            def stop(*unused):
                self.stopped = True
            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGINT, stop)
            try:
                while not self.stopped:
                    try:
                        connection, _ = server.accept()
                    except socket.timeout:
                        self.collect_empty()
                        continue
                    with connection:
                        connection.settimeout(3)
                        pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        try:
                            data = bytearray()
                            while b'\n' not in data:
                                chunk = connection.recv(4096)
                                if not chunk or len(data) + len(chunk) > 16384:
                                    raise PolicyError('Invalid policy request size')
                                data.extend(chunk)
                            response = self.handle(json.loads(bytes(data).split(b'\n', 1)[0]), pid, uid)
                        except Exception as error:
                            response = {'ok': False, 'error': str(error)}
                            print(json.dumps({'event': 'policy-rejected', 'peer_uid': uid, 'error': str(error)}), flush=True)
                        try:
                            connection.sendall(json.dumps(response).encode() + b'\n')
                        except (BrokenPipeError, ConnectionResetError):
                            pass
            finally:
                SOCKET.unlink(missing_ok=True)
                self.collect_empty()


def require_native_cpu_peer(membership):
    """A non-root legacy CPU placement intentionally selects that controller."""
    for line in membership.splitlines():
        fields = line.split(':', 2)
        if len(fields) != 3:
            raise PolicyError('Malformed peer cgroup membership')
        if {'cpu', 'cpu_legacy'} & set(fields[1].split(',')) and fields[2] != '/':
            raise PolicyError('Native policy refused: peer still belongs to a non-root legacy CPU group')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    serve = commands.add_parser('serve')
    serve.add_argument('--cpu-root', type=Path, required=True)
    serve.add_argument('--detach', action='store_true')
    commands.add_parser('validate')
    commands.add_parser('status')
    commands.add_parser('ping')
    put = commands.add_parser('set')
    put.add_argument('name')
    put.add_argument('--mode', choices=['rootful', 'rootless'], required=True)
    put.add_argument('--cpus', type=decimal.Decimal, required=True)
    put.add_argument('--memory-mib', type=int, required=True)
    put.add_argument('--memory-high-mib', type=int, help='Optional V2 reclaim threshold below the hard memory limit')
    put.add_argument('--pids', type=int, required=True)
    put.add_argument('--read-bps', type=int, required=True)
    put.add_argument('--write-bps', type=int, required=True)
    put.add_argument('--oom-group', action='store_true')
    remove = commands.add_parser('remove')
    remove.add_argument('name')
    args = parser.parse_args()
    if args.command in {'ping', 'status'}:
        print(json.dumps(send_request({'action': args.command}), indent=2))
        return
    if os.getuid() != 0 or not Path('/etc/droidspaces').is_file():
        raise PolicyError('Policy administration requires isolated guest root')
    if args.command == 'serve':
        if not args.detach:
            Server(args.cpu_root).serve()
        else:
            read_fd, write_fd = os.pipe()
            child = os.fork()
            if child:
                os.close(write_fd)
                os.waitpid(child, 0)
                ready = select.select([read_fd], [], [], 10)[0]
                result = os.read(read_fd, 1) if ready else b''
                os.close(read_fd)
                if result != b'1':
                    raise PolicyError('Detached policy server did not report readiness; inspect its log/state')
            else:
                os.close(read_fd)
                os.setsid()
                if os.fork():
                    os._exit(0)
                try:
                    Server(args.cpu_root).serve(ready_fd=write_fd)
                except Exception as error:
                    print('RMX1931_RESOURCE_POLICY_ERROR: ' + str(error), file=sys.stderr, flush=True)
                finally:
                    os._exit(0)
    elif args.command == 'validate':
        print(json.dumps(registry(), indent=2))
    else:
        if not NAME.fullmatch(args.name):
            raise PolicyError('Invalid profile name')
        data = registry()
        if args.command == 'set':
            if not args.cpus.is_finite() or args.cpus != args.cpus.quantize(decimal.Decimal('.00001')):
                raise PolicyError('Invalid CPU count')
            replacement = {'uid': 0 if args.mode == 'rootful' else 1000,
                'cpu_quota_us': int(args.cpus * 100000), 'memory_bytes': args.memory_mib * 1024**2,
                'pids': args.pids, 'read_bps': args.read_bps, 'write_bps': args.write_bps,
                'oom_group': args.oom_group}
            if args.memory_high_mib is not None:
                replacement['memory_high_bytes'] = args.memory_high_mib * 1024**2
            if args.name in data['profiles'] and data['profiles'][args.name] != replacement and profile_references(args.name):
                raise PolicyError('Profile is referenced by an existing container; recreate with a new profile to change limits')
            data['profiles'][args.name] = replacement
        else:
            if profile_references(args.name):
                raise PolicyError('Profile is referenced by an existing container; remove those containers first')
            del data['profiles'][args.name]
        validate_registry(data)
        atomic_json(REGISTRY, data)
        print(json.dumps(data, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('RMX1931_RESOURCE_POLICY_ERROR: ' + str(error), file=sys.stderr)
        raise SystemExit(125)
