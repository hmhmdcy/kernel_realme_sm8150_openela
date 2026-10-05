#!/usr/bin/env python3
"""Apply or release a V1 CPU quota to one verified rootful/rootless container.

Android root operator entry. Freeze only the identified V2 payload while moving
its processes, so descendants inherit the V1 quota. Android task placement is
preserved. This does not claim native Podman --cpus on the unified hierarchy.
"""
import argparse
import datetime as dt
import decimal
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root

PREFIX = '/sys/fs/cgroup/droidspaces/' + NAME


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['apply', 'release'])
    p.add_argument('--container', required=True)
    p.add_argument('--rootless', action='store_true')
    p.add_argument('--cpus', type=decimal.Decimal)
    p.add_argument('--state', type=Path)
    p.add_argument('--label', required=True)
    args = p.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', args.container)
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.label)
    destination = ROOT / 'artifacts/droidspaces/runtime' / (args.label + '.json')
    assert not destination.exists(), 'Use a new evidence label'
    adb = device()
    identity = read_identity(adb)
    init = guest_info(adb)['pid']
    assert read_root(adb, 'getenforce').strip() == b'Enforcing'
    guest_proc = '/proc/' + str(init) + '/root/proc/'
    launcher = 'podman-rootless' if args.rootless else 'podman'

    def mutate(command):
        result = subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        return result.stdout.decode().strip()

    def inspect():
        result = mutate(shlex.join([DS, '--name=' + NAME, 'run', launcher, 'inspect', args.container]))
        record = json.loads(result)[0]
        assert re.fullmatch(r'[0-9a-f]{64}', record['Id'])
        assert record['State']['Running'] and not record['State'].get('Paused', False)
        pid = record['State']['Pid']
        assert isinstance(pid, int) and pid > 1
        rows = read_root(adb, 'cat ' + guest_proc + str(pid) + '/cgroup').decode().splitlines()
        unified = [row.split(':', 2)[2] for row in rows if row.startswith('0::')]
        assert len(unified) == 1
        path = unified[0]
        assert re.fullmatch(r'/[a-zA-Z0-9_./@:-]+', path) and '..' not in path.split('/')
        target = '/sys/fs/cgroup' + path
        assert target.startswith(PREFIX + '/')
        assert '/libpod-' + record['Id'] + '.scope' in target
        assert read_root(adb, 'stat -f -c %t ' + shlex.quote(target)).strip() == b'63677270'
        return record, target

    record, target = inspect()
    runtime = record['OCIRuntime']
    assert runtime in {'crun', 'runc'}
    expected_wrapper = '/usr/local/libexec/rmx1931-oci-' + runtime
    wrapper = '/proc/' + str(init) + '/root' + expected_wrapper
    wrapper_sha = read_root(adb, 'sha256sum ' + wrapper).decode().split()[0]
    assert wrapper_sha in {'f44643b25d86b62b749e1d63a421ccc6c21318f6ca21a4d5df23424b875235f9',
                           '338415df58e5167efb17c5fc3319b7d6ecb6890570682410431f84ecf1b19228'}, 'Install the reviewed CPU runtime entry first'
    assert 'io.rmx1931.resource-policy' not in record.get('Config', {}).get('Annotations', {}), 'Persistent CPU policy must be managed through its profile'
    command = record.get('Config', {}).get('CreateCommand', [])
    for index, argument in enumerate(command):
        if argument.startswith('--runtime='):
            assert argument.split('=', 1)[1] in {runtime, expected_wrapper}, 'Explicit runtime path bypasses quota inheritance'
        if argument == '--runtime':
            assert command[index + 1] in {runtime, expected_wrapper}, 'Explicit runtime path bypasses quota inheritance'
    frozen = False
    created = False
    moved = False
    mounted = False
    state = None
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
              'container_id': record['Id'], 'container_name': args.container, 'rootless': args.rootless,
              'v2_payload': target, 'interface': 'v1 cpu.cfs_quota_us',
              'managed_runtime': expected_wrapper,
              'android_processes_moved': False, 'action': args.action, 'completed': False}
    if args.action == 'apply':
        assert args.cpus is not None and args.cpus.is_finite() and decimal.Decimal('.01') <= args.cpus <= 8
        quota = int(args.cpus * 100000)
        group = '/dev/cpuctl/rmx1931-container-' + record['Id']
        assert read_root(adb, 'if test -e ' + group + '; then echo exists; fi').strip() != b'exists', 'Quota already exists; release it first'
    else:
        assert args.state is not None
        source = args.state.resolve()
        assert source.parent == destination.parent.resolve()
        state = json.loads(source.read_text())
        assert state['completed'] and state['action'] == 'apply'
        assert state['boot_id'] == identity['boot_id'] and state['container_id'] == record['Id']
        assert state['rootless'] == args.rootless and state['v2_payload'] == target
        group = state['v1_cpu_group']
        assert group == '/dev/cpuctl/rmx1931-container-' + record['Id']
        original = state['original_cpu_path']
        assert re.fullmatch(r'/[a-zA-Z0-9_./-]*', original) and '..' not in original.split('/')
    report['v1_cpu_group'] = group
    guest_mount = '/proc/' + str(init) + '/root/run/rmx1931-cpu/' + record['Id']
    busybox = '/proc/' + str(init) + '/root/usr/bin/busybox'

    def mount_entry(unmount=False):
        # A bind source must belong to this mount namespace (an inherited
        # host descriptor is rejected with EINVAL). Mount the existing CPU
        # hierarchy temporarily behind a root-only directory, bind its one
        # owned leaf, then remove that temporary root view before returning.
        argv = [busybox, 'nsenter', '-t', str(init), '-m', '-p',
                '-r/proc/' + str(init) + '/root', '--', '/bin/sh', '-c']
        inner_mount = '/run/rmx1931-cpu/' + record['Id']
        if unmount:
            inner = 'set -e; umount ' + inner_mount + '; echo CPU_LEAF_UNMOUNT_PASS'
            expected = 'CPU_LEAF_UNMOUNT_PASS'
        else:
            stage = '/run/rmx1931-cpu-source-' + record['Id']
            inner = ('set -e; test ! -e ' + stage + '; mkdir -m 700 ' + stage + '; '
                     'trap "umount ' + stage + ' 2>/dev/null || true; rmdir ' + stage + ' 2>/dev/null || true" EXIT; '
                     'mount -t cgroup -o cpu cpu ' + stage + '; '
                     'mount --bind ' + stage + '/' + group.rsplit('/', 1)[1] + ' ' + inner_mount + '; '
                     'umount ' + stage + '; rmdir ' + stage + '; trap - EXIT; echo CPU_LEAF_BIND_PASS')
            expected = 'CPU_LEAF_BIND_PASS'
        inner = 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; ' + inner
        output = mutate(shlex.join(argv + [inner]))
        assert output.splitlines()[-1:] == [expected], 'Guest mount operation did not complete: ' + output
    try:
        mutate('printf "1\\n" > ' + shlex.quote(target + '/cgroup.freeze'))
        frozen = True
        for _ in range(50):
            if 'frozen 1' in read_root(adb, 'cat ' + shlex.quote(target + '/cgroup.events')).decode():
                break
            time.sleep(.1)
        else:
            raise RuntimeError('Container did not freeze; no CPU placement changed')
        assert inspect()[0]['Id'] == record['Id']
        # Recursively enumerate payload children only; never include the guest,
        # user manager or conmon outside this verified payload cgroup.
        listing = read_root(adb, 'find ' + shlex.quote(target) + ' -name cgroup.procs -type f').decode().splitlines()
        assert listing and all(path == target + '/cgroup.procs' or path.startswith(target + '/') for path in listing)
        pids = sorted({int(pid) for path in listing for pid in read_root(adb, 'cat ' + shlex.quote(path)).split()})
        assert pids and all(pid > 1 for pid in pids)
        origins = set()
        for pid in pids:
            rows = read_root(adb, 'cat /proc/' + str(pid) + '/cgroup').decode().splitlines()
            cpu = [row.split(':', 2)[2] for row in rows if 'cpu' in row.split(':', 2)[1].split(',')]
            assert len(cpu) == 1
            origins.add(cpu[0])
        assert len(origins) == 1, 'Mixed CPU placement requires individual operator review'
        if args.action == 'apply':
            original = origins.pop()
            assert re.fullmatch(r'/[a-zA-Z0-9_./-]*', original) and '..' not in original.split('/')
            mutate('mkdir ' + group)
            created = True
            mutate('printf "100000\\n" > ' + group + '/cpu.cfs_period_us; printf "' + str(quota) + '\\n" > ' + group + '/cpu.cfs_quota_us')
            destination_group = group
            report.update(quota_us=quota, period_us=100000)
            if args.rootless:
                mutate('chown 1000:1000 ' + group + '/cgroup.procs; chmod 600 ' + group + '/cgroup.procs')
            mutate('test ! -L /proc/' + str(init) + '/root/run/rmx1931-cpu; mkdir -p /proc/' + str(init) + '/root/run/rmx1931-cpu; test ! -e ' + guest_mount + '; mkdir ' + guest_mount)
        else:
            assert origins == {group.removeprefix('/dev/cpuctl')}
            destination_group = '/dev/cpuctl' + original
            assert read_root(adb, 'test -d ' + shlex.quote(destination_group) + ' && echo verified').strip() == b'verified'
            mount_entry(unmount=True)
            mutate('rmdir ' + guest_mount)
        report.update(original_cpu_path=original, moved_payload_pids=pids)
        for pid in pids:
            mutate('printf "' + str(pid) + '\\n" > ' + shlex.quote(destination_group + '/cgroup.procs'))
            moved = True
        for pid in pids:
            rows = read_root(adb, 'cat /proc/' + str(pid) + '/cgroup').decode().splitlines()
            expected = destination_group.removeprefix('/dev/cpuctl') or '/'
            assert any(row.split(':', 2)[2] == expected and 'cpu' in row.split(':', 2)[1].split(',') for row in rows)
        if args.action == 'release':
            mutate('test -z "$(cat ' + group + '/cgroup.procs)" && rmdir ' + group)
        else:
            mount_entry()
            mounted = True
            assert read_root(adb, 'test -f ' + guest_mount + '/cgroup.procs && cat ' + guest_mount + '/cpu.cfs_quota_us').strip() == str(quota).encode(), 'CPU leaf is not visible from the guest root'
            report['runtime_cpu_leaf_mounted'] = True
        report['completed'] = True
    except Exception as error:
        report['error'] = str(error)
        if args.action == 'apply' and created:
            # A frozen, verified payload can be returned to its one original
            # group after a partial move. Record any rollback failure.
            try:
                if moved:
                    for pid in pids:
                        mutate('printf "' + str(pid) + '\\n" > ' + shlex.quote('/dev/cpuctl' + original + '/cgroup.procs'))
                if mounted:
                    mount_entry(unmount=True)
                if read_root(adb, 'if test -d ' + guest_mount + '; then echo exists; fi').strip() == b'exists':
                    mutate('rmdir ' + guest_mount)
                mutate('test -z "$(cat ' + group + '/cgroup.procs)" && rmdir ' + group)
                report['rollback_completed'] = True
            except Exception as rollback:
                report['rollback_error'] = str(rollback)
        raise
    finally:
        if frozen:
            try:
                mutate('printf "0\\n" > ' + shlex.quote(target + '/cgroup.freeze'))
                report['payload_unfrozen'] = True
            except Exception as error:
                report['payload_unfrozen'] = False
                report['unfreeze_error'] = str(error)
                report['completed'] = False
        report['end_identity'] = read_identity(adb)
        if report['end_identity'] != identity:
            report['completed'] = False
        destination.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2), flush=True)
    assert report['completed'] and report.get('payload_unfrozen')


if __name__ == '__main__':
    main()
