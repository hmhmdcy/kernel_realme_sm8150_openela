#!/usr/bin/env python3
"""Record stopped PSI fixtures and installed code around a real guest restart."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', required=True)
    p.add_argument('--stage', choices=('android16-group-psi', 'android16-group-psi-reclaim-fix'), default='android16-group-psi')
    p.add_argument('--base', required=True)
    p.add_argument('--previous', type=Path)
    args = p.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
    assert re.fullmatch(r'/var/tmp/rmx1931-psi-persist-[A-Za-z0-9-]+', args.base)
    art = ROOT / 'artifacts/droidspaces'
    target = art / 'runtime' / (args.label + '.json')
    assert not target.exists()
    boot = json.loads((art / ('extensions-' + args.stage + '-boot-result.json')).read_text())
    adb = device()
    identity = read_identity(adb)
    assert identity == {k: boot[k] for k in ('kernel', 'boot_id')}
    guest = guest_info(adb)
    root = '/proc/' + str(guest['pid']) + '/root'
    def read(command):
        return read_root(adb, command)
    fixture = json.loads(read('cat ' + root + args.base + '/state.json'))
    assert fixture['prepare_passed'] and not fixture['resume_passed']
    assert len(fixture['modes']) == 4
    expected = {row['name']: row['container_id'] for row in fixture['modes']}
    containers = {}
    for launcher in ('podman', 'podman-rootless'):
        records = json.loads(read(shlex.join([DS, '--name=' + NAME, 'run', launcher, 'ps', '-a', '--format=json'])))
        for record in records:
            assert record['State'] != 'running' and len(record['Names']) == 1
            name = record['Names'][0]
            assert name in expected and record['Id'] == expected[name]
            containers[name] = record['Id']
    assert containers == expected
    registry = read('cat ' + root + '/etc/rmx1931/resource-policies.json')
    profiles = json.loads(registry)
    assert set(profiles['profiles']) == set(expected)
    assert all(row['memory_high_bytes'] == 33554432 and row['memory_bytes'] == 67108864 for row in profiles['profiles'].values())
    sources = {}
    for local, remote in (
        ('rmx1931_resource_policy.py', '/usr/local/libexec/rmx1931_resource_policy.py'),
        ('oci_resource_entry.py', '/usr/local/libexec/rmx1931-oci-crun'),
        ('oci_resource_entry.py', '/usr/local/libexec/rmx1931-oci-runc'),
        ('rmx1931_pressure.py', '/usr/local/bin/rmx1931-pressure')):
        expected_sha = hashlib.sha256((ROOT / 'scripts' / local).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
        actual_sha = read('sha256sum ' + root + remote).decode().split()[0]
        assert actual_sha == expected_sha
        sources[remote] = actual_sha
    namespace = read('readlink /proc/' + str(guest['pid']) + '/ns/pid').decode().strip()
    server = json.loads(read(shlex.join([DS, '--name=' + NAME, 'run', 'rmx1931-policy', 'ping'])))
    assert server['cpu_backend'] == 'v2' and server['pid_namespace'] == namespace and server['boot_id'] == identity['boot_id']
    status = read('cat ' + root + '/proc/1/status').decode()
    assert re.search(r'^Seccomp:\s+2$', status, re.M)
    assert read('getenforce').strip() == b'Enforcing'
    assert read('sha256sum /dev/block/by-name/boot').decode().split()[0] == boot['boot_sha256']
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
        'guest_pid': guest['pid'], 'guest_pid_namespace': namespace, 'containers': containers,
        'registry_sha256': hashlib.sha256(registry).hexdigest(), 'profiles': profiles,
        'sources': sources, 'server': server, 'selinux': 'Enforcing', 'ordinary_guest_seccomp': 2,
        'passed': True, 'script_source_sha256': hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n', b'\n')).hexdigest()}
    if args.previous:
        assert args.previous.resolve().parent == target.parent.resolve()
        before = json.loads(args.previous.read_text())
        assert before['passed']
        assert all(before[k] == report[k] for k in ('kernel', 'boot_id', 'containers', 'registry_sha256', 'profiles', 'sources'))
        assert before['guest_pid_namespace'] != namespace and before['guest_pid'] != guest['pid']
        report.update(guest_restart_proven=True, previous_sha256=digest(args.previous))
    else:
        assert namespace == fixture['before_namespace']
    report['end_identity'] = read_identity(adb)
    assert report['end_identity'] == identity
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': True, 'guest_pid': guest['pid'], 'namespace': namespace,
        'guest_restart_proven': report.get('guest_restart_proven', False)}, indent=2))


if __name__ == '__main__':
    main()
