#!/usr/bin/env python3
"""Read-only identity/configuration evidence around a controlled guest restart."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--base', required=True)
    parser.add_argument('--previous', type=Path)
    args = parser.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.label)
    assert re.fullmatch(r'/var/tmp/rmx1931-policy-test-[a-zA-Z0-9-]+', args.base)
    path = ROOT / 'artifacts/droidspaces/runtime' / (args.label + '.json')
    assert not path.exists()
    adb = device()
    identity = read_identity(adb)
    init = guest_info(adb)['pid']
    root = '/proc/' + str(init) + '/root'
    assert read_root(adb, 'getenforce').strip() == b'Enforcing'
    status = read_root(adb, 'cat ' + root + '/proc/1/status').decode()
    assert re.search(r'^Seccomp:\s+2$', status, re.M)
    fixture = json.loads(read_root(adb, 'cat ' + root + args.base + '/state.json'))
    assert fixture['prepare_passed'] and fixture['outage_passed'] and fixture['admission_passed']
    assert {row['mode'] for row in fixture['modes']} == {'rootful', 'rootless'}
    expected = {row['name']: row['recreated_cid'] for row in fixture['modes']}
    expected.update({row['name'] + '-neighbor': row['neighbor_cid'] for row in fixture['modes']})
    containers = {}
    for launcher in ('podman', 'podman-rootless'):
        command = shlex.join([DS, '--name=' + NAME, 'run', launcher, 'ps', '-a', '--format', 'json'])
        observed = json.loads(read_root(adb, command))
        assert all(record['State'] != 'running' for record in observed), 'Stop owned test workloads before guest restart'
        for record in observed:
            names = record['Names']
            assert len(names) == 1 and names[0] in expected and record['Id'] == expected[names[0]], 'Unexpected Podman workload'
            containers[names[0]] = record['Id']
    assert containers == expected
    policy_content = read_root(adb, 'cat ' + root + '/etc/rmx1931/resource-policies.json')
    policies = json.loads(policy_content)
    assert set(policies['profiles']) == {row['profile'] for row in fixture['modes']}
    actual_sources = {}
    for local, remote in [('rmx1931_resource_policy.py', 'rmx1931_resource_policy.py'),
                          ('oci_resource_entry.py', 'rmx1931-oci-crun'), ('oci_resource_entry.py', 'rmx1931-oci-runc')]:
        expected_sha = hashlib.sha256((ROOT / 'scripts' / local).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
        actual_sha = read_root(adb, 'sha256sum ' + root + '/usr/local/libexec/' + remote).decode().split()[0]
        assert actual_sha == expected_sha
        actual_sources[remote] = actual_sha
    health = json.loads(read_root(adb, shlex.join([DS, '--name=' + NAME, 'run', 'rmx1931-policy', 'ping'])))
    namespace = read_root(adb, 'readlink /proc/' + str(init) + '/ns/pid').decode().strip()
    assert health['boot_id'] == identity['boot_id'] and health['pid_namespace'] == namespace
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
              'guest_pid': init, 'guest_pid_namespace': namespace,
              'registry_sha256': hashlib.sha256(policy_content).hexdigest(), 'profiles': policies,
              'containers': containers, 'installed_source_sha256': actual_sources,
              'server': health, 'normal_guest_seccomp': 2, 'selinux': 'Enforcing', 'passed': True}
    if args.previous:
        previous = args.previous.resolve()
        assert previous.parent == path.parent.resolve()
        before = json.loads(previous.read_text(encoding='utf-8'))
        assert before['passed'] and all(before[key] == report[key] for key in
            ('kernel', 'boot_id', 'registry_sha256', 'profiles', 'containers', 'installed_source_sha256'))
        assert before['guest_pid_namespace'] != namespace, 'Guest restart has not been proven'
        report['previous'] = previous.name
        report['previous_sha256'] = hashlib.sha256(previous.read_bytes()).hexdigest()
        report['guest_restart_proven'] = True
    report['end_identity'] = read_identity(adb)
    assert report['end_identity'] == identity
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
