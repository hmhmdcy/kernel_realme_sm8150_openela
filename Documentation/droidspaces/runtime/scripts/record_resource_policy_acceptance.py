#!/usr/bin/env python3
"""Bind stage 2 to actual lifecycle, restart, failure and cleanup evidence."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root

RUNTIME = ROOT / 'artifacts/droidspaces/runtime'
PHASES = {
    'prepare': ('policy-lifecycle-prepare-retained-20261004', 'probe_resource_policy_lifecycle.sh', 'RESOURCE_POLICY_PREPARE_PASS'),
    'admission': ('policy-admission-retained-20261004', 'probe_resource_policy_admission.sh', 'RESOURCE_POLICY_ADMISSION_PASS_KERNEL_OOM_LOG_REQUIRED'),
    'outage-stop': ('policy-server-outage-stop-20261004', 'stop_guest_resource_policy.sh', 'VERIFIED_RESOURCE_POLICY_SERVER_STOP_PASS'),
    'outage': ('policy-outage-retained-20261004', 'probe_resource_policy_lifecycle.sh', 'RESOURCE_POLICY_OUTAGE_PASS'),
    'resume': ('policy-after-outage-retained-20261004', 'probe_resource_policy_lifecycle.sh', 'RESOURCE_POLICY_VERIFY_PASS'),
    'guest-stop-workloads': ('policy-guest-restart-workloads-stopped-20261004', 'probe_resource_policy_lifecycle.sh', 'RESOURCE_POLICY_STOP_PASS'),
    'guest-resume': ('policy-after-guest-restart-retained-20261004', 'probe_resource_policy_lifecycle.sh', 'RESOURCE_POLICY_VERIFY_PASS'),
    'runc': ('policy-runc-first-payload-20261004', 'probe_resource_policy_smoke.sh', 'POLICY_FIRST_PAYLOAD_ROOTFUL_ROOTLESS_SMOKE_PASS'),
    'cleanup': ('policy-lifecycle-final-cleanup-20261004', 'probe_resource_policy_lifecycle.sh', 'RESOURCE_POLICY_CLEANUP_PASS')}


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(stdout):
    start = stdout.index('{\n  "base":')
    return json.JSONDecoder().raw_decode(stdout[start:])[0]


def main():
    destination = ROOT / 'artifacts/droidspaces/resource-policy-acceptance.json'
    assert not destination.exists(), 'Keep accepted evidence immutable'
    identity = read_identity(device())
    reports = {}
    for phase, (label, script, marker) in PHASES.items():
        path = RUNTIME / (label + '.json')
        record = load(path)
        assert record['returncode'] == 0 and marker in record['stdout'], phase
        assert all(record[key] == value for key, value in identity.items()), phase
        assert record['end_identity'] == identity, phase
        expected = hashlib.sha256((ROOT / 'scripts' / script).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
        assert record['script_source_sha256'] == expected, phase
        reports[phase] = {'path': 'runtime/' + path.name, 'sha256': sha(path)}
    before_path = RUNTIME / 'policy-guest-before-20261004.json'
    after_path = RUNTIME / 'policy-guest-after-20261004.json'
    before, after = load(before_path), load(after_path)
    assert before['passed'] and after['passed'] and after['guest_restart_proven']
    assert after['previous_sha256'] == sha(before_path)
    assert before['guest_pid_namespace'] != after['guest_pid_namespace']
    assert before['registry_sha256'] == after['registry_sha256'] and before['containers'] == after['containers']
    assert all(after[key] == value for key, value in identity.items())
    complete = fixture(load(RUNTIME / (PHASES['cleanup'][0] + '.json'))['stdout'])
    assert all(complete.get(key) for key in ('passed', 'prepare_passed', 'admission_passed', 'outage_passed', 'cleanup_passed'))
    assert not complete['cleanup_errors'] and {row['mode'] for row in complete['modes']} == {'rootful', 'rootless'}
    assert [row['pid_namespace'] for row in complete['resume_passes']] == [before['guest_pid_namespace'], after['guest_pid_namespace']]
    log_path = RUNTIME / 'policy-oom-log-bound-20261004.json'
    log = load(log_path)
    assert log['returncode'] == 0 and identity['kernel'] == complete['kernel']
    assert log['stdout'].splitlines()[:2] == [identity['kernel'], identity['boot_id']]
    summaries = []
    for row in complete['modes']:
        assert row['initial_cid'] != row['recreated_cid']
        assert len([entry for entry in row['measurements'] if entry['phase'] == 'resume']) == 2
        assert {'create', 'stop-start', 'recreate', 'resume', 'unmanaged'} <= {entry['phase'] for entry in row['measurements']}
        for entry in row['measurements']:
            if entry['neighbor']:
                assert entry['used_cores'] > 2 and all(io['seconds'] < 2 for io in entry['io'])
            else:
                assert .3 < entry['used_cores'] < .75 and all(2.8 < io['seconds'] < 12 for io in entry['io'])
                assert entry['pids']['errno'] == 11 and entry['pids']['children'] < 32
            assert entry['cpu']['seccomp'] == 2 and all(io['seccomp'] == 2 for io in entry['io'])
        cid = row['admission']['oom_container_id']
        domain = '/libpod-' + cid + '.scope/container'
        assert any(domain in line and 'killed as a result of limit of' in line for line in log['stdout'].splitlines())
        assert any(domain in line and 'are going to be killed due to memory.oom.group set' in line for line in log['stdout'].splitlines())
        assert row['admission']['oom_exec_exit'] == 137
        assert {entry['case'] for entry in row['admission']['negative']} == {'unknown', 'wrong-user'}
        assert row['admission']['profile_change_exit'] == row['admission']['profile_remove_exit'] == row['admission']['rootless_admin_exit'] == 125
        assert all(row['outage'][key] != 0 for key in ('exec_exit', 'start_exit', 'create_exit'))
        assert 'policy service unavailable' in row['outage']['diagnostic']
        summaries.append({'mode': row['mode'], 'container_id': row['recreated_cid'],
            'measurements': row['measurements'], 'snapshots': row['snapshots'],
            'admission': row['admission'], 'outage': row['outage']})
    legacy_path = RUNTIME / 'policy-legacy-cpu-regression-20261004.json'
    legacy = load(legacy_path)
    assert legacy['passed'] and legacy['end_identity'] == identity and {row['mode'] for row in legacy['containers']} == {'rootful', 'rootless'}
    for path in (before_path, after_path, log_path, legacy_path):
        reports[path.stem] = {'path': 'runtime/' + path.name, 'sha256': sha(path)}
    adb = device()
    init = guest_info(adb)['pid']
    root = '/proc/' + str(init) + '/root'
    assert init == after['guest_pid']
    assert read_root(adb, 'getenforce').strip() == b'Enforcing'
    assert not json.loads(read_root(adb, 'cat ' + root + '/etc/rmx1931/resource-policies.json'))['profiles']
    assert not read_root(adb, 'find ' + root + '/var/lib/rmx1931-policy/containers -mindepth 1 -maxdepth 1 -type f').strip()
    assert not read_root(adb, 'find /dev/cpuctl -mindepth 1 -maxdepth 1 -name "rmx1931-policy-*"').strip()
    assert not read_root(adb, 'find /dev/cpuctl -mindepth 1 -maxdepth 1 -name "rmx1931-container-*"').strip()
    assert not read_root(adb, 'find ' + root + '/run/rmx1931-cpu -mindepth 1 -maxdepth 1').strip()
    assert re.search(r'^Seccomp:\s+2$', read_root(adb, 'cat ' + root + '/proc/1/status').decode(), re.M)
    for launcher in ('podman', 'podman-rootless'):
        assert not read_root(adb, shlex.join([DS, '--name=' + NAME, 'run', launcher, 'ps', '-aq'])).strip()
    health = json.loads(read_root(adb, shlex.join([DS, '--name=' + NAME, 'run', 'rmx1931-policy', 'ping'])))
    assert health['boot_id'] == identity['boot_id'] and health['pid_namespace'] == after['guest_pid_namespace']
    fatal = read_root(adb, "dmesg | grep -E 'Kernel panic - not syncing|Oops:|BUG:|Unable to handle kernel|soft lockup' || true").decode()
    assert not fatal, fatal
    sources = {}
    for name in ('rmx1931_resource_policy.py', 'oci_resource_entry.py', 'install_guest_resource_policy.py',
                 'start_podman_guest.py', 'install_guest_cpu_runtime.sh', 'set_container_cpu_quota.py',
                 'device_runtime.py', 'probe_container_cpu_quota.py'):
        sources[name] = hashlib.sha256((ROOT / 'scripts' / name).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    assert after['installed_source_sha256']['rmx1931_resource_policy.py'] == sources['rmx1931_resource_policy.py']
    assert after['installed_source_sha256']['rmx1931-oci-crun'] == sources['oci_resource_entry.py']
    assert after['installed_source_sha256']['rmx1931-oci-runc'] == sources['oci_resource_entry.py']
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity, 'passed': True,
        'scope': 'stage 2 CPU/IO/memory/pids persistent OCI policies', 'kernel_changed': False,
        'cpu_interface': 'existing V1 CFS, not native V2 CPU', 'v2_interfaces': ['io.max', 'memory.max', 'memory.oom.group', 'pids.max'],
        'guest_restart_before': before['guest_pid_namespace'], 'guest_restart_after': after['guest_pid_namespace'],
        'registry_persisted_sha256': after['registry_sha256'], 'runtime_source_sha256': sources,
        'evidence': reports, 'modes': summaries, 'legacy_cpu_regression_passed': True,
        'cleanup_passed': True, 'selinux': 'Enforcing', 'normal_guest_seccomp': 2,
        'wifi_requested': False, 'hardware_tests_requested': False, 'remaining_plan_stages': [3, 4, 5, 6]}
    assert read_identity(adb) == identity
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'passed': True, 'modes': len(summaries), 'guest_restart_proven': True,
                      'evidence_reports': len(reports), 'path': str(destination)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
