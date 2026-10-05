#!/usr/bin/env python3
"""Seal Binder callback acceptance only after current-boot functional evidence."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
STAGE = 'harden5-binder-freeze-fix'
LABEL = 'h5bf2-20261005'

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path): return json.loads(path.read_text(encoding='utf-8'))

def main():
    receipt_path = ART / 'binder-freeze-acceptance.json'
    assert not receipt_path.exists(), 'Acceptance is immutable; inspect prior receipt'
    boot_path = ART / f'extensions-{STAGE}-boot-result.json'
    boot = read(boot_path)
    check_path = ART / f'boot-images/ext-{STAGE}-candidate-check.json'
    check = read(check_path)
    audit_path = ART / f'kernel-ext-{STAGE}/audit.json'
    audit = read(audit_path)
    assert boot['kernel'].endswith('-ext-h5bf2') and boot['running_config_matches']
    assert boot['selinux'] == 'Enforcing' and 'uid=0(root)' in boot['root']
    assert boot['boot_completed'] == '1' and boot['boot_sha256'] == check['candidate_sha256']
    assert audit['build_audit_passed'] and audit['existing_export_crc_preserved']
    assert not audit['export_crc']['changed'] and not audit['export_crc']['missing']
    evidence = {}
    names = {
        'native-callbacks-and-features': ('binder-freeze-callbacks-' + LABEL, 'BINDER_FREEZE_CALLBACKS_PASS cases=15', None),
        'android16-public-api': ('binder-public-api-' + LABEL, 'ANDROID16_BINDER_PUBLIC_CALLBACKS_PASS', None),
        'filter-preservation': ('binder-filter-' + LABEL, 'CONTAINER_SECCOMP_SETRESUID_PASS', 'probe_container_seccomp_setresuid.sh'),
        'native-cpu-cpuset': ('binder-native-cpu-' + LABEL, 'NATIVE_CPU_PODMAN_PASS', 'probe_native_cpu_podman.sh'),
        'policy-crun': ('binder-policy-crun-' + LABEL, 'POLICY_FIRST_PAYLOAD_ROOTFUL_ROOTLESS_SMOKE_PASS', 'probe_resource_policy_smoke.sh'),
        'policy-runc': ('binder-policy-runc-' + LABEL, 'POLICY_FIRST_PAYLOAD_ROOTFUL_ROOTLESS_SMOKE_PASS', 'probe_resource_policy_smoke.sh'),
        'host-health': ('binder-host-health-' + LABEL, 'BINDER_HOST_HEALTH_PASS', 'probe_binder_host_health.py'),
    }
    for key, (label, marker, source_name) in names.items():
        path = ART / 'runtime' / (label + '.json')
        report = read(path)
        assert report['returncode'] == 0 and report['end_identity'] == {k: boot[k] for k in ('kernel', 'boot_id')}, key
        assert all(report[k] == boot[k] for k in ('kernel', 'boot_id')), key
        output = report.get('listener_stdout', '') if key == 'android16-public-api' else report.get('stdout', '')
        assert marker in output, (key, marker)
        entry = {'path': path.relative_to(ART).as_posix(), 'sha256': sha(path)}
        if source_name:
            source = ROOT / 'scripts' / source_name
            digest = hashlib.sha256(source.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
            assert report['script_source_sha256'] == digest
            entry.update(source_path=source.relative_to(ROOT).as_posix(), source_sha256=digest)
        if key == 'native-callbacks-and-features':
            assert report['fixture_mount_directory_removed'] and report['ordinary_guest_seccomp'] == '2'
            assert 'binderfs_freeze_feature_readonly_and_no_false_capabilities' in output
            assert report['fixture_source_sha256'] == sha(ROOT / 'references/runtime-probes/binder-freeze/binder_freeze_test.c')
            assert report['runner_source_sha256'] == sha(ROOT / 'scripts/run_binder_freeze_probe.py')
        if key == 'android16-public-api':
            assert report['listener_status'] == '0' and not report['cleanup_errors'] and all(report['owned_pids_removed'].values())
            assert report['selinux'] == 'Enforcing' and report['ordinary_guest_seccomp'] == '2'
            assert report['listener_stdout'].splitlines().count('PUBLIC_FREEZE_CALLBACK 1') == 2
            assert report['listener_stdout'].splitlines().count('PUBLIC_FREEZE_CALLBACK 0') == 1
            for field, source in [('java_source_sha256', 'references/runtime-probes/binder-freeze/RmxBinderFreezeApi.java'),
                                  ('native_control_source_sha256', 'references/runtime-probes/binder-freeze/binder_api_control.c'),
                                  ('runner_source_sha256', 'scripts/run_binder_public_api_probe.py')]:
                assert report[field] == sha(ROOT / source)
        if key == 'host-health':
            assert report['passed'] is True and all(report['checks'].values())
            assert report['shell_feature_read']['returncode'] == 0 and report['shell_feature_read']['stdout'].strip() == '1'
        evidence[key] = entry
    predecessor = ART / 'seccomp-notify-stage5-acceptance.json'
    assert read(predecessor)['complete_stage_5_accepted']
    receipt = {'passed': True, 'binder_freeze_callbacks_accepted': True, 'stage': STAGE,
        **{k: boot[k] for k in ('kernel', 'boot_id', 'boot_sha256')},
        'boot_verification_sha256': sha(boot_path), 'build_audit_sha256': sha(audit_path),
        'packaging_sha256': sha(check_path), 'predecessor_stage5_acceptance_sha256': sha(predecessor),
        'evidence': evidence, 'module_export_crcs_preserved': True,
        'scope': 'Independent Binderfs notifications and read-only feature discovery; actual Android 16 public API subscription/state changes/removal/death plus affected Linux container regression.',
        'limitations': ['Existing freeze ioctl uses host PID semantics.', 'Extended-error and transaction-report interfaces were not added.',
            'Historical native baseline EINVAL used an invalid packed ABI and is not accepted as proof of a missing callback.',
            'No claim of performance or battery improvement.'],
        'complete_android16_desktop_status': 'paused by user; not deployed or accepted',
        'remaining_current_scope': ['LMKD/group PSI and container memory-policy linkage', 'Current-ROM eBPF interface requirements']}
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    runtime = {'runtime_passed': True, 'binder_freeze_callbacks_accepted': True, **{k: boot[k] for k in ('kernel', 'boot_id', 'boot_sha256')},
        'boot_verification_sha256': sha(boot_path), 'binder_acceptance_sha256': sha(receipt_path)}
    runtime_path = ART / f'extensions-{STAGE}-runtime-result.json'
    assert not runtime_path.exists()
    runtime_path.write_text(json.dumps(runtime, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'binder_freeze_callbacks_accepted': True, 'evidence_reports': len(evidence), 'kernel': boot['kernel']}))

if __name__ == '__main__': main()
