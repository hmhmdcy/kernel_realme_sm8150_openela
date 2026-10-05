#!/usr/bin/env python3
"""Accept group PSI only with same-boot workloads, identity and persistence proof."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import shlex
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root

ART = ROOT / 'artifacts/droidspaces'
STAGE = 'android16-group-psi'
LABEL = 'a16ps-20261005'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_sha(path):
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def rows(report):
    return [json.loads(line) for line in report['stdout'].splitlines() if line.startswith('{')]


def main(stage=STAGE, label=LABEL):
    STAGE, LABEL = stage, label
    repaired = STAGE == 'android16-group-psi-reclaim-fix'
    receipt_path = ART / 'group-psi-acceptance.json'
    runtime_path = ART / f'extensions-{STAGE}-runtime-result.json'
    assert not receipt_path.exists() and not runtime_path.exists(), 'Acceptance is immutable'
    boot_path = ART / f'extensions-{STAGE}-boot-result.json'
    boot_digest = sha(boot_path)
    boot = read(boot_path)
    identity = {k: boot[k] for k in ('kernel', 'boot_id')}
    assert boot['kernel'].endswith('-ext-a16pf' if repaired else '-ext-a16ps') and boot['running_config_matches']
    assert boot['boot_completed'] == '1' and boot['selinux'] == 'Enforcing'
    audit_path = ART / f'kernel-ext-{STAGE}/audit.json'
    audit = read(audit_path)
    predecessor_audit = read(ART / 'kernel-ext-harden5-binder-freeze-fix/audit.json')
    assert audit['build_audit_passed']
    if not audit['existing_export_crc_preserved']:
        from audit_group_psi_reclaim_fix import validate_abi_review
        assert repaired and audit['abi_review_sha256'] == validate_abi_review(audit)
    if repaired:
        from audit_group_psi_reclaim_fix import provenance
        prep, _, bindings = provenance()
        assert all(audit['source'][key] == value for key, value in bindings.items())
        assert audit['cumulative_source_sha256'] == {**predecessor_audit['cumulative_source_sha256'], **prep['modified_sources']}
        assert audit['modified_sources'] == prep['modified_sources'] and audit['pf_memstall_mask_verified'] == '0x01000000'
        assert audit['iteration_config_changes'] == {} and audit['source']['iteration_baseline_runtime_accepted'] is False
    else:
        assert audit['cumulative_source_sha256'] == predecessor_audit['cumulative_source_sha256']
    assert audit['config_changes'] == {'CONFIG_CMDLINE': {'before': '"cgroup_disable=pressure"', 'after': '"psi=1"'}}
    assert not audit['export_crc']['missing']
    if audit['existing_export_crc_preserved']:
        assert not audit['export_crc']['changed']
    for name, field in (('Image.gz-dtb', 'kernel_sha256'), ('resolved.config', 'resolved_config_sha256'),
                        ('Module.symvers', 'module_symvers_sha256'), ('System.map', 'system_map_sha256')):
        assert sha(audit_path.parent / name) == audit[field]
    pack_path = ART / f'boot-images/ext-{STAGE}-candidate-check.json'
    pack = read(pack_path)
    assert sha(ROOT / pack['candidate']) == pack['candidate_sha256'] == boot['boot_sha256']
    assert pack['candidate_kernel_sha256'] == audit['kernel_sha256']
    assert pack['ramdisk_preserved'] and pack['dtb_matches_original'] and pack['avb_hash_verified']
    assert pack['non_kernel_header_fields_except_psi_cmdline_preserved'] and pack['psi_cmdline_change']['validated']
    deployment_path = ART / f'extensions-{STAGE}-deployment.json'
    deployment = read(deployment_path)
    assert deployment['boot_write_confirmed'] and deployment['candidate_sha256'] == boot['boot_sha256']
    if not audit['existing_export_crc_preserved']:
        assert not deployment['loaded_modules'] and not deployment['available_external_modules']
        authorization = read(ART / 'authorized-native-cpu-repair.json')['authorization']
        assert deployment['authorization'] == authorization and deployment['changed_existing_export_crcs'] == 3916
    predecessor = ART / 'binder-freeze-acceptance.json'
    predecessor_field = 'accepted_kernel_receipt_sha256' if repaired else 'predecessor_acceptance_sha256'
    assert sha(predecessor) == audit['source'][predecessor_field] and read(predecessor)['passed']

    evidence = {}
    reports = {}
    def proof(key, label, marker=None, source=None):
        path = ART / 'runtime' / (label + '.json')
        report = read(path)
        assert all(report[k] == identity[k] for k in identity) and report['end_identity'] == identity, key
        assert report.get('returncode', 0) == 0, key
        if marker:
            assert marker in report['stdout'], key
        entry = {'path': path.relative_to(ART).as_posix(), 'sha256': sha(path)}
        if source:
            source_path = ROOT / source
            assert report['script_source_sha256'] == normalized_sha(source_path), key
            entry.update(source_path=source, source_sha256=normalized_sha(source_path))
        evidence[key] = entry
        reports[key] = report
        return report

    for kind, label, source in (
        ('some', ('psi-policy-some-' if repaired else 'psi-policy3-') + LABEL,
         'scripts/probe_group_psi_policy.sh' if repaired else 'artifacts/droidspaces/runtime/source-versions/psi-policy-some-passed/probe_group_psi_policy.sh'),
        ('full', ('psi-policy-full2-' if repaired else 'psi-policy-full-') + LABEL, 'scripts/probe_group_psi_policy.sh')):
        report = proof('pressure-' + kind, label, 'GROUP_PSI_POLICY_ROOTFUL_ROOTLESS_CRUN_RUNC_PASS', source)
        cases = [row for row in rows(report) if row.get('stop_start_passed')]
        assert {(r['mode'], r['runtime']) for r in cases} == {(m, rt) for m in ('rootful', 'rootless') for rt in ('crun', 'runc')}
        assert len(cases) == 4 and not report['stderr']
        assert any(row.get('cleanup_errors') == [] for row in rows(report))
        for row in cases:
            limits = {'max': 67108864, 'high': 33554432, 'seccomp': 2}
            assert row.get('stall', 'some') == kind and {key: row['initial_payload'][key] for key in limits} == limits
            if repaired:
                assert row['initial_payload']['starttime'] != row['restart_payload']['starttime']
                assert all({key: row[phase][key] for key in limits} == limits for phase in ('restart_payload', 'recreate_payload'))
            assert row['delta'][kind] >= 1000 and row['parent_delta'][kind] >= 1000
            assert row['parent_trigger_notified'] and not row['parent_trigger_errors']
            assert row['neighbor_before'] == row['neighbor_after'] == {'some': 0, 'full': 0}
            assert row['events_after']['high'] > row['events_before']['high']
            assert row['events_after']['oom_kill'] == row['events_before']['oom_kill'] == 0
            assert row['invalid_trigger_cases'] == 4 and row['duplicate_trigger_rejected'] and row['trigger_close_cycles'] == 32
            assert row['recreate_passed'] and row['container_id'] != row['recreated_container_id']
            assert len([n for n in row['notifications'] if n['event'] == 'memory-pressure']) == 1

    monitor = proof('monitor-lifecycle', 'psi-monitor-lifecycle-' + LABEL, 'GROUP_PSI_MONITOR_LIFECYCLE_PASS', 'scripts/probe_group_psi_monitor_lifecycle.sh')
    cases = [row for row in rows(monitor) if row.get('passed')]
    assert len(cases) == 4 and not monitor['stderr']
    assert {(r['mode'], r['runtime']) for r in cases} == {(m, rt) for m in ('rootful', 'rootless') for rt in ('crun', 'runc')}
    for row in cases:
        assert row['limits_unchanged'] and row['old_container_id'] != row['new_container_id']
        assert row['deadline']['returncode'] == 3
        for phase in ('move', 'replace'):
            assert row[phase]['returncode'] not in (0, 3)
            assert all(n['container_id'] == row['old_container_id'] for n in row[phase]['records'])
    if repaired:
        migration = proof('reclaim-migration', 'psi-reclaim-migration-' + LABEL, 'GROUP_PSI_RECLAIM_MIGRATION_PASS', 'scripts/probe_group_psi_reclaim_migration.sh')
        cases = [row for row in rows(migration) if row.get('passed')]
        assert len(cases) == 4 and {(r['mode'], r['runtime']) for r in cases} == {(m, rt) for m in ('rootful', 'rootless') for rt in ('crun', 'runc')}
        assert any(row.get('cleanup_errors') == [] for row in rows(migration)) and not migration['stderr']
        for row in cases:
            assert row['moves'] >= 128 and row['memstall_observed_moves'] >= 8 and row['pf_memstall_mask'] == audit['pf_memstall_mask_verified']
            assert row['restored_original_group'] and row['owned_descendants_removed'] and row['payload']['seccomp'] == 2
            assert row['initial_payload'] == {'phase': 'ready', 'max': 67108864, 'high': 33554432, 'seccomp': 2}
            assert all(child['some'] >= 1000 and child['full'] >= 1000 for child in row['descendants'])
            assert row['events_before']['oom_kill'] == row['events_after']['oom_kill'] == 0
    proof('persistence-prepare', 'psi-persistence-prepare-' + LABEL, 'GROUP_PSI_PERSISTENCE_PREPARE_PASS',
          'scripts/probe_group_psi_persistence.sh' if repaired else 'artifacts/droidspaces/runtime/source-versions/psi-persistence-initial/probe_group_psi_persistence.sh')
    resumed = proof('persistence-resume', ('psi-persistence-resume-' if repaired else 'psi-persistence-collected2-') + LABEL, 'GROUP_PSI_PERSISTENCE_RESUME_PASS', 'scripts/probe_group_psi_persistence.sh')
    state = next(row for row in rows(resumed) if row.get('resume_passed'))
    assert state['prepare_passed'] and state['cleanup_passed'] and state['registry_preserved']
    assert state['sources_before'] == state['sources_after'] and state['before_namespace'] != state['after_namespace']
    assert len(state['modes']) == 4
    for row in state['modes']:
        assert row['passed'] and row['first_payload_before'] == row['first_payload_after'] == row['exec_payload_after'] == ['67108864', '33554432', '2']
        if repaired:
            assert row['first_starttime_before'] != row['first_starttime_after']
    before = proof('restart-before', 'psi-restart-before-' + LABEL, source='scripts/record_group_psi_restart.py')
    after = proof('restart-after', 'psi-restart-after-' + LABEL, source='scripts/record_group_psi_restart.py')
    assert before['passed'] and after['passed'] and after['guest_restart_proven']
    assert after['previous_sha256'] == evidence['restart-before']['sha256']
    assert before['registry_sha256'] == after['registry_sha256'] == state['registry_sha256']

    for key, label, marker, source in (
        ('filter', 'psi-filter-' + LABEL, 'CONTAINER_SECCOMP_SETRESUID_PASS', 'probe_container_seccomp_setresuid.sh'),
        ('native-cpu', 'psi-native-cpu-' + LABEL, 'NATIVE_CPU_PODMAN_PASS', 'probe_native_cpu_podman.sh'),
        ('legacy-policy-crun', 'psi-policy-crun-' + LABEL, 'POLICY_FIRST_PAYLOAD_ROOTFUL_ROOTLESS_SMOKE_PASS', 'probe_resource_policy_smoke.sh'),
        ('legacy-policy-runc', 'psi-policy-runc-' + LABEL, 'POLICY_FIRST_PAYLOAD_ROOTFUL_ROOTLESS_SMOKE_PASS', 'probe_resource_policy_smoke.sh')):
        proof(key, label, marker, 'scripts/' + source)
    native = next(row for row in rows(reports['native-cpu']) if 'modes' in row)
    assert native['passed'] and len(native['modes']) == 2 and all(row['weight_passed'] and not row['cleanup_errors'] for row in native['modes'])
    binder = proof('android16-binder-public-api', 'psi-binder-public-api-' + LABEL)
    assert binder['listener_status'] == '0' and 'ANDROID16_BINDER_PUBLIC_CALLBACKS_PASS' in binder['listener_stdout']
    assert binder['listener_stdout'].splitlines()[:3] == ['PUBLIC_FREEZE_CALLBACK 1', 'PUBLIC_FREEZE_CALLBACK 0', 'PUBLIC_FREEZE_CALLBACK 1']
    assert not binder['cleanup_errors'] and all(binder['owned_pids_removed'].values()) and binder['ordinary_guest_seccomp'] == '2' and binder['selinux'] == 'Enforcing'
    for field, source in (('runner_source_sha256', 'scripts/run_binder_public_api_probe.py'),
                          ('java_source_sha256', 'references/runtime-probes/binder-freeze/RmxBinderFreezeApi.java'),
                          ('native_control_source_sha256', 'references/runtime-probes/binder-freeze/binder_api_control.c')):
        assert binder[field] == sha(ROOT / source)
    for key, label in (('host-before', 'psi-host-before-' + LABEL), ('host-final', 'psi-host-final-' + LABEL)):
        report = proof(key, label, 'GROUP_PSI_HOST_HEALTH_PASS', 'scripts/probe_group_psi_host_health.py')
        assert report['passed'] and all(report['checks'].values()) and not report['fatal_diagnostics']
    assert reports['host-final']['baseline_sha256'] == evidence['host-before']['sha256']
    assert reports['host-final']['services'] == reports['host-before']['services']
    offline_path = ART / 'group-psi-offline-checks.json'
    offline = read(offline_path)
    assert offline['passed'] and all(row['returncode'] == 0 for row in offline['tests'])
    for name, digest in offline['tested_sources'].items():
        assert digest == normalized_sha(ROOT / 'scripts' / name)
    evidence['offline'] = {'path': offline_path.relative_to(ART).as_posix(), 'sha256': sha(offline_path)}

    # Finish against actual device state, rather than just accepting saved reports.
    adb = device()
    assert read_identity(adb) == identity
    guest = guest_info(adb)
    actual = json.loads(read_root(adb, shlex.join([DS, '--name=' + NAME, 'run', 'rmx1931-policy', 'validate'])))
    assert actual['profiles'] == {}
    for cli in ('podman', 'podman-rootless'):
        assert not read_root(adb, shlex.join([DS, '--name=' + NAME, 'run', cli, 'ps', '-q'])).strip()
    assert guest['pid'] == after['guest_pid']
    assert read_root(adb, 'sha256sum /dev/block/by-name/boot').decode().split()[0] == boot['boot_sha256']
    if not audit['existing_export_crc_preserved']:
        assert not read_root(adb, 'cat /proc/modules').strip()
        assert not read_root(adb, 'set -e; for d in /vendor/lib/modules /odm/lib/modules /system/lib/modules '
            '/vendor_dlkm/lib/modules /odm_dlkm/lib/modules /system_dlkm/lib/modules /data/adb/modules; '
            'do if test -d "$d"; then find "$d" -type f -name "*.ko"; fi; done').strip()
    assert read_identity(adb) == identity and sha(boot_path) == boot_digest
    receipt = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'passed': True,
        'group_psi_memory_policy_accepted': True, 'stage': STAGE, **identity, 'boot_sha256': boot['boot_sha256'],
        'boot_verification_sha256': boot_digest, 'build_audit_sha256': sha(audit_path),
        'packaging_sha256': sha(pack_path), 'deployment_sha256': sha(deployment_path),
        'predecessor_binder_acceptance_sha256': sha(predecessor), 'evidence': evidence,
        'guest_pid': guest['pid'], 'installed_sources': offline['tested_sources'],
        'new_kernel_source_code': repaired, 'module_export_crcs_preserved': audit['existing_export_crc_preserved'],
        'scope': 'Enable existing cgroup PSI; pre-execution optional memory.high, some/full real bounded workloads, separate ancestor notifications and idle neighbors; watcher target binding, real guest restart persistence and affected Android/container regression.',
        'limitations': ['No automatic process killing or changes to LMKD thresholds.', 'No performance, battery or OOM-resilience improvement claim.',
                       'PSI uses per-group non-idle CPU weighting; parent total need not exceed child total.', 'Export CRC identity does not establish external module binary compatibility.'],
        'complete_android16_desktop_status': 'paused by user; not deployed or accepted',
        'remaining_current_scope': ['Current-ROM eBPF interface requirements']}
    if repaired:
        receipt.update(upstream_commit=audit['upstream_commit'], psi_reclaim_full_fix_accepted=True,
            abi_review_sha256=audit.get('abi_review_sha256'), changed_existing_export_crcs=len(audit['export_crc']['changed']),
            external_module_compatibility=False, external_modules_absent=True,
            repaired_source_sha256=audit['modified_sources'], iteration_baseline_runtime_accepted=False,
            iteration_baseline_failure_sha256=audit['source']['iteration_full_failure_sha256'],
            scope=receipt['scope'] + ' Reclaiming runnable tasks contribute to full state; owned descendant migrations overlap actual PF_MEMSTALL observations without underflow.')
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    runtime_path.write_text(json.dumps({'runtime_passed': True, 'group_psi_memory_policy_accepted': True,
        **identity, 'boot_sha256': boot['boot_sha256'], 'boot_verification_sha256': boot_digest,
        'group_psi_acceptance_sha256': sha(receipt_path)}, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'group_psi_memory_policy_accepted': True, 'evidence_reports': len(evidence), **identity}))


if __name__ == '__main__':
    main()
