#!/usr/bin/env python3
"""Prepare and audit the real full-trigger repair without accepting a16ps."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from audit_lowrisk_kernel import config, symbols

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
BASE = ART / 'kernel-ext-android16-group-psi'
ACCEPTED = ART / 'kernel-ext-harden5-binder-freeze-fix'
STAGE = 'android16-group-psi-reclaim-fix'
DEST = ART / ('kernel-ext-' + STAGE)
RELEASE = '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf'
PATCH = ROOT / 'patches/rmx1931-psi-reclaim-full.patch'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def crc_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_abi_review(audit):
    path = DEST / 'abi-change/review.json'
    review = read(path)
    assert review['allowed'] and review['stage'] == STAGE
    assert review['external_module_compatibility'] is False
    assert review['required_deployment_condition'] == 'no loaded or available external .ko modules'
    assert review['changed_export_count'] == len(audit['export_crc']['changed']) == 3916
    assert not audit['export_crc']['missing'] and review['export_crc_sha256'] == crc_digest(audit['export_crc'])
    for name, key in (('Image.gz-dtb', 'kernel_sha256'), ('Module.symvers', 'module_symvers_sha256'), ('resolved.config', 'resolved_config_sha256')):
        assert sha(DEST / name) == audit[key] == review[key]
    assert review['source_record_sha256'] == sha(DEST / 'source.json')
    assert review['type_analysis_sha256'] == sha(DEST / 'abi-change/type-analysis.json')
    assert review['human_authorization_sha256'] == sha(ART / 'authorized-native-cpu-repair.json')
    assert review['original_failed_build_audit_sha256'] == sha(DEST / 'abi-change/build-audit-before-review.json')
    return sha(path)


def provenance():
    prep_path = DEST / 'preparation.json'
    prep = read(prep_path)
    assert sha(prep_path) == 'b5a0e2427353685d3bb29dedcc6c9d63bcf7dfded69a2b2e95461641a2596ed6'
    assert prep['stage'] == STAGE and prep['adaptation_patch_sha256'] == sha(PATCH)
    assert sha(ROOT / 'references/group-psi-upstream/source-lock.json') == prep['source_lock_sha256']
    checked = read(DEST / 'patch-check.json')
    assert checked['passed'] and checked['preparation_sha256'] == sha(prep_path)
    for name, digest in prep['modified_sources'].items():
        assert sha(DEST / 'modified-sources' / name) == digest
    receipt_path = ART / 'binder-freeze-acceptance.json'
    receipt = read(receipt_path)
    assert sha(receipt_path) == 'd7942418ddcb7443552c14b417d7c9e3e0dc5342813f108cb071da7a93c79aa0'
    assert receipt['passed'] and receipt['build_audit_sha256'] == sha(ACCEPTED / 'audit.json')
    accepted_runtime = read(ART / 'extensions-harden5-binder-freeze-fix-runtime-result.json')
    assert accepted_runtime['runtime_passed'] and accepted_runtime['binder_acceptance_sha256'] == sha(receipt_path)
    for entry in receipt['evidence'].values():
        path = (ART / entry['path']).resolve()
        assert path.is_relative_to(ART.resolve()) and sha(path) == entry['sha256']
    prior = read(BASE / 'audit.json')
    assert prior['build_audit_passed'] and prior['existing_export_crc_preserved']
    accepted = read(ACCEPTED / 'audit.json')
    assert prior['cumulative_source_sha256'] == accepted['cumulative_source_sha256']
    for name, key in (('Image.gz-dtb', 'kernel_sha256'), ('resolved.config', 'resolved_config_sha256'),
                      ('Module.symvers', 'module_symvers_sha256'), ('System.map', 'system_map_sha256')):
        assert sha(BASE / name) == prior[key]
    boot = read(ART / 'extensions-android16-group-psi-boot-result.json')
    assert boot['running_config_matches'] and boot['runtime_passed'] is False
    assert boot['kernel'].endswith('-ext-a16ps')
    failure_path = ART / prep['full_trigger_failure']
    failure = read(failure_path)
    assert failure['returncode'] == 1 and failure['end_identity'] == {k: boot[k] for k in ('kernel', 'boot_id')}
    assert all(failure[k] == boot[k] for k in ('kernel', 'boot_id'))
    records = [json.loads(line) for line in failure['stdout'].splitlines() if line.startswith('{')]
    payload = next(row for row in records if row.get('event') == 'payload-finished')
    assert payload['stall'] == 'full' and payload['after']['full'] - payload['before']['full'] >= 1000
    assert payload['events_after']['oom_kill'] == 0
    monitor = next(row for row in records if 'monitor_stdout' in row)
    done = [json.loads(line) for line in monitor['monitor_stdout'].splitlines()][-1]
    assert done['event'] == 'complete' and done['reason'] == 'deadline' and done['notifications'] == 0
    assert next(row for row in records if 'cleanup_errors' in row)['cleanup_errors'] == []
    bindings = {'accepted_kernel_receipt_sha256': sha(receipt_path),
        'accepted_kernel_audit_sha256': sha(ACCEPTED / 'audit.json'),
        'iteration_baseline_audit_sha256': sha(BASE / 'audit.json'),
        'iteration_boot_verification_sha256': sha(ART / 'extensions-android16-group-psi-boot-result.json'),
        'iteration_full_failure_sha256': sha(failure_path), 'preparation_sha256': sha(prep_path),
        'patch_check_sha256': sha(DEST / 'patch-check.json'), 'patch_sha256': sha(PATCH)}
    return prep, prior, bindings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--after-build', action='store_true')
    parser.add_argument('--approve-abi-review', action='store_true')
    args = parser.parse_args()
    prep, prior, bindings = provenance()
    before = Path(prior['source']['source'])
    assert all(sha(before / name) == digest for name, digest in prior['cumulative_source_sha256'].items())
    assert all(sha(before / name) == digest for name, digest in prep['baseline_sha256'].items())
    if args.prepare:
        assert args.source and args.source.is_dir() and args.source.resolve() != before.resolve()
        assert args.config and args.config.read_bytes() == (BASE / 'resolved.config').read_bytes()
        assert all(sha(args.source / name) == digest for name, digest in prior['cumulative_source_sha256'].items())
        source_path = DEST / 'source.json'
        record = {'stage': STAGE, 'source': str(args.source.resolve()), 'base_source': str(before),
            **bindings, 'modified_sources': prep['modified_sources'],
            'iteration_baseline_runtime_accepted': False, 'same_functional_stage_repair': True,
            'implementation': 'cb0e52b runnable-reclaimer state adapted to PF_MEMSTALL, old dequeue and local cgroup_move_task; CPU PSI, WALT and generic cgroup core unchanged.'}
        if source_path.exists():
            assert read(source_path) == record
            assert all(sha(args.source / name) == digest for name, digest in prep['modified_sources'].items())
        else:
            assert all(sha(args.source / name) == digest for name, digest in prep['baseline_sha256'].items())
            subprocess.run(['git', '-C', str(args.source), '-c', 'core.autocrlf=false', 'apply', '--check', str(PATCH)], check=True)
            subprocess.run(['git', '-C', str(args.source), '-c', 'core.autocrlf=false', 'apply', str(PATCH)], check=True)
            assert all(sha(args.source / name) == digest for name, digest in prep['modified_sources'].items())
            save(source_path, record)
        print('GROUP_PSI_RECLAIM_SOURCE_READY')
        return
    record = read(DEST / 'source.json')
    assert all(record[key] == value for key, value in bindings.items())
    source = Path(record['source'])
    assert re.search(r'^#define PF_MEMSTALL\s+0x01000000\b', (source / 'include/linux/sched.h').read_text(), re.M)
    hashes = {**prior['cumulative_source_sha256'], **prep['modified_sources']}
    assert all(sha(source / name) == digest for name, digest in hashes.items())
    current = config(DEST / 'resolved.config')
    previous_config = config(BASE / 'resolved.config')
    assert current == previous_config, 'Unexpected configuration change relative to a16ps'
    accepted_config = config(ACCEPTED / 'resolved.config')
    delta = {key: {'before': accepted_config.get(key), 'after': current.get(key)}
        for key in sorted(accepted_config.keys() | current.keys()) if accepted_config.get(key) != current.get(key)}
    assert delta == {'CONFIG_CMDLINE': {'before': '"cgroup_disable=pressure"', 'after': '"psi=1"'}}
    result = {'stage': STAGE, 'source': record, 'cumulative_stages': prior['cumulative_stages'] + [STAGE],
        'cumulative_source_sha256': hashes, 'verified_source_files': len(hashes),
        'modified_sources': prep['modified_sources'], 'config_changes': delta, 'iteration_config_changes': {},
        'walt_source_sha256': sha(source / 'kernel/sched/walt.c'),
        'generic_cgroup_core_sha256': sha(source / 'kernel/cgroup/cgroup.c'),
        'generic_cgroup_core_unchanged_from_harden1': True, 'build_audit_passed': False,
        'runtime_acceptance': 'pending', 'android_v1_cpu_cpuset_retained': True,
        'upstream_commit': prep['upstream_commit'], 'new_psi_backport_claimed': True,
        'pf_memstall_mask_verified': '0x01000000', 'task_header_sha256': sha(source / 'include/linux/sched.h')}
    for key in ('walt_source_sha256', 'generic_cgroup_core_sha256'):
        assert result[key] == prior[key]
    if args.after_build:
        assert (DEST / 'kernel.release').read_text().strip() == RELEASE
        old = symbols(BASE / 'Module.symvers')
        new = symbols(DEST / 'Module.symvers')
        missing = sorted(old.keys() - new.keys())
        changed = sorted(name for name in old.keys() & new.keys() if old[name] != new[name])
        linked = {line.split()[-1] for line in (DEST / 'System.map').read_text().splitlines() if line.split()}
        required = sorted(set(prior['linked_symbols']) | {'psi_memstall_enter', 'psi_memstall_leave'})
        assert set(required) <= linked, 'Previously required interfaces are absent'
        result.update(export_crc={'missing': missing, 'changed': changed,
            'details': {name: {'before': old[name], 'after': new[name]} for name in changed},
            'baseline_symbols': len(old), 'candidate_symbols': len(new)},
            existing_export_crc_preserved=not missing and not changed, linked_symbols=required,
            build_audit_passed=not missing and not changed,
            abi_review='passed; existing CRCs unchanged' if not missing and not changed else 'pending review; packaging/deployment gate remains closed')
        result.update({key: sha(DEST / name) for key, name in [('kernel_sha256', 'Image.gz-dtb'),
            ('resolved_config_sha256', 'resolved.config'), ('module_symvers_sha256', 'Module.symvers'), ('system_map_sha256', 'System.map')]})
        if args.approve_abi_review:
            assert changed and not missing
            result['abi_review_sha256'] = validate_abi_review(result)
            result.update(build_audit_passed=True,
                abi_review='reviewed genuine ABI change; deployment requires standing human authorization and no external modules')
    save(DEST / 'audit.json', result)
    print(json.dumps({'build_audit_passed': result['build_audit_passed'],
        'verified_source_files': len(hashes), 'kernel_sha256': result.get('kernel_sha256'),
        'changed_export_count': len(result.get('export_crc', {}).get('changed', [])),
        'missing_export_count': len(result.get('export_crc', {}).get('missing', []))}))
    if args.after_build and not result['build_audit_passed']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
