#!/usr/bin/env python3
"""Archive accepted a16pf/BPF evidence and sync the three actual PSI sources."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
REPO = ROOT / 'worktrees/rmx1931-ksunext3'
PUBLIC = REPO / 'Documentation/droidspaces'
TARGET = PUBLIC / 'runtime/candidates/a16pf'
GIT = r'C:\Program Files\Git\bin\git.exe'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads(p.read_text(encoding='utf-8'))


def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    assert sha(source) == sha(target)


def main():
    assert not TARGET.exists(), 'Existing snapshots are immutable'
    psi = load(ART / 'group-psi-acceptance.json')
    bpf = load(ART / 'android16-bpf-acceptance.json')
    assert psi['passed'] and bpf['passed'] and psi['boot_id'] == bpf['boot_id']
    frozen = {p: sha(p) for p in PUBLIC.glob('source-lock*.json')}
    for stage in ('h2cp', 'h3bm', 'h4sn', 'h5bf', 'a16ps'):
        frozen.update({p: sha(p) for p in (PUBLIC / 'runtime/candidates' / stage).rglob('*') if p.is_file()})
    stage = 'android16-group-psi-reclaim-fix'
    kernel = ART / ('kernel-ext-' + stage)
    for name in ('audit.json', 'source.json', 'preparation.json', 'patch-check.json', 'resolved.config',
                 'Module.symvers', 'System.map', 'kernel.release', 'build.log', 'configure.log'):
        copy(kernel / name, TARGET / 'evidence' / (kernel.name + '/' + name))
    for p in (kernel / 'modified-sources').rglob('*'):
        if p.is_file(): copy(p, TARGET / 'source' / p.relative_to(kernel / 'modified-sources'))
    for name in ('review.json', 'type-analysis.json', 'build-audit-before-review.json'):
        copy(kernel / 'abi-change' / name, TARGET / 'evidence' / kernel.name / 'abi-change' / name)
    for suffix in ('preflight', 'deployment', 'boot-result', 'runtime-result'):
        p = ART / f'extensions-{stage}-{suffix}.json'
        copy(p, TARGET / 'evidence' / p.name)
    for name in (f'boot-images/ext-{stage}-candidate-check.json', f'kernel-ext-{stage}-dtb-comparison.json',
                 'group-psi-acceptance.json', 'android16-bpf-acceptance.json', 'group-psi-offline-checks.json'):
        copy(ART / name, TARGET / 'evidence' / name)
    for receipt in (psi, bpf):
        for entry in receipt['evidence'].values():
            copy(ART / entry['path'], TARGET / 'evidence' / entry['path'])
    for p in (ART / 'runtime').glob('*a16pf*.json'):
        copy(p, TARGET / 'evidence/runtime' / p.name)
    for p in (ART / 'runtime/source-versions/psi-a16pf-first-payload-filter').rglob('*'):
        if p.is_file(): copy(p, TARGET / 'evidence' / p.relative_to(ART))
    scripts = ('audit_group_psi_reclaim_fix.py', 'build_kernel_group_psi_reclaim_fix.sh',
        'prepare_group_psi_reclaim_fix.py', 'explain_group_psi_abi.py', 'review_group_psi_abi.py',
        'deploy_group_psi_reclaim.py', 'group_psi_boot.py', 'record_group_psi_acceptance.py',
        'record_group_psi_reclaim_acceptance.py', 'run_group_psi_reclaim_checks.py',
        'probe_group_psi_policy.sh', 'probe_group_psi_reclaim_migration.sh',
        'probe_group_psi_monitor_lifecycle.sh', 'probe_group_psi_persistence.sh',
        'record_group_psi_restart.py', 'probe_group_psi_host_health.py',
        'rmx1931_resource_policy.py', 'rmx1931_pressure.py', 'oci_resource_entry.py',
        'device_runtime.py', 'start_podman_guest.py', 'delegate_guest_cgroup_v2.py',
        'deploy_kernel_extensions.py', 'prepare_boot_candidate.py', 'inspect_kernel_dtb.py',
        'probe_container_seccomp_setresuid.sh', 'probe_native_cpu_podman.sh',
        'probe_resource_policy_smoke.sh', 'run_binder_public_api_probe.py',
        'build_android16_bpf_rom_probe.py', 'probe_android16_bpf_rom_inventory.py',
        'probe_android16_bpf_rom_workload.py', 'cleanup_android16_bpf_probes.py',
        'record_android16_bpf_acceptance.py', 'seal_android16_acceptance.py',
        'accept_phone.py', 'test_runtime_acceptance.py')
    for name in scripts: copy(ROOT / 'scripts' / name, TARGET / 'scripts' / name)
    for directory in ('android16-bpf-aosp', 'android16-bpf-current-kernel', 'runtime-probes/android16-bpf'):
        base = ROOT / 'references' / directory
        for p in base.rglob('*'):
            if p.is_file(): copy(p, TARGET / 'references' / directory / p.relative_to(base))
    for name in ('rmx1931-group-psi-config.patch', 'rmx1931-psi-reclaim-full.patch'):
        copy(ROOT / 'patches' / name, TARGET / 'patches' / name)

    # Populate only missing sparse files. Refuse to replace user work/staged changes.
    modified = load(kernel / 'preparation.json')['modified_sources']
    assert not subprocess.check_output([GIT, 'diff', '--cached', '--numstat', '--', *modified], cwd=REPO).strip()
    for name, digest in modified.items():
        assert not (REPO / name).exists() and sha(TARGET / 'source' / name) == digest
    subprocess.run([GIT, 'update-index', '--no-skip-worktree', '--', *modified], cwd=REPO, check=True)
    for name in modified: copy(TARGET / 'source' / name, REPO / name)

    def artifact_link(relative):
        for base in (TARGET / 'evidence', PUBLIC / 'runtime/candidates/a16ps/evidence', PUBLIC):
            p = base / relative
            if p.is_file(): return p.relative_to(PUBLIC).as_posix()
        copy(ART / relative, TARGET / 'evidence' / relative)
        return (TARGET / 'evidence' / relative).relative_to(PUBLIC).as_posix()

    mapping = {'group-psi-validation.md': 'GROUP-PSI-VALIDATION.md',
        'android16-bpf-validation.md': 'ANDROID16-BPF-VALIDATION.md',
        'container-hardening-plan.md': 'CONTAINER-HARDENING-PLAN.md',
        'test-policy.md': 'TEST-POLICY.md', 'validation-review.md': 'VALIDATION-REVIEW.md',
        'hardening1-validation.md': 'HARDENING1-VALIDATION.md',
        'resource-policy-validation.md': 'RESOURCE-POLICY-VALIDATION.md',
        'binfmt-namespace-validation.md': 'BINFMT-NAMESPACE-VALIDATION.md',
        'seccomp-notify-validation.md': 'SECCOMP-NOTIFY-VALIDATION.md',
        'binder-freeze-validation.md': 'BINDER-FREEZE-VALIDATION.md',
        'android16-cgroup-v2-migration.md': 'ANDROID16-CGROUP-V2-MIGRATION.md',
        'virtualization-feasibility.md': 'VIRTUALIZATION-FEASIBILITY.md'}
    for name in ('group-psi-validation.md', 'android16-bpf-validation.md', 'container-hardening-plan.md'):
        text = (ROOT / 'docs' / name).read_text(encoding='utf-8')
        text = re.sub(r'\]\(\.\./artifacts/droidspaces/([^)]*)\)', lambda m: '](' + artifact_link(m[1]) + ')', text)
        text = text.replace('../references/group-psi-upstream/', 'runtime/candidates/a16ps/source-versions/group-psi-upstream/')
        text = text.replace('../references/android16-bpf-aosp/', 'runtime/candidates/a16pf/references/android16-bpf-aosp/')
        for a, b in mapping.items(): text = text.replace('(' + a, '(' + b)
        (PUBLIC / mapping[name]).write_text(text, encoding='utf-8')
        for url in re.findall(r'\]\(([^)]+)\)', text):
            if '://' not in url and not url.startswith('#'):
                assert (PUBLIC / url.split('#')[0]).exists(), (name, url)
    scope = load(ART / 'container-hardening-current-scope.json')
    for feature in scope['accepted_features']:
        feature['acceptance'] = artifact_link(feature['acceptance'].removeprefix('artifacts/droidspaces/'))
    scope['next_work_evidence'] = [artifact_link(p.removeprefix('artifacts/droidspaces/')) for p in scope['next_work_evidence']]
    scope['current_candidate']['acceptance'] = artifact_link('group-psi-acceptance.json')
    scope['prepared_successor']['preparation'] = artifact_link('kernel-ext-' + stage + '/preparation.json')
    (PUBLIC / 'container-hardening-current-scope.json').write_text(json.dumps(scope, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    copy(ART / 'container-hardening-current-scope.json', TARGET / 'evidence/container-hardening-current-scope.json')
    audit = load(kernel / 'audit.json')
    source_lock = {'stage': stage, 'kernel': psi['kernel'], 'runtime_accepted': True,
        'psi_acceptance': artifact_link('group-psi-acceptance.json'), 'psi_acceptance_sha256': sha(ART / 'group-psi-acceptance.json'),
        'bpf_acceptance': artifact_link('android16-bpf-acceptance.json'), 'bpf_acceptance_sha256': sha(ART / 'android16-bpf-acceptance.json'),
        'image_sha256': audit['kernel_sha256'], 'boot_sha256': psi['boot_sha256'],
        'cumulative_source_sha256': audit['cumulative_source_sha256'], 'modified_sources': modified,
        'resolved_config_sha256': audit['resolved_config_sha256'], 'module_export_crcs_preserved': False,
        'abi_review_sha256': psi['abi_review_sha256'], 'external_module_compatibility': False,
        'complete_android16_desktop': 'paused by user'}
    (PUBLIC / 'source-lock-group-psi-a16pf.json').write_text(json.dumps(source_lock, indent=2) + '\n')
    assert all(sha(p) == digest for p, digest in frozen.items()), 'Historical snapshots changed'
    manifest = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'runtime_accepted': True,
        'kernel': psi['kernel'], 'psi_accepted': True, 'current_rom_bpf_accepted': True,
        'previous_frozen_files': len(frozen), 'prior_accepted_snapshots_preserved': True,
        'no_binary_images_duplicated': True,
        'file_sha256': {p.relative_to(TARGET).as_posix(): sha(p) for p in TARGET.rglob('*') if p.is_file()}}
    (TARGET / 'progress.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'accepted_snapshot_created': True, 'files': len(manifest['file_sha256']),
        'historical_frozen_files_preserved': len(frozen), 'actual_psi_sources_synced': len(modified)}))


if __name__ == '__main__': main()
