#!/usr/bin/env python3
"""Publish Binder iterations and current scope without touching prior snapshots."""
import hashlib
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
PUBLIC = ROOT / 'worktrees/rmx1931-ksunext3/Documentation/droidspaces'
TARGET = PUBLIC / 'runtime/candidates/h5bf'

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path): return json.loads(path.read_text(encoding='utf-8'))
def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    assert sha(source) == sha(target)

def main():
    frozen = {p: sha(p) for p in PUBLIC.glob('source-lock*.json')}
    for stage in ('h2cp', 'h3bm', 'h4sn'):
        frozen.update({p: sha(p) for p in (PUBLIC / 'runtime/candidates' / stage).rglob('*') if p.is_file()})
    receipt_path = ART / 'binder-freeze-acceptance.json'
    accepted = receipt_path.exists() and read(receipt_path).get('binder_freeze_callbacks_accepted') is True
    for stage in ('harden5-binder-freeze', 'harden5-binder-freeze-fix'):
        directory = ART / ('kernel-ext-' + stage)
        for p in directory.rglob('*'):
            if p.is_file() and p.name != 'Image.gz-dtb':
                copy(p, TARGET / 'evidence' / directory.name / p.relative_to(directory))
        for suffix in ('preflight', 'deployment', 'boot-result', 'runtime-result'):
            p = ART / f'extensions-{stage}-{suffix}.json'
            if p.exists(): copy(p, TARGET / 'evidence' / p.name)
        for name in (f'kernel-ext-{stage}-dtb-comparison.json', f'boot-images/ext-{stage}-candidate-check.json'):
            p = ART / name
            if p.exists(): copy(p, TARGET / 'evidence' / name)
        for p in (ART / 'deployment-attempts' / stage).rglob('*.json'):
            copy(p, TARGET / 'evidence' / p.relative_to(ART))
    for p in sorted((ART / 'runtime').glob('binder-*.json')):
        copy(p, TARGET / 'evidence/runtime' / p.name)
    for name in ('android16-memory-bpf-inventory-h5bf-20261005.json', 'android16-psi-enablement-inventory-h5bf-20261005.json', 'binder-freeze-inventory-h4sn-20261005.json'):
        p = ART / 'runtime' / name
        if p.exists(): copy(p, TARGET / 'evidence/runtime' / p.name)
    for name in ('binder-freeze-acceptance.json', 'container-hardening-current-scope.json'):
        p = ART / name
        if p.exists(): copy(p, TARGET / 'evidence' / name)
    source_hashes = {}
    scripts = ['prepare_binder_freeze.py', 'build_kernel_binder_freeze.sh', 'prepare_binder_features_fix.py',
        'build_kernel_binder_features_fix.sh', 'build_binder_public_api_probe.py', 'run_binder_freeze_probe.py',
        'run_binder_public_api_probe.py', 'record_binder_freeze_acceptance.py', 'seal_binder_freeze_progress.py', 'probe_binder_host_health.py',
        'device_runtime.py', 'deploy_kernel_extensions.py', 'prepare_boot_candidate.py', 'inspect_kernel_dtb.py',
        'start_podman_guest.py', 'delegate_guest_cgroup_v2.py', 'install_guest_resource_policy.py',
        'install_guest_podman_oom_wrapper.sh', 'probe_container_seccomp_setresuid.sh', 'probe_native_cpu_podman.sh',
        'probe_resource_policy_smoke.sh']
    for name in scripts:
        p = ROOT / 'scripts' / name
        copy(p, TARGET / 'scripts' / name); source_hashes['scripts/' + name] = sha(p)
    for name in ('rmx1931-binder-freeze-notification.patch', 'rmx1931-binder-freeze-feature-discovery.patch'):
        p = ROOT / 'patches' / name
        copy(p, TARGET / 'patches' / name); source_hashes['patches/' + name] = sha(p)
    for directory in (ROOT / 'references/android16-binder-upstream', ROOT / 'references/runtime-probes/binder-freeze'):
        for p in directory.rglob('*'):
            if p.is_file(): copy(p, TARGET / 'source-versions' / p.relative_to(ROOT / 'references'))
    for name in ('source-lock.json', 'sdk-ref.json', 'maven-metadata.xml'):
        p = ROOT / 'tools/downloads/android16-binder-api' / name
        if p.exists(): copy(p, TARGET / 'tool-source-locks' / name)
    for name in ('build-result.json', 'classes.dex'):
        p = ART / 'binder-public-api-fixture' / name
        if p.exists(): copy(p, TARGET / 'evidence/binder-public-api-fixture' / name)
    progress = {'feature': 'Android 16 Binder frozen-state notifications and capability discovery',
        'binder_freeze_callbacks_accepted': bool(accepted), 'source_sha256': source_hashes,
        'complete_android16_desktop_status': 'paused by user; not deployed or accepted',
        'historical_baseline_correction': 'Original native EINVAL used an invalid packed ABI; not accepted as capability absence proof.'}
    if accepted:
        receipt = read(receipt_path)
        progress.update(kernel=receipt['kernel'], boot_id=receipt['boot_id'], acceptance_sha256=sha(receipt_path), evidence=receipt['evidence'])
    (TARGET / 'progress.json').write_text(json.dumps(progress, indent=2) + '\n', encoding='utf-8')
    scope = read(ART / 'container-hardening-current-scope.json')
    scope['plan'] = 'CONTAINER-HARDENING-PLAN.md'
    for feature in scope.get('accepted_features', []):
        feature['acceptance'] = 'runtime/candidates/h5bf/evidence/' + Path(feature['acceptance']).name
    scope['next_work_evidence'] = ['runtime/candidates/h5bf/evidence/runtime/' + Path(path).name for path in scope.get('next_work_evidence', [])]
    (PUBLIC / 'container-hardening-current-scope.json').write_text(json.dumps(scope, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    mapping = {'binder-freeze-validation.md': 'BINDER-FREEZE-VALIDATION.md', 'container-hardening-plan.md': 'CONTAINER-HARDENING-PLAN.md',
        'test-policy.md': 'TEST-POLICY.md', 'hardening1-validation.md': 'HARDENING1-VALIDATION.md',
        'resource-policy-validation.md': 'RESOURCE-POLICY-VALIDATION.md', 'binfmt-namespace-validation.md': 'BINFMT-NAMESPACE-VALIDATION.md',
        'seccomp-notify-validation.md': 'SECCOMP-NOTIFY-VALIDATION.md', 'android16-cgroup-v2-migration.md': 'ANDROID16-CGROUP-V2-MIGRATION.md',
        'virtualization-feasibility.md': 'VIRTUALIZATION-FEASIBILITY.md'}
    for name in ('binder-freeze-validation.md', 'container-hardening-plan.md'):
        text = (ROOT / 'docs' / name).read_text(encoding='utf-8')
        if name.startswith('binder'):
            text = text.replace('../artifacts/droidspaces/', 'runtime/candidates/h5bf/evidence/')
            text = text.replace('../references/', 'runtime/candidates/h5bf/source-versions/')
            text = text.replace('../patches/', 'runtime/candidates/h5bf/patches/')
        else:
            text = text.replace('../artifacts/droidspaces/', '')
        for a, b in mapping.items(): text = text.replace('(' + a, '(' + b)
        target = PUBLIC / mapping[name]; target.write_text(text, encoding='utf-8')
        for url in re.findall(r'\]\(([^)]+)\)', text):
            if '://' not in url and not url.startswith('#'):
                assert (PUBLIC / url.split('#', 1)[0]).exists(), (name, url)
    assert all(sha(path) == digest for path, digest in frozen.items()), 'Prior accepted snapshot changed'
    print(json.dumps({'binder_freeze_callbacks_accepted': bool(accepted), 'prior_snapshots_preserved': True, 'scripts_and_patches': len(source_hashes)}))

if __name__ == '__main__': main()
