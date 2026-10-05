#!/usr/bin/env python3
"""Bind the accepted harden1 source, helpers and documentation to the build."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from check_kernel_extensions_syntax import NAMES

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
TREE = ROOT / 'worktrees/rmx1931-ksunext3'
DOC = TREE / 'Documentation/droidspaces'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def linux_file(path):
    return subprocess.check_output(['wsl', '--exec', 'cat', path], timeout=30)


def main():
    source = read(ART / 'kernel-ext-harden1/source.json')
    audit = read(ART / 'kernel-ext-harden1/audit.json')
    acceptance = read(ART / 'hardening1-acceptance.json')
    boot = read(ART / 'boot-images/ext-harden1-candidate-check.json')
    release = (ART / 'kernel-ext-harden1/kernel.release').read_text().strip()
    assert audit['build_audit_passed'] and acceptance['passed']
    assert acceptance['kernel'] == release and acceptance['boot_sha256'] == boot['candidate_sha256']
    history = DOC / 'source-lock-ext-dualio.json'
    if not history.exists():
        old = read(DOC / 'source-lock.json')
        assert old['tested_kernel_release'].endswith('-ext-dualio')
        shutil.copyfile(DOC / 'source-lock.json', history)
    previous = read(history)
    hashes = {**previous['modified_source_sha256'],
              **{name: record['after_sha256'] for name, record in source['modified_sources'].items()}}
    comparison = subprocess.run(['wsl', '--exec', 'diff', '-qr', '--exclude=.git',
                                 source['base_source'], source['source']], capture_output=True, timeout=180)
    assert comparison.returncode == 1 and not comparison.stderr, comparison.stderr
    changed = []
    for line in comparison.stdout.decode().splitlines():
        match = re.fullmatch(r'Files ' + re.escape(source['base_source']) + r'/(.+) and ' +
                             re.escape(source['source']) + r'/\1 differ', line)
        assert match, line
        changed.append(match[1])
    assert set(changed) == set(source['modified_sources'])
    for name, expected in hashes.items():
        data = linux_file(source['source'] + '/' + name)
        assert sha(data) == expected, name
        destination = TREE / name
        if name in source['modified_sources']:
            assert sha(destination.read_bytes()) in {source['modified_sources'][name]['before_sha256'], expected}, name
            destination.write_bytes(data)
        assert sha(destination.read_bytes()) == expected, name
    config = (ART / 'kernel-ext-harden1/resolved.config').read_bytes()
    assert sha(config) == audit['resolved_config_sha256']
    (TREE / 'arch/arm64/configs/rmx1931_droidspaces_defconfig').write_bytes(config)
    builder = DOC / 'build-ksunext.sh'
    text = builder.read_text().replace('-ksu3-ext-dualio', '-ksu3-ext-harden1')
    builder.write_text(text, encoding='utf-8', newline='\n')
    patch = ROOT / 'patches/container-lifecycle-4.14.patch'
    assert sha(patch.read_bytes()) == source['patch_sha256']
    shutil.copyfile(patch, DOC / patch.name)
    helpers = {}
    for name in sorted(set(NAMES) | {'sync_hardening_source.py'}):
        local = ROOT / 'scripts' / name
        destination = DOC / 'runtime/scripts' / name
        shutil.copyfile(local, destination)
        helpers[name] = sha(local.read_bytes())
    documents = {'container-hardening-plan.md': 'CONTAINER-HARDENING-PLAN.md',
                 'resource-policy.md': 'RESOURCE-POLICY.md',
                 'resource-policy-validation.md': 'RESOURCE-POLICY-VALIDATION.md',
                 'virtualization-feasibility.md': 'VIRTUALIZATION-FEASIBILITY.md',
                 'hardening1-validation.md': 'HARDENING1-VALIDATION.md',
                 'test-policy.md': 'TEST-POLICY.md', 'container-operations.md': 'RUNTIME-RESOURCES.md',
                 'boot-flashing.md': 'FLASHING.md', 'remaining-validation.md': 'REMAINING-VALIDATION.md'}
    for local, public in documents.items():
        text = (ROOT / 'docs' / local).read_text(encoding='utf-8')
        for source_name, target_name in documents.items():
            text = text.replace('(' + source_name + ')', '(' + target_name + ')')
        text = text.replace('../artifacts/droidspaces/hardening1-acceptance.json', 'hardening1-acceptance.json')
        text = text.replace('../artifacts/droidspaces/resource-policy-acceptance.json', 'resource-policy-acceptance.json')
        text = text.replace('../artifacts/droidspaces/runtime/harden1-el2-readonly-20261004.json', 'virtualization-platform-evidence.json')
        text = text.replace('../artifacts/droidspaces/runtime/harden1-avf-readonly-20261004.json', 'virtualization-avf-evidence.json')
        (DOC / public).write_text(text, encoding='utf-8', newline='\n')
    platform = read(ART / 'runtime/harden1-el2-readonly-20261004.json')
    save(DOC / 'virtualization-platform-evidence.json',
         {'observed_at': platform['observed_at'], 'returncode': platform['returncode'],
          'kernel': release, 'observations': platform['stdout'].splitlines(),
          'read_only': True, 'source_sha256': sha((ART / 'runtime/harden1-el2-readonly-20261004.json').read_bytes())})
    avf_path = ART / 'runtime/harden1-avf-readonly-20261004.json'
    avf = read(avf_path)
    assert avf['returncode'] == 0 and release in avf['stdout'].splitlines()
    save(DOC / 'virtualization-avf-evidence.json',
         {'observed_at': avf['observed_at'], 'returncode': avf['returncode'],
          'kernel': release, 'observations': avf['stdout'].splitlines(),
          'read_only': True, 'source_sha256': sha(avf_path.read_bytes())})
    save(DOC / 'hardening1-acceptance.json', acceptance)
    policy_path = ART / 'resource-policy-acceptance.json'
    policy = read(policy_path) if policy_path.exists() else None
    if policy is not None:
        assert policy['passed'] and policy['kernel'] == release
        for name, expected in policy['runtime_source_sha256'].items():
            assert sha((ROOT / 'scripts' / name).read_bytes().replace(b'\r\n', b'\n')) == expected, name
        for evidence in policy['evidence'].values():
            relative = Path(evidence['path'])
            assert relative.parts[0] == 'runtime' and len(relative.parts) == 2 and relative.suffix == '.json'
            original = ART / relative
            assert sha(original.read_bytes()) == evidence['sha256']
            shutil.copyfile(original, DOC / relative)
        save(DOC / 'resource-policy-acceptance.json', policy)
    lock = dict(previous)
    lock.update(tested_kernel_release=release, tested_boot_sha256=boot['candidate_sha256'],
                kernel_sha256=audit['kernel_sha256'], resolved_config_sha256=audit['resolved_config_sha256'],
                modified_source_sha256=hashes, runtime_helpers_sha256=helpers,
                previous_extension_lock=history.name, runtime_acceptance='hardening1-acceptance.json',
                changed_export_crcs_vs_dualio=len(audit['export_crc']['changed']),
                external_modules_require_rebuild=True, source_iteration='local, uncommitted',
                lifecycle_upstream_patches_sha256=source['upstream_patches_sha256'])
    lock['iteration_patches_sha256'] = {**previous['iteration_patches_sha256'], patch.name: sha(patch.read_bytes())}
    if policy is not None:
        lock['resource_policy_acceptance'] = 'resource-policy-acceptance.json'
        lock['resource_policy_acceptance_sha256'] = sha(policy_path.read_bytes())
    save(DOC / 'source-lock.json', lock)
    workspace = read(ROOT / 'ksunext.sources.lock.json')
    workspace['latest_local_iteration'] = {key: lock[key] for key in
        ('tested_kernel_release', 'tested_boot_sha256', 'kernel_sha256', 'resolved_config_sha256',
         'modified_source_sha256', 'iteration_patches_sha256', 'external_modules_require_rebuild')}
    save(ROOT / 'ksunext.sources.lock.json', workspace)
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'passed': True,
              'compiled_tree': source['source'], 'local_tree': str(TREE),
              'full_tree_comparison_changed_files': sorted(changed),
              'full_tree_comparison_sha256': sha(comparison.stdout),
              'verified_source_sha256': hashes, 'runtime_helpers_sha256': helpers,
              'resolved_config_sha256': sha(config), 'publication_performed': False,
              'previous_local_changes_preserved': True}
    save(ART / 'harden1-local-source-sync.json', report)
    print(json.dumps({'passed': True, 'verified_sources': len(hashes), 'helpers': len(helpers),
                      'changed_files': len(changed), 'publication_performed': False}))


if __name__ == '__main__':
    main()
