#!/usr/bin/env python3
"""Audit only the resource candidate against the already accepted cumulative io kernel."""
import argparse
import hashlib
import json
from pathlib import Path
from audit_lowrisk_kernel import config, symbols

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
BASE = ART / 'kernel-ext-io'
DEST = ART / 'kernel-ext-resources'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--after-build', action='store_true')
    args = parser.parse_args()
    old, new = config(BASE / 'resolved.config'), config(DEST / 'resolved.config')
    changes = {key: {'before': old.get(key, 'n'), 'after': new.get(key, 'n')}
               for key in old.keys() | new.keys() if old.get(key, 'n') != new.get(key, 'n')}
    assert changes == {'CONFIG_CFS_BANDWIDTH': {'before': 'n', 'after': 'y'}}, changes
    assert new['CONFIG_SCHED_WALT'] == 'y'
    source = json.loads((DEST / 'source.json').read_text())
    for name, hashes in source['modified_sources'].items():
        assert digest(Path(source['source']) / name) == hashes['after_sha256']
        assert digest(Path(source['source']).with_name('src-ext-network') / name) == hashes['before_sha256']
    # Retain the predecessor's complete accepted source checks, except the reviewed Kconfig change.
    predecessor = json.loads((BASE / 'audit.json').read_text())
    assert predecessor['build_audit_passed']
    lock = json.loads((ROOT / 'ksunext.sources.lock.json').read_text())
    hashes = {**lock['accepted_podman_source_sha256'], **lock['manual_hook_source_sha256']}
    hashes.update({key: value['after_sha256'] for key, value in lock['upstream_kbuild_compatibility_backports'].items()})
    hashes.update({key: value['after_sha256'] for key, value in predecessor['additional_source_patch']['modified_sources'].items()})
    hashes.update({key: value['after_sha256'] for key, value in source['modified_sources'].items()})
    assert all(digest(Path(source['source']) / key) == value for key, value in hashes.items())
    result = {'stage': 'resources', 'cumulative_stages': ['utilities', 'bbr', 'checkpoint', 'network', 'io', 'resources'],
              'config_changes': changes, 'source': source,
              'verified_source_files': len(hashes), 'build_audit_passed': False,
              'runtime_acceptance': 'pending', 'walt_retained': True,
              'android_controller_ownership_changed': False}
    if args.after_build:
        before, after = symbols(BASE / 'Module.symvers'), symbols(DEST / 'Module.symvers')
        missing = sorted(before.keys() - after.keys())
        changed = sorted(key for key in before.keys() & after.keys() if before[key] != after[key])
        assert not missing, missing
        linked = {line.split()[-1] for line in (DEST / 'System.map').read_text().splitlines() if line.split()}
        required = ['tg_set_cfs_quota', 'throttle_cfs_rq', 'unthrottle_cfs_rq']
        assert all(name in linked for name in required)
        result.update({key: digest(DEST / filename) for key, filename in
                       [('kernel_sha256', 'Image.gz-dtb'), ('resolved_config_sha256', 'resolved.config'),
                        ('module_symvers_sha256', 'Module.symvers'), ('system_map_sha256', 'System.map')]})
        result.update(build_audit_passed=True, export_crc={'missing': missing, 'changed': changed},
                      existing_export_crc_preserved=not changed, linked_symbols=required)
    (DEST / 'audit.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
