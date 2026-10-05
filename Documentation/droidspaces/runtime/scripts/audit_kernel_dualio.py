#!/usr/bin/env python3
"""Fail-closed cumulative source/config/export audit for the dual IO fork."""
import argparse
import hashlib
import json
from pathlib import Path
from audit_lowrisk_kernel import config, symbols

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
BASE = ART / 'kernel-ext-resources'
DEST = ART / 'kernel-ext-dualio'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--after-build', action='store_true')
    args = parser.parse_args()
    old, new = config(BASE / 'resolved.config'), config(DEST / 'resolved.config')
    changes = {k: {'before': old.get(k, 'n'), 'after': new.get(k, 'n')}
               for k in old.keys() | new.keys() if old.get(k, 'n') != new.get(k, 'n')}
    assert changes == {'CONFIG_RMX1931_DUAL_BLKIO': {'before': 'n', 'after': 'y'}}, changes
    assert new['CONFIG_SCHED_WALT'] == new['CONFIG_CFS_BANDWIDTH'] == 'y'
    assert new.get('CONFIG_BLK_DEV_THROTTLING_LOW', 'n') == 'n'
    source = json.loads((DEST / 'source.json').read_text())
    for name, hashes in source['modified_sources'].items():
        assert digest(Path(source['source']) / name) == hashes['after_sha256']
        assert digest(Path(source['base_source']) / name) == hashes['before_sha256']
    assert digest(ROOT / 'patches/rmx1931-opt-in-dual-blkio.patch') == source['patch_sha256']
    predecessor = json.loads((BASE / 'audit.json').read_text())
    assert predecessor['build_audit_passed']
    lock = json.loads((ROOT / 'ksunext.sources.lock.json').read_text())
    hashes = {**lock['accepted_podman_source_sha256'], **lock['manual_hook_source_sha256']}
    hashes.update({k: v['after_sha256'] for k, v in lock['upstream_kbuild_compatibility_backports'].items()})
    io = json.loads((ART / 'kernel-ext-io/audit.json').read_text())
    hashes.update({k: v['after_sha256'] for k, v in io['additional_source_patch']['modified_sources'].items()})
    hashes.update({k: v['after_sha256'] for k, v in predecessor['source']['modified_sources'].items()})
    hashes.update({k: v['after_sha256'] for k, v in source['modified_sources'].items()})
    assert all(digest(Path(source['source']) / k) == v for k, v in hashes.items())
    result = {'stage': 'dualio', 'cumulative_stages': ['utilities', 'bbr', 'checkpoint', 'network', 'io', 'resources', 'dualio'],
              'config_changes': changes, 'source': source,
              'verified_source_files': len(hashes), 'build_audit_passed': False,
              'runtime_acceptance': 'pending', 'android_v1_blkio_retained': True,
              'native_v2_io_requires_explicit_subtree_selection': True}
    if args.after_build:
        before, after = symbols(BASE / 'Module.symvers'), symbols(DEST / 'Module.symvers')
        missing = sorted(before.keys() - after.keys())
        changed = sorted(k for k in before.keys() & after.keys() if before[k] != after[k])
        assert not missing, missing
        linked = {line.split()[-1] for line in (DEST / 'System.map').read_text().splitlines() if line.split()}
        required = ['blkio_cgrp_subsys', 'io_cgrp_subsys', 'blkcg_v2_delegate_write', 'blkcg_v2_root',
                    'tg_set_cfs_quota', 'throttle_cfs_rq']
        assert all(name in linked for name in required)
        result.update({key: digest(DEST / filename) for key, filename in
                       [('kernel_sha256', 'Image.gz-dtb'), ('resolved_config_sha256', 'resolved.config'),
                        ('module_symvers_sha256', 'Module.symvers'), ('system_map_sha256', 'System.map')]})
        result.update(build_audit_passed=True, export_crc={'missing': missing, 'changed': changed},
                      existing_export_crc_preserved=not changed, linked_symbols=required)
    (DEST / 'audit.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'build_audit_passed': result['build_audit_passed'], 'config_changes': changes,
                      'verified_source_files': len(hashes), 'kernel_sha256': result.get('kernel_sha256'),
                      'changed_export_crcs': len(result.get('export_crc', {}).get('changed', []))}))


if __name__ == '__main__':
    main()
