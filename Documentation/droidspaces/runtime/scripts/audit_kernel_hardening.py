#!/usr/bin/env python3
"""Bind the lifecycle feature build to its inherited and changed source hashes."""
import argparse
import hashlib
import json
from pathlib import Path
from audit_lowrisk_kernel import config, symbols

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
DEST = ART / 'kernel-ext-harden1'
BASE = ART / 'kernel-ext-dualio'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--after-build', action='store_true')
    args = parser.parse_args()
    before = config(BASE / 'resolved.config')
    after = config(DEST / 'resolved.config')
    assert before == after, 'Lifecycle backport must retain the complete accepted configuration'
    source = json.loads((DEST / 'source.json').read_text())
    inherited = json.loads((ROOT / 'worktrees/rmx1931-ksunext3/Documentation/droidspaces/source-lock.json').read_text())['modified_source_sha256']
    hashes = {**inherited, **{name: record['after_sha256'] for name, record in source['modified_sources'].items()}}
    for name, expected in hashes.items():
        assert digest(Path(source['source']) / name) == expected, name
    result = {'stage': 'harden1', 'config_changes': {}, 'source': source,
              'cumulative_stages': ['utilities', 'bbr', 'checkpoint', 'network', 'io', 'resources', 'dualio', 'harden1'],
              'verified_source_files': len(hashes), 'build_audit_passed': False,
              'runtime_acceptance': 'pending', 'default_oom_group_policy': False,
              'fork_race_fix': 'b69bb476dee99d564d65d418e9a20acca6f32c3f adapted to old fork API'}
    if args.after_build:
        previous, current = symbols(BASE / 'Module.symvers'), symbols(DEST / 'Module.symvers')
        missing = sorted(previous.keys() - current.keys())
        changed = sorted(name for name in previous.keys() & current.keys() if previous[name] != current[name])
        assert not missing, missing
        linked = {line.split()[-1] for line in (DEST / 'System.map').read_text().splitlines() if line.split()}
        required = ['cgroup_kill_write', 'memory_oom_group_write', 'mem_cgroup_get_oom_group',
                    'blkio_cgrp_subsys', 'io_cgrp_subsys', 'tg_set_cfs_quota']
        assert all(name in linked for name in required), required
        result.update({key: digest(DEST / filename) for key, filename in
                       [('kernel_sha256', 'Image.gz-dtb'), ('resolved_config_sha256', 'resolved.config'),
                        ('module_symvers_sha256', 'Module.symvers'), ('system_map_sha256', 'System.map')]})
        result.update(build_audit_passed=True, export_crc={'missing': missing, 'changed': changed},
                      existing_export_crc_preserved=not changed, linked_symbols=required)
        assert (DEST / 'kernel.release').read_text().strip() == '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-harden1'
    (DEST / 'audit.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'build_audit_passed': result['build_audit_passed'], 'verified_source_files': len(hashes),
                      'kernel_sha256': result.get('kernel_sha256'),
                      'changed_export_crcs': len(result.get('export_crc', {}).get('changed', []))}))


if __name__ == '__main__':
    main()
