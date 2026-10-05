#!/usr/bin/env python3
"""Bound the candidate config changes and compare existing export CRCs."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = Path('/var/tmp/rmx1931-droidspaces-1a5720a5213b')
ARTIFACTS = ROOT / 'artifacts/droidspaces/kernel-lowrisk'


def config(path):
    values = {}
    for line in path.read_text().splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
            values[key] = value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            values[line[2:-11]] = 'n'
    return values


def symbols(path):
    return {row[1]: row[0] for line in path.read_text().splitlines()
            if len(row := line.split()) >= 2}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--after-build', action='store_true')
    args = p.parse_args()
    old = config(ROOT / 'artifacts/droidspaces/kernel-podman2/resolved.config')
    new = config(BUILD / 'out-lowrisk/.config')
    changes = {key: {'before': old.get(key, 'n'), 'after': new.get(key, 'n')}
               for key in sorted(old.keys() | new.keys())
               if old.get(key, 'n') != new.get(key, 'n')}
    required = ('UNIX_DIAG', 'NETLINK_DIAG', 'PACKET_DIAG', 'SQUASHFS',
                'SQUASHFS_FILE_CACHE', 'SQUASHFS_DECOMP_SINGLE', 'SQUASHFS_ZLIB',
                'SQUASHFS_XZ', 'SQUASHFS_XATTR', 'MODVERSIONS', 'DEBUG_LIST', 'SCHED_WALT')
    for key in required:
        if new.get('CONFIG_' + key) != 'y':
            raise RuntimeError('Missing required config: ' + key)
    for key in changes:
        if key not in {'CONFIG_UNIX_DIAG', 'CONFIG_NETLINK_DIAG', 'CONFIG_PACKET_DIAG'} and not key.startswith(('CONFIG_SQUASHFS', 'CONFIG_XZ_DEC')):
            raise RuntimeError('Unexpected config delta: ' + key)
    for key in ('NET_L3_MASTER_DEV', 'VLAN_8021Q', 'IPVLAN', 'IPVTAP', 'CFS_BANDWIDTH'):
        if new.get('CONFIG_' + key, 'n') != old.get('CONFIG_' + key, 'n'):
            raise RuntimeError('Protected config changed: ' + key)
    lock = json.loads((ROOT / 'references/kernel-publish/Documentation/droidspaces/source-lock.json').read_text())
    source_hashes = {}
    for name, expected in lock['modified_source_sha256'].items():
        actual = hashlib.sha256((BUILD / 'src' / name).read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError('Accepted source changed: ' + name)
        source_hashes[name] = actual
    report = {'base_revision': (BUILD / 'source-revision').read_text().strip(),
              'base_variant': 'podman2', 'candidate_variant': 'lowrisk2',
              'config_changes': changes, 'accepted_modified_source_sha256': source_hashes,
              'unexpected_config_changes': [], 'source_code_changes': False}
    if args.after_build:
        before = symbols(ROOT / 'artifacts/droidspaces/kernel-podman2/Module.symvers')
        after = symbols(ARTIFACTS / 'Module.symvers')
        changed = [name for name in before if name in after and before[name] != after[name]]
        missing = sorted(before.keys() - after.keys())
        report['export_crc'] = {'baseline_symbols': len(before), 'candidate_symbols': len(after),
                                'changed_existing_symbols': changed, 'missing_existing_symbols': missing,
                                'added_symbols': sorted(after.keys() - before.keys())}
        if changed or missing:
            raise RuntimeError('Existing exported symbol CRCs differ: ' + str(changed + missing))
        report['kernel_sha256'] = hashlib.sha256((ARTIFACTS / 'Image.gz-dtb').read_bytes()).hexdigest()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
