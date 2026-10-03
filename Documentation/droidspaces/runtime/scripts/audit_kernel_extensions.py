#!/usr/bin/env python3
"""Fail closed on config drift, lost exports, source drift and missing linked code."""
import argparse
import hashlib
import json
from pathlib import Path
from audit_lowrisk_kernel import config, symbols

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'configs/kernel-extensions.json'
BASE = ROOT / 'artifacts/droidspaces/kernel-ksunext'
SOURCE = Path('/var/tmp/rmx1931-ksunext-cd739c788023/src')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(stage, after_build=False):
    stages = json.loads(MANIFEST.read_text())['stages']
    index = next(i for i, item in enumerate(stages) if item['name'] == stage)
    selected = stages[:index + 1]
    source = SOURCE if index < 3 else SOURCE.with_name('src-ext-network')
    directory = ROOT / ('artifacts/droidspaces/kernel-ext-' + stage)
    old, new = config(BASE / 'resolved.config'), config(directory / 'resolved.config')
    changes = {k: {'before': old.get(k, 'n'), 'after': new.get(k, 'n')}
               for k in sorted(old.keys() | new.keys()) if old.get(k, 'n') != new.get(k, 'n')}
    allowed = {k for item in selected for k in item['allowed_keys']}
    prefixes = tuple(p for item in selected for p in item['allowed_prefixes'])
    unexpected = [k for k in changes if k not in allowed and not k.startswith(prefixes)]
    required = {}
    for item in selected:
        for name in item['fragments']:
            required.update(config(ROOT / 'configs' / name))
    unsatisfied = [k for k, v in required.items() if new.get(k, 'n') != v]
    protected = ['SCHED_WALT', 'DEBUG_LIST', 'MODVERSIONS', 'NET_L3_MASTER_DEV',
                 'VLAN_8021Q', 'IPVLAN', 'IPVTAP', 'CFS_BANDWIDTH', 'KSU',
                 'KSU_MANUAL_HOOK', 'DEFAULT_TCP_CONG', 'DEFAULT_NET_SCH',
                 'PSTORE', 'PSTORE_RAM', 'PSTORE_CONSOLE', 'PSTORE_PMSG']
    drift = [k for k in protected if new.get('CONFIG_' + k, 'n') != old.get('CONFIG_' + k, 'n')]
    lock = json.loads((ROOT / 'ksunext.sources.lock.json').read_text())
    hashes = {**lock['accepted_podman_source_sha256'], **lock['manual_hook_source_sha256']}
    for name, record in lock['upstream_kbuild_compatibility_backports'].items():
        hashes[name] = record['after_sha256']
    source_drift = [name for name, expected in hashes.items() if digest(source / name) != expected]
    extra_source = None
    if index >= 3:
        extra_source = json.loads((ROOT / 'artifacts/droidspaces/extensions-network-source.json').read_text())
        for name, pair in extra_source['modified_sources'].items():
            if digest(SOURCE / name) != pair['before_sha256'] or digest(source / name) != pair['after_sha256']:
                source_drift.append(name)
        if digest(ROOT / 'patches/nft-socket-4.14-compat.patch') != extra_source['patch_sha256']:
            source_drift.append('patches/nft-socket-4.14-compat.patch')
    report = {'stage': stage, 'cumulative_stages': [x['name'] for x in selected],
              'config_changes': changes, 'unexpected_config_changes': unexpected,
              'unsatisfied_requested_settings': unsatisfied, 'protected_config_drift': drift,
              'source_drift': source_drift, 'verified_source_files': len(hashes),
              'candidate_source': str(source), 'additional_source_patch': extra_source,
              'runtime_acceptance': 'pending', 'panic_retention_acceptance': 'pending'}
    if after_build:
        before, after = symbols(BASE / 'Module.symvers'), symbols(directory / 'Module.symvers')
        missing = sorted(before.keys() - after.keys())
        changed = sorted(k for k in before.keys() & after.keys() if before[k] != after[k])
        linked = {line.split()[-1] for line in (directory / 'System.map').read_text().splitlines() if line.split()}
        absent = [s for item in selected for s in item['linked_symbols'] if s not in linked]
        report.update({'kernel_sha256': digest(directory / 'Image.gz-dtb'),
                       'resolved_config_sha256': digest(directory / 'resolved.config'),
                       'module_symvers_sha256': digest(directory / 'Module.symvers'),
                       'system_map_sha256': digest(directory / 'System.map'),
                       'export_crc': {'baseline_symbols': len(before), 'candidate_symbols': len(after),
                                      'missing': missing, 'changed': changed,
                                      'added': sorted(after.keys() - before.keys())},
                       'missing_linked_symbols': absent,
                       'existing_export_crc_preserved': not (missing or changed),
                       'external_module_binary_compatibility': 'not established by CRC comparison',
                       'deployment_requires_runtime_validation': True})
    report['build_audit_passed'] = not (unexpected or unsatisfied or drift or source_drift or
                                      report.get('missing_linked_symbols') or
                                      report.get('export_crc', {}).get('missing'))
    (directory / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'stage': stage, 'passed': report['build_audit_passed'],
                      'changes': len(changes), 'unexpected': unexpected, 'unsatisfied': unsatisfied,
                      'protected_drift': drift, 'source_drift': source_drift,
                      'missing_linked': report.get('missing_linked_symbols'),
                      'crc_changed': len(report.get('export_crc', {}).get('changed', []))}))
    if not report['build_audit_passed']:
        raise RuntimeError('Candidate audit failed; see ' + str(directory / 'audit.json'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['utilities', 'bbr', 'checkpoint', 'network', 'io'])
    parser.add_argument('--after-build', action='store_true')
    args = parser.parse_args()
    audit(args.stage, args.after_build)
