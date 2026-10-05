#!/usr/bin/env python3
"""Seal lifecycle and inherited resource evidence for the current harden1 boot."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
from check_kernel_extension_runtime import current_probe
from deploy_kernel_extensions import candidate
from device_runtime import ROOT, device, guest_info, read_identity, read_root

ART = ROOT / 'artifacts/droidspaces'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def payload(text, key):
    decoder = json.JSONDecoder()
    objects = []
    for match in re.finditer(r'^\{', text, re.M):
        try:
            item, _ = decoder.raw_decode(text[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and key in item:
            objects.append(item)
    assert len(objects) == 1, 'Expected exactly one fixture summary: ' + key
    return objects[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-label', required=True)
    parser.add_argument('--lifecycle-label', required=True)
    parser.add_argument('--cpu-label', required=True)
    parser.add_argument('--io-label', required=True)
    parser.add_argument('--writeback-label', required=True)
    parser.add_argument('--cleanup-label', required=True)
    args = parser.parse_args()
    assert all(re.fullmatch(r'[a-zA-Z0-9_-]+', value) for value in vars(args).values())
    destination = ART / 'hardening1-acceptance.json'
    assert not destination.exists(), 'Do not overwrite sealed stage evidence'
    adb = device()
    identity = read_identity(adb)
    _, check, audit, release = candidate('harden1')
    assert identity['kernel'] == release
    cumulative_path = ART / ('extensions-harden1-' + args.run_label + '-acceptance.json')
    cumulative = read(cumulative_path)
    assert cumulative['runtime_passed'] and all(cumulative[key] == value for key, value in identity.items())
    assert cumulative['boot_sha256'] == check['candidate_sha256']
    assert len(cumulative['probe_evidence']) == 20 and cumulative['official_capabilities_passed'] == 27
    evidence = {'cumulative': {'path': cumulative_path.relative_to(ROOT).as_posix(), 'sha256': sha(cumulative_path)}}
    records = {}
    for key in ('lifecycle', 'cpu', 'io', 'writeback', 'cleanup'):
        path = ART / 'runtime' / (getattr(args, key + '_label') + '.json')
        record = read(path)
        if key == 'cpu':
            assert record['passed'] and record['end_identity'] == identity
            assert all(record[field] == value for field, value in identity.items())
        else:
            assert current_probe(record, identity), key
        assert record.get('cleanup_errors', []) == [], key
        evidence[key] = {'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(path)}
        records[key] = record
    lifecycle = payload(records['lifecycle']['stdout'], 'cases')
    assert lifecycle['passed'] and lifecycle['cleanup_errors'] == [] and not lifecycle['android_processes_moved']
    assert len(lifecycle['cases']) == 13 and all(item['passed'] for item in lifecycle['cases'])
    assert all(item.get('payload_seccomp') == 2 for item in lifecycle['cases'] if 'actual_container' in item['name'])
    expected = hashlib.sha256((ROOT / 'scripts/probe_container_lifecycle.sh').read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    assert records['lifecycle']['script_source_sha256'] == expected
    assert not records['lifecycle']['guest_filters_changed']
    assert {item['mode'] for item in records['cpu']['containers']} == {'rootful', 'rootless'}
    assert all(item['passed'] and not item.get('cleanup_error') and not item.get('release_error')
               for item in records['cpu']['containers'])
    io = payload(records['io']['stdout'], 'modes')
    assert io['passed'] and not io['cleanup_errors']
    assert {item['mode'] for item in io['modes']} == {'guest', 'rootful', 'rootless'}
    assert all(item['passed'] for item in io['modes'])
    writeback = payload(records['writeback']['stdout'], 'measurements')
    assert writeback['passed'] and not writeback['cleanup_errors']
    assert 'HARDEN1_FINAL_CLEANUP_PASS' in records['cleanup']['stdout']
    assert read_root(adb, 'sha256sum /dev/block/by-name/boot').decode().split()[0] == check['candidate_sha256']
    assert read_root(adb, 'getenforce').strip() == b'Enforcing'
    pid = guest_info(adb)['pid']
    seccomp = re.search(rb'^Seccomp:\s+(\d+)\s*$', read_root(adb, 'cat /proc/' + str(pid) + '/status'), re.M)
    assert seccomp and seccomp[1] == b'2'
    assert read_root(adb, 'if test ! -e /sys/fs/cgroup/cgroup.kill; then echo GLOBAL_ROOT_KILL_ABSENT; fi').strip() == b'GLOBAL_ROOT_KILL_ABSENT'
    dmesg = read_root(adb, 'dmesg')
    fatal = [line for line in dmesg.decode(errors='replace').splitlines() if any(word in line for word in
             ('BUG:', 'Oops:', 'Kernel panic -', 'Unknown symbol', 'disagrees about version'))]
    assert not fatal, fatal[:3]
    directory = ART / 'extension-phone/harden1-final'
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'dmesg.txt').write_bytes(dmesg)
    assert read_identity(adb) == identity
    report = {'accepted_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
              'passed': True, 'stage': 'harden1', 'boot_sha256': check['candidate_sha256'],
              'running_config_matches': True, 'selinux': 'Enforcing', 'ordinary_guest_seccomp': 2,
              'cumulative_probes_passed': 20, 'official_capabilities_passed': 27,
              'lifecycle_cases': lifecycle['cases'], 'bounded_fork_race_iterations': 12,
              'cpu_modes_passed': ['rootful', 'rootless'], 'native_io_modes_passed': ['guest', 'rootful', 'rootless'],
              'io_hierarchy_writeback_passed': True, 'global_root_cgroup_kill_absent': True,
              'kernel_fatal_errors_observed': [], 'final_dmesg_sha256': hashlib.sha256(dmesg).hexdigest(),
              'default_wifi_sensor_tests_requested': False, 'evidence': evidence,
              'changed_export_crcs_vs_dualio': len(audit['export_crc']['changed']),
              'scope': 'Stage 1 lifecycle backports and inherited CPU/IO/container regression',
              'remaining_goal_stages': [2, 3, 4, 5, 6],
              'virtualization': 'EL1 boot observed; KVM/AVF requires separate platform research',
              'android16_container_target': 'Complete desktop and actual application execution',
              'publication_performed': False}
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    # Preserve the full fresh report and give the deployment predecessor guard a canonical identity.
    canonical = ART / 'extensions-harden1-acceptance.json'
    assert not canonical.exists()
    canonical.write_text(json.dumps({**cumulative, 'extended_stage_acceptance': evidence,
        'hardening_stage_passed': True, 'hardening_summary_sha256': sha(destination)}, indent=2) + '\n')
    print(json.dumps({'passed': True, 'lifecycle_cases': 13, 'cumulative_probes': 20,
                      'official_capabilities': 27, 'remaining_goal_stages': [2, 3, 4, 5, 6]}))


if __name__ == '__main__':
    main()
