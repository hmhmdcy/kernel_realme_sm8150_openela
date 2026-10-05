#!/usr/bin/env python3
"""Require real per-kernel feature and Podman evidence; Wi-Fi regression is opt-in."""
import argparse
import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
from device_runtime import device, read_identity, read_root
from check_kernel_extension_runtime import current_probe
from deploy_kernel_extensions import STAGES, candidate

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wifi_evidence(path, identity, not_before, requested=False):
    if not requested:
        return {'requested': False, 'passed': None, 'evidence_sha256': None}
    wifi = read(path)
    if (not wifi.get('passed') or wifi['kernel'] != identity['kernel'] or
            wifi.get('boot_id') != identity['boot_id'] or wifi.get('packet_loss_percent') != 0 or
            dt.datetime.fromisoformat(wifi['observed_at']) < dt.datetime.fromisoformat(not_before)):
        raise RuntimeError('Current kernel Wi-Fi regression is incomplete')
    return {'requested': True, 'passed': True, 'evidence_sha256': sha(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=STAGES, required=True)
    parser.add_argument('--run-label', help='Accept a separate current-boot suite without replacing historical acceptance')
    parser.add_argument('--with-wifi', action='store_true', help='Require current-boot Wi-Fi regression evidence')
    args = parser.parse_args()
    if args.run_label and not re.fullmatch(r'[a-zA-Z0-9_-]+', args.run_label):
        raise RuntimeError('Invalid run label')
    prefix = 'extensions-' + args.stage + '-' + (args.run_label + '-' if args.run_label else '')
    _, check, audit, release = candidate(args.stage)
    boot = read(ART / f'extensions-{args.stage}-boot-result.json')
    deployed = read(ART / f'extensions-{args.stage}-deployment.json')
    suite = read(ART / (prefix + 'probes.json'))
    adb = device()
    identity = read_identity(adb)
    if identity['kernel'] != release or suite.get('boot_id') != identity['boot_id']:
        raise RuntimeError('Suite evidence belongs to another boot or lacks a boot identity')
    if read_root(adb, 'sha256sum /dev/block/by-name/boot').decode().split()[0] != check['candidate_sha256']:
        raise RuntimeError('Live boot partition differs from the verified candidate')
    if hashlib.sha256(gzip.decompress(read_root(adb, 'cat /proc/config.gz'))).hexdigest() != audit['resolved_config_sha256']:
        raise RuntimeError('Live kernel configuration differs from the verified build')
    if (boot['kernel'] != release or boot['boot_sha256'] != check['candidate_sha256'] or
            not boot.get('running_config_matches') or not deployed.get('flashed') or
            deployed['candidate_sha256'] != check['candidate_sha256'] or
            suite['kernel'] != release or not suite['passed']):
        raise RuntimeError('Boot/deployment/probe identity is incomplete')
    markers = {'identity': ['EXTENSION_GUEST_IDENTITY_PASS'],
               'erofs': ['EROFS_HASH_XATTR_LINKS_READONLY_PASS', 'EROFS_MOUNT_UNMOUNT_PASS'],
               'binfmt': ['"automatic_dispatch": true', '"registration_removed": true'],
               'wireguard': ['"peer_handshakes": [true, true]', '"packet_loss_percent": 0'],
               'lxc': ['LXC_NATIVE_PID1_HOSTNAME_PROC_WRITE_PASS', 'LXC_CONTAINER_START_EXIT_PASS'],
               'rootful-build': ['ROOTFUL_IMAGE_BUILD_PASS'],
               'rootless-build': ['ROOTLESS_COPY_RUN_BUILD_PASS'],
               'sockets': ['UNIX_NETLINK_PACKET_DIAG_AND_SS_PASS'],
               'squashfs': ['SQUASHFS_gzip_MOUNT_HASH_EXEC_READONLY_UNMOUNT_PASS',
                            'SQUASHFS_xz_MOUNT_HASH_EXEC_READONLY_UNMOUNT_PASS', 'SQUASHFS_ACCEPTANCE_PASS']}
    for mode, uid in [('rootful', 0), ('rootless', 1000)]:
        markers[mode + '-functional'] = ['OVERLAY_WRITE_UID_GID_PASS', 'CONTAINER_DNS_PASS',
            'NAMED_VOLUME_PERSISTENCE_UID_GID_PASS', 'PORT_MEMORY_PIDS_LIMIT_PASS',
            'STOP_START_EXEC_PASS', 'FUNCTIONAL_ACCEPTANCE_' + mode + '_PASS']
        if mode == 'rootless':
            markers[mode + '-functional'].append('ROOTLESS_FUSE_MOUNT_PASS')
        markers[mode + '-memory'] = ['MEMORY_CHILD_EXIT=137', 'oom_kill 1',
                                   'MEMORY_LIMIT_ENFORCEMENT_PASS_UID_' + str(uid)]
        markers[mode + '-pids'] = ['UNLIMITED_FORK_CONTROL_PASS', 'PIDS_ENFORCEMENT_PASS_UID_' + str(uid)]
    for probe, minimum in [('bbr', 1), ('checkpoint', 2), ('nft', 3)]:
        if STAGES.index(args.stage) >= minimum:
            markers[probe] = ['"probe": "' + probe + '"', '"status": "passed"']
    if STAGES.index(args.stage) >= STAGES.index('harden1'):
        markers['lifecycle'] = ['CONTAINER_LIFECYCLE_ACCEPTANCE_PASS'] + [
            'LIFECYCLE_CASE_PASS ' + name for name in (
                'default_and_invalid_values', 'oom_group_disabled_control',
                'oom_group_and_protected_exception', 'parent_oom_group_reaches_descendants_only',
                'leaf_oom_does_not_kill_ancestor_or_sibling', 'recursive_kill_and_sibling_isolation',
                'kill_frozen_group', 'threaded_kill_refused', 'bounded_fork_race',
                'rootful_actual_container_oom_group_0', 'rootful_actual_container_oom_group_1',
                'rootless_actual_container_oom_group_0', 'rootless_actual_container_oom_group_1')]
    evidence = {}
    for label, expected in markers.items():
        item = suite['probes'][label]
        path = ROOT / item['path']
        if not path.resolve().is_relative_to((ART / 'runtime').resolve()) or sha(path) != item['sha256']:
            raise RuntimeError('Probe evidence changed: ' + label)
        result = read(path)
        if label == 'lifecycle':
            digest = hashlib.sha256((ROOT / 'scripts/probe_container_lifecycle.sh').read_bytes().replace(b'\r\n', b'\n')).hexdigest()
            if (result.get('script_source_sha256') != digest or result.get('cleanup_errors') != [] or
                    result.get('guest_filters_changed') is not False):
                raise RuntimeError('Lifecycle fixture identity, cleanup or guest filtering is incomplete')
        if (not current_probe(result, identity) or
                dt.datetime.fromisoformat(result['observed_at']) < dt.datetime.fromisoformat(boot['observed_at']) or
                any(marker not in result['stdout'] for marker in expected)):
            raise RuntimeError('Probe is stale, incomplete or failed: ' + label)
        evidence[label] = item
    if STAGES.index(args.stage) >= STAGES.index('io'):
        item = suite['probes']['io']
        path = (ROOT / item['path']).resolve()
        if not path.is_relative_to((ART / 'runtime').resolve()) or sha(path) != item['sha256']:
            raise RuntimeError('I/O evidence changed')
        result = read(path)
        if (result.get('status') != 'passed' or result.get('kernel') != release or
                result.get('boot_id') != identity['boot_id'] or
                result.get('end_identity') != identity or
                result.get('cleanup_errors') != [] or result.get('android_processes_moved') is not False or
                result.get('limit_bps') != 2097152 or result.get('fixture_bytes') != 16777216 or
                result['limited']['device_read_bytes'] < 16777216 or result['limited']['seconds'] < 4 or
                result['limited']['seconds'] < 2 * result['baseline']['seconds'] or
                dt.datetime.fromisoformat(result['observed_at']) < dt.datetime.fromisoformat(boot['observed_at'])):
            raise RuntimeError('Actual loop I/O enforcement or cleanup is incomplete')
        evidence['io'] = item
    wifi_path = ART / (prefix + 'wifi.json')
    wifi = wifi_evidence(wifi_path, identity, boot['observed_at'], requested=args.with_wifi)
    def root(command):
        return read_root(adb, command)
    if root('uname -r').decode().strip() != release or root('getenforce').strip() != b'Enforcing':
        raise RuntimeError('Phone state changed after the tests')
    host_algorithm = root('cat /proc/sys/net/ipv4/tcp_congestion_control').decode().strip()
    if host_algorithm != 'cubic':
        raise RuntimeError('Android default congestion algorithm changed')
    dmesg = root('dmesg')
    directory = ART / 'extension-phone' / (args.stage + ('-' + args.run_label if args.run_label else ''))
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'dmesg.txt').write_bytes(dmesg)
    fatal = [line for line in dmesg.decode(errors='replace').splitlines() if any(word in line for word in
             ('BUG:', 'Oops:', 'Kernel panic -', 'Unknown symbol', 'disagrees about version'))]
    if fatal:
        raise RuntimeError('Kernel errors require review: ' + repr(fatal[:3]))
    modules = root('/data/adb/ksud module list').decode()
    (directory / 'ksu-modules.json').write_text(modules, encoding='utf-8')
    enabled = json.loads(modules)
    for name in ('droidspaces', 'rmx1931-crashlog'):
        if not any(m.get('id') == name and m.get('enabled') in (True, 'true') for m in enabled):
            raise RuntimeError('Required KSU module is not enabled: ' + name)
    requirements_text = root('/data/local/tmp/rmx1931-droidspaces-check check').decode()
    clean = re.sub(r'\x1b\[[0-9;]*m', '', requirements_text)
    checks = [{'name': name.strip(), 'passed': status == '✓'}
              for status, name in re.findall(r'^\s*\[([✓✗])\]\s*(.+)$', clean, re.M)
              if name.strip() != 'All required features found!']
    if len(checks) != 27 or not all(item['passed'] for item in checks):
        raise RuntimeError('Official DroidSpaces capability regression failed: ' + repr(checks))
    requirements_path = ART / (prefix + 'requirements.json')
    requirements_path.write_text(json.dumps({'kernel': release, 'checks': checks,
        'source': 'pinned DroidSpaces v6.6.0 native check command'}, indent=2) + '\n')
    if read_identity(adb) != identity:
        raise RuntimeError('Phone rebooted while collecting acceptance evidence')
    report = {'accepted_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
              'run_label': args.run_label,
              'stage': args.stage, 'boot_sha256': check['candidate_sha256'], 'runtime_passed': True,
              'running_config_matches': True, 'selinux': 'Enforcing', 'probe_evidence': evidence,
              'android_default_tcp_congestion_control': host_algorithm,
              'wifi_regression': wifi, 'wifi_evidence_sha256': wifi['evidence_sha256'],
              'kernel_fatal_errors_observed': [],
              'dmesg_sha256': hashlib.sha256(dmesg).hexdigest(),
              'official_capabilities_passed': len(checks), 'requirements_sha256': sha(requirements_path),
              'existing_export_crc_preserved': audit['existing_export_crc_preserved'],
              'scope': 'Cumulative kernel, ordinary guest and Podman regression; Wi-Fi is opt-in and extended functional evidence is recorded separately',
              'limitations': [
                              'This regression report alone does not assess extended CPU/IO, device policy, whole-container recovery, external network or panic tests']}
    (ART / (prefix + 'acceptance.json')).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'stage': args.stage, 'runtime_passed': True, 'probes_passed': len(evidence),
                      'wifi_requested': wifi['requested'], 'wifi_passed': wifi['passed'],
                      'kernel_fatal_errors_observed': []}))


if __name__ == '__main__':
    main()
