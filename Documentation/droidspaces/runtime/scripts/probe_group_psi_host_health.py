#!/usr/bin/env python3
"""Bind PSI workload regression to current-boot host service and LMKD health."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
from device_runtime import ROOT, device, guest_info, read_identity, read_root


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', required=True)
    p.add_argument('--stage', choices=('android16-group-psi', 'android16-group-psi-reclaim-fix'), default='android16-group-psi')
    p.add_argument('--baseline', type=Path)
    args = p.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
    art = ROOT / 'artifacts/droidspaces'
    path = art / 'runtime' / (args.label + '.json')
    assert not path.exists()
    boot = json.loads((art / ('extensions-' + args.stage + '-boot-result.json')).read_text())
    adb = device()
    identity = read_identity(adb)
    assert identity == {k: boot[k] for k in ('kernel', 'boot_id')}
    guest = guest_info(adb)
    root = '/proc/' + str(guest['pid']) + '/root'
    def read(command):
        return read_root(adb, command).decode(errors='replace').strip()
    services = {}
    for name in ('system_server', 'lmkd', 'netd', 'surfaceflinger'):
        pids = read('pidof ' + name).split()
        assert len(pids) == 1, (name, pids)
        stat = read('cat /proc/' + pids[0] + '/stat')
        services[name] = {'pid': int(pids[0]), 'starttime': stat[stat.rindex(')') + 2:].split()[19]}
    lmkd = str(services['lmkd']['pid'])
    fd_lines = read('set -e; for f in /proc/' + lmkd + '/fd/*; do readlink "$f" || true; done').splitlines()
    results = {'cmdline': read('cat /proc/cmdline'), 'selinux': read('getenforce'),
        'boot_completed': read('getprop sys.boot_completed'),
        'boot_sha256': read('sha256sum /dev/block/by-name/boot').split()[0],
        'guest_seccomp': read('sed -n "s/^Seccomp:[[:space:]]*//p" ' + root + '/proc/1/status'),
        'binder_feature': read('cat /dev/binderfs/features/freeze_notification'),
        'global_memory_pressure': read('cat /proc/pressure/memory'),
        'guest_memory_pressure': read('cat /sys/fs/cgroup/droidspaces/rmx1931-podman/memory.pressure'),
        'guest_cpu_pressure': read('cat /sys/fs/cgroup/droidspaces/rmx1931-podman/cpu.pressure'),
        'guest_io_pressure': read('cat /sys/fs/cgroup/droidspaces/rmx1931-podman/io.pressure'),
        'meminfo': read('cat /proc/meminfo'), 'loaded_modules': read('cat /proc/modules'),
        'dmesg': read('dmesg'), 'root': read('id'), 'ksu': read('/data/adb/ksud debug info')}
    fatal = [line for line in results['dmesg'].splitlines() if re.search(
        r'BUG:|Kernel panic|Oops:|KASAN:|Unable to handle kernel|WARNING:.*(?:psi|cgroup)|psi:.*(?:underflow|leak|inconsistent)', line)]
    checks = {'same_boot': read_identity(adb) == identity,
        'actual_boot_matches': results['boot_sha256'] == boot['boot_sha256'],
        'no_pressure_disable_argument': 'cgroup_disable=pressure' not in results['cmdline'].split(),
        'standard_psi_enable_argument': 'psi=1' in results['cmdline'].split(),
        'selinux_enforcing': results['selinux'] == 'Enforcing', 'boot_completed': results['boot_completed'] == '1',
        'critical_services_alive': len(services) == 4,
        'lmkd_retains_global_psi_monitors': fd_lines.count('/proc/pressure/memory') >= 2,
        'guest_filters_retained': results['guest_seccomp'] == '2',
        'binder_feature_retained': results['binder_feature'] == '1',
        'root_ksu_retained': 'uid=0(root)' in results['root'] and 'version: 33304' in results['ksu'] and 'uapi_version: 4' in results['ksu'],
        'all_group_pressure_files': all('some avg10=' in results['guest_' + resource + '_pressure'] for resource in ('cpu', 'memory', 'io')),
        'no_loaded_modules': not results['loaded_modules'], 'no_fatal_diagnostics': not fatal}
    baseline_sha = None
    if args.baseline:
        before = json.loads(args.baseline.read_text())
        assert before['passed'] and all(before[k] == identity[k] for k in identity)
        checks['critical_services_not_restarted_during_load'] = services == before['services']
        baseline_sha = hashlib.sha256(args.baseline.read_bytes()).hexdigest()
    passed = all(checks.values())
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
        'end_identity': read_identity(adb), 'passed': passed, 'returncode': 0 if passed else 1,
        'checks': checks, 'services': services, 'lmkd_fds': fd_lines, 'results': results,
        'baseline_sha256': baseline_sha, 'fatal_diagnostics': fatal,
        'script_source_sha256': hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n', b'\n')).hexdigest(),
        'stdout': 'GROUP_PSI_HOST_HEALTH_PASS' if passed else 'GROUP_PSI_HOST_HEALTH_FAILED'}
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': passed, 'checks': checks}, indent=2))
    raise SystemExit(report['returncode'])


if __name__ == '__main__':
    main()
