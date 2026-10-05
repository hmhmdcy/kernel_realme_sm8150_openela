#!/usr/bin/env python3
"""Read current-boot Binder cleanup, unprivileged feature access and host health."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
from device_runtime import ROOT, device, guest_info, read_identity, read_root

def main():
    art = ROOT / 'artifacts/droidspaces'
    path = art / 'runtime/binder-host-health-h5bf2-20261005.json'
    assert not path.exists(), 'Inspect prior health result'
    boot = json.loads((art / 'extensions-harden5-binder-freeze-fix-boot-result.json').read_text())
    adb = device(); identity = read_identity(adb)
    assert identity == {k: boot[k] for k in ('kernel', 'boot_id')}
    raw = json.loads((art / 'runtime/binder-freeze-callbacks-h5bf2-20261005.json').read_text())
    public = json.loads((art / 'runtime/binder-public-api-h5bf2-20261005.json').read_text())
    assert raw['returncode'] == public['returncode'] == 0
    pids = [int(re.search(r'pid=(\d+)', raw['entry_stdout'])[1]), int(re.search(r'OWNED_BINDER_SERVER_PID (\d+)', raw['stdout'])[1])]
    for operation in public['operations']:
        match = re.search(r'OWNED_APP_PROCESS_LAUNCHED (?:service|listener) (\d+)', operation['stdout'])
        if match: pids.append(int(match[1]))
    assert len(pids) == 4 and len(set(pids)) == 4
    gone = {str(pid): read_root(adb, 'if test ! -d /proc/' + str(pid) + '; then echo gone; fi').strip() == b'gone' for pid in pids}
    guest_pid = guest_info(adb)['pid']
    guest_root = '/proc/' + str(guest_pid) + '/root'
    results = {}
    queries = {
        'services': 'set -e; for n in system_server lmkd netd surfaceflinger; do p=$(pidof "$n"); test -n "$p"; printf "HOST_SERVICE|%s|%s\\n" "$n" "$p"; done',
        'root': 'id', 'ksu': '/data/adb/ksud debug info', 'selinux': 'getenforce',
        'boot_completed': 'getprop sys.boot_completed', 'boot_sha256': 'sha256sum /dev/block/by-name/boot',
        'dmesg': 'dmesg', 'binder_features_label': 'ls -Zd /dev/binderfs/features /dev/binderfs/features/freeze_notification',
        'owned_service_entries': 'service list | grep rmx1931.binder.test. || true',
        'guest_seccomp': 'sed -n "s/^Seccomp:[[:space:]]*//p" ' + guest_root + '/proc/1/status',
        'binfmt_helper': 'sha256sum ' + guest_root + '/usr/local/bin/rmx1931-binfmt',
        'seccomp_helper': 'sha256sum ' + guest_root + '/usr/local/bin/rmx1931-seccomp-notify',
        'loaded_modules': 'cat /proc/modules'}
    for name, command in queries.items(): results[name] = read_root(adb, command).decode(errors='replace').strip()
    shell = subprocess.run(adb + ['exec-out', 'cat', '/dev/binderfs/features/freeze_notification'], capture_output=True, timeout=15)
    fatal = [line for line in results['dmesg'].splitlines() if re.search(r'BUG:|Kernel panic|Oops:|KASAN:|Unable to handle kernel|WARNING:.*binder', line)]
    checks = {'same_boot': read_identity(adb) == identity, 'owned_pids_gone': all(gone.values()),
        'owned_services_removed': not results['owned_service_entries'], 'critical_host_services_alive': results['services'].count('HOST_SERVICE|') == 4,
        'selinux_enforcing': results['selinux'] == 'Enforcing', 'root_ok': 'uid=0(root)' in results['root'],
        'ksu_ok': 'version: 33304' in results['ksu'] and 'uapi_version: 4' in results['ksu'],
        'boot_completed': results['boot_completed'] == '1', 'actual_boot_matches': results['boot_sha256'].split()[0] == boot['boot_sha256'],
        'guest_filters_retained': results['guest_seccomp'] == '2', 'binder_feature_readable_without_su': shell.returncode == 0 and shell.stdout.strip() == b'1',
        'binfmt_helper_unchanged': results['binfmt_helper'].split()[0] == '7d8a99cbf4755bb9df9de60c581b908654785423278f50705d9d7dd2a6e83eb0',
        'seccomp_helper_unchanged': results['seccomp_helper'].split()[0] == '873edd945f700c3abb915547a8a5d974cdfbad39e257650f73a832b027410637',
        'no_fatal_kernel_diagnostics': not fatal, 'no_loaded_modules': not results['loaded_modules']}
    passed = all(checks.values())
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity, 'end_identity': read_identity(adb),
        'returncode': 0 if passed else 1, 'passed': passed, 'checks': checks, 'owned_fixture_pids_gone': gone,
        'results': results, 'fatal_diagnostics': fatal, 'shell_feature_read': {'returncode': shell.returncode,
            'stdout': shell.stdout.decode(errors='replace'), 'stderr': shell.stderr.decode(errors='replace')},
        'script_source_sha256': hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n', b'\n')).hexdigest(),
        'stdout': 'BINDER_HOST_HEALTH_PASS' if passed else 'BINDER_HOST_HEALTH_FAILED'}
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': passed, 'checks': checks}, indent=2), flush=True)
    raise SystemExit(report['returncode'])

if __name__ == '__main__': main()
