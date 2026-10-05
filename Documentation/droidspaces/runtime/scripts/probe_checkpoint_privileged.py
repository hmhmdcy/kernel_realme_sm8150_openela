#!/usr/bin/env python3
"""Run the single-process CRIU fixture through explicit root entry to an isolated guest."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
from device_runtime import device, guest_info, read_identity, read_root

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[a-zA-Z0-9_-]+', args.label):
        raise RuntimeError('Invalid evidence label')
    path = ROOT / 'artifacts/droidspaces/runtime' / (args.label + '.json')
    if path.exists():
        raise RuntimeError('Do not overwrite previous probe evidence')
    adb = device()
    pid = guest_info(adb)['pid']
    guest_root = '/proc/' + str(pid) + '/root'
    namespaces = {}
    for name in ('pid', 'ipc', 'mnt', 'net', 'uts'):
        host = read_root(adb, 'readlink /proc/1/ns/' + name).decode().strip()
        guest = read_root(adb, 'readlink /proc/' + str(pid) + '/ns/' + name).decode().strip()
        if host == guest:
            raise RuntimeError('Distinct guest namespace required: ' + name)
        namespaces[name] = {'host': host, 'guest': guest}
    kernel = read_root(adb, 'uname -r').decode().strip()
    boot_id = read_root(adb, 'cat /proc/sys/kernel/random/boot_id').decode().strip()
    if read_root(adb, 'getenforce').strip() != b'Enforcing':
        raise RuntimeError('SELinux must remain Enforcing')
    source = (ROOT / 'scripts/probe_kernel_extensions.sh').read_bytes().replace(b'\r\n', b'\n')
    local = ROOT / 'tools/droidspaces' / (args.label + '.sh')
    local.write_bytes(source)
    staging = '/data/local/tmp/rmx1931-' + args.label + '.sh'
    subprocess.run(adb + ['push', str(local), staging], capture_output=True, check=True)
    directory = '/tmp/rmx1931-tests/privileged-' + args.label
    host_directory = guest_root + directory
    def mutate(command):
        result = subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('Inspect partial privileged launch before retry: ' + result.stderr.decode(errors='replace'))
        return result.stdout
    mutate('set -e; test -f ' + guest_root + '/etc/droidspaces; test ! -e ' + host_directory +
           '; test ! -L ' + guest_root + '/tmp/rmx1931-tests; mkdir -m 700 ' + host_directory +
           '; cp ' + staging + ' ' + host_directory + '/probe.sh')
    digest = hashlib.sha256(source).hexdigest()
    if read_root(adb, 'sha256sum ' + host_directory + '/probe.sh').decode().split()[0] != digest:
        raise RuntimeError('Probe transfer changed')
    inner = ('set -e; exec 3<&-; test -f /etc/droidspaces; '
             'test "$(sed -n "s/^Seccomp:[[:space:]]*//p" /proc/self/status)" = 0; '
             'printf "0\\n" > /proc/self/oom_score_adj; '
             'exec /bin/sh ' + directory + '/probe.sh checkpoint')
    command = shlex.join([guest_root + '/usr/bin/busybox', 'nsenter', '-t', str(pid),
                         '-m', '-p', '-n', '-i', '-u', '-r' + guest_root, '--',
                         '/usr/bin/env', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                         'HOME=/root', '/bin/sh', '-c', inner])
    wrapper = command + '; code=$?; printf "%s\\n" "$code" > ' + host_directory + '/status'
    # Keep the root entry foreground: Android may reap detached adb children.
    # Logs/status survive a client stream closure; never replay the command.
    subprocess.run(adb + ['exec-out', 'su', '-c', '(' + wrapper + ') > ' + host_directory +
                   '/stdout 2> ' + host_directory + '/stderr < /dev/null'], capture_output=True, timeout=70)
    for _ in range(60):
        status = read_root(adb, 'if test -f ' + host_directory + '/status; then cat ' + host_directory + '/status; fi').strip()
        if status:
            break
        time.sleep(1)
    if not status:
        raise RuntimeError('Privileged checkpoint task still pending; inspect before retry')
    result = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'action': 'privileged-checkpoint', 'command': command, 'kernel': kernel, 'boot_id': boot_id,
              'returncode': int(status), 'stdout': read_root(adb, 'cat ' + host_directory + '/stdout').decode(errors='replace'),
              'stderr': read_root(adb, 'cat ' + host_directory + '/stderr').decode(errors='replace'),
              'script_source_sha256': digest, 'namespaces': namespaces,
              'execution': 'explicit root entry; isolated guest namespaces; durable log and exit status',
              'guest_seccomp_disabled': False, 'scope': 'unfiltered single-process fixture only; privileged runner required'}
    result['end_identity'] = read_identity(adb)
    if result['end_identity'] != {'kernel': kernel, 'boot_id': boot_id}:
        result['returncode'] = 125
        result['stderr'] += '\nPhone rebooted during the checkpoint probe.\n'
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(result['returncode'])


if __name__ == '__main__':
    main()
