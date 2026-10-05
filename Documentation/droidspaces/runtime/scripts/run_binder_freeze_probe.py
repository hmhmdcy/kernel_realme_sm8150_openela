#!/usr/bin/env python3
"""Compile an owned static ARM64 fixture and run it once in private Binderfs.

The host PID view matches the existing Binder freeze ioctl ABI. Host Android
Binder devices are never opened. Ordinary guest filters are left installed.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--mode', choices=['baseline', 'callbacks', 'callbacks-features'], required=True)
    parser.add_argument('--stage', choices=['harden5-binder-freeze', 'harden5-binder-freeze-fix', 'android16-group-psi', 'android16-group-psi-reclaim-fix'], default='harden5-binder-freeze')
    args = parser.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.label)
    report_path = ROOT / 'artifacts/droidspaces/runtime' / (args.label + '.json')
    pending = report_path.with_name(args.label + '-launch.json')
    assert not report_path.exists() and not pending.exists(), 'Collect the original owned launch; never replay'
    ref = ROOT / 'references/android16-binder-upstream'
    lock = json.loads((ref / 'android16-fixed-source-lock.json').read_text(encoding='utf-8'))
    header = ref / 'android16-6.12-include-uapi-linux-android-binder.h'
    assert sha(header) == lock['files'][header.name]
    source = ROOT / 'references/runtime-probes/binder-freeze/binder_freeze_test.c'
    adb = device()
    identity = read_identity(adb)
    accepted = json.loads((ROOT / 'artifacts/droidspaces/seccomp-notify-stage5-acceptance.json').read_text(encoding='utf-8'))
    if args.mode == 'baseline':
        assert identity == {k: accepted[k] for k in ('kernel', 'boot_id')}
    else:
        boot = json.loads((ROOT / ('artifacts/droidspaces/extensions-' + args.stage + '-boot-result.json')).read_text(encoding='utf-8'))
        assert boot.get('running_config_matches') is True
        assert identity == {k: boot[k] for k in ('kernel', 'boot_id')}
        assert read_root(adb, 'sha256sum /dev/block/by-name/boot').decode().split()[0] == boot['boot_sha256']
    assert read_root(adb, 'getenforce').strip() == b'Enforcing'
    pid = guest_info(adb)['pid']
    guest_root = '/proc/' + str(pid) + '/root'
    guest_work = '/tmp/rmx1931-tests/binder-freeze-' + args.label
    host_work = '/data/local/tmp/rmx1931-binder-' + args.label

    def prelaunch_failure(command, result):
        report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
                  'returncode': result.returncode, 'phase': 'setup/compile failure before native launch',
                  'command': command, 'stdout': result.stdout.decode(errors='replace'),
                  'stderr': result.stderr.decode(errors='replace'), 'fixture_launched': False,
                  'work': host_work, 'guest_work': guest_work,
                  'fixture_source_sha256': sha(source), 'runner_source_sha256': sha(Path(__file__))}
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2), flush=True)

    def mutate(command, timeout=30):
        result = subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=timeout)
        if result.returncode:
            prelaunch_failure(command, result)
            raise RuntimeError('Inspect owned partial setup; never replay: ' + result.stderr.decode(errors='replace'))
        return result.stdout.decode(errors='replace')

    mutate('set -e; test ! -e ' + host_work + '; mkdir -m 700 ' + host_work +
           '; test -f ' + guest_root + '/etc/droidspaces; test ! -L ' + guest_root + '/tmp/rmx1931-tests; '
           'mkdir -p ' + guest_root + '/tmp/rmx1931-tests; test ! -e ' + guest_root + guest_work +
           '; mkdir -m 700 ' + guest_root + guest_work + '; mkdir -p ' + guest_root + guest_work + '/uapi/linux/android')
    transfers = [(source, 'fixture.c'), (header, 'uapi/linux/android/binder.h')]
    for local, relative in transfers:
        # adbd runs as shell and cannot write into our root-owned 0700 folder.
        staging = '/data/local/tmp/rmx1931-' + args.label + '-' + local.name
        transfer = subprocess.run(adb + ['push', str(local), staging], capture_output=True, timeout=30)
        if transfer.returncode:
            prelaunch_failure('adb push ' + local.name + ' to owned staging', transfer)
            raise RuntimeError('Transfer failed before native launch')
        mutate('cp ' + staging + ' ' + host_work + '/' + local.name)
        destination = guest_root + guest_work + '/' + relative
        mutate('cp ' + staging + ' ' + destination)
        assert read_root(adb, 'sha256sum ' + destination).decode().split()[0] == sha(local)
    compile_command = ('set -eu; test "$(sed -n "s/^Seccomp:[[:space:]]*//p" /proc/self/status)" = 2; '
                       'cd ' + guest_work + '; gcc -static -O2 -Wall -Wextra -Werror -Iuapi fixture.c -o fixture; '
                       'sha256sum fixture; printf "BINDER_FIXTURE_COMPILE_PASS\\n"')
    compiled = mutate(shlex.join([DS, '--name=' + NAME, 'run', '/bin/sh', '-c', compile_command]), timeout=60)
    assert 'BINDER_FIXTURE_COMPILE_PASS' in compiled, compiled
    binary_sha = compiled.splitlines()[0].split()[0]
    assert re.fullmatch('[a-f0-9]{64}', binary_sha)
    mutate('cp ' + guest_root + guest_work + '/fixture ' + host_work + '/fixture; chmod 700 ' + host_work + '/fixture')
    assert read_root(adb, 'sha256sum ' + host_work + '/fixture').decode().split()[0] == binary_sha
    record = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
              'mode': args.mode, 'guest_pid': pid, 'work': host_work, 'guest_work': guest_work,
              'fixture_source_sha256': sha(source), 'binder_uapi_sha256': sha(header),
              'fixture_binary_sha256': binary_sha, 'runner_source_sha256': sha(Path(__file__)),
              'compile_stdout': compiled, 'phase': 'prepared; next operation launches once'}
    pending.parent.mkdir(parents=True, exist_ok=True)
    pending.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    launched = subprocess.run(adb + ['exec-out', 'su', '-c', shlex.join([host_work + '/fixture', host_work, args.mode])],
                              capture_output=True, timeout=20)
    record['entry_returncode'] = launched.returncode
    record['entry_stdout'] = launched.stdout.decode(errors='replace')
    record['entry_stderr'] = launched.stderr.decode(errors='replace')
    pending.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    # A stream failure is never permission to relaunch: collect the durable status.
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        status = read_root(adb, 'if test -f ' + host_work + '/status; then cat ' + host_work + '/status; fi').strip()
        if status.isdigit():
            break
        time.sleep(.5)
    record.update(returncode=int(status) if status.isdigit() else 124,
                  stdout=read_root(adb, 'if test -f ' + host_work + '/stdout; then cat ' + host_work + '/stdout; fi').decode(errors='replace'),
                  stderr=read_root(adb, 'if test -f ' + host_work + '/stderr; then cat ' + host_work + '/stderr; fi').decode(errors='replace'),
                  end_identity=read_identity(adb), ordinary_guest_seccomp=read_root(adb, 'sed -n "s/^Seccomp:[[:space:]]*//p" ' + guest_root + '/proc/1/status').decode().strip(),
                  execution='durable native static fixture; private mount/IPC namespace and owned Binderfs only',
                  phase='terminal' if status.isdigit() else 'pending; inspect original launcher')
    if record['end_identity'] != identity or record['ordinary_guest_seccomp'] != '2':
        record['returncode'] = 125
    record['fixture_mount_directory_removed'] = read_root(adb, 'if test ! -e ' + host_work + '/binderfs; then echo yes; fi').strip() == b'yes'
    marker = 'BINDER_FREEZE_BASELINE_MISSING' if args.mode == 'baseline' else 'BINDER_FREEZE_CALLBACKS_PASS'
    if record['returncode'] == 0 and (marker not in record['stdout'] or not record['fixture_mount_directory_removed']):
        record['returncode'] = 125
    report_path.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(record, indent=2), flush=True)
    raise SystemExit(record['returncode'])


if __name__ == '__main__':
    main()
