#!/usr/bin/env python3
"""Run two bounded Android 16 app_process fixtures; control only their owned PID.

No installed application, global hidden API setting or system-service freeze.
Native launch and each control mutation are issued once with durable evidence.
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
    parser.add_argument('--stage', choices=['harden5-binder-freeze', 'harden5-binder-freeze-fix', 'android16-group-psi', 'android16-group-psi-reclaim-fix'], default='harden5-binder-freeze')
    args = parser.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]{1,90}', args.label)
    art = ROOT / 'artifacts/droidspaces'
    report_path = art / 'runtime' / (args.label + '.json')
    assert not report_path.exists(), 'Inspect original owned processes; never replay'
    source = ROOT / 'references/runtime-probes/binder-freeze/binder_api_control.c'
    java = source.with_name('RmxBinderFreezeApi.java')
    fixture = art / 'binder-public-api-fixture'
    build = json.loads((fixture / 'build-result.json').read_text(encoding='utf-8'))
    dex = fixture / 'classes.dex'
    # The builder records exact source/tool/dex digests.
    assert build['returncode'] == 0 and sha(java) == build['source_sha256']
    assert sha(dex) == build['classes_dex_sha256']
    ref = ROOT / 'references/android16-binder-upstream'
    lock = json.loads((ref / 'android16-fixed-source-lock.json').read_text(encoding='utf-8'))
    header = ref / 'android16-6.12-include-uapi-linux-android-binder.h'
    assert sha(header) == lock['files'][header.name]
    adb = device()
    identity = read_identity(adb)
    boot = json.loads((art / ('extensions-' + args.stage + '-boot-result.json')).read_text(encoding='utf-8'))
    assert boot.get('running_config_matches') is True
    assert identity == {k: boot[k] for k in ('kernel', 'boot_id')}
    assert read_root(adb, 'sha256sum /dev/block/by-name/boot').decode().split()[0] == boot['boot_sha256']
    assert read_root(adb, 'getenforce').strip() == b'Enforcing'
    pid = guest_info(adb)['pid']
    guest_root = '/proc/' + str(pid) + '/root'
    guest_work = '/tmp/rmx1931-tests/binder-api-' + args.label
    work = '/data/local/tmp/rmx1931-binder-api-' + args.label
    service = 'rmx1931.binder.test.' + args.label.replace('-', '_')
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
              'work': work, 'guest_work': guest_work, 'service': service, 'guest_pid': pid,
              'java_source_sha256': sha(java), 'dex_sha256': sha(dex),
              'native_control_source_sha256': sha(source), 'runner_source_sha256': sha(Path(__file__)),
              'build_result_sha256': sha(fixture / 'build-result.json'),
              'operations': [], 'returncode': 1, 'phase': 'owned setup pending'}

    def save():
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    def mutate(command, timeout=20):
        report['phase'] = 'issuing once: ' + command
        save()
        try:
            result = subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            report['operations'].append({'command': command, 'returncode': 124,
                'stdout': (error.stdout or b'').decode(errors='replace'), 'stderr': (error.stderr or b'').decode(errors='replace')})
            save()
            raise RuntimeError('Native mutation timed out; collect its original state') from error
        output = result.stdout.decode(errors='replace')
        report['operations'].append({'command': command, 'returncode': result.returncode,
                                     'stdout': output, 'stderr': result.stderr.decode(errors='replace')})
        save()
        if result.returncode:
            raise RuntimeError('Owned operation failed: ' + result.stderr.decode(errors='replace'))
        return output

    def read(name):
        assert re.fullmatch(r'[a-zA-Z0-9.-]+', name)
        return read_root(adb, 'if test -f ' + work + '/' + name + '; then cat ' + work + '/' + name + '; fi').decode(errors='replace').strip()

    def wait_file(name, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = read(name)
            if value:
                return value
            status = read('listener.status' if name.startswith('listener.') else 'service.status')
            if status:
                raise RuntimeError('Fixture terminated before ' + name + ' (status ' + status + ')')
            time.sleep(.2)
        raise RuntimeError('Owned fixture marker timeout: ' + name)

    def control(action, role='service'):
        return mutate(shlex.join([work + '/control', action, work, role]))

    def live(role):
        value = read(role + '.launcher.pid')
        if not value.isdigit():
            return False
        command = 'if test -d /proc/' + value + '; then cat /proc/' + value + '/cmdline; fi'
        command_line = read_root(adb, command).decode(errors='replace').split('\0')[0]
        return command_line == read(role + '.nice-name')

    save()
    try:
        mutate('set -e; test ! -e ' + work + '; mkdir -m 700 ' + work +
               '; test -f ' + guest_root + '/etc/droidspaces; test ! -L ' + guest_root + '/tmp/rmx1931-tests; '
               'mkdir -p ' + guest_root + '/tmp/rmx1931-tests; test ! -e ' + guest_root + guest_work +
               '; mkdir -m 700 ' + guest_root + guest_work + '; mkdir -p ' + guest_root + guest_work + '/uapi/linux/android')
        for local, destination in [(source, guest_root + guest_work + '/control.c'),
                                   (header, guest_root + guest_work + '/uapi/linux/android/binder.h'),
                                   (dex, work + '/classes.dex')]:
            staging = '/data/local/tmp/rmx1931-' + args.label + '-' + local.name
            transfer = subprocess.run(adb + ['push', str(local), staging], capture_output=True, timeout=30)
            report['operations'].append({'command': 'adb push ' + local.name, 'returncode': transfer.returncode,
                'stdout': transfer.stdout.decode(errors='replace'), 'stderr': transfer.stderr.decode(errors='replace')})
            save()
            transfer.check_returncode()
            mutate('cp ' + staging + ' ' + destination)
            assert read_root(adb, 'sha256sum ' + destination).decode().split()[0] == sha(local)
        mutate('chmod 400 ' + work + '/classes.dex')
        compile_command = ('set -eu; test "$(sed -n "s/^Seccomp:[[:space:]]*//p" /proc/self/status)" = 2; '
            'cd ' + guest_work + '; gcc -static -O2 -Wall -Wextra -Werror -Iuapi control.c -o control; sha256sum control; '
            'echo BINDER_API_CONTROL_COMPILE_PASS')
        compiled = mutate(shlex.join([DS, '--name=' + NAME, 'run', '/bin/sh', '-c', compile_command]), timeout=45)
        assert 'BINDER_API_CONTROL_COMPILE_PASS' in compiled
        binary_sha = compiled.splitlines()[0].split()[0]
        assert re.fullmatch(r'[a-f0-9]{64}', binary_sha)
        mutate('cp ' + guest_root + guest_work + '/control ' + work + '/control; chmod 700 ' + work + '/control')
        assert read_root(adb, 'sha256sum ' + work + '/control').decode().split()[0] == binary_sha
        report['native_control_binary_sha256'] = binary_sha
        output = mutate(shlex.join([work + '/control', 'launch', work, 'service', service, 'service']))
        assert 'OWNED_APP_PROCESS_LAUNCHED service' in output
        server_pid = wait_file('service.pid')
        assert server_pid == read('service.launcher.pid')
        control('check')
        output = mutate(shlex.join([work + '/control', 'launch', work, 'listener', service, 'callbacks']))
        assert 'OWNED_APP_PROCESS_LAUNCHED listener' in output
        wait_file('listener.ready')
        control('check', 'listener')
        control('freeze')
        wait_file('listener.frozen')
        control('unfreeze')
        wait_file('listener.removed')
        control('freeze')
        control('unfreeze')
        mutate('test ! -e ' + work + '/controller.post-remove-done; printf "1\\n" > ' + work + '/controller.post-remove-done')
        wait_file('listener.death-ready')
        control('terminate')
        status = wait_file('listener.status')
        assert status == '0', 'Android public API fixture failed'
        assert 'ANDROID16_BINDER_PUBLIC_CALLBACKS_PASS' in read('listener.stdout')
        report['returncode'] = 0
    except Exception as error:
        report['error'] = repr(error)
    finally:
        cleanup_errors = []
        for role in ('service', 'listener'):
            try:
                if live(role):
                    if role == 'service':
                        control('unfreeze')
                    control('terminate', role)
                deadline = time.monotonic() + 5
                while live(role) and time.monotonic() < deadline:
                    time.sleep(.2)
                if live(role):
                    cleanup_errors.append('owned ' + role + ' still live; inspect original PID')
            except Exception as error:
                cleanup_errors.append(str(error))
        report.update(cleanup_errors=cleanup_errors, service_stdout=read('service.stdout'), service_stderr=read('service.stderr'),
                      listener_stdout=read('listener.stdout'), listener_stderr=read('listener.stderr'),
                      listener_status=read('listener.status'), end_identity=read_identity(adb),
                      ordinary_guest_seccomp=read_root(adb, 'sed -n "s/^Seccomp:[[:space:]]*//p" ' + guest_root + '/proc/1/status').decode().strip(),
                      selinux=read_root(adb, 'getenforce').decode().strip(), phase='terminal')
        report['owned_pids_removed'] = {}
        for role in ('service', 'listener'):
            value = read(role + '.launcher.pid')
            gone = not value.isdigit() or read_root(adb, 'if test ! -d /proc/' + value + '; then echo gone; fi').strip() == b'gone'
            report['owned_pids_removed'][role] = gone
            if not gone:
                report['cleanup_errors'].append(role + ' original PID still present; inspect recorded starttime')
        if cleanup_errors or report['end_identity'] != identity or report['ordinary_guest_seccomp'] != '2' or report['selinux'] != 'Enforcing':
            report['returncode'] = 125
        save()
    print(json.dumps(report, indent=2), flush=True)
    raise SystemExit(report['returncode'])


if __name__ == '__main__':
    main()
