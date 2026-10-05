#!/usr/bin/env python3
"""Guarded ADB entry point for the authorized RMX1931 Podman tests.

Does not flash partitions or change Android SELinux/time settings.
Commands and bounded output are saved as evidence; do not use for secrets.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
# Platform-tools 37.0.1 introduced libadbusb on Windows. This workspace's
# authorized phone intermittently disappeared with that backend. Use the
# documented legacy option for child tools without changing global settings.
if sys.platform == 'win32':
    os.environ.setdefault('ADB_USB_LEGACY', '1')

ROOT = Path(__file__).resolve().parents[1]
NAME = 'rmx1931-podman'
BASE = '/data/local/Droidspaces/Containers/' + NAME
DS = '/data/local/tmp/rmx1931-droidspaces-check'


def device():
    adb = [str(ROOT / 'tools/platform-tools/adb.exe')]
    pinned = os.environ.get('RMX1931_ADB_SERIAL')
    if pinned:
        if not re.fullmatch(r'[A-Za-z0-9._-]+', pinned):
            raise RuntimeError('Invalid pinned ADB target')
        digest = hashlib.sha256(pinned.encode()).hexdigest()
        verified = False
        for path in (ROOT / 'artifacts/droidspaces').glob('extensions-*-preflight.json'):
            record = json.loads(path.read_text(encoding='utf-8'))
            if record.get('preflight_passed') and record.get('transport_id_sha256') == digest:
                verified = True
                break
        if not verified:
            raise RuntimeError('Pinned ADB target has no verified preflight identity')
        # Reuse the already verified identity. Each action still checks the
        # required kernel/boot/guest state; avoid extra USB detection traffic.
        return adb + ['-s', pinned]
    for attempt in range(20):
        rows = [r.split() for r in subprocess.check_output(adb + ['devices'], text=True, timeout=15).splitlines()[1:] if r.strip()]
        if len(rows) > 1 or any(len(r) != 2 or r[1] not in {'device', 'offline'} for r in rows):
            raise RuntimeError('Unexpected or unauthorized ADB device state')
        ids = [r[0] for r in rows if r[1] == 'device']
        if len(ids) == 1:
            break
        if attempt < 19:
            time.sleep(1)
    if len(ids) != 1:
        raise RuntimeError('Exactly one authorized device is required')
    adb += ['-s', ids[0]]
    # Model reads are safe to retry across a short USB/ADB transport closure.
    # Mutating commands below retain their stricter no-replay policy.
    for attempt in range(4):
        model_read = subprocess.run(adb + ['shell', 'getprop ro.product.device'],
                                    capture_output=True, text=True, timeout=15)
        if model_read.returncode == 0:
            break
        if attempt < 3:
            time.sleep(1)
    if model_read.returncode:
        raise RuntimeError('ADB model read failed: ' + model_read.stderr.strip())
    model = model_read.stdout.strip()
    if model not in {'RMX1931', 'RMX1931CN'}:
        raise RuntimeError('Unexpected device model')
    return adb


def guest_info(adb):
    command = shlex.join([DS, '--name=' + NAME, '--format', 'info'])
    for attempt in range(3):
        result = subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=15)
        try:
            info = json.loads(result.stdout) if result.returncode == 0 else None
        except json.JSONDecodeError:
            info = None
        if info is not None:
            if info['name'] != NAME or not isinstance(info['pid'], int) or info['pid'] <= 1:
                raise RuntimeError('Unexpected guest identity')
            return info
        if attempt < 2:
            if attempt == 0 and any(word in result.stderr for word in (b'not found', b'closed', b'offline')):
                # A single server-side wait for the pinned transport avoids
                # enumerating the USB device or repeatedly probing its model.
                subprocess.run(adb + ['wait-for-device'], capture_output=True, timeout=20, check=True)
            else:
                time.sleep(1)
    raise RuntimeError('Guest info is unavailable or malformed: ' + result.stderr.decode(errors='replace'))


def read_root(adb, command, timeout=30):
    """Read-only root queries can retry a short USB closure; never use for mutations."""
    for attempt in range(4):
        result = subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=timeout)
        if result.returncode == 0:
            return result.stdout
        if not any(word in result.stderr for word in (b'not found', b'closed', b'offline')):
            break
        if attempt < 3:
            if attempt == 0:
                subprocess.run(adb + ['wait-for-device'], capture_output=True, timeout=20, check=True)
            else:
                time.sleep(1)
    raise RuntimeError('Read-only query failed (exit ' + str(result.returncode) + '): ' + result.stderr.decode(errors='replace'))


def read_identity(adb):
    observed = read_root(adb, 'uname -r; cat /proc/sys/kernel/random/boot_id', timeout=15).decode().splitlines()
    if len(observed) != 2 or not re.fullmatch(r'[a-f0-9-]{36}', observed[1]):
        raise RuntimeError('Kernel/boot identity cannot be recorded')
    return {'kernel': observed[0], 'boot_id': observed[1]}


def collect_service(adb, label, timeout):
    """Read an existing service result through the verified guest's proc root."""
    info = guest_info(adb)
    work = '/proc/' + str(info['pid']) + '/root/tmp/rmx1931-tests/service-' + label
    def read(text):
        try:
            output = read_root(adb, text, timeout=15)
            return subprocess.CompletedProcess([], 0, output, b'')
        except RuntimeError as error:
            return subprocess.CompletedProcess([], 1, b'', str(error).encode())
    guard = read('set -e; test -f /proc/' + str(info['pid']) + '/root/etc/droidspaces; test -d ' + work + '; test ! -L ' + work)
    if guard.returncode:
        raise RuntimeError('Service result directory is unverified')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = read('if test -f ' + work + '/status; then cat ' + work + '/status; else echo pending; fi')
        status = result.stdout.strip()
        if result.returncode == 0 and status.isdigit():
            output = read('cat ' + work + '/stdout')
            errors = read('cat ' + work + '/stderr')
            if output.returncode or errors.returncode:
                raise RuntimeError('Probe finished, but durable output collection failed')
            return subprocess.CompletedProcess([], int(status), output.stdout, errors.stdout)
        time.sleep(1)
    return subprocess.CompletedProcess([], 124, b'',
        ('Guest service is still unverified; inspect rmx1931-test-' + label + ' before retrying.').encode())


def guest_service(adb, command, label, timeout, retain_detached=False):
    """Launch once, then collect output independently of the entry stream."""
    argv = shlex.split(command)
    work = '/tmp/rmx1931-tests/service-' + label
    unit = 'rmx1931-test-' + label
    payload = (shlex.join(argv[3:]) + ' > ' + work + '/stdout 2> ' + work + '/stderr; '
               'status=$?; printf "%s\\n" "$status" > ' + work + '/status; exit "$status"')
    service = ['systemd-run', '--quiet', '--no-block', '--collect',
               '--unit=' + unit, '--property=OOMScoreAdjust=0']
    if retain_detached:
        # Explicit multi-phase lifecycle fixtures leave bounded containers for
        # subsequent tests. Their detached conmon must outlive the probe unit.
        service.append('--property=KillMode=process')
    launch = shlex.join(service + ['/bin/sh', '-c', payload])
    setup = ('set -e; test -f /etc/droidspaces; test ! -L /tmp/rmx1931-tests; '
             'mkdir -p /tmp/rmx1931-tests; test -d /tmp/rmx1931-tests; test ! -e ' + work + '; '
             'test ! -L ' + work + '; mkdir -m 700 ' + work + '; ' + launch)
    entry = argv[:3]
    def invoke(arguments, limit=15):
        text = shlex.join(entry + arguments)
        return subprocess.run(adb + ['shell', 'su -c ' + shlex.quote(text)], capture_output=True, timeout=limit)
    launched = invoke(['/bin/sh', '-c', setup])
    if launched.returncode:
        return launched
    return collect_service(adb, label, timeout)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['shell', 'prepare', 'start', 'run', 'run-file', 'stop', 'info', 'collect-service'])
    p.add_argument('--command')
    p.add_argument('--script', type=Path)
    p.add_argument('--script-arg', action='append', default=[])
    p.add_argument('--label', required=True)
    p.add_argument('--verbose', action='store_true', help='Print the full saved report; default: compact result and report path')
    p.add_argument('--timeout', type=int, default=60)
    p.add_argument('--resume-extract', action='store_true')
    p.add_argument('--auto-cgroup', action='store_true')
    p.add_argument('--force-cgroupv1', action='store_true', help='Legacy diagnostic only; Podman profile requires v2')
    p.add_argument('--guest-service', action='store_true', help='Run a probe as a transient guest systemd service with collected exit status')
    p.add_argument('--retain-detached-workloads', action='store_true', help='Multi-phase fixtures only: retain detached container monitors after the probe service exits')
    args = p.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', args.label):
        raise RuntimeError('Invalid report label')
    directory = ROOT / 'artifacts/droidspaces/runtime'
    report_path = directory / (args.label + '.json')
    if args.action in {'run', 'run-file'} and report_path.exists():
        raise RuntimeError('Do not overwrite probe evidence; use a fresh label or collect-service for a pending task')
    adb = device()
    script_digest = None
    identity = None
    if args.action in {'run', 'run-file', 'collect-service'}:
        identity = read_identity(adb)
    if args.action == 'collect-service' and report_path.exists():
        previous = json.loads(report_path.read_text(encoding='utf-8'))
        if previous.get('returncode') != 124 or any(previous.get(key) != value for key, value in identity.items()):
            raise RuntimeError('Only a pending service from the current boot may be collected over its existing report')
    if args.action == 'prepare':
        archive = ROOT / 'tools/downloads/droidspaces/Ubuntu-24.04-Minimal-Droidspaces-rootfs-aarch64-20260920-v20260920-040926.tar.xz'
        digest = 'aa3c7fbd7ec7a905704bb79c374d75f10af7a9a5ee2ddab5e9439fa8035b2bd3'
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Rootfs release checksum mismatch')
        files = [(archive, '/data/local/tmp/rmx1931-ubuntu24-rootfs.tar.xz'),
                 (ROOT / 'scripts/prepare_phone_rootfs.sh', '/data/local/tmp/rmx1931-prepare-rootfs.sh'),
                 (ROOT / 'references/droidspaces/Android/app/src/main/assets/post_extract_fixes.sh', '/data/local/tmp/rmx1931-post-extract.sh')]
        for local, remote in files:
            if local.suffix == '.sh':
                normalized = ROOT / 'tools/droidspaces' / local.name
                normalized.parent.mkdir(parents=True, exist_ok=True)
                normalized.write_bytes(local.read_bytes().replace(b'\r\n', b'\n'))
                local = normalized
            subprocess.run(adb + ['push', str(local), remote], check=True, capture_output=True)
        command = '/system/bin/sh /data/local/tmp/rmx1931-prepare-rootfs.sh'
        if args.resume_extract:
            previous = json.loads((ROOT / 'artifacts/droidspaces/runtime/ubuntu24-prepare.json').read_text(encoding='utf-8'))
            if previous['returncode'] != 1 or "unrecognized option `--show'" not in previous['stderr']:
                raise RuntimeError('Resume only the recorded pre-mount losetup failure')
            command += ' --resume-extract'
    elif args.action == 'start':
        options = [DS, '--name=' + NAME, '--rootfs-img=' + BASE + '/rootfs.img', '--net=nat']
        if args.force_cgroupv1:
            options.append('--force-cgroupv1')
        else:
            options.append('--reset')
        command = shlex.join(options + ['--allow-sandboxing', 'start'])
    elif args.action == 'run-file':
        if not args.script:
            raise RuntimeError('--script is required')
        local = args.script.resolve()
        if local.suffix != '.sh' or not local.is_relative_to(ROOT / 'scripts'):
            raise RuntimeError('Only reviewed shell scripts in this workspace are accepted')
        content = local.read_bytes().replace(b'\r\n', b'\n')
        normalized = ROOT / 'tools/droidspaces' / (args.label + '.sh')
        normalized.parent.mkdir(parents=True, exist_ok=True)
        normalized.write_bytes(content)
        remote = '/data/local/tmp/rmx1931-test-' + args.label + '.sh'
        subprocess.run(adb + ['push', str(normalized), remote], check=True, capture_output=True)
        info = guest_info(adb)
        if info['name'] != NAME or not isinstance(info['pid'], int) or info['pid'] <= 1:
            raise RuntimeError('Container identity is not verified')
        target = '/proc/' + str(info['pid']) + '/root/tmp/rmx1931-tests'
        guest_script = target + '/' + args.label + '.sh'
        copy_command = ('set -e; test -f /proc/' + str(info['pid']) + '/root/etc/droidspaces; '
                        'test ! -L ' + target + '; mkdir -p ' + target + '; '
                        'test ! -L ' + guest_script + '; cp ' + remote + ' ' + guest_script + '; '
                        'chmod 600 ' + guest_script + '; sha256sum ' + guest_script)
        checksum = subprocess.check_output(adb + ['shell', 'su -c ' + shlex.quote(copy_command)]).decode().split()[0]
        if checksum != hashlib.sha256(content).hexdigest():
            raise RuntimeError('Script transfer checksum mismatch')
        script_digest = checksum
        command = shlex.join([DS, '--name=' + NAME, 'run', '/bin/sh', '/tmp/rmx1931-tests/' + args.label + '.sh', *args.script_arg])
    elif args.action == 'run':
        if not args.command:
            raise RuntimeError('--command is required')
        command = shlex.join([DS, '--name=' + NAME, 'run', '/bin/sh', '-c', args.command])
    elif args.action == 'collect-service':
        command = 'Read existing guest service rmx1931-test-' + args.label
    elif args.action in {'stop', 'info'}:
        command = shlex.join([DS, '--name=' + NAME, args.action])
    else:
        if not args.command:
            raise RuntimeError('--command is required')
        command = args.command
    if args.guest_service:
        if args.action not in {'run', 'run-file'}:
            raise RuntimeError('--guest-service requires run or run-file')
    if args.retain_detached_workloads and not args.guest_service:
        raise RuntimeError('--retain-detached-workloads requires --guest-service')
    try:
        if args.action == 'collect-service':
            result = collect_service(adb, args.label, args.timeout)
        elif args.guest_service:
            result = guest_service(adb, command, args.label, args.timeout, retain_detached=args.retain_detached_workloads)
        else:
            result = subprocess.run(adb + ['shell', 'su -c ' + shlex.quote(command)],
                                    capture_output=True, timeout=args.timeout)
            # ADB can lose its transport briefly while Android finishes boot.
            # Retry only the client's explicit pre-execution missing-device
            # error. Never replay timed-out or partially executed commands.
            if result.returncode == 1 and not result.stdout and re.search(
                    rb"device '[^']+' not found", result.stderr):
                subprocess.run(adb + ['wait-for-device'], capture_output=True, timeout=20, check=True)
                refreshed = device()
                if refreshed[-1] != adb[-1]:
                    raise RuntimeError('ADB target changed during reconnection')
                result = subprocess.run(refreshed + ['shell', 'su -c ' + shlex.quote(command)],
                                        capture_output=True, timeout=args.timeout)
    except subprocess.TimeoutExpired as error:
        result = subprocess.CompletedProcess([], 124, error.stdout or b'',
                    (error.stderr or b'') + b'\nADB command timed out; check remote task state before retrying.\n')
    directory.mkdir(parents=True, exist_ok=True)
    output = result.stdout.decode(errors='replace')
    output = re.sub(r'androidboot\.serialno=\S+', 'androidboot.serialno=[redacted]', output)
    output = re.sub(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', '[MAC redacted]', output)
    errors = result.stderr.decode(errors='replace')
    errors = re.sub(r'androidboot\.serialno=\S+', 'androidboot.serialno=[redacted]', errors)
    errors = re.sub(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', '[MAC redacted]', errors)
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'action': args.action, 'command': command, 'returncode': result.returncode,
              'stdout': output,
              'stderr': errors}
    if args.guest_service or args.action == 'collect-service':
        report['execution'] = 'guest systemd service; durable log and explicit exit status'
        if args.retain_detached_workloads:
            report['detached_workloads_retained'] = True
    if identity:
        report.update(identity)
        try:
            report['end_identity'] = read_identity(adb)
            if report['end_identity'] != identity:
                report['returncode'] = 125
                report['stderr'] += '\nPhone rebooted during the probe; this result is not accepted.\n'
        except RuntimeError as error:
            report['returncode'] = 125
            report['stderr'] += '\nProbe end identity is unverified: ' + str(error) + '\n'
    if script_digest:
        report['script_source_sha256'] = script_digest
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    summary = {'label': args.label, 'action': args.action, 'returncode': report['returncode'],
               'report': str(report_path), 'report_sha256': hashlib.sha256(report_path.read_bytes()).hexdigest(),
               'stdout_bytes': len(output.encode('utf-8')), 'stderr_bytes': len(report['stderr'].encode('utf-8'))}
    for key in ('kernel', 'boot_id', 'end_identity', 'script_source_sha256'):
        if key in report:
            summary[key] = report[key]
    if report['returncode']:
        summary.update(stdout_tail=output[-1200:], stderr_tail=report['stderr'][-1200:])
    print(json.dumps(report if args.verbose else summary, ensure_ascii=False), flush=True)
    raise SystemExit(report['returncode'])


if __name__ == '__main__':
    main()
