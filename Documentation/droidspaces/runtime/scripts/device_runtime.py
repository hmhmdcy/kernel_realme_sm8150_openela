#!/usr/bin/env python3
"""Guarded ADB entry point for the authorized RMX1931 Podman tests.

Does not flash partitions or change Android SELinux/time settings.
Commands and bounded output are saved as evidence; do not use for secrets.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = Path(__file__).resolve().parents[1]
NAME = 'rmx1931-podman'
BASE = '/data/local/Droidspaces/Containers/' + NAME
DS = '/data/local/tmp/rmx1931-droidspaces-check'


def device():
    adb = [str(ROOT / 'tools/platform-tools/adb.exe')]
    for attempt in range(6):
        rows = [r.split() for r in subprocess.check_output(adb + ['devices'], text=True, timeout=15).splitlines()[1:] if r.strip()]
        if len(rows) > 1 or any(len(r) != 2 or r[1] not in {'device', 'offline'} for r in rows):
            raise RuntimeError('Unexpected or unauthorized ADB device state')
        ids = [r[0] for r in rows if r[1] == 'device']
        if len(ids) == 1:
            break
        if attempt < 5:
            time.sleep(1)
    if len(ids) != 1:
        raise RuntimeError('Exactly one authorized device is required')
    adb += ['-s', ids[0]]
    model = subprocess.check_output(adb + ['shell', 'getprop ro.product.device'], text=True).strip()
    if model not in {'RMX1931', 'RMX1931CN'}:
        raise RuntimeError('Unexpected device model')
    return adb


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['shell', 'prepare', 'start', 'run', 'run-file', 'stop', 'info'])
    p.add_argument('--command')
    p.add_argument('--script', type=Path)
    p.add_argument('--script-arg', action='append', default=[])
    p.add_argument('--label', required=True)
    p.add_argument('--timeout', type=int, default=60)
    p.add_argument('--resume-extract', action='store_true')
    p.add_argument('--auto-cgroup', action='store_true')
    p.add_argument('--force-cgroupv1', action='store_true', help='Legacy diagnostic only; Podman profile requires v2')
    args = p.parse_args()
    if not args.label.replace('-', '').replace('_', '').isalnum():
        raise RuntimeError('Invalid report label')
    adb = device()
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
        info_command = shlex.join([DS, '--name=' + NAME, '--format', 'info'])
        info = json.loads(subprocess.check_output(adb + ['shell', 'su -c ' + shlex.quote(info_command)]))
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
        command = shlex.join([DS, '--name=' + NAME, 'run', '/bin/sh', '/tmp/rmx1931-tests/' + args.label + '.sh', *args.script_arg])
    elif args.action == 'run':
        if not args.command:
            raise RuntimeError('--command is required')
        command = shlex.join([DS, '--name=' + NAME, 'run', '/bin/sh', '-c', args.command])
    elif args.action in {'stop', 'info'}:
        command = shlex.join([DS, '--name=' + NAME, args.action])
    else:
        if not args.command:
            raise RuntimeError('--command is required')
        command = args.command
    try:
        result = subprocess.run(adb + ['shell', 'su -c ' + shlex.quote(command)],
                                capture_output=True, timeout=args.timeout)
    except subprocess.TimeoutExpired as error:
        result = subprocess.CompletedProcess([], 124, error.stdout or b'',
                    (error.stderr or b'') + b'\nADB command timed out; check remote task state before retrying.\n')
    directory = ROOT / 'artifacts/droidspaces/runtime'
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
    (directory / (args.label + '.json')).write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
