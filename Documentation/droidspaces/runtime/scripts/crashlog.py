#!/usr/bin/env python3
"""Install the reversible KSU collector or export logs without deleting pstore."""
import argparse
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import uuid
import zipfile
from device_runtime import device

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'packages/rmx1931-crashlog'
REMOTE = '/data/adb/modules/rmx1931-crashlog'
ARCHIVE = '/data/adb/rmx1931-crashlog'
FILES = ['module.prop', 'post-fs-data.sh', 'service.sh', 'collect.sh']
sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def shell(adb, command, timeout=30):
    return subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=timeout)


def checked(adb, command, timeout=30):
    result = shell(adb, command, timeout)
    if result.returncode:
        raise RuntimeError('Device command failed: ' + result.stderr.decode(errors='replace'))
    return result.stdout


def readonly(adb, command, timeout=30):
    """Only for export reads: retry short transport closures, never installation."""
    for attempt in range(4):
        result = shell(adb, command, timeout)
        if result.returncode == 0:
            return result
        if not any(word in result.stderr for word in (b'not found', b'closed', b'offline')):
            return result
        if attempt < 3:
            time.sleep(1)
            if device()[-1] != adb[-1]:
                raise RuntimeError('ADB target changed during export')
    return result


def package():
    version = re.search(r'^version=(\d+\.\d+)$', (PACKAGE / 'module.prop').read_text(), re.M)[1]
    target = ROOT / ('artifacts/droidspaces/crashlog/rmx1931-crashlog-' + version + '.zip')
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as z:
        for name in FILES:
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 3, 0, 0, 0))
            info.external_attr = (0o100755 if name.endswith('.sh') else 0o100644) << 16
            z.writestr(info, (PACKAGE / name).read_bytes().replace(b'\r\n', b'\n'))
    print(json.dumps({'package': str(target), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}))


def install(adb):
    # Replacing an unrelated or locally edited module requires manual review.
    checked(adb, 'test "$(getenforce)" = Enforcing; test ! -L /data/adb; '
                 'test -d /data/adb/modules; test ! -L /data/adb/modules; '
                 'test ! -e ' + REMOTE + '; test ! -L ' + REMOTE)
    staging = '/data/adb/modules/.rmx1931-crashlog-stage'
    checked(adb, 'set -e; test ! -e ' + staging + '; test ! -L ' + staging + '; mkdir -m 700 ' + staging)
    for name in FILES:
        local = ROOT / 'artifacts/droidspaces/crashlog/staging' / name
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes((PACKAGE / name).read_bytes().replace(b'\r\n', b'\n'))
        # exec-out does not provide a reliable input EOF on this ADB build.
        encoded = base64.b64encode(local.read_bytes()).decode('ascii')
        checked(adb, "printf '%s' '" + encoded + "' | base64 -d > " + staging + '/' + name)
        expected = hashlib.sha256(local.read_bytes()).hexdigest()
        checked(adb, 'test "$(sha256sum ' + staging + '/' + name + ' | cut -d " " -f 1)" = ' + expected)
    command = 'set -e; '
    for name in FILES:
        command += 'chmod ' + ('755' if name.endswith('.sh') else '644') + ' ' + staging + '/' + name + '; '
    command += 'mv ' + staging + ' ' + REMOTE
    checked(adb, command)
    print('CRASHLOG_MODULE_INSTALLED (active next boot; use collect to archive now)')


def update(adb):
    # Replace only our previously installed, byte-verified 1.0 source. Preserve
    # the entire previous directory for rollback and all collected archives.
    checked(adb, 'set -e; test "$(getenforce)" = Enforcing; test ! -L /data/adb; '
                 'test ! -L /data/adb/modules; test -d ' + REMOTE + '; test ! -L ' + REMOTE +
                 '; test ! -e ' + REMOTE + '/disable; '
                 'for p in ' + ARCHIVE + '/.lock-*; do test ! -d "$p"; done')
    old_hashes = {}
    new_hashes = {}
    for name in FILES:
        old = ROOT / 'artifacts/droidspaces/crashlog/staging' / name
        expected = hashlib.sha256(old.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
        actual = readonly(adb, 'sha256sum ' + REMOTE + '/' + name)
        if actual.returncode or actual.stdout.decode().split()[0] != expected:
            raise RuntimeError('Installed module differs from original 1.0; inspect before updating')
        old_hashes[name] = expected
    token = uuid.uuid4().hex
    staging = '/data/adb/modules/.rmx1931-crashlog-update-' + token
    backup = '/data/adb/rmx1931-crashlog-module-backup-' + token
    checked(adb, 'set -e; test ! -e ' + staging + '; test ! -L ' + staging +
                 '; test ! -e ' + backup + '; test ! -L ' + backup + '; mkdir -m 700 ' + staging)
    for name in FILES:
        source = (PACKAGE / name).read_bytes().replace(b'\r\n', b'\n')
        digest = hashlib.sha256(source).hexdigest()
        encoded = base64.b64encode(source).decode('ascii')
        checked(adb, "set -e; printf '%s' '" + encoded + "' | base64 -d > " + staging + '/' + name +
                     '; chmod ' + ('755' if name.endswith('.sh') else '644') + ' ' + staging + '/' + name +
                     '; test "$(sha256sum ' + staging + '/' + name + ' | cut -d " " -f 1)" = ' + digest)
        new_hashes[name] = digest
    checked(adb, 'set -e; for p in ' + ARCHIVE + '/.lock-*; do test ! -d "$p"; done; '
                 'mv ' + REMOTE + ' ' + backup + '; mv ' + staging + ' ' + REMOTE)
    for name, expected in new_hashes.items():
        result = readonly(adb, 'sha256sum ' + REMOTE + '/' + name)
        if result.returncode or result.stdout.decode().split()[0] != expected:
            raise RuntimeError('Updated source verification failed; backup is at ' + backup)
    report = {'updated_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'old_hashes': old_hashes,
              'installed_hashes': new_hashes, 'backup': backup, 'archives_preserved': True,
              'kernel': readonly(adb, 'uname -r').stdout.decode().strip()}
    (ROOT / 'artifacts/droidspaces/crashlog/update-1.1.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


def export(adb):
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    directory = ROOT / 'artifacts/droidspaces/crashlog/private' / stamp
    directory.mkdir(parents=True)
    record = {'observed_at': stamp, 'files': {}, 'errors': {},
              'panic_retention_verified': False, 'pstore_deleted': False}
    commands = {'kernel.txt': 'uname -r', 'boot-id.txt': 'cat /proc/sys/kernel/random/boot_id',
                'uptime.txt': 'cat /proc/uptime', 'selinux.txt': 'getenforce',
                'dmesg.txt': 'dmesg', 'config.gz': 'cat /proc/config.gz',
                'pstore-list.txt': 'ls -la /sys/fs/pstore',
                'ramoops-parameters.txt': 'for p in /sys/module/ramoops/parameters/*; do '
                                         'echo ${p##*/}; cat "$p"; done',
                'ramoops-dt.txt': 'for p in reg record-size console-size pmsg-size ftrace-size devinfo-size; do '
                                  'echo "$p"; od -An -tx1 /sys/bus/platform/devices/b7e00000.ramoops/of_node/$p; done'}
    listing_result = readonly(adb, 'ls /sys/fs/pstore')
    if listing_result.returncode:
        raise RuntimeError('Pstore listing failed')
    listing = listing_result.stdout.decode().split()
    for name in listing:
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', name):
            raise RuntimeError('Unexpected pstore entry')
        commands['pstore-' + name] = 'cat /sys/fs/pstore/' + name
    # Export retained module records using a bounded, validated listing.
    result = readonly(adb, 'if test -d ' + ARCHIVE + '; then find ' + ARCHIVE + ' -maxdepth 2 -type f; fi')
    if result.returncode == 0:
        for path in result.stdout.decode().splitlines():
            match = re.fullmatch(re.escape(ARCHIVE) + r'/((?:boot|snapshot)-[a-z0-9-]+)/([a-zA-Z0-9_.-]+)', path)
            if not match:
                raise RuntimeError('Unexpected crash archive path: ' + path)
            commands['retained/' + '/'.join(match.groups())] = 'cat ' + shlex.quote(path)
    for name, command in commands.items():
        result = readonly(adb, command)
        if result.returncode:
            record['errors'][name] = {'returncode': result.returncode, 'stderr': result.stderr.decode(errors='replace')}
            continue
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(result.stdout)
        record['files'][name] = {'bytes': len(result.stdout), 'sha256': hashlib.sha256(result.stdout).hexdigest()}
    record['pstore_records'] = listing
    (directory / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    verify_exports(directory)
    print(json.dumps({'directory': str(directory), 'files': len(record['files']),
                      'pstore_records': listing, 'errors': record['errors'],
                      'panic_retention_verified': False}))
    if record['errors']:
        raise RuntimeError('Export contains incomplete reads; inspect manifest.json')


def verify_exports(directory):
    for sums in directory.glob('retained/*/SHA256SUMS'):
        for line in sums.read_text().splitlines():
            digest, name = line.split('  ', 1)
            if not re.fullmatch('[0-9a-f]{64}', digest) or not re.fullmatch('[a-zA-Z0-9_.-]+', name):
                raise RuntimeError('Malformed retained manifest')
            if hashlib.sha256((sums.parent / name).read_bytes()).hexdigest() != digest:
                raise RuntimeError('Retained record checksum differs: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['package', 'install', 'update', 'collect', 'export', 'disable', 'mark', 'verify-marker'])
    parser.add_argument('--export-directory', type=Path)
    parser.add_argument('--reset-path', choices=['normal', 'bootloader'], default='normal')
    parser.add_argument('--test-name', default='default', help='Separate retention evidence across reset paths')
    args = parser.parse_args()
    if not re.fullmatch('[a-zA-Z0-9_-]+', args.test_name):
        raise RuntimeError('Invalid retention test name')
    suffix = '' if args.test_name == 'default' else '-' + args.test_name
    marker_path = ROOT / ('artifacts/droidspaces/crashlog/marker' + suffix + '.json')
    retention_path = ROOT / ('artifacts/droidspaces/crashlog/retention' + suffix + '.json')
    if args.action == 'package':
        package()
        return
    adb = device()
    if args.action == 'install':
        install(adb)
    elif args.action == 'update':
        update(adb)
    elif args.action == 'collect':
        print(checked(adb, '/system/bin/sh ' + REMOTE + '/collect.sh boot', timeout=50).decode())
    elif args.action == 'disable':
        checked(adb, 'test -f ' + REMOTE + '/module.prop; test ! -L ' + REMOTE + '; touch ' + REMOTE + '/disable')
        print('Module disabled; retained logs preserved')
    elif args.action == 'mark':
        marker = 'RMX1931_PSTORE_MARKER_' + uuid.uuid4().hex
        boot_id = checked(adb, 'cat /proc/sys/kernel/random/boot_id').decode().strip()
        # Android's console_loglevel=4 drops informational <6> messages.
        # A diagnostic <3> marker reaches pstore-console without changing levels.
        checked(adb, "printf '%s\\n' '<3>" + marker + "' > /dev/kmsg")
        checked(adb, "test -c /dev/pmsg0; printf '%s\\n' '" + marker + "' > /dev/pmsg0")
        record = {'marker': marker, 'boot_id_before': boot_id,
                  'created_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'reset_path': args.reset_path, 'marker_log_level': 3,
                  'marker_channels': ['kmsg', 'pmsg'],
                  'purpose': 'non-panic retention only; no panic is triggered'}
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record))
    elif args.action == 'verify-marker':
        directory = args.export_directory
        private = ROOT / 'artifacts/droidspaces/crashlog/private'
        if directory is None:
            directory = sorted(p for p in private.iterdir() if p.is_dir())[-1]
        directory = directory.resolve()
        if not directory.is_relative_to(private.resolve()):
            raise RuntimeError('Only our private export directories are accepted')
        marker = json.loads(marker_path.read_text())
        boot_id = (directory / 'boot-id.txt').read_text().strip()
        if boot_id == marker['boot_id_before']:
            raise RuntimeError('No reboot occurred; retention cannot be tested on the same boot')
        matches = [p.name for p in directory.glob('pstore-*') if p.is_file() and marker['marker'].encode() in p.read_bytes()]
        record = {'boot_id_before': marker['boot_id_before'], 'boot_id_after': boot_id,
                  'reset_path': marker.get('reset_path', 'legacy unspecified; first test crossed bootloader'),
                  'marker_found_in_pstore_records': matches,
                  'non_panic_retention_verified': bool(matches),
                  'normal_reboot_retention_verified': bool(matches) and marker.get('reset_path') == 'normal',
                  'panic_retention_verified': False}
        retention_path.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record))
        if not matches:
            raise RuntimeError('Marker did not survive in the exported pstore records')
    else:
        export(adb)


if __name__ == '__main__':
    main()
