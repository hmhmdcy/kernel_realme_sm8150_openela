#!/usr/bin/env python3
"""Measure v1 read throttling on the guest's actual loop rootfs, never a disk-wide limit."""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import uuid
from device_runtime import device, guest_info, read_root, DS, NAME

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', default='extensions-io-enforcement')
    args = parser.parse_args()
    if not re.fullmatch('[a-zA-Z0-9_-]+', args.label):
        raise RuntimeError('Invalid label')
    adb = device()
    info = guest_info(adb)
    pid = info['pid']
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'status': 'pending', 'io_max_verified': False, 'android_processes_moved': False,
              'kernel': read_root(adb, 'uname -r').decode().strip(),
              'boot_id': read_root(adb, 'cat /proc/sys/kernel/random/boot_id').decode().strip()}

    def shell(command, timeout=45):
        result = subprocess.run(adb + ['exec-out', 'su', '-c', command],
                                capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError('Probe command failed: ' + result.stderr.decode(errors='replace'))
        return result.stdout.decode(errors='replace').strip()

    def guest(command):
        return shlex.join([DS, '--name=' + NAME, 'run', '/bin/sh', '-c', command])

    record = ROOT / 'artifacts/droidspaces/runtime' / (args.label + '.json')
    record.parent.mkdir(parents=True, exist_ok=True)
    group = None
    fixture = None
    dev = None
    try:
        shell('test -f /proc/' + str(pid) + '/root/etc/droidspaces; test "$(getenforce)" = Enforcing; '
              'test "$(stat -f -c %t /dev/blkio)" = 27e0eb; test -f /dev/blkio/blkio.throttle.read_bps_device')
        source = shell(guest('findmnt -n -o SOURCE /'))
        match = re.fullmatch(r'/dev/block/(loop[0-9]+)', source)
        if not match:
            raise RuntimeError('Guest rootfs is not the expected loop device: ' + source)
        dev = shell('cat /sys/class/block/' + match[1] + '/dev')
        if not re.fullmatch('7:[0-9]+', dev):
            raise RuntimeError('Unexpected loop major/minor')
        token = uuid.uuid4().hex
        fixture = '/var/tmp/rmx1931-io-' + token
        group = '/dev/blkio/rmx1931-io-' + token
        # Only the new probe shell and its descendants enter this cgroup.
        shell('test ! -e ' + group + '; mkdir ' + group)
        if shell(guest('findmnt -n -o SOURCE -T /var/tmp')) != source:
            raise RuntimeError('I/O fixture must reside on the verified ext4 loop rootfs')
        shell(guest('test ! -e ' + fixture + '; mkdir -m 700 ' + fixture + '; '
                    'dd if=/dev/zero of=' + fixture + '/payload.bin bs=1M count=16 conv=fsync status=none'))
        # DroidSpaces run moves its child into the guest's cgroup. Read the same
        # loop-mounted file directly with its static BusyBox instead, keeping
        # only this newly created host shell/reader in the temporary test group.
        guest_root = '/proc/' + str(pid) + '/root'
        command = guest_root + '/usr/bin/busybox dd if=' + guest_root + fixture + '/payload.bin of=/dev/null bs=1M count=16 iflag=direct'
        def measure():
            start = time.monotonic()
            shell('set -e; echo $$ > ' + group + '/cgroup.procs; ' + command)
            elapsed = time.monotonic() - start
            accounting = shell('cat ' + group + '/blkio.throttle.io_service_bytes')
            reads = sum(int(row.split()[2]) for row in accounting.splitlines()
                        if len(row.split()) == 3 and row.split()[:2] == [dev, 'Read'])
            return {'seconds': elapsed, 'device_read_bytes': reads, 'accounting': accounting}
        baseline = measure()
        shell('echo 0 > ' + group + '/blkio.reset_stats; echo "' + dev + ' 2097152" > ' + group + '/blkio.throttle.read_bps_device')
        limited = measure()
        # Require actual per-device accounting plus a material timing difference.
        passed = (limited['device_read_bytes'] >= 16 * 1024 * 1024 and
                  limited['seconds'] >= 4 and limited['seconds'] >= 2 * baseline['seconds'])
        report.update({'status': 'passed' if passed else 'failed', 'interface': 'v1 blkio.throttle.read_bps_device',
                       'device': source, 'major_minor': dev, 'limit_bps': 2097152,
                       'baseline': baseline, 'limited': limited, 'fixture_bytes': 16 * 1024 * 1024,
                       'scope': 'only test subprocesses; not the entire guest'})
        if not passed:
            raise RuntimeError('Throttling is not proven on the actual loop path')
    except Exception as error:
        report.update({'status': 'failed', 'error': str(error)})
        raise
    finally:
        cleanup_errors = []
        if group and dev:
            try:
                shell('echo "' + dev + ' 0" > ' + group + '/blkio.throttle.read_bps_device; '
                      'test -z "$(cat ' + group + '/cgroup.procs)" && rmdir ' + group)
            except Exception as error:
                cleanup_errors.append(str(error))
        if fixture:
            try:
                shell(guest('test ! -L ' + fixture + '; rm -f ' + fixture + '/payload.bin; rmdir ' + fixture))
            except Exception as error:
                cleanup_errors.append(str(error))
        report['cleanup_errors'] = cleanup_errors
        if cleanup_errors:
            report['status'] = 'failed'
        record.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        if cleanup_errors:
            raise RuntimeError('I/O probe cleanup is incomplete; inspect the report before retrying')


if __name__ == '__main__':
    main()
