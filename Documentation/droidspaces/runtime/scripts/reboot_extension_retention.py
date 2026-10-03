#!/usr/bin/env python3
"""Authorized normal reboot of the already verified extension kernel; never flashes."""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import subprocess
import sys
from deploy_kernel_extensions import STAGES, candidate
from device_runtime import device, read_root

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=STAGES, required=True)
    parser.add_argument('--authorization', required=True)
    parser.add_argument('--test-name')
    args = parser.parse_args()
    if not args.authorization.strip():
        raise RuntimeError('Normal reboot authorization required')
    test_name = args.test_name or args.stage + '-normal'
    if not re.fullmatch('[a-zA-Z0-9_-]+', test_name):
        raise RuntimeError('Invalid retention test name')
    _, check, _, release = candidate(args.stage)
    adb = device()
    if (read_root(adb, 'uname -r').decode().strip() != release or
            read_root(adb, 'sha256sum /dev/block/by-name/boot').decode().split()[0] != check['candidate_sha256'] or
            read_root(adb, 'getenforce').strip() != b'Enforcing' or
            read_root(adb, 'getprop sys.boot_completed').strip() != b'1'):
        raise RuntimeError('Phone differs from verified running candidate')
    mounted = read_root(adb, 'cat /proc/mounts').decode()
    if '/mnt/Droidspaces/rmx1931-podman' in mounted:
        raise RuntimeError('Stop test guest before reboot')
    subprocess.run([sys.executable, str(ROOT / 'scripts/crashlog.py'), 'mark', '--reset-path', 'normal',
                    '--test-name', test_name], check=True)
    record = {'reboot_sent_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'authorization': args.authorization,
              'kernel': release, 'boot_sha256': check['candidate_sha256'], 'partition_writes': False,
              'reset_path': 'normal', 'reboot_sent': False}
    path = ROOT / f'artifacts/droidspaces/extensions-{test_name}-reboot.json'
    path.write_text(json.dumps(record, indent=2) + '\n')
    subprocess.run(adb + ['exec-out', 'su', '-c', 'sync; /system/bin/reboot'],
                   capture_output=True, timeout=30, check=True)
    record['reboot_sent'] = True
    path.write_text(json.dumps(record, indent=2) + '\n')
    print('NORMAL_REBOOT_SENT_WITH_RETENTION_MARKER')


if __name__ == '__main__':
    main()
