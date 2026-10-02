#!/usr/bin/env python3
"""Prepare only the isolated guest's pristine sysfs for older crun.

crun 1.14 creates sysfs RW before remounting it RO. A RO pristine seed
is insufficient on old kernels without open_tree/mount_setattr. Preserve
kernel mount visibility checks and all Android /sys mount flags.
"""
import datetime as dt
import argparse
import json
import shlex
import subprocess
from pathlib import Path
from device_runtime import device, DS, NAME

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', default='podman-pristine-sysfs')
    args = p.parse_args()
    if not args.label.replace('-', '').isalnum():
        raise RuntimeError('Invalid evidence label')
    adb = device()

    def execute(text):
        r = subprocess.run(adb + ['shell', 'su -c ' + shlex.quote(text)],
                           capture_output=True, timeout=35)
        if r.returncode:
            raise RuntimeError(r.stderr.decode(errors='replace'))
        return r.stdout.decode(errors='replace').strip()

    info = json.loads(execute(shlex.join([DS, '--name=' + NAME, '--format', 'info'])))
    pid = info['pid']
    if info['name'] != NAME or not isinstance(pid, int) or pid <= 1:
        raise RuntimeError('Unexpected container identity')
    execute('test -f /proc/' + str(pid) + '/root/etc/droidspaces')
    host_net = execute('readlink /proc/1/ns/net')
    guest_net = execute('readlink /proc/' + str(pid) + '/ns/net')
    if host_net == guest_net or not guest_net.startswith('net:['):
        raise RuntimeError('The guest must have its own network namespace')
    before = execute('grep " /sys " /proc/mounts')
    text = ('set -eu; test -f /etc/droidspaces; printf "0\\n" > /proc/self/oom_score_adj; '
            'test "$(findmnt -n -o FSTYPE -T /run/droidspaces/sys)" = sysfs; '
            'mount -o remount,rw /run/droidspaces/sys; '
            'findmnt -n -o TARGET,FSTYPE,OPTIONS -T /run/droidspaces/sys; '
            'install -d -m 700 -o podmantest -g podmantest /run/user/1000; '
            'runuser -u podmantest -- env XDG_RUNTIME_DIR=/run/user/1000 '
            'timeout 15 podman --log-level=warn system migrate')
    output = execute(shlex.join([DS, '--name=' + NAME, 'run', '/bin/sh', '-c', text]))
    after = execute('grep " /sys " /proc/mounts')
    if before != after:
        raise RuntimeError('Android sysfs mount flags unexpectedly changed')
    report = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'host_netns': host_net, 'guest_netns': guest_net,
              'android_sysfs_before': before, 'android_sysfs_after': after,
              'android_sysfs_unchanged': True, 'guest_output': output,
              'kernel_mount_visibility_checks_modified': False}
    target = ROOT / 'artifacts/droidspaces/runtime' / (args.label + '.json')
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
