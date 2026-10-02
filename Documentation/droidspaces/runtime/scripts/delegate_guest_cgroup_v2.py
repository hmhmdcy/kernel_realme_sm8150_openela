#!/usr/bin/env python3
"""Delegate available memory/pids controllers to this test guest.

Move only the verified DroidSpaces monitor processes into their own child.
Enable pids accounting at the root without changing Android process placement
or any Android resource limits. Preserve the previous controller settings.
"""
import datetime as dt
import argparse
import json
import shlex
import subprocess
from pathlib import Path
from device_runtime import device, DS, NAME, BASE

ROOT = Path(__file__).resolve().parents[1]
CG = '/sys/fs/cgroup'
PARENT = CG + '/droidspaces'
TARGET = PARENT + '/' + NAME


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', default='podman-controller-delegation')
    args = p.parse_args()
    if not args.label.replace('-', '').isalnum():
        raise RuntimeError('Invalid evidence label')
    adb = device()

    def shell(text):
        r = subprocess.run(adb + ['shell', 'su -c ' + shlex.quote(text)],
                           capture_output=True, timeout=25)
        if r.returncode:
            raise RuntimeError(r.stderr.decode(errors='replace'))
        return r.stdout.decode(errors='replace').strip()

    info = json.loads(shell(shlex.join([DS, '--name=' + NAME, '--format', 'info'])))
    init = info['pid']
    if info['name'] != NAME or not isinstance(init, int) or init <= 1:
        raise RuntimeError('Unexpected container identity')
    shell('test -f /proc/' + str(init) + '/root/etc/droidspaces')
    if shell('stat -f -c %t ' + CG) != '63677270':
        raise RuntimeError('Host unified hierarchy is not verified')
    if shell('cat ' + PARENT + '/cgroup.procs'):
        raise RuntimeError('The shared DroidSpaces parent has internal processes')
    before = {path: shell('cat ' + path + '/cgroup.subtree_control')
              for path in [CG, PARENT, TARGET]}
    available = shell('cat ' + CG + '/cgroup.controllers').split()
    if not {'memory', 'pids'}.issubset(available):
        raise RuntimeError('Required controllers are unavailable at the root')
    monitor = shell('cat ' + TARGET + '/cgroup.procs').split()
    already_moved = not monitor
    if already_moved:
        monitor = shell('cat ' + TARGET + '/host-monitor/cgroup.procs').split()
    if len(monitor) != 2 or not all(p.isdigit() and int(p) > 1 for p in monitor):
        raise RuntimeError('Unexpected number of internal monitor processes')
    for pid in monitor:
        if shell('cat /proc/' + pid + '/comm') != '[ds-monitor]':
            raise RuntimeError('An internal process is not a DroidSpaces monitor')
        process_args = shell('cat /proc/' + pid + '/cmdline').replace('\0', ' ').split()
        if not { '--name=' + NAME, '--rootfs-img=' + BASE + '/rootfs.img', 'start' }.issubset(process_args):
            raise RuntimeError('Monitor belongs to a different container')
    if str(init) not in shell('cat ' + TARGET + '/init.scope/cgroup.procs').split():
        raise RuntimeError('Guest PID 1 is outside its expected child group')
    directory = ROOT / 'artifacts/droidspaces/runtime'
    report_path = directory / (args.label + '.json')
    report = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'before_subtree_control': before, 'monitor_pids': list(map(int, monitor)),
              'guest_pid': init, 'android_processes_moved': False,
              'android_resource_limits_changed': False, 'completed': False}
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    if not already_moved:
        shell('mkdir ' + TARGET + '/host-monitor')
        for pid in monitor:
            shell('test "$(cat /proc/' + pid + '/comm)" = "[ds-monitor]"; '
                  'echo ' + pid + ' > ' + TARGET + '/host-monitor/cgroup.procs')
    if shell('cat ' + TARGET + '/cgroup.procs'):
        raise RuntimeError('Internal process removal was not complete')
    for path in [CG, PARENT, TARGET]:
        shell('echo "+memory +pids" > ' + path + '/cgroup.subtree_control')
    report['after_subtree_control'] = {path: shell('cat ' + path + '/cgroup.subtree_control')
                                       for path in [CG, PARENT, TARGET]}
    report['guest_available_controllers'] = shell('cat ' + TARGET + '/cgroup.controllers')
    report['completed'] = True
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
