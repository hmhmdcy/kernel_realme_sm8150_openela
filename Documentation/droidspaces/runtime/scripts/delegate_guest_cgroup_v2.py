#!/usr/bin/env python3
"""Delegate available memory/pids controllers to this test guest.

Move only the verified DroidSpaces monitor processes into their own child.
Enable pids accounting at the root without changing Android process placement
or any Android resource limits. Preserve the previous controller settings.
"""
import datetime as dt
import argparse
import json
import re
import shlex
import subprocess
from pathlib import Path
from device_runtime import device, read_root, DS, NAME, BASE

ROOT = Path(__file__).resolve().parents[1]
CG = '/sys/fs/cgroup'
PARENT = CG + '/droidspaces'
TARGET = PARENT + '/' + NAME
CONFIG = BASE + '/container.config'
BINARY_SHA256 = '26dbd935d24b8ba8b55a9cb65b2edc43ebbaf298317f243939e67a92a8a8558e'


def monitor_launch(arguments, config_text=None):
    if len(arguments) == 3 and arguments[1:] == ['--config=' + CONFIG, 'start']:
        if config_text is None:
            raise RuntimeError('App monitor configuration must be verified')
        settings = {}
        for line in config_text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            key, separator, value = line.partition('=')
            if not separator or key.strip() in settings:
                raise RuntimeError('Malformed or duplicate app monitor configuration')
            settings[key.strip()] = value.strip()
        if settings.get('name') != NAME or settings.get('rootfs_path') != BASE + '/rootfs.img' or settings.get('force_cgroupv1', '0') != '0':
            raise RuntimeError('App monitor configuration belongs to a different container or hierarchy')
        return 'app-config'
    expected = {'--name': NAME, '--rootfs-img': BASE + '/rootfs.img'}
    for key, value in expected.items():
        options = [arg for arg in arguments[1:] if arg.startswith(key + '=')]
        if options != [key + '=' + value]:
            raise RuntimeError('Monitor belongs to a different container')
    if arguments[-1:] != ['start'] or any(arg.startswith('--config') for arg in arguments[1:]):
        raise RuntimeError('Unexpected monitor launch arguments')
    return 'direct'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', default='podman-controller-delegation')
    args = p.parse_args()
    if not args.label.replace('-', '').isalnum():
        raise RuntimeError('Invalid evidence label')
    adb = device()

    def shell(text, mutate=False):
        if not mutate:
            return read_root(adb, text, timeout=25).decode(errors='replace').strip()
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
    controllers = '+memory +pids'
    release = shell('uname -r')
    native_cpu_cpuset = release.endswith(('-ext-h2cp', '-ext-h2cp2', '-ext-h2cp3', '-ext-h2cp4', '-ext-h3bm', '-ext-h3bm2', '-ext-h4sn', '-ext-h5bf', '-ext-h5bf2', '-ext-a16ps', '-ext-a16pf'))
    dualio = release.endswith(('-ext-dualio', '-ext-harden1', '-ext-h2cp', '-ext-h2cp2', '-ext-h2cp3', '-ext-h2cp4', '-ext-h3bm', '-ext-h3bm2', '-ext-h4sn', '-ext-h5bf', '-ext-h5bf2', '-ext-a16ps', '-ext-a16pf'))
    if dualio:
        if 'io' not in available:
            raise RuntimeError('Dual IO controller is unavailable')
        controllers += ' +io'
    if native_cpu_cpuset:
        if not {'cpu', 'cpuset'}.issubset(available):
            raise RuntimeError('Native CPU/cpuset controllers are unavailable')
        controllers += ' +cpu +cpuset'
    monitor = shell('cat ' + TARGET + '/cgroup.procs').split()
    already_moved = not monitor
    if already_moved:
        monitor = shell('cat ' + TARGET + '/host-monitor/cgroup.procs').split()
    if len(monitor) != 2 or not all(p.isdigit() and int(p) > 1 for p in monitor):
        raise RuntimeError('Unexpected number of internal monitor processes')
    launch_modes = []
    for pid in monitor:
        if shell('cat /proc/' + pid + '/comm') != '[ds-monitor]':
            raise RuntimeError('An internal process is not a DroidSpaces monitor')
        if shell('sha256sum /proc/' + pid + '/exe').split()[0] != BINARY_SHA256:
            raise RuntimeError('Monitor executable differs from the pinned official binary')
        process_args = read_root(adb, 'cat /proc/' + pid + '/cmdline').decode().rstrip('\0').split('\0')
        config_text = None
        if '--config=' + CONFIG in process_args:
            if shell('readlink -f ' + CONFIG) != CONFIG:
                raise RuntimeError('App configuration path is not canonical')
            owner, mode = shell('stat -c %u:%a ' + CONFIG).split(':')
            if owner != '0' or int(mode, 8) & 0o022:
                raise RuntimeError('App configuration must be root-owned and not writable by other users')
            config_text = read_root(adb, 'cat ' + CONFIG).decode()
        launch_modes.append(monitor_launch(process_args, config_text))
    # Both verified monitors must form the actual parent chain of this PID 1.
    parent = re.search(r'^PPid:\s+(\d+)\r?$', shell('cat /proc/' + str(init) + '/status'), re.M)
    if not parent or parent[1] not in monitor:
        raise RuntimeError('Guest PID 1 is not a child of the verified monitors')
    grandparent = re.search(r'^PPid:\s+(\d+)\r?$', shell('cat /proc/' + parent[1] + '/status'), re.M)
    if not grandparent or grandparent[1] not in set(monitor) - {parent[1]}:
        raise RuntimeError('DroidSpaces monitor parent chain is unverified')
    if str(init) not in shell('cat ' + TARGET + '/init.scope/cgroup.procs').split():
        raise RuntimeError('Guest PID 1 is outside its expected child group')
    directory = ROOT / 'artifacts/droidspaces/runtime'
    report_path = directory / (args.label + '.json')
    report = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'before_subtree_control': before, 'monitor_pids': list(map(int, monitor)),
              'guest_pid': init, 'android_processes_moved': False,
              'monitor_launch_modes': launch_modes, 'monitor_binary_sha256': BINARY_SHA256,
              'monitor_parent_chain_verified': True,
              'android_resource_limits_changed': False, 'completed': False}
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    if not already_moved:
        shell('mkdir ' + TARGET + '/host-monitor', mutate=True)
        for pid in monitor:
            shell('test "$(cat /proc/' + pid + '/comm)" = "[ds-monitor]"; '
                  'echo ' + pid + ' > ' + TARGET + '/host-monitor/cgroup.procs', mutate=True)
    if shell('cat ' + TARGET + '/cgroup.procs'):
        raise RuntimeError('Internal process removal was not complete')
    for path in [CG, PARENT, TARGET]:
        enabled = set(shell('cat ' + path + '/cgroup.subtree_control').split())
        missing = [entry for entry in controllers.split() if entry[1:] not in enabled]
        if missing:
            shell('echo "' + ' '.join(missing) + '" > ' + path + '/cgroup.subtree_control', mutate=True)
        if dualio and path == PARENT:
            if shell('cat ' + PARENT + '/io.v2_delegate') != '1':
                shell('test -f ' + PARENT + '/io.v2_delegate; echo 1 > ' + PARENT + '/io.v2_delegate', mutate=True)
            if shell('cat ' + PARENT + '/io.v2_delegate') != '1':
                raise RuntimeError('Guest IO subtree selection did not persist')
    report['native_v2_io_selected'] = dualio
    report['native_v2_cpu_cpuset_delegated'] = native_cpu_cpuset
    report['android_blkio_weights'] = shell('cat /dev/blkio/blkio.weight /dev/blkio/background/blkio.weight')
    report['after_subtree_control'] = {path: shell('cat ' + path + '/cgroup.subtree_control')
                                       for path in [CG, PARENT, TARGET]}
    report['guest_available_controllers'] = shell('cat ' + TARGET + '/cgroup.controllers')
    report['completed'] = True
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
