#!/usr/bin/python3
"""Foreground memory PSI notifications for one running Podman container.

Read only: never changes limits, stops containers, or changes host LMKD.
Pin the full container ID, process start time and open cgroup directory.
"""
import argparse
import json
import os
from pathlib import Path
import re
import select
import subprocess
import time


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout


def process_identity(pid):
    text = Path('/proc', str(pid), 'stat').read_text()
    fields = text[text.rindex(')') + 2:].split()
    return fields[19]  # Field 22, with pid and comm removed.


def group_path(pid):
    rows = [line[3:] for line in Path('/proc', str(pid), 'cgroup').read_text().splitlines() if line.startswith('0::')]
    if len(rows) != 1:
        raise RuntimeError('Unified cgroup identity unavailable')
    return rows[0]


def container_group_matches(relative, cid):
    components = relative.strip('/').split('/')
    if not components or any(part in ('', '.', '..') for part in components):
        return False
    scopes = ('libpod-' + cid + '.scope', 'libpod-' + cid)
    # crun/runc can put the payload in the standard scope's "container"
    # child. Accept that exact child as well as the scope itself.
    return components[-1] in scopes or (len(components) >= 2 and
        components[-1] == 'container' and components[-2] in scopes)


def open_group(relative):
    components = relative.strip('/').split('/')
    if not components or any(part in ('', '.', '..') for part in components):
        raise RuntimeError('Invalid cgroup path')
    fd = os.open('/sys/fs/cgroup', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in components:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(fd) as stream:
        return stream.read(16384).strip()


def emit(data):
    print(json.dumps(data, sort_keys=True), flush=True)


def watch(args):
    if os.getuid() != 0 or not Path('/etc/droidspaces').is_file():
        raise RuntimeError('This operator tool requires isolated guest root')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.name):
        raise RuntimeError('Invalid container name or ID')
    if not (500000 <= args.window_us <= 10000000 and 0 < args.threshold_us < args.window_us
            and 0 < args.timeout <= 600 and 1 <= args.events <= 100):
        raise RuntimeError('Pressure threshold, window or deadline outside bounds')
    cli = ['podman-rootless'] if args.mode == 'rootless' else ['podman']
    metadata = json.loads(command(cli + ['inspect', '--type=container', args.name]))
    if len(metadata) != 1:
        raise RuntimeError('Ambiguous container')
    container = metadata[0]
    cid = container['Id']
    pid = container['State']['Pid']
    if not re.fullmatch(r'[a-f0-9]{64}', cid) or type(pid) is not int or pid <= 1 or not container['State']['Running']:
        raise RuntimeError('Container is not running')
    start = process_identity(pid)
    relative = group_path(pid)
    if not container_group_matches(relative, cid):
        raise RuntimeError('Container ID does not match process cgroup')
    directory = open_group(relative)
    pressure = None
    try:
        if str(pid) not in read_file(directory, 'cgroup.procs').split():
            raise RuntimeError('Container process left its group')
        maximum = read_file(directory, 'memory.max')
        high = read_file(directory, 'memory.high')
        pressure = os.open('memory.pressure', os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        trigger = f'{args.stall} {args.threshold_us} {args.window_us}\0'.encode()
        if os.write(pressure, trigger) != len(trigger):
            raise RuntimeError('Partial PSI trigger write')
        poller = select.poll()
        poller.register(pressure, select.POLLPRI | select.POLLERR | select.POLLHUP)
        inode = os.fstat(directory).st_ino
        emit({'event': 'ready', 'mode': args.mode, 'container_id': cid, 'pid': pid,
              'process_starttime': start, 'cgroup': relative, 'cgroup_inode': inode,
              'memory_max': maximum, 'memory_high': high,
              'threshold_us': args.threshold_us, 'window_us': args.window_us,
              'pressure': read_file(directory, 'memory.pressure')})
        deadline = time.monotonic() + args.timeout
        count = 0
        while time.monotonic() < deadline and count < args.events:
            if process_identity(pid) != start or group_path(pid) != relative:
                raise RuntimeError('Pinned process exited or moved; refusing a replacement')
            for _, event in poller.poll(min(250, max(1, int((deadline - time.monotonic()) * 1000)))):
                if event & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
                    raise RuntimeError('Pinned pressure group is gone')
                if event & select.POLLPRI:
                    count += 1
                    emit({'event': 'memory-pressure', 'count': count, 'container_id': cid,
                          'cgroup_inode': inode, 'pressure': read_file(directory, 'memory.pressure'),
                          'memory_events': read_file(directory, 'memory.events')})
        emit({'event': 'complete', 'notifications': count, 'container_id': cid,
              'reason': 'event limit' if count == args.events else 'deadline'})
        return 0 if count == args.events else 3
    finally:
        if pressure is not None:
            os.close(pressure)
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['rootful', 'rootless'], required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--stall', choices=['some', 'full'], default='some')
    parser.add_argument('--threshold-us', type=int, default=50000)
    parser.add_argument('--window-us', type=int, default=1000000)
    parser.add_argument('--timeout', type=float, default=60)
    parser.add_argument('--events', type=int, default=1)
    return watch(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
