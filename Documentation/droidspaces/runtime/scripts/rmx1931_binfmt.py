#!/usr/bin/python3
"""Run a foreground command with its own userns QEMU amd64 registry.

Use VFS storage for Podman in this legacy kernel's user namespaces. For a
rootless command, enter the normal Podman user namespace first:
  podman-rootless unshare rmx1931-binfmt -- podman --storage-driver=vfs ...
The handler exists only for this foreground command's lifetime.
"""
import argparse
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


def checked(result, operation):
    if result != 0:
        raise OSError(ctypes.get_errno(), operation)


def identity_map(name):
    # map_id_range_down() requires each range to fit one parent extent.
    # Podman maps its UID 0 separately from the subordinate UID interval.
    extents = sorted(tuple(map(int, line.split())) for line in
                     Path('/proc/self/' + name).read_text().splitlines())
    next_id = 0
    rows = []
    for first, lower, count in extents:
        if next_id == 65536:
            break
        if first != next_id:
            raise RuntimeError('Parent ' + name + ' does not cover IDs 0..65535')
        length = min(count, 65536 - first)
        rows.append('%d %d %d\n' % (first, first, length))
        next_id += length
    if next_id != 65536 or len(rows) > 5:
        raise RuntimeError('Parent mapping exceeds this kernel\'s supported extent layout')
    return ''.join(rows)


def execute(command, interpreter):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_ulong, ctypes.c_void_p]
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    checked(libc.mount(None, b'/', None, (1 << 18) | (1 << 14), None), 'private mounts')
    directory = Path(tempfile.mkdtemp(prefix='rmx1931-binfmt-', dir='/var/tmp'))
    mounted = False
    child = None

    def forward(signum, frame):
        if child is not None:
            child.send_signal(signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, forward)
    try:
        checked(libc.mount(b'none', os.fsencode(directory), b'binfmt_misc', 0, None), 'binfmt mount')
        mounted = True
        # This namespace was just created by us. Never change an ancestor's registry.
        assert sorted(p.name for p in directory.iterdir()) == ['register', 'status']
        magic = bytes.fromhex('7f454c4602010100000000000000000002003e00')
        mask = bytes.fromhex('ffffffffffffff00fffffffffffffffffeffffff')
        escape = lambda data: ''.join('\\x%02x' % b for b in data)
        (directory / 'register').write_text(':qemu-x86_64:M::' + escape(magic) + ':' +
                                            escape(mask) + ':' + str(interpreter) + ':F')
        assert 'flags: F' in (directory / 'qemu-x86_64').read_text()
        child = subprocess.Popen(command)
        status = child.wait()
        return status if status >= 0 else 128 - status
    finally:
        if mounted:
            handler = directory / 'qemu-x86_64'
            if handler.exists():
                handler.write_text('-1')
            checked(libc.umount2(os.fsencode(directory), 0), 'binfmt unmount')
        directory.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interpreter', type=Path, default=Path('/usr/bin/qemu-x86_64-static'))
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == '--':
        command = command[1:]
    if not command:
        parser.error('a foreground command is required after --')
    if not Path('/etc/droidspaces').is_file():
        parser.error('run inside the isolated Droidspaces guest')
    if os.geteuid() != 0:
        parser.error('use podman-rootless unshare first for a non-root user')
    if any(a in ('-d', '--detach') or a.startswith('--detach=') for a in command):
        parser.error('detached commands require a persistent namespace service')
    interpreter = args.interpreter.resolve(strict=True)
    if ':' in str(interpreter) or '\n' in str(interpreter):
        parser.error('invalid interpreter path')
    if not os.access(interpreter, os.X_OK):
        parser.error('interpreter must be executable')
    maps = {name: identity_map(name) for name in ('uid_map', 'gid_map')}
    ready_r, ready_w = os.pipe()
    go_r, go_w = os.pipe()
    pid = os.fork()
    if not pid:
        os.close(ready_r)
        os.close(go_w)
        libc = ctypes.CDLL(None, use_errno=True)
        checked(libc.unshare(0x10000000 | 0x00020000), 'new user and mount namespace')
        os.write(ready_w, b'1')
        os.close(ready_w)
        if os.read(go_r, 1) != b'1':
            os._exit(125)
        os.close(go_r)
        raise SystemExit(execute(command, interpreter))
    os.close(ready_w)
    os.close(go_r)

    def forward(signum, frame):
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, forward)
    try:
        if os.read(ready_r, 1) != b'1':
            raise RuntimeError('namespace creation failed')
        # A bounded map also permits crun/runc to recognize the user namespace.
        # Supports container UIDs/GIDs 0..65535 without initial-userns BPF rights.
        setgroups = Path('/proc') / str(pid) / 'setgroups'
        if setgroups.exists():
            setgroups.write_text('deny\n')
        for name in ('uid_map', 'gid_map'):
            try:
                (Path('/proc') / str(pid) / name).write_text(maps[name])
            except OSError as error:
                raise RuntimeError('Cannot write ' + name + '; parent map=' +
                                   Path('/proc/self/' + name).read_text().strip()) from error
        os.write(go_w, b'1')
    finally:
        os.close(ready_r)
        os.close(go_w)
        _, status = os.waitpid(pid, 0)
    result = os.waitstatus_to_exitcode(status)
    raise SystemExit(result if result >= 0 else 128 - result)


if __name__ == '__main__':
    main()
