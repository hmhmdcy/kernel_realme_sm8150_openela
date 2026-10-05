#!/usr/bin/env python3
"""Foreground, single-process OCI notification example for ARM64.

The caller owns the OCI bundle/profile and starts crun under the same UID.
Only four pointer-free demonstration syscalls have handlers. This is an
explicit opt-in profile, not a replacement for the ordinary seccomp profile.
"""
import argparse
import array
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import time

class Data(ctypes.Structure):
    _fields_ = [('nr', ctypes.c_int), ('arch', ctypes.c_uint32),
                ('ip', ctypes.c_uint64), ('args', ctypes.c_uint64 * 6)]
class Notification(ctypes.Structure):
    _fields_ = [('id', ctypes.c_uint64), ('pid', ctypes.c_uint32),
                ('flags', ctypes.c_uint32), ('data', Data)]
class Response(ctypes.Structure):
    _fields_ = [('id', ctypes.c_uint64), ('val', ctypes.c_int64),
                ('error', ctypes.c_int32), ('flags', ctypes.c_uint32)]
class AddFD(ctypes.Structure):
    _fields_ = [('id', ctypes.c_uint64), ('flags', ctypes.c_uint32),
                ('srcfd', ctypes.c_uint32), ('newfd', ctypes.c_uint32),
                ('newfd_flags', ctypes.c_uint32)]
assert ctypes.sizeof(Notification) == 80 and ctypes.sizeof(Response) == 24
assert ctypes.sizeof(AddFD) == 24
libc = ctypes.CDLL(None, use_errno=True)
libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
libc.ioctl.restype = ctypes.c_int

def ioctl(fd, operation, value):
    result = libc.ioctl(fd, operation, ctypes.byref(value))
    if result < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return result

def emit(event, **values):
    print(json.dumps({'event': event, **values}, sort_keys=True), flush=True)

def target_identity(pid):
    base = Path('/proc') / str(pid)
    # comm can contain spaces and parentheses. Field 22 follows final ')'.
    fields = (base / 'stat').read_text().rsplit(')', 1)[1].split()
    status = (base / 'status').read_text().splitlines()
    uid = int(next(x for x in status if x.startswith('Uid:')).split()[1])
    return (fields[19], uid, os.readlink(base / 'ns/pid'), os.readlink(base / 'ns/user'))

def alarm_handler(*unused):
    raise TimeoutError('Notification operation deadline expired')

def accept_listener(server, args, deadline):
    while time.monotonic() < deadline:
        server.settimeout(max(.01, deadline - time.monotonic()))
        connection, _ = server.accept()
        descriptors = []
        accepted = False
        try:
            peer_pid, peer_uid, peer_gid = struct.unpack('3i', connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer_uid != os.getuid():
                raise ValueError('Peer UID does not own this broker')
            connection.settimeout(max(.01, deadline - time.monotonic()))
            content = b''
            while True:
                data, ancillary, flags, _ = connection.recvmsg(8192,
                    socket.CMSG_SPACE(16 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
                for level, kind, raw in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        values = array.array('i')
                        values.frombytes(raw[:len(raw) - len(raw) % values.itemsize])
                        descriptors.extend(values)
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    raise ValueError('Truncated listener message')
                content += data
                if not data or len(content) > 65536:
                    raise ValueError('Missing or oversized listener message')
                try:
                    message = json.loads(content)
                    break
                except json.JSONDecodeError:
                    continue
            state = message.get('state', {})
            pid = message.get('pid')
            if (message.get('ociVersion') != '0.2.0' or
                    message.get('fds') != ['seccompFd'] or len(descriptors) != 1 or
                    message.get('metadata') != args.token or
                    state.get('id') != args.container_id or state.get('pid') != pid or
                    state.get('bundle') != str(args.bundle) or state.get('status') != 'creating' or
                    not isinstance(pid, int) or pid <= 1):
                raise ValueError('Listener metadata does not match the owned OCI launch')
            identity = target_identity(pid)
            if identity[1] != os.getuid():
                raise ValueError('Target UID does not own this broker')
            kind = os.readlink('/proc/self/fd/' + str(descriptors[0]))
            if not kind.startswith('anon_inode:') or 'seccomp notify' not in kind:
                raise ValueError('Received descriptor is not a seccomp notification listener')
            emit('listener_accepted', target_pid=pid, target_starttime=identity[0],
                 peer_pid=peer_pid, peer_uid=peer_uid, pid_ns=identity[2], user_ns=identity[3],
                 container_id=args.container_id)
            accepted = True
            return descriptors[0], pid, identity
        except (ValueError, OSError) as error:
            emit('listener_rejected', reason=str(error))
        finally:
            connection.close()
            if not accepted:
                for descriptor in descriptors:
                    os.close(descriptor)
    raise TimeoutError('No authenticated OCI listener arrived')

def serve(listener, pid, identity, args, deadline):
    poller = select.poll()
    poller.register(listener, select.POLLIN | select.POLLHUP | select.POLLERR)
    while time.monotonic() < deadline:
        events = poller.poll(max(1, int((deadline - time.monotonic()) * 1000)))
        if not events:
            break
        event = events[0][1]
        if event & select.POLLHUP:
            emit('listener_hup')
            return
        if not event & select.POLLIN:
            raise RuntimeError('Unexpected listener poll event')
        request = Notification()
        try:
            ioctl(listener, 0xc0502100, request)
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.EINTR):
                emit('request_gone', errno=error.errno)
                continue
            raise
        ident = ctypes.c_uint64(request.id)
        try:
            ioctl(listener, 0x40082102, ident)
            same_target = request.pid == pid and target_identity(pid) == identity
        except (OSError, FileNotFoundError):
            emit('request_gone', id=request.id)
            continue
        response = Response(id=request.id, error=-errno.EPERM)
        decision = 'deny'
        if same_target and request.data.arch == 0xc00000b7:
            if args.close_on_request:
                emit('listener_closed_on_request', id=request.id)
                return
            if request.data.nr == 173:  # getppid: fixed numeric emulation
                response.error, response.val = 0, 777
                decision = 'emulate'
            elif request.data.nr == 172:  # getpid: harmless pointer-free CONTINUE
                response.error, response.flags = 0, 1
                decision = 'continue'
            elif request.data.nr == 176:  # getgid: inject broker-created data only
                descriptor = os.memfd_create('rmx1931-notify-example', os.MFD_CLOEXEC)
                try:
                    os.write(descriptor, b'notify-owned-data\n')
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    add = AddFD(id=request.id, srcfd=descriptor, newfd_flags=os.O_CLOEXEC)
                    response.val = ioctl(listener, 0x40182103, add)
                    response.error = 0
                    decision = 'addfd'
                finally:
                    os.close(descriptor)
        try:
            ioctl(listener, 0x40082102, ident)
            ioctl(listener, 0xc0182101, response)
            emit('request_answered', id=request.id, target_pid=request.pid,
                 syscall=request.data.nr, decision=decision, value=response.val, error=response.error)
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise
            emit('request_gone', id=request.id)
    emit('deadline_closed_listener')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--container-id', required=True)
    parser.add_argument('--token', required=True)
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('--close-on-request', action='store_true')
    args = parser.parse_args()
    args.bundle = args.bundle.resolve(strict=True)
    parent = args.socket.parent.resolve(strict=True)
    if (not args.socket.is_absolute() or args.socket.exists() or
            parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077 or
            len(args.token) < 32 or not 1 <= args.timeout <= 300):
        raise RuntimeError('Broker requires a new socket in an owned private directory and a launch token')
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(args.timeout + 2)
    deadline = time.monotonic() + args.timeout
    listener = None
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(args.socket))
        os.chmod(args.socket, 0o600)
        server.listen(4)
        emit('broker_ready', uid=os.getuid(), socket_mode='0600', timeout=args.timeout)
        listener, pid, identity = accept_listener(server, args, deadline)
        serve(listener, pid, identity, args, deadline)
    finally:
        if listener is not None:
            os.close(listener)
        server.close()
        args.socket.unlink(missing_ok=True)
        signal.alarm(0)

if __name__ == '__main__':
    main()
