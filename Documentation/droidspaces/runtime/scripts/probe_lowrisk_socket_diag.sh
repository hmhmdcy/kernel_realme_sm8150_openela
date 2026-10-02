#!/bin/sh
set -eu
test -f /etc/droidspaces
python3 - <<'PY'
import json, os, socket, struct, subprocess, tempfile

def dump(family):
    # Linux 4.14 UAPI: SOCK_DIAG_BY_FAMILY over NETLINK_SOCK_DIAG.
    request = (struct.pack('=BBHIIIII', family, 0, 0, 0xffffffff, 0, 1, 0xffffffff, 0xffffffff)
               if family == socket.AF_UNIX else
               struct.pack('=BBHIIII', family, 0, 0, 0, 1, 0xffffffff, 0xffffffff))
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as diag:
        diag.settimeout(5)
        diag.bind((0, 0))
        diag.send(struct.pack('=IHHII', 16 + len(request), 20, 0x301, 123, 0) + request)
        inodes = []
        while True:
            data = diag.recv(1024 * 1024)
            offset = 0
            while offset + 16 <= len(data):
                length, kind, flags, seq, pid = struct.unpack_from('=IHHII', data, offset)
                if length < 16 or offset + length > len(data):
                    raise RuntimeError('Malformed diagnostic response')
                payload = data[offset + 16:offset + length]
                if kind == 2:
                    error = struct.unpack_from('=i', payload)[0]
                    if error:
                        raise OSError(-error, os.strerror(-error))
                elif kind == 3:
                    if flags & 0x10:
                        raise RuntimeError('Interrupted diagnostic dump')
                    return inodes
                elif kind == 20:
                    inodes.append(struct.unpack_from('=I', payload, 16 if family == socket.AF_NETLINK else 4)[0])
                offset += (length + 3) & ~3

results = []
with tempfile.TemporaryDirectory(prefix='rmx1931-socket-diag-') as directory:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix, socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as netlink, socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as packet:
        path = directory + '/probe.sock'
        unix.bind(path)
        unix.listen(1)
        netlink.bind((0, 0))
        packet.bind(('lo', 0))
        for label, sock, options in [('unix', unix, ['-xapn']), ('netlink', netlink, ['-f', 'netlink', '-apn']), ('packet', packet, ['-0apn'])]:
            inode = os.fstat(sock.fileno()).st_ino
            row = {'family': label, 'test_inode': inode}
            try:
                inodes = dump(sock.family)
                if inode not in inodes:
                    raise RuntimeError('Live test socket missing from kernel diagnostic dump')
                ss = subprocess.run(['ss', *options], capture_output=True, text=True, timeout=10)
                if ss.returncode or str(os.getpid()) not in ss.stdout:
                    raise RuntimeError('ss did not report the live test process: ' + ss.stderr)
                row.update(passed=True, dump_socket_count=len(inodes), ss_test_rows=[line for line in ss.stdout.splitlines() if str(os.getpid()) in line])
            except Exception as error:
                row.update(passed=False, error=str(error))
            results.append(row)
print(json.dumps(results, indent=2))
if not all(row['passed'] for row in results):
    raise SystemExit(1)
print('UNIX_NETLINK_PACKET_DIAG_AND_SS_PASS')
PY
