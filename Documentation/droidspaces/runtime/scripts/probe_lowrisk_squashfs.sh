#!/bin/sh
set -eu
test -f /etc/droidspaces
base=/tmp/rmx1931-lowrisk-fixtures
test -d "$base"
test ! -L "$base"
mountpoint="$base/mounted"
test ! -L "$mountpoint"
mkdir -p "$mountpoint"
loopnode=/dev/rmx1931-lowrisk-loop-device
control=/dev/rmx1931-lowrisk-loop-control
test ! -e "$loopnode"
test ! -L "$loopnode"
test ! -e "$control"
test ! -L "$control"
attached=0
cleanup() {
    if mountpoint -q "$mountpoint"; then umount "$mountpoint"; fi
    if [ "$attached" = 1 ]; then losetup -d "$loopnode"; attached=0; fi
    rm -f "$loopnode" "$control"
}
trap cleanup EXIT HUP INT TERM
for compression in gzip xz; do
    image="$base/$compression.squashfs"
    test -f "$image"
    test ! -L "$image"
    # DroidSpaces hw_access=none intentionally has no /dev/loop* nodes.
    # Create temporary nodes in this guest's isolated /dev, obtain a
    # free kernel loop via the control ioctl, and never touch Android nodes.
    loopnumber="$(python3 - "$control" "$loopnode" <<'PY'
import fcntl, os, stat, sys
from pathlib import Path
os.mknod(sys.argv[1], stat.S_IFCHR | 0o600, os.makedev(10, 237))
with open(sys.argv[1], 'rb', buffering=0) as control:
    number = fcntl.ioctl(control, 0x4c82)
os.unlink(sys.argv[1])
# This Android kernel reserves partition minors for each loop device.
major, minor = map(int, Path('/sys/class/block/loop' + str(number) + '/dev').read_text().split(':'))
assert major == 7
os.mknod(sys.argv[2], stat.S_IFBLK | 0o600, os.makedev(major, minor))
print(number)
PY
)"
    losetup --read-only "$loopnode" "$image"
    attached=1
    mount -t squashfs -o ro,nodev,nosuid "$loopnode" "$mountpoint"
    test "$(findmnt -n -o FSTYPE -T "$mountpoint")" = squashfs
    findmnt -n -o FSTYPE,OPTIONS -T "$mountpoint"
    (cd "$mountpoint" && sha256sum -c SHA256SUMS)
    test "$(stat -c %u:%g "$mountpoint/payload/data.bin")" = 0:0
    test "$(stat -c %i "$mountpoint/payload/data.bin")" = "$(stat -c %i "$mountpoint/data-hardlink")"
    test "$(readlink "$mountpoint/tool-alias")" = payload/tool.sh
    test "$("$mountpoint/tool-alias")" = SQUASHFS_TOOL_EXEC_PASS
    python3 - "$mountpoint" <<'PY'
import errno, os, sys
assert os.getxattr(sys.argv[1] + '/payload/data.bin', 'user.rmx1931') == b'LOWRISK_XATTR'
print('SQUASHFS_USER_XATTR_READ_PASS')
try:
    descriptor = os.open(sys.argv[1] + '/forbidden-write', os.O_WRONLY | os.O_CREAT, 0o600)
except OSError as error:
    assert error.errno == errno.EROFS, error
else:
    os.close(descriptor)
    raise RuntimeError('Read-only filesystem accepted a write')
print('READ_ONLY_EROFS_PASS')
PY
    umount "$mountpoint"
    losetup -d "$loopnode"
    attached=0
    test ! -e "/sys/class/block/loop$loopnumber/loop/backing_file"
    rm "$loopnode"
    printf 'SQUASHFS_%s_MOUNT_HASH_EXEC_READONLY_UNMOUNT_PASS\n' "$compression"
done
rmdir "$mountpoint"
printf 'SQUASHFS_ACCEPTANCE_PASS\n'
