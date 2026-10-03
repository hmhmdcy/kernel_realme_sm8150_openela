#!/bin/sh
# Build and mount only a disposable read-only EROFS image in the isolated guest.
set -eu
test -f /etc/droidspaces
if ! grep -qw erofs /proc/filesystems; then echo EROFS_KERNEL_UNAVAILABLE; exit 77; fi
command -v mkfs.erofs >/dev/null || { echo EROFS_TOOL_UNAVAILABLE; exit 77; }
base=$(mktemp -d /var/tmp/rmx1931-erofs-XXXXXXXX)
case "$base" in /var/tmp/rmx1931-erofs-????????) ;; *) exit 1 ;; esac
mkdir "$base/source" "$base/mounted"
control="$base/unused-control"
# Temporary device nodes belong to this guest's isolated /dev (not nodev /tmp).
loopnode=/dev/rmx1931-erofs-probe-loop
control=/dev/rmx1931-erofs-probe-control
test ! -e "$loopnode"; test ! -L "$loopnode"
test ! -e "$control"; test ! -L "$control"
attached=0
cleanup() {
    if mountpoint -q "$base/mounted"; then umount "$base/mounted"; fi
    if [ "$attached" = 1 ]; then losetup -d "$loopnode"; fi
    rm -f "$loopnode" "$control"
    # Keep the image and metadata on failure for diagnosis; no recursive deletion.
}
trap cleanup EXIT HUP INT TERM
python3 - "$base/source" <<'PY'
import hashlib, os, sys
from pathlib import Path
base = Path(sys.argv[1])
data = (bytes(range(256)) * 256 + b'EROFS_COMPRESSED_BLOCK\n') * 16
(base / 'payload.bin').write_bytes(data)
os.setxattr(base / 'payload.bin', 'user.rmx1931', b'EROFS_XATTR_PASS')
os.link(base / 'payload.bin', base / 'hardlink')
os.symlink('payload.bin', base / 'symlink')
(base / 'SHA256SUMS').write_text(hashlib.sha256(data).hexdigest() + '  payload.bin\n')
PY
# Legacy compression avoids requiring new packed/fragment inode features.
mkfs.erofs -E legacy-compress -zlz4 "$base/probe.erofs" "$base/source"
number=$(python3 - "$control" "$loopnode" <<'PY'
import fcntl, os, stat, sys
from pathlib import Path
os.mknod(sys.argv[1], stat.S_IFCHR | 0o600, os.makedev(10, 237))
with open(sys.argv[1], 'rb', buffering=0) as control:
    number = fcntl.ioctl(control, 0x4c82)
os.unlink(sys.argv[1])
major, minor = map(int, Path('/sys/class/block/loop%s/dev' % number).read_text().split(':'))
assert major == 7
os.mknod(sys.argv[2], stat.S_IFBLK | 0o600, os.makedev(major, minor))
print(number)
PY
)
losetup --read-only "$loopnode" "$base/probe.erofs"
attached=1
mount -t erofs -o ro,nodev,nosuid "$loopnode" "$base/mounted"
(cd "$base/mounted" && sha256sum -c SHA256SUMS)
python3 - "$base/mounted" <<'PY'
import errno, os, sys
from pathlib import Path
base = Path(sys.argv[1])
assert os.getxattr(base / 'payload.bin', 'user.rmx1931') == b'EROFS_XATTR_PASS'
assert (base / 'payload.bin').stat().st_ino == (base / 'hardlink').stat().st_ino
assert (base / 'symlink').read_bytes() == (base / 'payload.bin').read_bytes()
try:
    (base / 'forbidden-write').write_bytes(b'x')
except OSError as error:
    assert error.errno == errno.EROFS, error
else:
    raise RuntimeError('Read-only image accepted a write')
print('EROFS_HASH_XATTR_LINKS_READONLY_PASS')
PY
umount "$base/mounted"
losetup -d "$loopnode"
attached=0
test ! -e "/sys/class/block/loop$number/loop/backing_file"
echo "EROFS_MOUNT_UNMOUNT_PASS fixture=$base"
