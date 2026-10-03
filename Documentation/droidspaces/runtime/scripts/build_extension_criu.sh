#!/bin/sh
# Native guest build from one verified upstream release, without replacing apt packages.
set -eu
test -f /etc/droidspaces
test "$(uname -m)" = aarch64
revision=f8b14286b092853a4485813e1efd564109df9123
digest=5cbbeda7313b8f8299f7bfbc63ce4289a0f715e1e2ca57d1e887ff2e0fecd9bd
base=/opt/rmx1931-extensions/criu-3.19
test ! -L /opt/rmx1931-extensions
test ! -L "$base"
if [ "${1:-}" = --resume ]; then
    test -f "$base/source.tar.gz"
    echo "$digest  $base/source.tar.gz" | sha256sum -c -
else
    test ! -e "$base"
    mkdir -p "$base"
fi
export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends build-essential pkgconf libprotobuf-c-dev libprotobuf-dev protobuf-c-compiler libnl-3-dev libnl-route-3-dev libcap-dev libnet1-dev libaio-dev libbsd-dev busybox-static
if [ ! -f "$base/source.tar.gz" ]; then
    curl --fail --location --connect-timeout 15 --max-time 120 "https://codeload.github.com/checkpoint-restore/criu/tar.gz/$revision" -o "$base/source.tar.gz"
fi
echo "$digest  $base/source.tar.gz" | sha256sum -c -
python3 - "$base" "$revision" <<'PY'
import shutil, sys, tarfile
from pathlib import Path
base, revision = Path(sys.argv[1]), sys.argv[2]
with tarfile.open(base / 'source.tar.gz') as archive:
    assert all(member.name == 'criu-' + revision or member.name.startswith('criu-' + revision + '/') for member in archive)
    members = []
    for member in archive:
        if member.issym() and member.linkname.startswith('/'):
            assert member.name == 'criu-' + revision + '/images/google/protobuf/descriptor.proto'
            assert member.linkname == '/usr/include/google/protobuf/descriptor.proto'
            continue
        members.append(member)
    archive.extractall(base, members=members, filter='data')
# Upstream's sole absolute symlink references a distro build dependency.
shutil.copyfile('/usr/include/google/protobuf/descriptor.proto',
                base / ('criu-' + revision) / 'images/google/protobuf/descriptor.proto')
PY
cd "$base/criu-$revision"
python3 - "$base" <<'PY'
import difflib, hashlib, sys
from pathlib import Path
base = Path(sys.argv[1])
target = next(base.glob('criu-*/criu/net.c'))
before = target.read_text()
old = '\tfor (i = 0; i < *n; i++) {\n\t\tsnprintf(path[i], MAX_CONF_UNIX_PATH, CONF_UNIX_FMT, unix_conf_entries[i]);'
new = '\tfor (i = 0; i < ARRAY_SIZE(unix_conf_entries); i++) {\n\t\tsnprintf(path[i], MAX_CONF_UNIX_PATH, CONF_UNIX_FMT, unix_conf_entries[i]);'
assert before.count(old) == 1
after = before.replace(old, new)
# *n was checked against this exact count above the loop. A constant bound
# also lets GCC 13/FORTIFY prove the per-row array size without disabling it.
target.write_text(after)
(base / 'gcc13-array-bound.patch').write_text(''.join(difflib.unified_diff(
    before.splitlines(True), after.splitlines(True), fromfile='a/criu/net.c', tofile='b/criu/net.c')))
(base / 'modified-source.txt').write_text('criu/net.c ' + hashlib.sha256(after.encode()).hexdigest() + '\n')
PY
if ! make -j2 criu > "$base/build.log" 2>&1; then
    tail -n 60 "$base/build.log"
    exit 1
fi
./criu/criu --version
test ! -e /usr/local/sbin/criu; test ! -L /usr/local/sbin/criu
install -m 755 criu/criu /usr/local/sbin/criu
printf 'upstream_commit=%s\narchive_sha256=%s\n' "$revision" "$digest" > "$base/source-lock.txt"
sha256sum /usr/local/sbin/criu >> "$base/source-lock.txt"
sha256sum "$base/gcc13-array-bound.patch" >> "$base/source-lock.txt"
cat "$base/modified-source.txt" >> "$base/source-lock.txt"
cat "$base/source-lock.txt"
echo CRIU_NATIVE_ARM64_BUILD_PASS
