#!/bin/sh
# A minimal disposable native ARM64 container, with no daemon or host networking.
set -eu
test -f /etc/droidspaces
command -v lxc-start >/dev/null || { echo LXC_TOOL_UNAVAILABLE; exit 77; }
command -v busybox >/dev/null || { echo LXC_STATIC_BUSYBOX_UNAVAILABLE; exit 77; }
base=$(mktemp -d /tmp/rmx1931-lxc-XXXXXXXX)
case "$base" in /tmp/rmx1931-lxc-????????) ;; *) exit 1 ;; esac
name=rmx1931-extension-probe-$$
before=$(hostname)
mkdir -p "$base/rootfs/bin" "$base/rootfs/dev" "$base/rootfs/proc" "$base/rootfs/sys" "$base/rootfs/tmp" "$base/rootfs/run"
cp "$(command -v busybox)" "$base/rootfs/bin/busybox"
chmod 755 "$base/rootfs/bin/busybox"
ln -s busybox "$base/rootfs/bin/sh"
cat > "$base/rootfs/probe.sh" <<'CHILD'
#!/bin/sh
set -eu
test "$$" = 1
test "$(/bin/busybox hostname)" = rmx1931-lxc-probe
test -r /proc/1/status
/bin/busybox mkdir /tmp/native-lxc-write
echo NATIVE_ARM64_LXC > /tmp/native-lxc-write/payload
test "$(/bin/busybox cat /tmp/native-lxc-write/payload)" = NATIVE_ARM64_LXC
echo LXC_NATIVE_PID1_HOSTNAME_PROC_WRITE_PASS
echo LXC_NATIVE_PID1_HOSTNAME_PROC_WRITE_PASS > /tmp/result.txt
CHILD
cat > "$base/config" <<CONFIG
lxc.rootfs.path = dir:$base/rootfs
lxc.uts.name = rmx1931-lxc-probe
lxc.net.0.type = empty
lxc.mount.auto = proc:rw sys:ro
lxc.autodev = 1
lxc.init.cmd = /bin/busybox sh /probe.sh
lxc.log.file = $base/lxc.log
lxc.log.level = INFO
CONFIG
mkdir "$base/$name"
cp "$base/config" "$base/$name/config"
if ! timeout 35 lxc-start -n "$name" -P "$base" -F > "$base/stdout" 2> "$base/stderr"; then
    cat "$base/stderr"
    tail -n 40 "$base/lxc.log"
    echo "LXC_PROBE_FAILED diagnostics=$base"
    exit 1
fi
cat "$base/stdout"
if ! grep -q LXC_NATIVE_PID1_HOSTNAME_PROC_WRITE_PASS "$base/rootfs/tmp/result.txt"; then
    cat "$base/stderr"
    tail -n 40 "$base/lxc.log"
    exit 1
fi
cat "$base/rootfs/tmp/result.txt"
test "$(hostname)" = "$before"
test "$(lxc-info -n "$name" -P "$base" -sH)" = STOPPED
if grep -q 'Failed to load bpf program' "$base/lxc.log"; then
    echo LXC_DEVICE_BPF_FILTER_NOT_VERIFIED
fi
echo "LXC_CONTAINER_START_EXIT_PASS diagnostics=$base"
