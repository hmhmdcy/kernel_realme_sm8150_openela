#!/bin/sh
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
temporary=$(mktemp /tmp/rmx1931-lxc-start-XXXXXXXX)
trap 'rm -f "$temporary"' EXIT HUP INT TERM
cat > "$temporary" <<'SH'
#!/bin/sh
# The kernel charges BPF maps/programs against the shared UID's memlock budget.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
ulimit -l 65536
exec /usr/bin/lxc-start "$@"
SH
target=/usr/local/bin/lxc-start-bpf
test ! -L "$target"
if [ -e "$target" ]; then cmp "$temporary" "$target"; else install -m 755 -o root -g root "$temporary" "$target"; fi
sha256sum "$target"
printf 'LXC_SCOPED_BPF_LAUNCHER_INSTALLED\n'
