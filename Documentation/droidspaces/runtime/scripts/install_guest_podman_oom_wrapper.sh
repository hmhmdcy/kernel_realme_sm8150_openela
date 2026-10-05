#!/bin/sh
# This isolated guest only: preserve daemon protection, normalize Podman callers.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
case "$(uname -r)" in
    4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2|4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2-lowrisk2|4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2-lr2-ksu3) ;;
    4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-utilities|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-bbr|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-checkpoint|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-network|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-io) ;;
    4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-resources|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-dualio|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-harden1) ;;
    4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp2|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp3|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp4) ;;
    4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h3bm|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h3bm2|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h4sn|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h5bf|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h5bf2|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16ps|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf) ;;
    *) exit 1 ;;
esac
temporary=/tmp/rmx1931-tests/podman-oom-wrapper
test ! -L "$temporary"
cat > "$temporary" <<'EOF'
#!/bin/sh
# DroidSpaces may pass -1000 OOM protection to commands. Podman workloads
# need eligible victims for memcg enforcement. Normalize only this caller.
if [ -f /etc/droidspaces ] && [ "$(cat /proc/self/oom_score_adj)" = -1000 ]; then
    printf '0\n' > /proc/self/oom_score_adj || exit 1
fi
exec /usr/bin/podman "$@"
EOF
target=/usr/local/bin/podman
test ! -L "$target"
if [ -e "$target" ]; then
    cmp "$temporary" "$target"
else
    install -o root -g root -m 755 "$temporary" "$target"
fi
sha256sum "$target"
test "$(command -v podman)" = "$target"
printf 'GUEST_PODMAN_OOM_WRAPPER_INSTALLED\n'
launcher=/tmp/rmx1931-tests/podman-rootless-launcher
test ! -L "$launcher"
cat > "$launcher" <<'EOF'
#!/bin/sh
set -eu
test -f /etc/droidspaces
if [ "$(id -u)" != 0 ]; then exec /usr/local/bin/podman "$@"; fi
printf '0\n' > /proc/self/oom_score_adj
exec runuser -u podmantest -- env HOME=/home/podmantest USER=podmantest \
    LOGNAME=podmantest XDG_RUNTIME_DIR=/run/user/1000 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus /usr/bin/podman "$@"
EOF
target=/usr/local/bin/podman-rootless
test ! -L "$target"
if [ -e "$target" ]; then cmp "$launcher" "$target"; else install -o root -g root -m 755 "$launcher" "$target"; fi
sha256sum "$target"
printf 'GUEST_ROOTLESS_LAUNCHER_INSTALLED\n'
