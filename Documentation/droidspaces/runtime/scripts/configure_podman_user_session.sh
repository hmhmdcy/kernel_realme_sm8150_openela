#!/bin/sh
set -eu
test -f /etc/droidspaces
test "$(cat /proc/1/comm)" = systemd
test "$(id -u podmantest)" = 1000
# This is the Ubuntu PID 1, not Android init. Descendants need normal OOM
# eligibility; DroidSpaces monitors outside the guest retain their protection.
printf '0\n' > /proc/self/oom_score_adj
printf '0\n' > /proc/1/oom_score_adj
systemctl daemon-reexec
systemctl daemon-reload
loginctl enable-linger podmantest
systemctl set-property user-1000.slice MemoryAccounting=yes TasksAccounting=yes
systemctl set-property user@1000.service MemoryAccounting=yes TasksAccounting=yes
if grep -qw io /sys/fs/cgroup/cgroup.controllers; then
    # Include native cpuset when available; delegating only at the guest root
    # leaves it unavailable below user@1000.service for rootless Podman.
    directory=/etc/systemd/system/user@1000.service.d
    target=$directory/90-rmx1931-io.conf
    test ! -L "$directory"
    mkdir -p "$directory"
    temporary=$(mktemp /tmp/rmx1931-io-delegate-XXXXXXXX)
    controllers='pids memory cpu io'
    if grep -qw cpuset /sys/fs/cgroup/cgroup.controllers; then controllers="$controllers cpuset"; fi
    printf '[Service]\nDelegate=%s\n' "$controllers" > "$temporary"
    test ! -L "$target"
    if test -e "$target" && ! cmp -s "$temporary" "$target"; then
        # Upgrade only the exact previously installed workspace drop-in.
        previous=$(mktemp /tmp/rmx1931-io-previous-XXXXXXXX)
        printf '[Service]\nDelegate=pids memory cpu io\n' > "$previous"
        cmp "$previous" "$target"
        rm -f "$previous"
        install -o root -g root -m 644 "$temporary" "$target"
    elif test ! -e "$target"; then
        install -o root -g root -m 644 "$temporary" "$target"
    fi
    rm -f "$temporary"
    systemctl daemon-reload
    systemctl set-property user-1000.slice IOAccounting=yes
    systemctl set-property user@1000.service IOAccounting=yes
fi
systemctl daemon-reload
systemctl restart user@1000.service
test -S /run/user/1000/bus
test "$(systemctl is-system-running)" = running
printf 'PODMAN_USER_SESSION_READY\n'
