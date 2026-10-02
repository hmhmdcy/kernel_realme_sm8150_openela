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
systemctl daemon-reload
systemctl restart user@1000.service
test -S /run/user/1000/bus
test "$(systemctl is-system-running)" = running
printf 'PODMAN_USER_SESSION_READY\n'
