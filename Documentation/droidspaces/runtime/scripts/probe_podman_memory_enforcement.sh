#!/bin/sh
# At most 32 MiB RAM and no swap in the task's own bounded container.
set -eu
test -f /etc/droidspaces
if [ "$(id -u)" = 0 ]; then printf '0\n' > /proc/self/oom_score_adj; fi
test "$(cat /proc/self/oom_score_adj)" = 0
name=rmx1931-memory-enforcement-$(id -u)
existing=$(podman ps -a --filter name="^$name$" --format '{{.Names}}')
test -z "$existing"
cleanup() { podman rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT HUP INT TERM
timeout 15 podman run --name "$name" --memory=32m --memory-swap=32m \
    localhost/rmx1931-probe:1 sh -c '
    awk '\''BEGIN { s="x"; for(i=0;i<26;i++) s=s s; print length(s); }'\''
    status=$?
    printf "MEMORY_CHILD_EXIT=%s\n" "$status"
    test "$status" = 137 || exit 1
    cat /sys/fs/cgroup/memory.events
    count=$(awk '\''$1=="oom_kill" {print $2}'\'' /sys/fs/cgroup/memory.events)
    test "$count" -gt 0 || exit 1'
printf 'MEMORY_LIMIT_ENFORCEMENT_PASS_UID_%s\n' "$(id -u)"
