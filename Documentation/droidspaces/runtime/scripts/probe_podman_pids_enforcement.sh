#!/bin/sh
set -eu
test -f /etc/droidspaces
image=localhost/rmx1931-probe:1
work='yes 1 | head -n 20 | xargs -n 1 -P 20 sleep'
timeout 8 podman run --rm "$image" sh -ec "$work"
printf 'UNLIMITED_FORK_CONTROL_PASS\n'
set +e
timeout 8 podman run --rm --pids-limit=8 "$image" sh -ec "$work" > /tmp/rmx1931-pids-proof-$(id -u) 2>&1
status=$?
set -e
cat /tmp/rmx1931-pids-proof-$(id -u)
printf 'PIDS_LIMIT_EXIT=%s\n' "$status"
test "$status" != 0
test "$status" != 124
grep -qi -e 'resource temporarily unavailable' -e 'cannot fork' /tmp/rmx1931-pids-proof-$(id -u)
printf 'PIDS_ENFORCEMENT_PASS_UID_%s\n' "$(id -u)"
