#!/bin/sh
set -eu
test -f /etc/droidspaces
podman run --rm quay.io/podman/hello >/dev/null
podman-rootless run --rm quay.io/podman/hello >/dev/null
podman-rootless run --rm localhost/rmx1931-probe:1 sh -ec 'test "$(cat /proc/self/oom_score_adj)" = 0'
printf 'ROOTFUL_ROOTLESS_AFTER_GUEST_RESTART_PASS\n'
