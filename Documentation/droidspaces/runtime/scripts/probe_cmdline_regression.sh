#!/bin/sh
set -eu
test -f /etc/droidspaces
sh -c 'test "$(dd if=/proc/$$/cmdline bs=256 2>/dev/null | tail -c 1 | od -An -tu1 | tr -d " \n")" = 0; echo CMDLINE_FINAL_NUL_PASS' rmx1931-cmdline first last
runuser -u podmantest -- env XDG_RUNTIME_DIR=/run/user/1000 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus sh -ec '
    for i in 1 2 3 4 5; do timeout 15 podman info --format=json > /dev/null; done
    echo ROOTLESS_JSON_REPEAT_PASS'
