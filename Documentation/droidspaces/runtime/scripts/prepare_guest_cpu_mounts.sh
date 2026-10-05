#!/bin/sh
# Share only this dedicated CPU leaf source, then renew an idle rootless pause.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
cd /var/tmp
test -z "$(podman-rootless ps -q)"
source=/run/rmx1931-cpu
test ! -L "$source"
mkdir -p "$source"
test -z "$(find "$source" -mindepth 1 -maxdepth 1 -print)"
if ! mountpoint -q "$source"; then mount --bind "$source" "$source"; fi
mount --make-shared "$source"
test "$(findmnt -n -o PROPAGATION -M "$source")" = shared
podman-rootless system migrate
findmnt -n -o TARGET,PROPAGATION -M "$source"
printf 'GUEST_CPU_LEAF_PROPAGATION_READY\n'
