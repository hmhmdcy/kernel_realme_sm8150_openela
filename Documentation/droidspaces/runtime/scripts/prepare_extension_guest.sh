#!/bin/sh
# The 4.14 binfmt registration table is global across guest namespaces.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
if grep -qw binfmt_misc /proc/filesystems; then
    echo 'Running kernel already has binfmt_misc; inspect live handlers before changing boot services' >&2
    exit 1
fi
systemctl mask --now systemd-binfmt.service binfmt-support.service
systemctl is-enabled systemd-binfmt.service || true
systemctl is-enabled binfmt-support.service || true
echo GUEST_BINFMT_AUTOREGISTRATION_DISABLED_EXPLICIT_QEMU_REMAINS_AVAILABLE
