#!/bin/sh
# Exercise only a dedicated guest mount tree, including rootless namespace boundaries.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
base=$(mktemp -d /var/tmp/rmx1931-bind-XXXXXXXX)
name=$(basename "$base" | tr '[:upper:]' '[:lower:]')
image=localhost/rmx1931-probe:1
mkdir "$base/source" "$base/source/incoming" "$base/source/outgoing"
chmod 755 "$base"
cd "$base"
chown -R 1000:1000 "$base/source"
mount --bind "$base/source" "$base/source"
mount --make-rshared "$base/source"
active=
mode=rootful
run_podman() { if [ "$mode" = rootful ]; then podman "$@"; else podman-rootless "$@"; fi; }
cleanup() {
    if [ -n "$active" ]; then run_podman rm -f --time=0 "$active" >/dev/null 2>&1 || true; fi
    umount "$base/source/incoming" 2>/dev/null || true
    umount "$base/source/outgoing" 2>/dev/null || true
    umount "$base/source" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
for mode in rootful rootless; do
    if [ "$mode" = rootless ]; then
        test -z "$(podman-rootless ps -q)"
        # The rootless pause namespace predates this dedicated shared mount.
        # Recreate it only after proving that no rootless workload is running.
        podman-rootless system migrate
        podman-rootless unshare findmnt --target "$base/source" -o TARGET,PROPAGATION
    fi
    for propagation in rslave rprivate; do
        active=$name-$mode-$propagation
        test -z "$(run_podman ps -a --filter name="^$active$" --format '{{.Names}}')"
        run_podman run -d --name "$active" --network=none -v "$base/source:/mnt:$propagation" "$image" sleep 60 >/dev/null
        mount -t tmpfs -o size=1m tmpfs "$base/source/incoming"
        printf '%s\n' "$active" > "$base/source/incoming/proof"
        if [ "$propagation" = rslave ]; then
            test "$(run_podman exec "$active" cat /mnt/incoming/proof)" = "$active"
        else
            if run_podman exec "$active" test -e /mnt/incoming/proof; then exit 1; fi
        fi
        umount "$base/source/incoming"
        if run_podman exec "$active" test -e /mnt/incoming/proof; then exit 1; fi
        run_podman rm -f --time=0 "$active" >/dev/null
        active=
        printf 'BIND_%s_%s_HOST_TO_CONTAINER_AND_UNMOUNT_PASS\n' "$mode" "$propagation"
    done
    active=$name-$mode-ro
    test -z "$(run_podman ps -a --filter name="^$active$" --format '{{.Names}}')"
    run_podman run -d --name "$active" --network=none -v "$base/source:/mnt:ro,rslave" "$image" sleep 60 >/dev/null
    if run_podman exec "$active" sh -c 'echo unexpected > /mnt/should-not-exist'; then exit 1; fi
    test ! -e "$base/source/should-not-exist"
    run_podman rm -f --time=0 "$active" >/dev/null
    active=
    printf 'BIND_%s_READ_ONLY_ENFORCEMENT_PASS\n' "$mode"
done
# Bidirectional propagation explicitly needs SYS_ADMIN in this one fixture.
mode=rootful
active=$name-rootful-rshared
test -z "$(podman ps -a --filter name="^$active$" --format '{{.Names}}')"
podman run -d --name "$active" --network=none --cap-add=SYS_ADMIN --security-opt=seccomp=unconfined -v "$base/source:/mnt:rshared" "$image" sleep 60 >/dev/null
podman exec "$active" mount -t tmpfs -o size=1m tmpfs /mnt/outgoing
podman exec "$active" sh -c 'echo reverse-propagation > /mnt/outgoing/proof'
test "$(cat "$base/source/outgoing/proof")" = reverse-propagation
podman exec "$active" umount /mnt/outgoing
test ! -e "$base/source/outgoing/proof"
podman rm -f --time=0 "$active" >/dev/null
active=
printf 'BIND_ROOTFUL_RSHARED_BIDIRECTIONAL_PASS\n'
umount "$base/source"
if findmnt -rn --mountpoint "$base/source"; then exit 1; fi
trap - EXIT HUP INT TERM
printf 'BIND_PROPAGATION_CLEANUP_PASS diagnostics=%s\n' "$base"
