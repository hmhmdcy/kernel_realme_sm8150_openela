#!/bin/sh
# Actual OCI, overlay/FUSE, network, build, volume and cgroup tests.
# Run as root or as the dedicated mapped user; all names are task-specific.
set -eu
test -f /etc/droidspaces
mode="${1:?rootful or rootless}"
case "$mode" in
    rootful) test "$(id -u)" = 0; port=18081 ;;
    rootless) test "$(id -u)" = 1000; port=18082 ;;
    *) exit 1 ;;
esac
image=localhost/rmx1931-probe:1
name=rmx1931-acceptance-$mode
volume=rmx1931-acceptance-$mode
cleanup() {
    podman rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
test "$(podman ps -a --filter name="^$name$" --format '{{.Names}}')" = ''
printf 'MODE=%s\n' "$mode"
podman info --format=json > "/tmp/$name-info.json"
head -n 14 "/tmp/$name-info.json"
podman run --rm "$image" sh -ec 'echo WRITE_TEST > /overlay-test; chown 1234:2345 /overlay-test; test "$(stat -c %u:%g /overlay-test)" = 1234:2345; test "$(cat /overlay-test)" = WRITE_TEST'
printf 'OVERLAY_WRITE_UID_GID_PASS\n'
timeout 15 podman run --rm "$image" nslookup quay.io
printf 'CONTAINER_DNS_PASS\n'
podman volume create "$volume" >/dev/null
podman run --rm -v "$volume:/data" "$image" sh -ec 'printf PERSISTED > /data/test; chown 1234:2345 /data/test'
podman run --rm -v "$volume:/data" "$image" sh -ec 'test "$(cat /data/test)" = PERSISTED; test "$(stat -c %u:%g /data/test)" = 1234:2345'
printf 'NAMED_VOLUME_PERSISTENCE_UID_GID_PASS\n'
podman run -d --name "$name" --memory=64m --pids-limit=64 -p "127.0.0.1:$port:8080" "$image" sh -ec 'test "$(cat /sys/fs/cgroup/memory.max)" = 67108864; test "$(cat /sys/fs/cgroup/pids.max)" = 64; mkdir -p /www; printf CONTAINER_HTTP_OK > /www/index.html; trap "exit 0" TERM INT; httpd -f -p 8080 -h /www & wait'
for attempt in 1 2 3 4 5; do
    if curl --noproxy '*' --fail --silent --max-time 3 "http://127.0.0.1:$port/" > "/tmp/$name-http"; then break; fi
    sleep 1
done
test "$(cat "/tmp/$name-http")" = CONTAINER_HTTP_OK
printf 'PORT_MEMORY_PIDS_LIMIT_PASS\n'
podman exec "$name" sh -ec 'test "$(cat /sys/fs/cgroup/memory.max)" = 67108864; test "$(cat /sys/fs/cgroup/pids.max)" = 64'
podman stop --time=2 "$name" >/dev/null
podman start "$name" >/dev/null
for attempt in 1 2 3 4 5; do
    if curl --noproxy '*' --fail --silent --max-time 3 "http://127.0.0.1:$port/" > "/tmp/$name-http"; then break; fi
    sleep 1
done
test "$(cat "/tmp/$name-http")" = CONTAINER_HTTP_OK
printf 'STOP_START_EXEC_PASS\n'
if [ "$mode" = rootless ]; then
    podman unshare sh -ec 'findmnt -t fuse.fuse-overlayfs -n | head -n 3; test "$(findmnt -t fuse.fuse-overlayfs -n | wc -l)" -gt 0'
    printf 'ROOTLESS_FUSE_MOUNT_PASS\n'
fi
cleanup
test "$(podman ps -a --filter name="^$name$" --format '{{.Names}}')" = ''
podman volume rm "$volume" >/dev/null
printf 'FUNCTIONAL_ACCEPTANCE_%s_PASS\n' "$mode"
