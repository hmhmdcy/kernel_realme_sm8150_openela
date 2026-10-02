#!/bin/sh
set -eu
test -f /etc/droidspaces
# Remove only our earlier timed-out registry probe in the dedicated user's store.
for cid in $(podman-rootless ps -q --filter ancestor=localhost/rmx1931-probe:1); do
    command=$(podman-rootless inspect --format '{{json .Config.Cmd}}' "$cid")
    case "$command" in
        *ports.ubuntu.com/ubuntu-ports/dists/noble/InRelease*) podman-rootless rm -f "$cid" ;;
    esac
done
address=$(getent ahostsv4 ports.ubuntu.com | awk 'NR==1 {print $1}')
test -n "$address"
printf 'UBUNTU_PORTS_IPV4=%s\n' "$address"
name=rmx1931-rootless-external-tcp
cleanup() { podman-rootless rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT HUP INT TERM
test "$(podman-rootless ps -a --filter name="^$name$" --format '{{.Names}}')" = ''
timeout 18 podman-rootless run --name "$name" localhost/rmx1931-probe:1 sh -ec '
    mkdir -p /tmp
    wget -T 8 --header "Host: ports.ubuntu.com" -O /tmp/repo "http://$1/ubuntu-ports/dists/noble/Release"
    grep -q Ubuntu /tmp/repo
    echo ROOTLESS_EXTERNAL_TCP_PASS' probe "$address"
