#!/bin/sh
set -eu
umask 077
test -f /etc/droidspaces
command -v iperf3 >/dev/null
cd /var/tmp
peer=${1:?peer public key}
label=${2:?test label}
port=${3:-51873}
case "$port" in ''|*[!0-9]*) exit 2 ;; esac
test "$port" -ge 1024 && test "$port" -le 65535
case "$label" in ''|*[!a-zA-Z0-9_-]*) exit 2 ;; esac
base=/var/tmp/rmx1931-wg-$label
namespace=rmxwg-$label
test ! -e "$base"
mkdir -m 700 "$base"
active=0
server=
cleanup() {
    if [ -n "$server" ]; then kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; fi
    if [ "$active" = 1 ]; then ip netns del "$namespace"; fi
    ip link del rmx1931wge 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
wg genkey > "$base/private.key"
wg pubkey < "$base/private.key" > "$base/public.key"
ip netns add "$namespace"
active=1
ip link add rmx1931wge type wireguard
wg set rmx1931wge private-key "$base/private.key" listen-port "$port" peer "$peer" allowed-ips 10.193.2.1/32
ip link set rmx1931wge netns "$namespace"
ip netns exec "$namespace" ip addr add 10.193.2.2/24 dev rmx1931wge
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip link set rmx1931wge mtu 1420 up
ip netns exec "$namespace" iperf3 -s -p 52073 > "$base/iperf.log" 2>&1 &
server=$!
sleep .2
kill -0 "$server"
printf '{"public_key":"%s","namespace":"%s","mtu":1420}\n' "$(cat "$base/public.key")" "$namespace" > "$base/ready.json"
for attempt in $(seq 1 1400); do
    if [ -f "$base/finish" ]; then break; fi
    sleep .1
done
test -f "$base/finish"
ip netns exec "$namespace" wg show rmx1931wge latest-handshakes
ip netns exec "$namespace" wg show rmx1931wge transfer
ip netns exec "$namespace" wg show rmx1931wge endpoints
cleanup
active=0
server=
test ! -e /run/netns/"$namespace"
trap - EXIT HUP INT TERM
printf 'EXTERNAL_WIREGUARD_GUEST_CLEANUP_PASS diagnostics=%s\n' "$base"
