#!/bin/sh
# Install signed distro packages inside the existing Ubuntu guest only.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
test ! -L /usr/sbin/policy-rc.d
created_policy=0
cleanup() {
    if [ "$created_policy" = 1 ]; then rm /usr/sbin/policy-rc.d; fi
}
trap cleanup EXIT HUP INT TERM
if [ ! -e /usr/sbin/policy-rc.d ]; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
    chmod 755 /usr/sbin/policy-rc.d
    created_policy=1
fi
export DEBIAN_FRONTEND=noninteractive
had_lxc=0
if dpkg-query -W -f='${Status}' lxc 2>/dev/null | grep -q 'install ok installed'; then had_lxc=1; fi
apt-get update
packages='nftables erofs-utils lxc-utils wireguard-tools'
has_criu=0
if apt-cache policy criu | grep -q 'Candidate: (none)'; then
    echo 'CRIU_UNAVAILABLE: no native arm64 package in these configured signed repositories'
else
    packages="$packages criu"
    has_criu=1
fi
apt-get install -y --no-install-recommends $packages
if [ "$had_lxc" = 0 ]; then
    systemctl disable lxc-net.service lxc.service lxc-monitord.service
fi
dpkg-query -W -f='${Package} ${Version}\n' $packages
echo EXTENSION_USERSPACE_TOOLS_READY
[ "$has_criu" = 1 ] || exit 77
