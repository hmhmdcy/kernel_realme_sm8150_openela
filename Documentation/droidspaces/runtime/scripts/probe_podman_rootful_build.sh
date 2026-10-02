#!/bin/sh
# Build a local ARM64 image from the signed Ubuntu busybox-static package.
set -eu
test -f /etc/droidspaces
test "$(dpkg-query -W -f='${Status}' busybox-static)" = 'install ok installed'
context=/tmp/rmx1931-tests/build-rootful
test ! -L "$context"
mkdir -p "$context"
cp /usr/bin/busybox "$context/busybox"
sha256sum /usr/bin/busybox "$context/busybox"
cat > "$context/Containerfile" <<'EOF'
FROM scratch
COPY busybox /bin/busybox
RUN ["/bin/busybox", "--install", "-s", "/bin"]
CMD ["/bin/sh"]
EOF
timeout 40 podman build --network=none -t localhost/rmx1931-probe:1 "$context"
printf 'ROOTFUL_IMAGE_BUILD_PASS\n'
