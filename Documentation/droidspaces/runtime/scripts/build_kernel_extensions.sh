#!/usr/bin/env bash
# Cumulative, independent output trees. Never flash or change the running phone.
set -euo pipefail
workspace_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
build_root=/var/tmp/rmx1931-ksunext-cd739c788023
stage=${1:?usage: build_kernel_extensions.sh utilities|bbr|checkpoint|network|io}
jobs=${RMX1931_BUILD_JOBS:-4}
[[ "$jobs" =~ ^[1-8]$ ]] || { echo 'RMX1931_BUILD_JOBS must be between 1 and 8' >&2; exit 2; }
stages=(utilities bbr checkpoint network io)
case "$stage" in utilities|bbr|checkpoint|network|io) ;; *) exit 2 ;; esac
source="$build_root/src"
if [[ "$stage" == network || "$stage" == io ]]; then
    python3 "$workspace_root/scripts/prepare_kernel_extensions.py"
    source="$build_root/src-ext-network"
fi
[[ "$(cat "$build_root/ksunext-revision")" == cd739c78802333455391df973db17d9f28328b83 ]]
export PATH="$build_root/clang/bin:$PATH"
export LD_LIBRARY_PATH="$build_root/clang/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export KBUILD_BUILD_USER=rmx1931 KBUILD_BUILD_HOST=codex-wsl KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP='2026-10-03 00:00:00 UTC'
out="$build_root/out-ext-$stage"
artifacts="$workspace_root/artifacts/droidspaces/kernel-ext-$stage"
mkdir -p "$artifacts"
if [[ ! -d "$out" ]]; then
    cp -a --reflink=auto "$build_root/out" "$out"
fi
cp "$workspace_root/artifacts/droidspaces/kernel-ksunext/resolved.config" "$out/.config"
fragments=()
for item in "${stages[@]}"; do
    # This 4.14 merge_config.sh splits its file list on spaces internally.
    cp "$workspace_root/configs/extensions-$item.config" "$build_root/extensions-$item.config"
    fragments+=("$build_root/extensions-$item.config")
    [[ "$item" != "$stage" ]] || break
done
args=(ARCH=arm64 LLVM=1 LLVM_IAS=1 CLANG_TRIPLE=aarch64-linux-gnu-
      CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi-
      CROSS_COMPILE_COMPAT=arm-linux-gnueabi- CC=clang LD=ld.lld
      LOCALVERSION="-droidspaces-lr2-ksu3-ext-$stage"
      KSU_VERSION_OVERRIDE=33304 KSU_VERSION_TAG_OVERRIDE=v3.4.0-legacy-cd739c7)
"$source/scripts/kconfig/merge_config.sh" -m -O "$out" "$out/.config" "${fragments[@]}" > "$artifacts/merge.log" 2>&1
make -C "$source" O="$out" "${args[@]}" olddefconfig > "$artifacts/configure.log" 2>&1
cp "$out/.config" "$artifacts/resolved.config"
python3 "$workspace_root/scripts/audit_kernel_extensions.py" "$stage"
if [[ "$stage" == network || "$stage" == io ]]; then
    if ! make -C "$source" O="$out" "${args[@]}" net/netfilter/nft_socket.o > "$artifacts/socket-compile.log" 2>&1; then
        cat "$artifacts/socket-compile.log"
        exit 1
    fi
fi
if ! make -C "$source" O="$out" "${args[@]}" -j"$jobs" Image.gz-dtb modules > "$artifacts/build.log" 2>&1; then
    tail -n 60 "$artifacts/build.log"
    exit 1
fi
cp "$out/arch/arm64/boot/Image.gz-dtb" "$out/System.map" "$out/Module.symvers" "$artifacts/"
cp "$out/include/config/kernel.release" "$artifacts/kernel.release"
python3 "$workspace_root/scripts/audit_kernel_extensions.py" "$stage" --after-build
sha256sum "$artifacts/Image.gz-dtb" > "$artifacts/Image.gz-dtb.sha256"
printf 'EXTENSION_BUILD_PASSED %s\n' "$stage"
