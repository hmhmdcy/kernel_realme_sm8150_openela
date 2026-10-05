#!/usr/bin/env bash
set -euo pipefail
source_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
revision=cd739c78802333455391df973db17d9f28328b83
[[ "$(git -C "$source_root/KernelSU-Next" rev-parse HEAD)" == "$revision" ]]
[[ "$(git -C "$source_root/KernelSU-Next" rev-list --count HEAD)" == 3015 ]]
python3 "$source_root/Documentation/droidspaces/verify-source.py" --apply-ksu-overlay
: "${CLANG_DIR:?Set CLANG_DIR to AOSP clang-r547379}"
[[ -x "$CLANG_DIR/bin/clang" ]]
export PATH="$CLANG_DIR/bin:$PATH"
export LD_LIBRARY_PATH="$CLANG_DIR/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
out="${OUT_DIR:-$source_root/out-extensions}"
args=(ARCH=arm64 LLVM=1 LLVM_IAS=1 CLANG_TRIPLE=aarch64-linux-gnu-
      CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi-
      CROSS_COMPILE_COMPAT=arm-linux-gnueabi- CC=clang LD=ld.lld
      LOCALVERSION=-droidspaces-lr2-ksu3-ext-a16pf
      KERNELRELEASE=4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf
      KSU_VERSION_OVERRIDE=33304 KSU_VERSION_TAG_OVERRIDE=v3.4.0-legacy-cd739c7)
export KBUILD_BUILD_USER=rmx1931 KBUILD_BUILD_HOST=codex-wsl KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP='2026-10-05 00:00:00 UTC'
make -C "$source_root" O="$out" "${args[@]}" rmx1931_droidspaces_defconfig
cmp "$out/.config" "$source_root/arch/arm64/configs/rmx1931_droidspaces_defconfig"
make -C "$source_root" O="$out" "${args[@]}" -j"${JOBS:-4}" Image.gz-dtb modules
