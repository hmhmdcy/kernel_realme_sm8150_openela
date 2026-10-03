#!/usr/bin/env bash
set -euo pipefail
source_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
revision=cd739c78802333455391df973db17d9f28328b83
[[ "$(git -C "$source_root/KernelSU-Next" rev-parse HEAD)" == "$revision" ]]
[[ "$(git -C "$source_root/KernelSU-Next" rev-list --count HEAD)" == 3015 ]]
: "${CLANG_DIR:?Set CLANG_DIR to AOSP clang-r547379}"
[[ -x "$CLANG_DIR/bin/clang" ]]
export PATH="$CLANG_DIR/bin:$PATH"
export LD_LIBRARY_PATH="$CLANG_DIR/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
out="${OUT_DIR:-$source_root/out-ksunext}"
args=(ARCH=arm64 LLVM=1 LLVM_IAS=1 CLANG_TRIPLE=aarch64-linux-gnu-
      CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi-
      CROSS_COMPILE_COMPAT=arm-linux-gnueabi- CC=clang LD=ld.lld
      LOCALVERSION=-droidspaces-v6.6.0-podman2-lr2-ksu3
      KERNELRELEASE=4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2-lr2-ksu3
      KSU_VERSION_OVERRIDE=33304 KSU_VERSION_TAG_OVERRIDE=v3.4.0-legacy-cd739c7)
make -C "$source_root" O="$out" "${args[@]}" rmx1931_ksunext3_defconfig
make -C "$source_root" O="$out" "${args[@]}" -j"${JOBS:-4}" Image.gz-dtb modules
