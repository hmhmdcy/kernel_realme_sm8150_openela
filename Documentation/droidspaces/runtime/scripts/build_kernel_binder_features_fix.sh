#!/usr/bin/env bash
set -euo pipefail
workspace=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
base=/var/tmp/rmx1931-ksunext-cd739c788023
source=$base/src-ext-harden5-binder-freeze-fix
out=$base/out-ext-harden5-binder-freeze-fix
artifacts=$workspace/artifacts/droidspaces/kernel-ext-harden5-binder-freeze-fix
mkdir -p "$artifacts"
if [[ ! -d "$source" ]]; then cp -a --reflink=auto "$base/src-ext-harden5-binder-freeze" "$source"; fi
python3 "$workspace/scripts/prepare_binder_features_fix.py" --prepare --source "$source"
if [[ ! -d "$out" ]]; then cp -a --reflink=auto "$base/out-ext-harden5-binder-freeze" "$out"; fi
cp "$workspace/artifacts/droidspaces/kernel-ext-harden5-binder-freeze/resolved.config" "$out/.config"
export PATH="$base/clang/bin:$PATH"
export LD_LIBRARY_PATH="$base/clang/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export KBUILD_BUILD_USER=rmx1931 KBUILD_BUILD_HOST=codex-wsl KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP='2026-10-05 00:00:00 UTC'
args=(ARCH=arm64 LLVM=1 LLVM_IAS=1 CLANG_TRIPLE=aarch64-linux-gnu-
 CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi-
 CROSS_COMPILE_COMPAT=arm-linux-gnueabi- CC=clang LD=ld.lld
 LOCALVERSION=-droidspaces-lr2-ksu3-ext-h5bf2
 KSU_VERSION_OVERRIDE=33304 KSU_VERSION_TAG_OVERRIDE=v3.4.0-legacy-cd739c7)
make -C "$source" O="$out" "${args[@]}" olddefconfig > "$artifacts/configure.log" 2>&1
cp "$out/.config" "$artifacts/resolved.config"
python3 "$workspace/scripts/prepare_binder_features_fix.py"
if ! make -C "$source" O="$out" "${args[@]}" -j"${JOBS:-8}" drivers/android/binderfs.o > "$artifacts/binderfs-compile.log" 2>&1; then cat "$artifacts/binderfs-compile.log"; exit 1; fi
if ! make -C "$source" O="$out" "${args[@]}" -j"${JOBS:-8}" Image.gz-dtb modules > "$artifacts/build.log" 2>&1; then tail -n 60 "$artifacts/build.log"; exit 1; fi
cp "$out/arch/arm64/boot/Image.gz-dtb" "$out/System.map" "$out/Module.symvers" "$artifacts/"
cp "$out/include/config/kernel.release" "$artifacts/kernel.release"
python3 "$workspace/scripts/prepare_binder_features_fix.py" --after-build
printf 'BINDER_FREEZE_FEATURE_BUILD_PASS\n'
