#!/usr/bin/env bash
# Independent WALT + bandwidth candidate. Existing Android controller ownership stays unchanged.
set -euo pipefail
workspace=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
base=/var/tmp/rmx1931-ksunext-cd739c788023
source=$base/src-ext-resources
out=$base/out-ext-resources
artifacts=$workspace/artifacts/droidspaces/kernel-ext-resources
mkdir -p "$artifacts"
if [[ ! -d "$source" ]]; then cp -a --reflink=auto "$base/src-ext-network" "$source"; fi
python3 - "$source" "$artifacts" <<'PY'
import hashlib,json,sys
from pathlib import Path
source,artifacts=map(Path,sys.argv[1:])
path=source/'init/Kconfig'
before=(source.with_name('src-ext-network')/'init/Kconfig').read_bytes()
old=b'\tdepends on FAIR_GROUP_SCHED\n\tdepends on !SCHED_WALT\n'
new=b'\tdepends on FAIR_GROUP_SCHED\n'
assert before.count(old)==1
after=before.replace(old,new)
assert path.read_bytes() in (before,after)
path.write_bytes(after)
record={'source':str(source),'modified_sources':{'init/Kconfig':{'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest()}},
        'reason':'Exercise existing Qualcomm WALT/CFS_BANDWIDTH integration, retaining WALT; runtime regression required.'}
(artifacts/'source.json').write_text(json.dumps(record,indent=2)+'\n')
PY
if [[ ! -d "$out" ]]; then cp -a --reflink=auto "$base/out-ext-io" "$out"; fi
cp "$workspace/artifacts/droidspaces/kernel-ext-io/resolved.config" "$out/.config"
"$source/scripts/config" --file "$out/.config" -e CFS_BANDWIDTH
export PATH="$base/clang/bin:$PATH"
export LD_LIBRARY_PATH="$base/clang/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export KBUILD_BUILD_USER=rmx1931 KBUILD_BUILD_HOST=codex-wsl KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP='2026-10-03 00:00:00 UTC'
args=(ARCH=arm64 LLVM=1 LLVM_IAS=1 CLANG_TRIPLE=aarch64-linux-gnu-
 CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi-
 CROSS_COMPILE_COMPAT=arm-linux-gnueabi- CC=clang LD=ld.lld
 LOCALVERSION=-droidspaces-lr2-ksu3-ext-resources
 KSU_VERSION_OVERRIDE=33304 KSU_VERSION_TAG_OVERRIDE=v3.4.0-legacy-cd739c7)
make -C "$source" O="$out" "${args[@]}" olddefconfig > "$artifacts/configure.log" 2>&1
cp "$out/.config" "$artifacts/resolved.config"
python3 "$workspace/scripts/audit_kernel_resources.py"
if ! make -C "$source" O="$out" "${args[@]}" -j8 Image.gz-dtb modules > "$artifacts/build.log" 2>&1; then
 tail -n 60 "$artifacts/build.log"
 exit 1
fi
cp "$out/arch/arm64/boot/Image.gz-dtb" "$out/System.map" "$out/Module.symvers" "$artifacts/"
cp "$out/include/config/kernel.release" "$artifacts/kernel.release"
python3 "$workspace/scripts/audit_kernel_resources.py" --after-build
printf 'RESOURCE_KERNEL_BUILD_PASS\n'
