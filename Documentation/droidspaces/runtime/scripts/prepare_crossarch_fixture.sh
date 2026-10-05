#!/usr/bin/env bash
set -euo pipefail
workspace=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compiler=/var/tmp/rmx1931-ksunext-cd739c788023/clang/bin/clang
out=$workspace/artifacts/droidspaces/binfmt-crossarch-fixture
mkdir -p "$out"
for arch in x86_64 aarch64; do
 "$compiler" --target="$arch-linux-gnu" -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wl,-e,_start -Wl,--build-id=none -Wl,-s \
  "$workspace/references/runtime-probes/binfmt-crossarch/fixture.c" -o "$out/fixture-$arch"
done
python3 - "$workspace" <<'PY'
import hashlib,json,sys
from pathlib import Path
r=Path(sys.argv[1]);d=r/'artifacts/droidspaces/binfmt-crossarch-fixture'
source=r/'references/runtime-probes/binfmt-crossarch/fixture.c'
data={'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'toolchain':'pinned kernel clang; static freestanding binaries',
 'binaries':{a:{'sha256':hashlib.sha256((d/('fixture-'+a)).read_bytes()).hexdigest(),'bytes':(d/('fixture-'+a)).stat().st_size} for a in ('x86_64','aarch64')}}
for a,machine in [('x86_64',62),('aarch64',183)]:
 b=(d/('fixture-'+a)).read_bytes();assert b[:7]==b'\x7fELF\x02\x01\x01' and int.from_bytes(b[18:20],'little')==machine
(d/'source-lock.json').write_text(json.dumps(data,indent=2)+'\n')
print(json.dumps(data))
PY
