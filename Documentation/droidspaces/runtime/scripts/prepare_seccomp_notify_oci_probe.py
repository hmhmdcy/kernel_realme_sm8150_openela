#!/usr/bin/env python3
"""Package the owned OCI fixture and broker without changing runtime profiles."""
import base64
import hashlib
import json
from pathlib import Path
import zlib
ROOT=Path(__file__).resolve().parents[1]
files={'fixture.c':ROOT/'references/seccomp-notify-selftests/oci_payload.c',
       'worker.py':ROOT/'references/seccomp-notify-selftests/oci_worker.py',
       'broker.py':ROOT/'scripts/rmx1931_seccomp_notify.py'}
payload={n:base64.b64encode(p.read_bytes().replace(b'\r\n',b'\n')).decode() for n,p in files.items()}
blob=base64.b64encode(zlib.compress(json.dumps(payload,sort_keys=True).encode(),9)).decode()
script='''#!/bin/sh
set -eu
test -f /etc/droidspaces
cd /var/tmp
base=$(mktemp -d /var/tmp/rmx1931-notify-oci-XXXXXXXX)
trap 'rm -rf -- "$base"' EXIT
python3 - "$base" "${1:-default}" <<'PY'
import base64, hashlib, json, os, subprocess, sys, zlib
from pathlib import Path
base=Path(sys.argv[1])
assert 'Seccomp:\\t2' in Path('/proc/self/status').read_text()
payload=json.loads(zlib.decompress(base64.b64decode('''+repr(blob)+''')))
for mode in ('rootful','rootless'):
 work=base/mode
 work.mkdir(mode=0o700)
 for name,value in payload.items(): (work/name).write_bytes(base64.b64decode(value))
 subprocess.run(['gcc','-static','-O2','-Wall','-Wextra','-Werror',str(work/'fixture.c'),'-o',str(work/'fixture')],check=True)
 print(json.dumps({'mode':mode,'fixture_sha256':hashlib.sha256((work/'fixture').read_bytes()).hexdigest(),
  'broker_sha256':hashlib.sha256((work/'broker.py').read_bytes()).hexdigest()}),flush=True)
 if mode=='rootless':
  base.chmod(0o711)
  for p in [work,*work.iterdir()]: os.chown(p,1000,1000)
  command=['runuser','-u','podmantest','--','env','HOME=/home/podmantest',
   'USER=podmantest','LOGNAME=podmantest','XDG_RUNTIME_DIR=/run/user/1000',
   'python3',str(work/'worker.py'),str(work)]
 else: command=['python3',str(work/'worker.py'),str(work)]
 if sys.argv[2]!='default': command.append(sys.argv[2])
 subprocess.run(command,check=True,timeout=160)
assert 'Seccomp:\\t2' in Path('/proc/self/status').read_text()
print('SECCOMP_NOTIFY_CRUN_TARGET_BINDING_PASS' if sys.argv[2]=='target-change' else 'SECCOMP_NOTIFY_CRUN_BROKER_PASS',flush=True)
PY
'''
target=ROOT/'scripts/probe_seccomp_notify_crun.sh'
target.write_text(script,encoding='utf-8',newline='\n')
record={'files_sha256':{n:hashlib.sha256(base64.b64decode(v)).hexdigest() for n,v in payload.items()},
 'probe_sha256':hashlib.sha256(script.encode()).hexdigest()}
(ROOT/'references/seccomp-notify-selftests/oci-source-lock.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
print(json.dumps(record))
