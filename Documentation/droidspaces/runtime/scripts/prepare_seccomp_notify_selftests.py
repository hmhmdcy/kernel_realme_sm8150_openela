#!/usr/bin/env python3
"""Package pinned upstream test bodies and a name-only harness selector."""
import base64
import hashlib
import json
from pathlib import Path
import zlib

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / 'references/seccomp-notify-selftests'
LOCK = json.loads((REF / 'source-lock.json').read_text(encoding='utf-8'))
assert LOCK['commit'] == '587461ddf5d522bfcb50ebd55078c0dac37be496'
payload = {}
for name, record in LOCK['files'].items():
    data = (REF / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['sha256']
    payload[name] = base64.b64encode(data).decode()
# The two orphan-listener bodies need only CLONE_FILES + SIGCHLD. Preserve
# their bodies and translate this one helper to the existing 4.14 clone ABI.
clone_header = base64.b64decode(payload['clone3/clone3_selftests.h']).decode()
old_clone = 'return syscall(__NR_clone3, args, size);'
assert clone_header.count(old_clone) == 1
clone_adapter = '''if (size != sizeof(*args) || args->flags != CLONE_FILES ||
            args->exit_signal != SIGCHLD || args->stack || args->stack_size ||
            args->pidfd || args->parent_tid || args->child_tid || args->tls ||
            args->set_tid || args->set_tid_size || args->cgroup) {
        errno = EINVAL;
        return -1;
    }
    return syscall(SYS_clone, args->flags | args->exit_signal, NULL, NULL, NULL, 0);'''
payload['clone3/clone3_selftests.h'] = base64.b64encode(clone_header.replace(old_clone, clone_adapter).encode()).decode()
source = base64.b64decode(payload['seccomp/seccomp_bpf.c']).decode()
assert source.count('\nTEST_HARNESS_MAIN\n') == 1
selector = (REF / 'selected_main.c').read_text(encoding='utf-8').replace('\r\n', '\n')
payload['seccomp/selected.c'] = base64.b64encode(source.replace('\nTEST_HARNESS_MAIN\n', '\n' + selector).encode()).decode()
header = ROOT / 'references/seccomp-notify-upstream/linux-5.10.y-include-uapi-linux-seccomp.h'
exported_header = header.read_text(encoding='utf-8').replace('#include <linux/compiler.h>\n', '')
assert 'compiler.h' not in exported_header
payload['uapi/linux/seccomp.h'] = base64.b64encode(exported_header.encode()).decode()
blob = base64.b64encode(zlib.compress(json.dumps(payload, sort_keys=True).encode(), 9)).decode()
script = '''#!/bin/sh
# Only this scoped operator starts unfiltered; every tested filter is real.
set -eu
test -f /etc/droidspaces
cd /var/tmp
base=$(mktemp -d /var/tmp/rmx1931-notify-selftests-XXXXXXXX)
trap 'rm -rf -- "$base"' EXIT
python3 - "$base" "${1:-run}" <<'PY'
import base64, hashlib, json, os, subprocess, sys, zlib
from pathlib import Path
base=Path(sys.argv[1])
status=Path('/proc/self/status').read_text()
operator_seccomp=int(next(x for x in status.splitlines() if x.startswith('Seccomp:')).split()[1])
assert operator_seccomp==0 or (sys.argv[2]=='compile-only' and operator_seccomp==2)
payload=json.loads(zlib.decompress(base64.b64decode(''' + repr(blob) + ''')))
for name, encoded in payload.items():
 p=base/name
 assert p.is_relative_to(base) and '..' not in p.parts
 p.parent.mkdir(parents=True,exist_ok=True)
 p.write_bytes(base64.b64decode(encoded))
subprocess.run(['gcc','-static','-O2','-pthread','-Wall','-I'+str(base/'uapi'),
 str(base/'seccomp/selected.c'),'-o',str(base/'selftests')],check=True)
print(json.dumps({'upstream_commit':'587461ddf5d522bfcb50ebd55078c0dac37be496',
 'test_bodies_unchanged':True,'clone_helper_adapter':'CLONE_FILES + SIGCHLD only, legacy clone ABI',
 'selected_binary_sha256':hashlib.sha256((base/'selftests').read_bytes()).hexdigest(),
 'operator_seccomp':operator_seccomp}),flush=True)
if sys.argv[2]=='compile-only':
 print('SECCOMP_NOTIFY_SELFTEST_COMPILE_PASS',flush=True)
 raise SystemExit(0)
subprocess.run(['timeout','--kill-after=5','300',str(base/'selftests')],check=True)
print('SECCOMP_NOTIFY_UPSTREAM_SELFTESTS_PASS',flush=True)
PY
'''
target = ROOT / 'scripts/probe_seccomp_notify_selftests.sh'
target.write_text(script, encoding='utf-8', newline='\n')
record = {'upstream_source_lock_sha256': hashlib.sha256((REF / 'source-lock.json').read_bytes()).hexdigest(),
          'uapi_export_adapter': 'omit kernel-only linux/compiler.h include; ABI definitions unchanged',
          'clone_helper_adapter': 'CLONE_FILES + SIGCHLD only, legacy clone ABI; test bodies unchanged',
          'selector_sha256': hashlib.sha256(selector.encode()).hexdigest(),
          'payload_files_sha256': {n: hashlib.sha256(base64.b64decode(v)).hexdigest() for n, v in payload.items()},
          'probe_sha256': hashlib.sha256(script.encode()).hexdigest()}
(REF / 'selected-source-lock.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'files':len(payload),'probe_sha256':record['probe_sha256']}))
