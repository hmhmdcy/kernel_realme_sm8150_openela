#!/usr/bin/env python3
"""Freeze a failed, never packaged candidate before restoring three base files."""
import hashlib
import argparse
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces/kernel-ext-harden4-seccomp-notify'
BASE = ROOT / 'artifacts/droidspaces/kernel-ext-harden3-binfmt-fix'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
record = json.loads((ART / 'source.json').read_text(encoding='utf-8'))
audit = json.loads((ART / 'audit.json').read_text(encoding='utf-8'))
source = Path(record['source'])
base = Path(record['base_source'])
assert not audit['build_audit_passed'] and not (ART / 'Image.gz-dtb').exists()
assert not (ROOT / 'artifacts/droidspaces/boot-images/ext-harden4-seccomp-notify-candidate-check.json').exists()
parser=argparse.ArgumentParser()
parser.add_argument('--attempt',type=int,choices=[1,2],default=1)
args=parser.parse_args()
log = (ART / 'build.log').read_text(encoding='utf-8')
marker={1:"implicit declaration of function 'check_zeroed_user'",2:"conflicting types for 'sys_seccomp'"}[args.attempt]
assert marker in log and 'Error 2' in log
snapshot = ART / ('failed-attempts/compile-'+str(args.attempt))
assert not snapshot.exists()
snapshot.mkdir(parents=True)
files = {'source.json': ART / 'source.json', 'audit.json': ART / 'audit.json',
 'build.log': ART / 'build.log', 'configure.log': ART / 'configure.log',
 'resolved.config': ART / 'resolved.config',
 'prepare_seccomp_notify.py': ROOT / 'scripts/prepare_seccomp_notify.py',
 'rmx1931-seccomp-user-notification.patch': ROOT / 'patches/rmx1931-seccomp-user-notification.patch'}
for name, values in record['modified_sources'].items():
    p=source/name
    assert sha(p)==values['after_sha256'] and sha(base/name)==values['before_sha256']
    files[name.replace('/','-')]=p
for name,p in files.items(): shutil.copyfile(p,snapshot/name)
manifest={'reason':'4.14 compile adapters incomplete; never packaged or flashed',
 'files_sha256':{n:sha(snapshot/n) for n in files},'restore_sources':record['modified_sources']}
(snapshot/'failure.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
for name,values in record['modified_sources'].items():
    # Second attempt changes only the C adapter; preserve unchanged header
    # mtimes so its already compiled dependants do not need another rebuild.
    if args.attempt==1 or name=='kernel/seccomp.c':
        shutil.copyfile(base/name,source/name)
        assert sha(source/name)==values['before_sha256']
# Literal reviewed records only; archived copies have been digest verified.
for p in (ART/'source.json', ROOT/'patches/rmx1931-seccomp-user-notification.patch'):
    assert sha(p)==sha(snapshot/p.name)
    p.unlink()
print('UNBUILT_SECCOMP_FAILURE_ARCHIVED_AND_BASE_RESTORED')
