#!/bin/sh
# Diagnose native user-namespace mounting without changing global registrations.
set -eu
test -f /etc/droidspaces
python3 - <<'PY'
import hashlib,json,os,subprocess,tempfile,shutil
from pathlib import Path
root=Path('/proc/sys/fs/binfmt_misc')
def registry():
 return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.iterdir()) if p.is_file() and p.name!='register'}
before=registry();parent_ns=os.readlink('/proc/self/ns/user');base=Path(tempfile.mkdtemp(prefix='rmx1931-binfmt-baseline-',dir='/var/tmp'))
source=r'''
import ctypes,json,os,sys
from pathlib import Path
base=Path(sys.argv[1]);libc=ctypes.CDLL(None,use_errno=True)
libc.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p]
libc.umount2.argtypes=[ctypes.c_char_p,ctypes.c_int]
def mount(kind,name):
 p=base/name;p.mkdir();r=libc.mount(b'none',os.fsencode(p),kind.encode(),0,None);error=ctypes.get_errno() if r else 0
 if not r:assert libc.umount2(os.fsencode(p),0)==0
 p.rmdir();return error
status=Path('/proc/self/status').read_text().splitlines();cap=int(next(x.split(':')[1] for x in status if x.startswith('CapEff:')),16)
print(json.dumps({'user_namespace':os.readlink('/proc/self/ns/user'),'seccomp':int(next(x.split(':')[1] for x in status if x.startswith('Seccomp:'))),
 'cap_sys_admin':bool(cap&(1<<21)),'tmpfs_mount_errno':mount('tmpfs','tmpfs'),'binfmt_mount_errno':mount('binfmt_misc','binfmt')}))
'''
try:
 result=subprocess.run(['unshare','--user','--map-root-user','--mount','--propagation','private','--','python3','-c',source,str(base)],capture_output=True,text=True,timeout=20)
 assert result.returncode==0,(result.returncode,result.stdout,result.stderr)
 data=json.loads(result.stdout);assert data['user_namespace']!=parent_ns and data['cap_sys_admin'] and data['tmpfs_mount_errno']==0
 assert data['seccomp']==0,'Use the isolated unfiltered operator to distinguish seccomp denial from kernel FS capability'
 assert before==registry(),'Host/guest global registrations changed'
 assert not list(base.iterdir())
 report={'child':data,'parent_user_namespace':parent_ns,'global_registration_sha256_before':before,'global_registration_sha256_after':registry(),
  'feature_supported':data['binfmt_mount_errno']==0,'diagnostic_completed':True,'ordinary_guest_seccomp':int(next(x.split(':')[1] for x in Path('/proc/1/status').read_text().splitlines() if x.startswith('Seccomp:'))),'cleanup_errors':[]}
 assert report['ordinary_guest_seccomp']==2
 print(json.dumps(report));print('BINFMT_NAMESPACE_BASELINE_SUPPORTED' if report['feature_supported'] else 'BINFMT_NAMESPACE_BASELINE_MISSING')
finally:
 assert not list(base.iterdir()),'Inspect owned mount state before cleanup';base.rmdir()
PY
