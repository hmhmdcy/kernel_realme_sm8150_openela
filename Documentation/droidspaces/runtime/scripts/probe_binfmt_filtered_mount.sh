#!/bin/sh
# Ordinary filtered guest must be able to use its own binfmt mount.
set -eu
test -f /etc/droidspaces
python3 - <<'PY'
import json,os,subprocess,tempfile,shutil
from pathlib import Path
def seccomp():return int(next(x.split(':')[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('Seccomp:')))
assert seccomp()==2
base=Path(tempfile.mkdtemp(prefix='rmx1931-binfmt-filtered-',dir='/var/tmp'))
source=r'''
import ctypes,json,os,sys
from pathlib import Path
base=Path(sys.argv[1]);c=ctypes.CDLL(None,use_errno=True);c.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p];c.umount2.argtypes=[ctypes.c_char_p,ctypes.c_int]
assert c.mount(b'none',os.fsencode(base),b'binfmt_misc',0,None)==0,ctypes.get_errno()
try:
 seccomp=int(next(x.split(':')[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('Seccomp:')));assert seccomp==2
 assert sorted(p.name for p in base.iterdir())==['register','status'];(base/'status').write_text('0');assert (base/'status').read_text()=='disabled\n';(base/'status').write_text('1')
 print(json.dumps({'seccomp':seccomp,'user_namespace':os.readlink('/proc/self/ns/user'),'status':(base/'status').read_text().strip()}))
finally:assert c.umount2(os.fsencode(base),0)==0
'''
try:
 r=subprocess.run(['unshare','--user','--map-root-user','--mount','--propagation','private','--','python3','-c',source,str(base)],capture_output=True,text=True,timeout=15)
 assert r.returncode==0,(r.returncode,r.stdout,r.stderr)
 data=json.loads(r.stdout);assert data['user_namespace']!=os.readlink('/proc/self/ns/user') and data['seccomp']==seccomp()==2
 assert not list(base.iterdir());print(json.dumps({'passed':True,'child':data,'ordinary_guest_seccomp':seccomp(),'cleanup_errors':[]}));print('BINFMT_FILTERED_MOUNT_PASS')
finally:shutil.rmtree(base)
PY
