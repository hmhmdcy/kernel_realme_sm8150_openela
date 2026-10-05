#!/bin/sh
# Initial-userns mount permission exercises the binfmt lower-layer guard.
set -eu
test -f /etc/droidspaces
unshare --mount --propagation private -- python3 - <<'PY'
import ctypes,errno,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
root=Path('/proc/sys/fs/binfmt_misc')
def registry():return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.iterdir()) if p.is_file() and p.name!='register'}
before=registry();base=Path(tempfile.mkdtemp(prefix='rmx1931-binfmt-stack-',dir='/var/tmp'));child=None
libc=ctypes.CDLL(None,use_errno=True);libc.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p];libc.umount2.argtypes=[ctypes.c_char_p,ctypes.c_int]
def overlay(lower,label):
 directory=base/label;directory.mkdir()
 for name in ('upper','work','mount'):(directory/name).mkdir()
 options='lowerdir='+str(lower)+',upperdir='+str(directory/'upper')+',workdir='+str(directory/'work')
 r=libc.mount(b'overlay',os.fsencode(directory/'mount'),b'overlay',0,options.encode());error=ctypes.get_errno() if r else 0
 if not r:assert libc.umount2(os.fsencode(directory/'mount'),0)==0
 shutil.rmtree(directory);return error
worker=r'''
import ctypes,json,os,sys
from pathlib import Path
p=Path(sys.argv[1]);p.mkdir();c=ctypes.CDLL(None,use_errno=True)
c.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p];c.umount2.argtypes=[ctypes.c_char_p,ctypes.c_int]
assert c.mount(b'none',os.fsencode(p),b'binfmt_misc',0,None)==0,ctypes.get_errno()
print(json.dumps({'pid':os.getpid(),'user_namespace':os.readlink('/proc/self/ns/user')}),flush=True)
assert sys.stdin.readline().strip()=='exit'
assert c.umount2(os.fsencode(p),0)==0;p.rmdir()
'''
try:
 (base/'control-lower').mkdir();(base/'control-lower'/'data').write_text('control')
 control=overlay(base/'control-lower','control');assert control==0,control
 child=subprocess.Popen(['unshare','--user','--map-root-user','--mount','--propagation','private','--','python3','-c',worker,str(base/'binfmt')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 info=json.loads(child.stdout.readline());assert info['user_namespace']!=os.readlink('/proc/self/ns/user')
 lower=Path('/proc')/str(info['pid'])/'root'/str(base/'binfmt').lstrip('/')
 assert (lower/'register').is_file()
 denied=overlay(lower,'attack');assert denied==errno.EINVAL,denied
 child.stdin.write('exit\n');child.stdin.flush();assert child.wait(timeout=10)==0,child.stderr.read()
 assert before==registry()
 ordinary=int(next(x.split(':')[1] for x in Path('/proc/1/status').read_text().splitlines() if x.startswith('Seccomp:')));assert ordinary==2
 print(json.dumps({'passed':True,'ordinary_overlay_mount_errno':control,'binfmt_overlay_mount_errno':denied,'child_user_namespace':info['user_namespace'],'global_registration_sha256_before':before,'global_registration_sha256_after':registry(),'ordinary_guest_seccomp':ordinary,'cleanup_errors':[]}))
 print('BINFMT_STACK_GUARD_PASS')
finally:
 if child and child.poll() is None:child.terminate();child.wait(timeout=10)
 assert before==registry();shutil.rmtree(base)
PY
