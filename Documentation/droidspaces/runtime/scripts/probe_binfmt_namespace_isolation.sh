#!/bin/sh
# Only the scoped operator loses filtering; ordinary guest remains Seccomp=2.
set -eu
test -f /etc/droidspaces
python3 - <<'PY'
import ctypes,errno,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path

registry_root=Path('/proc/sys/fs/binfmt_misc')
def registry():
 return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(registry_root.iterdir()) if p.is_file() and p.name!='register'}
def run(args,**kwargs):
 r=subprocess.run(args,capture_output=True,text=True,timeout=25,**kwargs)
 assert r.returncode==0,(args,r.returncode,r.stdout,r.stderr)
 return r.stdout
before=registry();base=Path(tempfile.mkdtemp(prefix='rmx1931-binfmt-isolation-',dir='/var/tmp'));base.chmod(0o755)
worker=r'''
import ctypes,errno,json,os,subprocess,sys,threading,time
from pathlib import Path
base=Path(sys.argv[1]);tag=sys.argv[2];target=base/'one';other=base/'two';target.mkdir();other.mkdir()
libc=ctypes.CDLL(None,use_errno=True)
libc.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p]
libc.umount2.argtypes=[ctypes.c_char_p,ctypes.c_int]
def mount(path,kind='binfmt_misc',data=None):
 r=libc.mount(b'none',os.fsencode(path),kind.encode(),0,data.encode() if data else None)
 return ctypes.get_errno() if r else 0
def umount(path):
 assert libc.umount2(os.fsencode(path),0)==0,ctypes.get_errno()
def execute():
 return subprocess.run([str(base/'payload')],capture_output=True,text=True,timeout=8)
def register(path,name='same-name',interpreter=None):
 path.joinpath('register').write_text(':'+name+':M::RMX16BM::'+str(interpreter or base/'interpreter')+':F')
def report(command):
 if command=='ready':
  return {'user_namespace':os.readlink('/proc/self/ns/user'),'uid':os.getuid(),
   'uid_map':Path('/proc/self/uid_map').read_text().strip(),'seccomp':int(next(x.split(':')[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('Seccomp:'))),
   'registry':sorted(p.name for p in target.iterdir()),'payload':json.loads(execute().stdout)}
 if command=='disable':
  (target/'status').write_text('0')
  try:r=execute()
  except OSError as e:assert e.errno==errno.ENOEXEC;denied=e.errno
  else:assert r.returncode!=0;denied=r.returncode
  return {'denied':denied}
 if command=='enable':
  (target/'status').write_text('1');return {'payload':json.loads(execute().stdout)}
 if command=='inherit':
  code='import json,subprocess,sys; r=subprocess.run([sys.argv[1]],capture_output=True,text=True); assert r.returncode==0,(r.returncode,r.stderr); print(r.stdout)'
  r=subprocess.run(['unshare','--user','--map-root-user','--','python3','-c',code,str(base/'payload')],capture_output=True,text=True,timeout=10)
  assert r.returncode==0,(r.stdout,r.stderr);return {'payload':json.loads(r.stdout)}
 if command=='same-userns-mount':
  assert mount(other)==0
  assert (other/'same-name').read_text()==(target/'same-name').read_text()
  umount(target);r=execute();assert r.returncode==0
  assert mount(target)==0;umount(other)
  return {'shared':True,'payload':json.loads(r.stdout)}
 if command=='self-pin':
  node=target/'same-name';node.chmod(0o755)
  try:register(target,'selfpin',node)
  except OSError as e:assert e.errno==errno.EACCES;direct=e.errno
  else:raise AssertionError('F interpreter on its own binfmt mount was accepted')
  # Existing 4.14 overlayfs may lack FS_USERNS_MOUNT. Record the rejection
  # without attributing EPERM to stack-depth protection; audit binds the guard.
  for p in ('upper','work','overlay'): (base/p).mkdir()
  options='lowerdir='+str(target)+',upperdir='+str(base/'upper')+',workdir='+str(base/'work')
  error=mount(base/'overlay','overlay',options)
  if error==0:umount(base/'overlay');raise AssertionError('stacked binfmt mount accepted')
  assert error in (errno.EINVAL,errno.EPERM),error
  import shutil
  for p in ('overlay','work','upper'):shutil.rmtree(base/p)
  return {'own_interpreter_errno':direct,'stacked_mount_errno':error,'stack_guard_exercised':error==errno.EINVAL}
 if command=='remove-race':
  errors=[];done=threading.Event();counts={'ok':0,'denied':0}
  def executor():
   try:
    while not done.is_set():
     try:r=execute()
     except OSError as e:assert e.errno==errno.ENOEXEC;counts['denied']+=1;continue
     if r.returncode==0:assert json.loads(r.stdout)['tag']==tag;counts['ok']+=1
     else:raise AssertionError((r.returncode,r.stderr))
   except BaseException as e:errors.append(repr(e))
  thread=threading.Thread(target=executor);thread.start()
  for i in range(30):
   (target/'same-name').write_text('-1');register(target);time.sleep(.002)
  done.set();thread.join(10);assert not thread.is_alive() and not errors,errors
  return counts
 if command=='last-unmount':
  (target/'status').write_text('0');umount(target);assert mount(target)==0
  assert sorted(p.name for p in target.iterdir())==['register','status']
  assert (target/'status').read_text()=='enabled\n'
  try:r=execute()
  except OSError as e:assert e.errno==errno.ENOEXEC;denied=e.errno
  else:assert r.returncode!=0;denied=r.returncode
  register(target);return {'cleared':True,'re_enabled':True,'unregistered_exec_denied':denied,'payload':json.loads(execute().stdout)}
 if command=='exit':
  umount(target);target.rmdir();other.rmdir();return {'cleaned':True}
 raise AssertionError(command)
assert mount(target)==0
register(target)
for line in sys.stdin:
 command=line.strip()
 try:result=report(command);print(json.dumps({'command':command,'result':result}),flush=True)
 except BaseException as e:print(json.dumps({'command':command,'error':repr(e)}),flush=True);raise
 if command=='exit':break
'''
processes=[];results={};cleaned=[]
try:
 source=r'''#include <stdio.h>
#include <sys/prctl.h>
int main(void){printf("{\"tag\":\"%s\",\"seccomp\":%d}\n",TAG,prctl(PR_GET_SECCOMP));return 0;}
'''
 (base/'interpreter.c').write_text(source)
 for tag in ('alpha','beta'):
  directory=base/tag;directory.mkdir();os.chown(directory,1000,1000);directory.chmod(0o755)
  run(['gcc','-static','-O2','-Wall','-Wextra','-Werror','-DTAG="'+tag+'"',str(base/'interpreter.c'),'-o',str(directory/'interpreter')])
  (directory/'interpreter').chmod(0o755);(directory/'payload').write_bytes(b'RMX16BM'+b'\0'*128);(directory/'payload').chmod(0o755)
  proc=subprocess.Popen(['runuser','-u','podmantest','--','unshare','--user','--map-root-user','--mount','--propagation','private','--','python3','-c',worker,str(directory),tag],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  processes.append((tag,proc));results[tag]={}
 def command(tag,cmd):
  p=dict(processes)[tag];p.stdin.write(cmd+'\n');p.stdin.flush();line=p.stdout.readline()
  assert line,(tag,cmd,p.poll(),p.stderr.read() if p.poll() is not None else '')
  data=json.loads(line);assert 'error' not in data,data
  results[tag][cmd]=data['result'];return data['result']
 a=command('alpha','ready');b=command('beta','ready')
 assert a['user_namespace']!=b['user_namespace']!=os.readlink('/proc/self/ns/user')
 for tag in ('alpha','beta'):
  ready=results[tag]['ready'];assert ready['payload']=={'tag':tag,'seccomp':0} and ready['seccomp']==0 and ready['uid']==0 and ready['uid_map'].split()==['0','1000','1']
 command('alpha','disable');assert command('beta','ready')['payload']['tag']=='beta'
 assert command('alpha','enable')['payload']['tag']=='alpha'
 for tag in ('alpha','beta'):
  assert command(tag,'inherit')['payload']['tag']==tag
  assert command(tag,'same-userns-mount')['payload']['tag']==tag
  command(tag,'self-pin');command(tag,'remove-race');command(tag,'last-unmount')
 # F holds the native ELF interpreter even after the original pathname is gone.
 for tag in ('alpha','beta'):
  (base/tag/'interpreter').unlink()
  assert command(tag,'ready')['payload']['tag']==tag
  command(tag,'exit');p=dict(processes)[tag];assert p.wait(timeout=10)==0,p.stderr.read();cleaned.append(tag)
 assert before==registry(),'Global handlers changed'
 ordinary=int(next(x.split(':')[1] for x in Path('/proc/1/status').read_text().splitlines() if x.startswith('Seccomp:')))
 assert ordinary==2
 print(json.dumps({'passed':True,'cases':results,'global_registration_sha256_before':before,'global_registration_sha256_after':registry(),'ordinary_guest_seccomp':ordinary,'cleanup_errors':[]}))
 print('BINFMT_NAMESPACE_ISOLATION_PASS')
finally:
 for tag,p in processes:
  if p.poll() is None:p.terminate();p.wait(timeout=10)
 assert not any(p.poll() is None for _,p in processes)
 assert before==registry()
 shutil.rmtree(base)
PY
