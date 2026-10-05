#!/bin/sh
# Two private userns registries and temporary VFS stores; no global registration.
set -eu
test -f /etc/droidspaces
python3 - "$@" <<'PY'
import base64,hashlib,json,os,shutil,subprocess,tempfile,sys
from pathlib import Path

fixture_data={'x86_64': {'sha256': '002613a1d9e52753f1a1f1ea1df6b8c0b50f27460d42168429cfee3812206c75', 'base64': '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'}, 'aarch64': {'sha256': '1ee9f8b20c313bd5e6431a12bd3d64bf1f4119a09ab7106082161a6f8c369c1a', 'base64': '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'}}
entry_mode=sys.argv[1] if len(sys.argv)==2 else 'builtin'
assert len(sys.argv)<=2 and entry_mode in ('builtin','helper')
entry_seccomp=int(next(x.split(':')[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('Seccomp:')))
helper=Path('/usr/local/bin/rmx1931-binfmt')
if entry_mode=='helper':assert entry_seccomp==2 and helper.is_file()
registry_root=Path('/proc/sys/fs/binfmt_misc')
def registry():
 return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(registry_root.iterdir()) if p.is_file() and p.name!='register'}
def run(args,timeout=90):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if r.returncode:raise RuntimeError(json.dumps({'argv':args,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
 return r.stdout
before=registry();base=Path(tempfile.mkdtemp(prefix='rmx1931-crossarch-',dir='/var/tmp'));base.chmod(0o755);os.chdir(base)
worker=r'''
import ctypes,errno,hashlib,json,os,subprocess,sys
from pathlib import Path
base=Path(sys.argv[1]);mode=sys.argv[2];mountpoint=base/'binfmt';mountpoint.mkdir()
libc=ctypes.CDLL(None,use_errno=True);libc.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p];libc.umount2.argtypes=[ctypes.c_char_p,ctypes.c_int]
assert libc.mount(b'none',os.fsencode(mountpoint),b'binfmt_misc',0,None)==0,ctypes.get_errno()
magic=bytes.fromhex('7f454c4602010100000000000000000002003e00')
mask=bytes.fromhex('ffffffffffffff00fffffffffffffffffeffffff')
escape=lambda b:''.join('\\x%02x'%n for n in b)
if not (mountpoint/'qemu-x86_64').exists():
 (mountpoint/'register').write_text(':qemu-x86_64:M::'+escape(magic)+':'+escape(mask)+':/usr/bin/qemu-x86_64-static:F')
assert 'flags: F' in (mountpoint/'qemu-x86_64').read_text()
runtime=base/'runtime.py'
runtime.write_text(r"""#!/usr/bin/python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:];bundle=Path.cwd()
for i,a in enumerate(args):
 if a in ('--bundle','-b'):bundle=Path(args[i+1])
 elif a.startswith('--bundle='):bundle=Path(a.split('=',1)[1])
config=bundle/'config.json'
if config.is_file():
 spec=json.loads(config.read_text());profile=spec.get('linux',{}).get('seccomp')
 audit={'args':args,'uid_map':Path('/proc/self/uid_map').read_text().strip(),'user_namespace':os.readlink('/proc/self/ns/user'),
  'seccomp_present':bool(profile),'architectures':profile.get('architectures') if profile else None,
  'syscall_rules':len(profile.get('syscalls',[])) if profile else 0,'no_new_privileges':spec.get('process',{}).get('noNewPrivileges')}
 with (Path(__file__).parent/'runtime-audit.jsonl').open('a') as f:f.write(json.dumps(audit)+'\n')
os.execv('/usr/bin/crun',['crun',*args])
""")
runtime.chmod(0o755)
cli=['/usr/bin/podman','--storage-driver=vfs','--root='+str(base/'storage'),'--runroot='+str(base/'run'),
 '--cgroup-manager='+('systemd' if mode=='rootless' else 'cgroupfs'),'--events-backend=file','--runtime='+str(runtime)]
results={};images=[];containers=[]
def run(args,timeout=70,check=True):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if check and r.returncode:raise RuntimeError(json.dumps({'argv':args,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
 return r
def rows(text):return [json.loads(l) for l in text.splitlines() if l.startswith('{') and 'architecture' in l]
try:
 info=json.loads(run(cli+['info','--format=json']).stdout);driver=info['store']['graphDriverName'];assert driver=='vfs',driver
 for arch in ('amd64','arm64'):
  context=base/arch;image='localhost/rmx1931-binfmt-'+mode+'-'+arch+':1';images.append(image)
  (context/'Containerfile').write_text('FROM scratch\nCOPY fixture /fixture\nRUN ["/fixture", "build"]\nENTRYPOINT ["/fixture"]\n')
  built=run(cli+['build','--platform=linux/'+arch,'--isolation=oci','--runtime='+str(runtime),'--security-opt=seccomp=/usr/share/containers/seccomp.json','--network=none','-t',image,str(context)],timeout=90)
  build_rows=rows(built.stdout);assert build_rows and build_rows[-1]=={'architecture':arch,'build_marker':True,'seccomp':2,'mode':'build','uid':0,'gid':0},(built.stdout,built.stderr)
  configured=json.loads(run(cli+['image','inspect',image]).stdout)[0];assert configured['Architecture']==arch
  name='rmx1931-binfmt-'+mode+'-'+arch;containers.append(name)
  output=run(cli+['run','--name',name,'--network=none','--pull=never',image]).stdout
  actual=rows(output);assert actual==[{'architecture':arch,'build_marker':True,'seccomp':2,'mode':'run','uid':0,'gid':0}],output
  run(cli+['rm',name]);containers.remove(name)
  nonroot_name=name+'-uid1000';containers.append(nonroot_name)
  nonroot=rows(run(cli+['run','--name',nonroot_name,'--user=1000:1000','--network=none','--pull=never',image]).stdout)
  assert nonroot==[{**actual[0],'uid':1000,'gid':1000}],nonroot
  run(cli+['rm',nonroot_name]);containers.remove(nonroot_name)
  runc_name=name+'-runc';containers.append(runc_name)
  runc_cli=cli[:-1]+['--runtime=/usr/bin/runc']
  runc_payload=rows(run(runc_cli+['run','--name',runc_name,'--network=none','--pull=never',image]).stdout);assert runc_payload==actual,runc_payload
  run(cli+['rm',runc_name]);containers.remove(runc_name)
  results[arch]={'build_payload':build_rows[-1],'run_payload':actual[0],'nonroot_payload':nonroot[0],'runc_payload':runc_payload[0],'image_id':configured['Id'],'image_architecture':configured['Architecture']}
 # Removing the local handler must stop new amd64 exec while native still works.
 (mountpoint/'qemu-x86_64').write_text('-1')
 image='localhost/rmx1931-binfmt-'+mode+'-amd64:1';name='rmx1931-binfmt-'+mode+'-denied';containers.append(name)
 denied=run(cli+['run','--rm','--name',name,'--network=none','--pull=never',image],check=False)
 assert denied.returncode!=0 and 'exec format error' in (denied.stdout+denied.stderr).lower(),(denied.returncode,denied.stdout,denied.stderr)
 run(cli+['rm','-f',name],check=False);containers.remove(name)
 assert sorted(p.name for p in mountpoint.iterdir())==['register','status']
 print(json.dumps({'mode':mode,'passed':True,'user_namespace':os.readlink('/proc/self/ns/user'),'storage_driver':driver,'cases':results,
  'local_revocation_returncode':denied.returncode,'registry_after_revocation':sorted(p.name for p in mountpoint.iterdir()),'cleanup_errors':[]}),flush=True)
finally:
 if (base/'runtime-audit.jsonl').exists():print('OCI_SPEC_AUDIT '+(base/'runtime-audit.jsonl').read_text(),flush=True)
 for name in containers:run(cli+['rm','-f','--time','0',name],check=False)
 for image in images:run(cli+['rmi','-f',image],check=False)
 # Failed builds can leave intermediate images in this private temporary store.
 run(cli+['rmi','--all','--force'],check=False)
 assert not json.loads(run(cli+['ps','-aq','--format=json']).stdout or '[]')
 assert not json.loads(run(cli+['images','--format=json']).stdout)
 assert libc.umount2(os.fsencode(mountpoint),0)==0,ctypes.get_errno();mountpoint.rmdir()
'''
namespace_launcher=r'''
import ctypes,os,sys
from pathlib import Path
ready_r,ready_w=os.pipe();go_r,go_w=os.pipe();pid=os.fork()
if not pid:
 os.close(ready_r);os.close(go_w);c=ctypes.CDLL(None,use_errno=True)
 assert c.unshare(0x10000000|0x00020000)==0,ctypes.get_errno()
 os.write(ready_w,b'1');os.close(ready_w)
 if os.read(go_r,1)!=b'1':os._exit(125)
 os.close(go_r)
 c.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p]
 assert c.mount(None,b'/',None,(1<<18)|(1<<14),None)==0,ctypes.get_errno()
 os.execv(sys.executable,[sys.executable,'-c',*sys.argv[1:]])
os.close(ready_w);os.close(go_r)
try:
 assert os.read(ready_r,1)==b'1';os.close(ready_r)
 # The initial-userns root parent owns CAP_SETUID/CAP_SETGID. Write the
 # A bounded identity mapping covers root and UID 1000. crun's userns
 # detection treats a 4294967295-entry identity map as the initial namespace.
 for name in ('uid_map','gid_map'):(Path('/proc')/str(pid)/name).write_text('0 0 65536\n')
 os.write(go_w,b'1')
finally:os.close(go_w)
_,status=os.waitpid(pid,0);raise SystemExit(os.waitstatus_to_exitcode(status))
'''
results=[];roots={};cleanup=[]
try:
 qemu=Path('/usr/bin/qemu-x86_64-static');assert qemu.is_file()
 qemu_info={'sha256':hashlib.sha256(qemu.read_bytes()).hexdigest(),'version':run([str(qemu),'--version'],timeout=10).splitlines()[0]}
 for mode in ('rootful','rootless'):
  directory=base/mode;directory.mkdir(mode=0o755)
  for arch,binary in [('amd64','x86_64'),('arm64','aarch64')]:
   context=directory/arch;context.mkdir(mode=0o755)
   data=base64.b64decode(fixture_data[binary]['base64']);assert hashlib.sha256(data).hexdigest()==fixture_data[binary]['sha256']
   (context/'fixture').write_bytes(data);(context/'fixture').chmod(0o755)
  if mode=='rootful':
   argv=([str(helper),'--','python3','-c',worker,str(directory),mode] if entry_mode=='helper' else ['python3','-c',namespace_launcher,worker,str(directory),mode])
  else:
   for path in [directory,*directory.rglob('*')]:os.chown(path,1000,1000)
   roots[mode]=['runuser','-u','podmantest','--','env','HOME=/home/podmantest','USER=podmantest','LOGNAME=podmantest','XDG_RUNTIME_DIR=/run/user/1000','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus',
    '/usr/bin/podman','--storage-driver=vfs','--root='+str(directory/'storage'),'--runroot='+str(directory/'run'),'--events-backend=file']
   argv=roots[mode]+(['unshare',str(helper),'--','python3','-c',worker,str(directory),mode] if entry_mode=='helper' else ['unshare','unshare','--mount','--propagation','private','--','python3','-c',worker,str(directory),mode])
  output=run(argv,timeout=240)
  rows=[json.loads(l) for l in output.splitlines() if l.startswith('{') and '"cases"' in l and '"mode"' in l];assert len(rows)==1,output
  results.append(rows[0]);print(json.dumps(rows[0]),flush=True)
  if mode=='rootless':run(roots[mode]+['system','migrate'],timeout=25)
 assert results[0]['user_namespace']!=results[1]['user_namespace']
 assert before==registry()
 ordinary=int(next(x.split(':')[1] for x in Path('/proc/1/status').read_text().splitlines() if x.startswith('Seccomp:')));assert ordinary==2
 print(json.dumps({'passed':True,'entry_seccomp':entry_seccomp,'entry_mode':entry_mode,
  'helper_source_sha256':hashlib.sha256(helper.read_bytes()).hexdigest() if entry_mode=='helper' else None,'qemu':qemu_info,'fixtures':{k:{'sha256':v['sha256']} for k,v in fixture_data.items()},'modes':results,
  'global_registration_sha256_before':before,'global_registration_sha256_after':registry(),'ordinary_guest_seccomp':ordinary,'cleanup_errors':[]}))
 print('BINFMT_CROSSARCH_PODMAN_PASS')
finally:
 for mode,cli in roots.items():
  # Migrate only the temporary root/runroot; releases its rootless pause.
  try:run(cli+['system','migrate'],timeout=25)
  except BaseException as e:cleanup.append(repr(e))
 assert before==registry()
 assert not cleanup,cleanup
 shutil.rmtree(base)
PY
