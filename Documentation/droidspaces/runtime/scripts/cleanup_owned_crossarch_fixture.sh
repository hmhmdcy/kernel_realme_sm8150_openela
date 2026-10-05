#!/bin/sh
# Remove only a completed, empty temporary crossarch fixture store.
set -eu
test -f /etc/droidspaces
cd /var/tmp
python3 - "$@" <<'PY'
import json,os,re,shutil,subprocess,sys
from pathlib import Path
assert len(sys.argv)==2
target=Path(sys.argv[1]);assert re.fullmatch(r'/var/tmp/rmx1931-crossarch-[a-z0-9_]{8}',str(target))
assert target.is_dir() and not target.is_symlink() and target.resolve()==target
mounts=[line.split()[4] for line in Path('/proc/self/mountinfo').read_text().splitlines()]
assert not any(m==str(target) or m.startswith(str(target)+'/') for m in mounts),mounts
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit():continue
 try:
  name=(proc/'comm').read_text().strip();cmd=(proc/'cmdline').read_bytes()
 except (FileNotFoundError,PermissionError):continue
 assert name not in ('podman','conmon','crun','runc') or os.fsencode(target) not in cmd,(proc,name)
for mode in ('rootful','rootless'):
 directory=target/mode
 if not (directory/'storage').is_dir():continue
 cli=['/usr/bin/podman','--storage-driver=vfs','--root='+str(directory/'storage'),'--runroot='+str(directory/'run'),'--events-backend=file']
 if mode=='rootless':cli=['runuser','-u','podmantest','--','env','HOME=/home/podmantest','XDG_RUNTIME_DIR=/run/user/1000',*cli]
 for args in (['ps','-aq','--format=json'],['images','--format=json']):
  r=subprocess.run(cli+args,capture_output=True,text=True,timeout=30);assert r.returncode==0,(r.returncode,r.stderr)
  assert not json.loads(r.stdout or '[]'),r.stdout
 if mode=='rootless':
  r=subprocess.run(cli+['system','migrate'],capture_output=True,text=True,timeout=30);assert r.returncode==0,r.stderr
shutil.rmtree(target)
print(json.dumps({'passed':True,'owned_directory':str(target),'active_mounts':False,'private_stores_empty':True,'cleanup_errors':[]}))
PY
