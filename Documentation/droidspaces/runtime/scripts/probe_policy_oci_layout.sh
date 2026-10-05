#!/bin/sh
# Inspect owned, bounded OCI fixtures before changing the runtime entry.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
python3 - <<'PY'
import json, os, subprocess, uuid
from pathlib import Path
token='rmx1931-policy-layout-'+uuid.uuid4().hex[:8]
def run(argv):
    r=subprocess.run(argv,capture_output=True,text=True,timeout=30)
    if r.returncode:raise RuntimeError(json.dumps({'argv':argv,'stdout':r.stdout,'stderr':r.stderr,'rc':r.returncode}))
    return r.stdout.strip()
for mode,launcher,storage in [('rootful',['podman'],'/var/lib/containers/storage'),('rootless',['podman-rootless'],'/home/podmantest/.local/share/containers/storage')]:
    name=token+'-'+mode;created=False
    try:
        run(launcher+['run','-d','--name',name,'--network=none','--memory=64m','--pids-limit=32','localhost/rmx1931-probe:1','/bin/sleep','300']);created=True
        row=json.loads(run(launcher+['inspect',name]))[0];cid=row['Id']
        path=Path(storage,'overlay-containers',cid,'userdata','config.json')
        config=json.loads(path.read_text())
        print(json.dumps({'mode':mode,'id':cid,'name':name,'path':str(path),'file_uid':path.stat().st_uid,'annotations':config.get('annotations'),'resources':config['linux'].get('resources'),'cgroupsPath':config['linux'].get('cgroupsPath'),'pid':row['State']['Pid'],'staticDir':row.get('StaticDir'),'rootfsDevice':{'major':os.major(Path('/').stat().st_dev),'minor':os.minor(Path('/').stat().st_dev)}}),flush=True)
    finally:
        if created:run(launcher+['rm','-f','--time','0',name])
print('POLICY_OCI_LAYOUT_CLEANUP_PASS',flush=True)
PY
