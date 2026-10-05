#!/bin/sh
# Bound the foreground watcher to its original process and group.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
test "$(uname -r)" = 4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf
python3 - <<'PY'
import json,os,subprocess,time,uuid
from pathlib import Path

token='rmx1931-psi-watch-'+uuid.uuid4().hex[:10]
base=Path('/var/tmp')/token;base.mkdir(mode=0o700)
results=[];active=[];cleanup_errors=[]
def run(argv,check=True):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=30)
 if check and r.returncode:raise RuntimeError(json.dumps({'argv':argv,'rc':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
 return r
def out(argv):return run(argv).stdout.strip()
def metadata(cli,name):return json.loads(out(cli+['inspect','--type=container',name]))[0]
def group(pid):
 rows=[s[3:] for s in Path('/proc',str(pid),'cgroup').read_text().splitlines() if s.startswith('0::')]
 assert len(rows)==1 and '..' not in rows[0].split('/'),rows
 return Path('/sys/fs/cgroup'+rows[0])
def records(path):return [json.loads(s) for s in path.read_text().splitlines()]
def start(mode,name,case,cid):
 log=base/(name+'-'+case+'.log');err=base/(name+'-'+case+'.err')
 with log.open('w') as stdout,err.open('w') as stderr:
  p=subprocess.Popen(['rmx1931-pressure','--mode',mode,'--name',name,
     '--threshold-us','50000','--window-us','1000000','--timeout','2.5' if case=='deadline' else '15'],stdout=stdout,stderr=stderr)
 active.append(p);deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  rows=records(log)
  if rows:
   assert rows[0]['event']=='ready' and rows[0]['container_id']==cid,rows
   return p,log,err
  assert p.poll() is None,err.read_text()
  time.sleep(.03)
 raise AssertionError('Watcher did not become ready')
def finish(p,log,err,cid,expected):
 status=p.wait(timeout=8);rows=records(log);errors=err.read_text()
 assert rows and all(r.get('container_id')==cid for r in rows),rows
 assert not any(r['event']=='memory-pressure' for r in rows),rows
 if expected=='deadline':
  assert status==3 and not errors and rows[-1]['event']=='complete' and rows[-1]['reason']=='deadline' and rows[-1]['notifications']==0,(status,rows,errors)
 else:
  assert status not in (0,3) and ('refusing a replacement' in errors or 'Pinned pressure group is gone' in errors or 'No such file or directory' in errors),(status,rows,errors)
 return {'returncode':status,'records':rows,'stderr':errors}

try:
 for mode,cli in [('rootful',['podman']),('rootless',['podman-rootless'])]:
  for runtime in ('crun','runc'):
   name=token+'-'+mode+'-'+runtime;child=None
   argv=cli+['run','-d','--name',name,'--runtime='+runtime,'--network=none','--memory=96m','--pids-limit=32',
     '--entrypoint=/bin/sh','localhost/rmx1931-probe:1','-c',
     'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.high; sed -n "s/^Seccomp:[[:space:]]*//p" /proc/self/status; exec sleep 120']
   try:
    out(argv);old=metadata(cli,name);pid=old['State']['Pid'];g=group(pid)
    assert old['Id'] in str(g) and out(cli+['logs',name])=='100663296\nmax\n2'
    limits={f:(g/f).read_text().strip() for f in ('memory.max','memory.high','memory.oom.group')}
    p,log,err=start(mode,name,'deadline',old['Id']);deadline_case=finish(p,log,err,old['Id'],'deadline')
    assert {f:(g/f).read_text().strip() for f in limits}==limits

    # Move only this fixture's payload under its existing hard-limited group.
    # The watcher must reject the changed path even though PID and ID survive.
    p,log,err=start(mode,name,'move',old['Id']);child=g/'rmx1931-watch-move';child.mkdir()
    try:
     (child/'cgroup.procs').write_text(str(pid)+'\n');assert group(pid)==child
     move_case=finish(p,log,err,old['Id'],'move')
     assert metadata(cli,name)['State']['Pid']==pid
    finally:
     current=metadata(cli,name)
     if current['Id']==old['Id'] and current['State']['Running'] and current['State']['Pid']==pid:
      (g/'cgroup.procs').write_text(str(pid)+'\n')
     child.rmdir();child=None
    assert group(pid)==g and {f:(g/f).read_text().strip() for f in limits}==limits

    # Replacing a name must never redirect the old open subscription.
    p,log,err=start(mode,name,'replace',old['Id'])
    out(cli+['rm','-f','--time','0',name]);out(argv);new=metadata(cli,name)
    assert new['Id']!=old['Id'] and new['State']['Running']
    replace_case=finish(p,log,err,old['Id'],'replace')
    assert out(cli+['logs',name])=='100663296\nmax\n2'
    row={'mode':mode,'runtime':runtime,'old_container_id':old['Id'],'new_container_id':new['Id'],
     'deadline':deadline_case,'move':move_case,'replace':replace_case,'limits_unchanged':True,'passed':True}
    results.append(row);print(json.dumps(row),flush=True)
   finally:
    for p in active:
     if p.poll() is None:p.terminate();p.wait(timeout=5)
    r=run(cli+['rm','-f','--time','0',name],check=False)
    if r.returncode and 'no such container' not in r.stderr.lower():cleanup_errors.append(r.stderr)
    if child is not None and child.exists():child.rmdir()
 assert len(results)==4 and not cleanup_errors,(results,cleanup_errors)
 assert not out(['podman','ps','-q']) and not out(['podman-rootless','ps','-q'])
 assert json.loads(out(['rmx1931-policy','validate']))['profiles']=={}
 print('GROUP_PSI_MONITOR_LIFECYCLE_PASS',flush=True)
finally:
 for p in active:
  if p.poll() is None:p.terminate();p.wait(timeout=5)
 print(json.dumps({'cleanup_errors':cleanup_errors,'fixture_directory':str(base),'logs_retained':True}),flush=True)
PY
