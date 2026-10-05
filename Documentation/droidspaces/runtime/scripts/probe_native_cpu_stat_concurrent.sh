#!/bin/sh
# Exercise concurrent container-metrics readers against a live CPU workload.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
python3 - <<'PY'
import concurrent.futures,json,os,select,subprocess,sys,time,uuid
from pathlib import Path
cg=Path('/sys/fs/cgroup');assert 'cpu' in (cg/'cgroup.controllers').read_text().split()
token='rmx1931-stat-readers-'+uuid.uuid4().hex[:10];group=cg/token
source=r'''
import json,os,sys,time
from pathlib import Path
print('ready',flush=True);sys.stdin.readline();end=time.monotonic()+5;value=1
while time.monotonic()<end:
 for _ in range(4096):value=(value*1664525+1013904223)&0xffffffff
 for _ in range(32):os.stat('/proc/self/status')
print(json.dumps({'seccomp':int(next(x.split(':')[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('Seccomp:'))),
 'membership':Path('/proc/self/cgroup').read_text().splitlines()}),flush=True)
'''
def stat():return dict((x.split()[0],int(x.split()[1])) for x in (group/'cpu.stat').read_text().splitlines())
worker=None;cleanup=[];before=(cg/'cgroup.subtree_control').read_text()
try:
 group.mkdir();(group/'cpu.max').write_text('50000 100000\n')
 worker=subprocess.Popen([sys.executable,'-u','-c',source],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 assert select.select([worker.stdout],[],[],10)[0] and worker.stdout.readline().strip()=='ready'
 (group/'cgroup.procs').write_text(str(worker.pid)+'\n');os.sched_setaffinity(worker.pid,{max(os.sched_getaffinity(0))})
 def reader(index):
  previous=None;count=0;monotonic=True;consistent=True;maximum_difference=0;examples=[]
  for _ in range(1000):
   row=stat();difference=row['user_usec']+row['system_usec']-row['usage_usec'];count+=1
   maximum_difference=max(maximum_difference,abs(difference));consistent &= abs(difference)<=2
   if previous is not None:monotonic &= all(row[k]>=previous[k] for k in ['usage_usec','user_usec','system_usec'])
   if abs(difference)>2 and len(examples)<3:examples.append(row)
   previous=row
   if worker.poll() is not None:break
   time.sleep(.005)
  return {'reader':index,'snapshots':count,'monotonic':monotonic,'split_matches_usage':consistent,'maximum_split_difference_usec':maximum_difference,'examples':examples}
 worker.stdin.write('start\n');worker.stdin.flush()
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:readers=list(executor.map(reader,range(8)))
 out,err=worker.communicate(timeout=10);assert worker.returncode==0,(worker.returncode,out,err)
 payload=json.loads(out);assert payload['seccomp']==2
 assert all(x['snapshots']>=10 for x in readers),readers
 passed=all(x['monotonic'] and x['split_matches_usage'] for x in readers)
finally:
 if worker is not None:
  if worker.poll() is None:worker.terminate()
  worker.wait(timeout=5)
 for attempt in range(30):
  try:group.rmdir();break
  except OSError as error:
   if attempt==29:cleanup.append(str(error))
   time.sleep(.1)
assert not cleanup,cleanup
assert (cg/'cgroup.subtree_control').read_text()==before
print(json.dumps({'readers':readers,'payload':payload,'passed':passed,'cleanup_errors':cleanup}),flush=True)
print('NATIVE_CPU_STAT_CONCURRENT_PASS' if passed else 'NATIVE_CPU_STAT_CONCURRENT_FAILED',flush=True)
sys.exit(0 if passed else 1)
PY
