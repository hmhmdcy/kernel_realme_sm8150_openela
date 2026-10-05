#!/bin/sh
# Reviewed, scoped legacy scheduler fixture; ordinary guest filtering is retained.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
test "$(sed -n 's/^Seccomp:[[:space:]]*//p' /proc/self/status)" = 0
if test "${1:-}" != private-mount-namespace; then
    exec unshare --mount --propagation private -- /bin/sh "$0" private-mount-namespace
fi
python3 - <<'PY'
import json,os,select,subprocess,sys,tempfile,time,uuid
from pathlib import Path
assert os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt')
def seccomp(pid):return int(next(x.split(':')[1] for x in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if x.startswith('Seccomp:')))
assert seccomp(1)==2
token='rmx1931-legacy-weights-'+uuid.uuid4().hex[:10]
base=Path(tempfile.mkdtemp(prefix=token+'-',dir='/var/tmp'));mount=base/'cpu'
workers,leaves,cases,cleanup=[],[],[],[];mounted=False;root_state={}
def write(path,value):path.write_text(str(value)+'\n')
def run(argv):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=30)
 assert r.returncode==0,(argv,r.returncode,r.stdout,r.stderr)
def legacy(pid):
 for line in Path('/proc/'+str(pid)+'/cgroup').read_text().splitlines():
  _,names,path=line.split(':',2)
  if {'cpu','cpu_legacy'} & set(names.split(',')):return path
 raise AssertionError('Legacy CPU membership missing')
source=r'''
import json,os,resource,sys,time
from pathlib import Path
print('ready',flush=True)
for line in sys.stdin:
 start=float(line);warm=start+2;end=warm+6
 while time.monotonic()<start:time.sleep(.001)
 before=None;value=1
 while time.monotonic()<end:
  if before is None and time.monotonic()>=warm:
   r=resource.getrusage(resource.RUSAGE_SELF);before=(r.ru_utime+r.ru_stime,time.monotonic())
  for _ in range(4096):value=(value*1664525+1013904223)&0xffffffff
 r=resource.getrusage(resource.RUSAGE_SELF)
 print(json.dumps({'cpu':r.ru_utime+r.ru_stime-before[0],'wall':time.monotonic()-before[1],
  'affinity':sorted(os.sched_getaffinity(0)), 'membership':Path('/proc/self/cgroup').read_text().splitlines(),
  'seccomp':int(next(x.split(':')[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('Seccomp:')))}),flush=True)
'''
try:
 mount.mkdir();run(['mount','-t','cgroup','-o','cpu','none',str(mount)]);mounted=True
 assert legacy(os.getpid())=='/'
 root_state={str(p):p.read_text() for p in [mount/'cpu.shares',mount/'cpu.cfs_quota_us',mount/'cpu.cfs_period_us']}
 target=max(os.sched_getaffinity(0));old=min(os.sched_getaffinity(0));assert target!=old
 for i in range(2):
  leaf=mount/(token+'-'+str(i));leaf.mkdir();leaves.append(leaf)
  write(leaf/'cpu.shares',128 if i==0 else 512);write(leaf/'cpu.cfs_quota_us',-1)
  p=subprocess.Popen([sys.executable,'-u','-c',source],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,preexec_fn=lambda:os.sched_setaffinity(0,{old}))
  workers.append(p);assert select.select([p.stdout],[],[],10)[0] and p.stdout.readline().strip()=='ready'
  time.sleep(.05);assert Path('/proc/'+str(p.pid)+'/stat').read_text().rsplit(')',1)[1].split()[0]=='S'
  write(leaf/'cgroup.procs',p.pid);os.sched_setaffinity(p.pid,{target});assert legacy(p.pid)=='/'+leaf.name
 for tag,shares,limits in [('legacy-shares-1-to-4',[128,512],(2,7)),('legacy-shares-swapped',[512,128],(.15,.45))]:
  for leaf,value in zip(leaves,shares):write(leaf/'cpu.shares',value)
  start=time.monotonic()+.2
  for p in workers:p.stdin.write(str(start)+'\n');p.stdin.flush()
  rows=[]
  for p in workers:
   assert select.select([p.stdout],[],[],20)[0]
   row=json.loads(p.stdout.readline());assert row['affinity']==[target] and row['seccomp']==0,row
   rows.append(row)
  ratio=rows[1]['cpu']/rows[0]['cpu'];assert limits[0]<ratio<limits[1],(tag,ratio,rows)
  case={'case':tag,'shares':shares,'workloads':rows,'second_first_cpu_ratio':ratio}
  cases.append(case);print(json.dumps(case),flush=True)
finally:
 for p in workers:
  if p.poll() is None:p.terminate()
  p.wait(timeout=5)
 for leaf in reversed(leaves):
  for attempt in range(30):
   try:leaf.rmdir();break
   except OSError as error:
    if attempt==29:cleanup.append({'path':str(leaf),'error':str(error)})
    time.sleep(.1)
 if root_state:assert all(Path(p).read_text()==value for p,value in root_state.items())
 if mounted:run(['umount',str(mount)])
 mount.rmdir();base.rmdir()
assert not cleanup,cleanup
assert seccomp(1)==2
print(json.dumps({'cases':cases,'cleanup_errors':cleanup,'ordinary_guest_seccomp':2,'scope':'Legacy CPU group scheduler weights; scoped unfiltered workers only'}),flush=True)
print('LEGACY_CPU_WEIGHT_REGRESSION_PASS',flush=True)
PY
