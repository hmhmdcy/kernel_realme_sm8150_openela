#!/bin/sh
# Compare settled native CPU stats with real task runtime and hierarchical totals.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
python3 - <<'PY'
import json, os, select, subprocess, sys, time, uuid
from pathlib import Path
cg=Path('/sys/fs/cgroup');assert 'cpu' in (cg/'cgroup.controllers').read_text().split()
token='rmx1931-cpu-stat-'+uuid.uuid4().hex[:10];base=cg/token
created,workers,cleanup,observations=[],[],[],[]
root_before=(cg/'cgroup.subtree_control').read_text()
def write(path,value):path.write_text(str(value)+'\n')
def mkdir(path):path.mkdir();created.append(path);return path
def stat(path):return dict((x.split()[0],int(x.split()[1])) for x in (path/'cpu.stat').read_text().splitlines())
source=r'''
import json,os,resource,sys,time
from pathlib import Path
print('ready',flush=True);start=float(sys.stdin.readline());before=resource.getrusage(resource.RUSAGE_SELF)
while time.monotonic()<start:time.sleep(.001)
value=1
while time.monotonic()<start+2:
 for _ in range(4096):value=(value*1664525+1013904223)&0xffffffff
while time.monotonic()<start+4:
 for _ in range(64):os.stat('/proc/self/status');os.getpid();os.sched_getaffinity(0)
after=resource.getrusage(resource.RUSAGE_SELF)
print(json.dumps({'user':after.ru_utime-before.ru_utime,'system':after.ru_stime-before.ru_stime,
 'cpu':after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
 'affinity':sorted(os.sched_getaffinity(0)), 'membership':Path('/proc/self/cgroup').read_text().splitlines(),
 'seccomp':int(next(x.split(':')[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('Seccomp:')))}),flush=True)
'''
try:
 mkdir(base);write(base/'cgroup.subtree_control','+cpu')
 leaves=[mkdir(base/str(i)) for i in range(2)]
 for leaf in leaves:write(leaf/'cpu.max','50000 100000')
 selected=sorted(os.sched_getaffinity(0))[-2:];assert len(selected)==2
 for i,leaf in enumerate(leaves):
  p=subprocess.Popen([sys.executable,'-u','-c',source],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  workers.append(p);assert select.select([p.stdout],[],[],10)[0] and p.stdout.readline().strip()=='ready'
  write(leaf/'cgroup.procs',p.pid);os.sched_setaffinity(p.pid,{selected[i]})
 time.sleep(.1)
 assert all(Path('/proc/'+str(p.pid)+'/stat').read_text().rsplit(')',1)[1].split()[0]=='S' for p in workers)
 paths=[base,*leaves];before=[stat(x) for x in paths];start=time.monotonic()+.2
 for p in workers:p.stdin.write(str(start)+'\n');p.stdin.flush()
 while any(p.poll() is None for p in workers):
  observations.append([stat(x) for x in paths]);time.sleep(.05)
 workloads=[]
 for p in workers:
  out,err=p.communicate(timeout=5);assert p.returncode==0,(p.returncode,out,err)
  workloads.append(json.loads(out))
 time.sleep(.1);after=[stat(x) for x in paths]
 assert all(not (leaf/'cgroup.procs').read_text().strip() for leaf in leaves)
 assert all(x['seccomp']==2 and x['affinity']==[selected[i]] for i,x in enumerate(workloads)),workloads
 fields=['usage_usec','user_usec','system_usec']
 deltas=[{k:last[k]-first[k] for k in fields} for first,last in zip(before,after)]
 identities=[{'path':str(path),'usage_usec':row['usage_usec'],'user_plus_system_usec':row['user_usec']+row['system_usec'],
   'difference_usec':row['user_usec']+row['system_usec']-row['usage_usec']} for path,row in zip(paths,after)]
 monotonic=all(all(curr[k]>=prev[k] for k in fields) for prev_rows,curr_rows in zip([before,*observations],observations+[after]) for prev,curr in zip(prev_rows,curr_rows))
 # Runtime is exactly propagated. Each group's tick split is normalized
 # independently, as in upstream cputime_adjust; user/system sums can differ.
 hierarchy=abs(after[0]['usage_usec']-sum(x['usage_usec'] for x in after[1:]))<=2
 split_errors={k:deltas[0][k]-sum(x[k] for x in deltas[1:]) for k in ['user_usec','system_usec']}
 split_close=all(abs(value)<max(20000,deltas[0]['usage_usec']*.01) for value in split_errors.values())
 runtimes=[{'group_delta_usage_usec':row['usage_usec'],'task_cpu_usec':task['cpu']*1e6,
   'difference_usec':row['usage_usec']-task['cpu']*1e6} for row,task in zip(deltas[1:],workloads)]
 runtime_matches=all(abs(x['difference_usec'])<50000 for x in runtimes)
 identities_match=all(abs(x['difference_usec'])<=2 for x in identities)
 passed=identities_match and monotonic and hierarchy and split_close and runtime_matches
 report={'workloads':workloads,'before':before,'after':after,'settled_identities':identities,'deltas':deltas,
  'runtime_comparison':runtimes,'snapshot_count':len(observations),'sampled_monotonic':monotonic,
  'parent_children_usage_match':hierarchy,'parent_children_split_difference_usec':split_errors,
  'parent_children_split_within_normalization_tolerance':split_close,'runtime_matches':runtime_matches,
  'settled_user_system_usage_match':identities_match,'passed':passed}
finally:
 for p in workers:
  if p.poll() is None:p.terminate()
  p.wait(timeout=5)
 for path in reversed(created):
  for attempt in range(30):
   try:path.rmdir();break
   except OSError as error:
    if attempt==29:cleanup.append({'path':str(path),'error':str(error)})
    time.sleep(.1)
assert not cleanup,cleanup
assert (cg/'cgroup.subtree_control').read_text()==root_before
report['cleanup_errors']=cleanup;print(json.dumps(report),flush=True)
print('NATIVE_CPU_STAT_CONSISTENCY_PASS' if passed else 'NATIVE_CPU_STAT_CONSISTENCY_FAILED',flush=True)
sys.exit(0 if passed else 1)
PY
