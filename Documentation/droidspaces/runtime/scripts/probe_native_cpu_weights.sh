#!/bin/sh
# Isolate native CFS weights from Podman startup and nested scope placement.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
python3 - <<'PY'
import json,os,select,subprocess,sys,time,uuid
from pathlib import Path
cg=Path('/sys/fs/cgroup');assert {'cpu','cpuset'}<=set((cg/'cgroup.controllers').read_text().split())
def write(path,value):
    with path.open('w') as f:f.write(str(value)+'\n')
def cpus(value):
    result=set()
    for piece in value.strip().split(','):
        a,sep,b=piece.partition('-');result.update(range(int(a),int(b)+1) if sep else [int(a)])
    return result
worker=r'''
import json,os,resource,sys,time
from pathlib import Path
print('ready',flush=True)
start=float(sys.stdin.readline());warm=start+2;end=warm+8;x=1
while time.monotonic()<start:time.sleep(.001)
def cpu():
 r=resource.getrusage(resource.RUSAGE_SELF);return r.ru_utime+r.ru_stime
before=None
while time.monotonic()<end:
 for _ in range(4096):x=(x*1664525+1013904223)&0xffffffff
 if before is None and time.monotonic()>=warm:before=(cpu(),time.monotonic())
assert before
print(json.dumps({'cpu':cpu()-before[0],'wall':time.monotonic()-before[1],
 'start':before[1],'affinity':sorted(os.sched_getaffinity(0)),'nice':os.getpriority(os.PRIO_PROCESS,0),
 'weight':Path('/sys/fs/cgroup').joinpath(next(l[3:] for l in Path('/proc/self/cgroup').read_text().splitlines() if l.startswith('0::')).lstrip('/'),'cpu.weight').read_text().strip(),
 'membership':Path('/proc/self/cgroup').read_text().splitlines(),
 'seccomp':int(next(l.split(':')[1] for l in Path('/proc/self/status').read_text().splitlines() if l.startswith('Seccomp:')))}),flush=True)
'''
base=cg/('rmx1931-native-weight-'+uuid.uuid4().hex[:10]);created=[];workers=[];cases=[];cleanup=[]
root_before=(cg/'cgroup.subtree_control').read_text();core=max(cpus((cg/'cpuset.cpus.effective').read_text()))
def mkdir(path):path.mkdir();created.append(path);return path
try:
    mkdir(base);write(base/'cpuset.cpus',core);write(base/'cpuset.mems',0);write(base/'cgroup.subtree_control','+cpu +cpuset')
    for tag,weights,nested in [('flat-equal',(100,100),False),('flat-4x',(10,39),False),('flat-swapped',(39,10),False),('nested-4x',(10,39),True)]:
        round_group=mkdir(base/tag);write(round_group/'cgroup.subtree_control','+cpu +cpuset');pair=[]
        for index,weight in enumerate(weights):
            group=mkdir(round_group/str(index));write(group/'cpu.weight',weight)
            if nested:
                write(group/'cgroup.subtree_control','+cpu +cpuset');group=mkdir(group/'payload');write(group/'cpu.weight',weight)
            p=subprocess.Popen([sys.executable,'-u','-c',worker],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            workers.append(p);assert p.stdout.readline().strip()=='ready';write(group/'cgroup.procs',p.pid);pair.append(p)
        start=time.monotonic()+.3
        for p in pair:p.stdin.write(str(start)+'\n');p.stdin.flush()
        rows=[]
        for p in pair:
            stdout,stderr=p.communicate(timeout=18);assert p.returncode==0,(p.returncode,stdout,stderr)
            rows.append(json.loads(stdout))
        assert all(r['affinity']==[core] and r['seccomp']==2 and r['nice']==0 for r in rows),rows
        ratio=rows[1]['cpu']/rows[0]['cpu'];expected=weights[1]/weights[0]
        passed=(.7<ratio<1.4 if expected==1 else 2<ratio<7 if expected>1 else 1/7<ratio<.5)
        row={'case':tag,'weights':weights,'workloads':rows,'high_index_to_low_index_ratio':ratio,'expected_relative_weight':expected,'passed':passed}
        cases.append(row);print(json.dumps(row),flush=True)
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
passed=all(r['passed'] for r in cases)
print(json.dumps({'core':core,'cases':cases,'cleanup_errors':cleanup,'passed':passed}),flush=True)
assert passed,'Native weight ratios failed; retain all diagnostic cases'
print('NATIVE_CPU_WEIGHT_DIAGNOSTIC_PASS',flush=True)
PY
