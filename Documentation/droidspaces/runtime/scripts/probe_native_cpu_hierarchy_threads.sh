#!/bin/sh
# Real native V2 parent quota and per-thread CPU/cpuset execution.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
python3 - <<'PY'
import errno, json, os, select, subprocess, sys, tempfile, time, uuid
from pathlib import Path
cg = Path('/sys/fs/cgroup')
assert {'cpu', 'cpuset', 'memory', 'pids'} <= set((cg / 'cgroup.controllers').read_text().split())
token = 'rmx1931-cpu-threaded-' + uuid.uuid4().hex[:10]
base = cg / token
created, workers, cases, cleanup = [], [], [], []
root_before = (cg / 'cgroup.subtree_control').read_text()

def cpus(text):
    result = set()
    for item in text.strip().split(','):
        first, sep, last = item.partition('-')
        result.update(range(int(first), int(last)+1) if sep else [int(first)])
    return result

available = sorted(cpus((cg / 'cpuset.cpus.effective').read_text()))
assert len(available) >= 2
selected = available[-2:]
def write(path, value): path.write_text(str(value) + '\n')
def mkdir(path): path.mkdir(); created.append(path); return path
def stat(path): return dict((line.split()[0], int(line.split()[1])) for line in (path / 'cpu.stat').read_text().splitlines())
def ready(p):
    workers.append(p)
    assert select.select([p.stdout], [], [], 15)[0]
    return json.loads(p.stdout.readline())
def collect(p):
    out, err = p.communicate(timeout=20)
    assert p.returncode == 0, (p.returncode, out, err)
    return [json.loads(line) for line in out.splitlines() if line.startswith('{')]

process_source = r'''
import json, os, resource, sys, time
from pathlib import Path
print(json.dumps({'ready': True, 'pid': os.getpid()}), flush=True)
start = float(sys.stdin.readline()); warm = start + 1; end = warm + 4
while time.monotonic() < start: time.sleep(.001)
before = None; value = 1
while time.monotonic() < end:
    if before is None and time.monotonic() >= warm:
        r=resource.getrusage(resource.RUSAGE_SELF);before=(r.ru_utime+r.ru_stime,time.monotonic())
    for _ in range(4096): value=(value*1664525+1013904223)&0xffffffff
r=resource.getrusage(resource.RUSAGE_SELF)
print(json.dumps({'cpu':r.ru_utime+r.ru_stime-before[0],'wall':time.monotonic()-before[1],
 'affinity':sorted(os.sched_getaffinity(0)), 'membership':Path('/proc/self/cgroup').read_text().splitlines(),
 'seccomp':int(next(x.split(':')[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('Seccomp:')))}),flush=True)
'''

thread_source = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv=PTHREAD_COND_INITIALIZER;
static long tids[2]; static int count, go; static double start;
static volatile unsigned char *memory;
static double clock_value(clockid_t id) {struct timespec t;if(clock_gettime(id,&t))abort();return t.tv_sec+t.tv_nsec/1e9;}
static void *burn(void *arg) {
 int index=*(int*)arg; cpu_set_t mask; unsigned long bits=0; double before=0, wall=0; unsigned value=1;
 pthread_mutex_lock(&lock);tids[index]=syscall(SYS_gettid);count++;pthread_cond_broadcast(&cv);
 while(!go)pthread_cond_wait(&cv,&lock);pthread_mutex_unlock(&lock);
 while(clock_value(CLOCK_MONOTONIC)<start)usleep(1000);
 while(clock_value(CLOCK_MONOTONIC)<start+5) {
  if(!wall && clock_value(CLOCK_MONOTONIC)>=start+1){before=clock_value(CLOCK_THREAD_CPUTIME_ID);wall=clock_value(CLOCK_MONOTONIC);}
  for(int k=0;k<4096;k++)value=value*1664525u+1013904223u;
  __asm__ volatile("" : "+r"(value));
 }
 double used=clock_value(CLOCK_THREAD_CPUTIME_ID)-before, elapsed=clock_value(CLOCK_MONOTONIC)-wall;
 if(!wall || sched_getaffinity(0,sizeof(mask),&mask))abort();
 for(unsigned k=0;k<8*sizeof(bits);k++)if(CPU_ISSET(k,&mask))bits|=1ul<<k;
 pthread_mutex_lock(&lock);
 printf("{\"index\":%d,\"tid\":%ld,\"cpu\":%.9f,\"wall\":%.9f,\"affinity_mask\":%lu,\"seccomp\":%d}\n",index,tids[index],used,elapsed,bits,prctl(PR_GET_SECCOMP,0,0,0,0));fflush(stdout);
 pthread_mutex_unlock(&lock);return NULL;
}
int main(void) {
 pthread_t threads[2];int indices[2]={0,1};char line[64];
 for(int k=0;k<2;k++)if(pthread_create(&threads[k],NULL,burn,&indices[k]))return 2;
 pthread_mutex_lock(&lock);while(count<2)pthread_cond_wait(&cv,&lock);
 printf("{\"pid\":%ld,\"tids\":[%ld,%ld]}\n",(long)getpid(),tids[0],tids[1]);fflush(stdout);pthread_mutex_unlock(&lock);
 if(!fgets(line,sizeof(line),stdin))return 3;start=strtod(line,NULL);
 memory=malloc(8*1024*1024);if(!memory)return 5;
 for(unsigned k=0;k<8*1024*1024;k+=4096)memory[k]=1;
 pthread_mutex_lock(&lock);go=1;pthread_cond_broadcast(&cv);pthread_mutex_unlock(&lock);
 for(int k=0;k<2;k++)if(pthread_join(threads[k],NULL))return 4;return 0;
}
'''

try:
    mkdir(base); write(base / 'cgroup.subtree_control', '+cpu +cpuset +memory +pids')
    parent = mkdir(base / 'quota-parent')
    write(parent / 'cpu.max', '50000 100000'); write(parent / 'cpuset.cpus', ','.join(map(str,selected)))
    write(parent / 'cgroup.subtree_control', '+cpu +cpuset')
    pair=[]
    for index,cpu in enumerate(selected):
        child=mkdir(parent / str(index)); write(child/'cpu.max','100000 100000'); write(child/'cpuset.cpus',cpu)
        assert (child/'cpu.max').read_text().strip()=='100000 100000'
        p=subprocess.Popen([sys.executable,'-u','-c',process_source],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        assert ready(p)['pid']==p.pid
        write(child/'cgroup.procs',p.pid); pair.append(p)
    before=stat(parent); start=time.monotonic()+.2
    for p in pair: p.stdin.write(str(start)+'\n');p.stdin.flush()
    rows=[collect(p)[0] for p in pair]; after=stat(parent)
    used=sum(x['cpu']/x['wall'] for x in rows)
    assert .40<used<.65 and after['nr_throttled']>before['nr_throttled'],(used,rows,before,after)
    assert all(x['seccomp']==2 and x['affinity']==[selected[i]] for i,x in enumerate(rows)),rows
    case={'case':'parent-quota-composes-over-higher-child-requests','requested_parent':'50000 100000','requested_children':'100000 100000','workloads':rows,'used_cores_sum':used,'parent_stat_before':before,'parent_stat_after':after}
    cases.append(case);print(json.dumps(case),flush=True)

    domain=mkdir(base/'thread-domain');write(domain/'cpu.max','50000 100000');write(domain/'memory.max',64*1024*1024);write(domain/'pids.max',32)
    write(domain/'cpuset.cpus',','.join(map(str,selected)))
    leaves=[mkdir(domain/str(i)) for i in range(2)]
    for leaf in leaves:write(leaf/'cgroup.type','threaded')
    assert (domain/'cgroup.type').read_text().strip()=='domain threaded'
    write(domain/'cgroup.subtree_control','+cpu +cpuset +pids')
    for i,leaf in enumerate(leaves):write(leaf/'cpu.max','25000 100000');write(leaf/'cpuset.cpus',selected[i])
    outside=mkdir(base/'other-resource-domain')
    with tempfile.TemporaryDirectory(prefix=token+'-') as directory:
        source=Path(directory)/'threads.c'; binary=Path(directory)/'threads';source.write_text(thread_source)
        build=subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-static','-pthread',str(source),'-o',str(binary)],capture_output=True,text=True)
        assert build.returncode==0,(build.stdout,build.stderr)
        p=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        info=ready(p);assert info['pid']==p.pid and len(set(info['tids']))==2
        write(domain/'cgroup.procs',p.pid)
        for tid,leaf in zip(info['tids'],leaves):write(leaf/'cgroup.threads',tid)
        memberships=[Path('/proc/'+str(tid)+'/cgroup').read_text().splitlines() for tid in info['tids']]
        for tid,leaf,member in zip(info['tids'],leaves,memberships):
            assert str(tid) in (leaf/'cgroup.threads').read_text().split()
            assert any(x.startswith('0::') and x.endswith('/'+token+'/thread-domain/'+leaf.name) for x in member),member
        try:write(outside/'cgroup.threads',info['tids'][0])
        except OSError as error:assert error.errno==errno.EOPNOTSUPP,error
        else:raise AssertionError('Thread escaped its resource domain')
        assert str(p.pid) in (domain/'cgroup.procs').read_text().split()
        assert int((domain/'pids.current').read_text())==3
        before=[stat(x) for x in leaves];p.stdin.write(str(time.monotonic()+.2)+'\n');p.stdin.flush()
        time.sleep(2)
        memory_current=int((domain/'memory.current').read_text());assert 8*1024*1024<=memory_current<64*1024*1024
        rows=sorted(collect(p),key=lambda x:x['index']);after=[stat(x) for x in leaves]
        assert len(rows)==2 and all(x['seccomp']==2 for x in rows),rows
        for i,row in enumerate(rows):
            assert row['affinity_mask']==1<<selected[i] and .18<row['cpu']/row['wall']<.34,(row,selected)
            assert after[i]['nr_throttled']>before[i]['nr_throttled']
        used=sum(x['cpu']/x['wall'] for x in rows);assert .40<used<.65,(used,rows)
        case={'case':'actual-threaded-cpu-cpuset-quota','threads':rows,'memberships':memberships,'resource_domain_memory_current':memory_current,'used_cores_sum':used,'cross_resource_domain_thread_migration_errno':errno.EOPNOTSUPP,'leaf_stats_before':before,'leaf_stats_after':after}
        cases.append(case);print(json.dumps(case),flush=True)
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
print(json.dumps({'cases':cases,'cleanup_errors':cleanup,'ordinary_guest_seccomp':2}),flush=True)
print('NATIVE_CPU_HIERARCHY_THREADED_PASS',flush=True)
PY
