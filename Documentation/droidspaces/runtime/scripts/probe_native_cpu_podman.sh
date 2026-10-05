#!/bin/sh
# Actual native OCI CPU quota, cpuset, fork/exec and competing weight workloads.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
python3 - "$@" <<'PY'
import json, subprocess, sys, time, uuid
from pathlib import Path

assert {'cpu','cpuset'}.issubset(Path('/sys/fs/cgroup/cgroup.controllers').read_text().split())
selected_mode=sys.argv[1] if len(sys.argv)==2 else 'all'
assert len(sys.argv)<=2 and selected_mode in ('all','rootful','rootless')
token='rmx1931-native-cpu-'+uuid.uuid4().hex[:10]
base=Path('/var/tmp')/token; base.mkdir(mode=0o755)
source=r'''
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static atomic_int done;
static atomic_int bad_affinity;
static uint64_t expected_affinity;
static double now(clockid_t c){struct timespec t;clock_gettime(c,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void *burn(void *arg){(void)arg;cpu_set_t set;uint64_t mask=0;if(sched_getaffinity(0,sizeof(set),&set)){atomic_store(&bad_affinity,1);return 0;}for(int i=0;i<64;i++)if(CPU_ISSET(i,&set))mask|=(uint64_t)1<<i;if(mask!=expected_affinity)atomic_store(&bad_affinity,1);volatile unsigned long x=1;while(!atomic_load(&done))x=x*1664525+1013904223;return 0;}
static void text(const char *name,char *buf,size_t size){char path[256];snprintf(path,sizeof(path),"/sys/fs/cgroup/%s",name);FILE *f=fopen(path,"r");if(!f||!fgets(buf,size,f))exit(2);fclose(f);buf[strcspn(buf,"\n")]=0;}
static long statval(const char *key){char name[64];long value;FILE *f=fopen("/sys/fs/cgroup/cpu.stat","r");if(!f)exit(3);while(fscanf(f,"%63s %ld",name,&value)==2){if(!strcmp(name,key)){fclose(f);return value;}}fclose(f);return -1;}
static double timeval_seconds(struct timeval t){return t.tv_sec+t.tv_usec/1e6;}
int main(int argc,char **argv){
 char max[128];text("cpu.max",max,sizeof(max));
 cpu_set_t allowed;if(sched_getaffinity(0,sizeof(allowed),&allowed))return 4;
 uint64_t mask=0;for(int i=0;i<64;i++)if(CPU_ISSET(i,&allowed))mask|=(uint64_t)1<<i;
 expected_affinity=mask;
 long usage=statval("usage_usec"),throttled=statval("nr_throttled");
 if(argc<2)return 5;
 if(!strcmp(argv[1],"hold")){for(;;)pause();}
 if(!strcmp(argv[1],"burn-gated")){
  if(argc!=6)return 14;
  char ready[512],fire[512];snprintf(ready,sizeof(ready),"%s/ready-%s",argv[4],argv[5]);snprintf(fire,sizeof(fire),"%s/fire",argv[4]);
  FILE *f=fopen(ready,"wx");if(!f)return 15;fclose(f);
  double deadline=now(CLOCK_MONOTONIC)+45;while(access(fire,F_OK)){if(now(CLOCK_MONOTONIC)>deadline)return 16;usleep(10000);}
 }
 double cpu=now(CLOCK_PROCESS_CPUTIME_ID),wall=now(CLOCK_MONOTONIC);
 if(!strcmp(argv[1],"family")){
  pid_t kids[2];for(int i=0;i<2;i++){kids[i]=fork();if(kids[i]<0)return 6;if(!kids[i]){execl("/fixture","/fixture","burn","4","4",(char *)0);_exit(7);}}
  for(int i=0;i<2;i++){int status;if(waitpid(kids[i],&status,0)<0||!WIFEXITED(status)||WEXITSTATUS(status))return 8;}
  struct rusage r;if(getrusage(RUSAGE_CHILDREN,&r))return 9;
  cpu=now(CLOCK_PROCESS_CPUTIME_ID)-cpu+timeval_seconds(r.ru_utime)+timeval_seconds(r.ru_stime);
 }else if(!strcmp(argv[1],"burn")||!strcmp(argv[1],"burn-gated")){
  if(argc!=4&&argc!=6)return 10;
  int seconds=atoi(argv[2]),count=atoi(argv[3]);
  if(seconds<1||seconds>12||count<1||count>4)return 11;
  pthread_t threads[4];for(int i=0;i<count;i++)if(pthread_create(&threads[i],0,burn,0))return 12;
  if(!strcmp(argv[1],"burn-gated")){
   struct timespec warmup={2,0};nanosleep(&warmup,0);
   cpu=now(CLOCK_PROCESS_CPUTIME_ID);wall=now(CLOCK_MONOTONIC);usage=statval("usage_usec");throttled=statval("nr_throttled");
  }
  struct timespec delay={seconds,0};nanosleep(&delay,0);atomic_store(&done,1);
  for(int i=0;i<count;i++)pthread_join(threads[i],0);
  if(atomic_load(&bad_affinity))return 18;
  cpu=now(CLOCK_PROCESS_CPUTIME_ID)-cpu;
 }else return 13;
 char weight[32];text("cpu.weight",weight,sizeof(weight));
 printf("{\"mode\":\"%s\",\"cpu_max\":\"%s\",\"affinity_mask\":%llu,\"cpu_weight\":%ld,\"cpu\":%.6f,\"wall\":%.6f,\"start_monotonic\":%.6f,\"usage_usec_delta\":%ld,\"nr_throttled_delta\":%ld,\"seccomp\":%d}\n",argv[1],max,(unsigned long long)mask,strtol(weight,0,10),cpu,now(CLOCK_MONOTONIC)-wall,wall,statval("usage_usec")-usage,statval("nr_throttled")-throttled,prctl(PR_GET_SECCOMP));
 return 0;
}
'''

def run(argv,check=True,timeout=30):
    r=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
    if check and r.returncode: raise RuntimeError(json.dumps({'argv':argv,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
    return r
def out(argv,timeout=30): return run(argv,timeout=timeout).stdout.strip()
def parse(output): return [json.loads(line) for line in output.splitlines() if line.startswith('{')]
def verify(rows,mask,limited):
    assert rows,rows
    for row in rows:
        assert row['affinity_mask']==mask and row['seccomp']==2,row
        assert row['cpu_max']==('50000 100000' if limited else 'max 100000'),row
        assert row['usage_usec_delta']>0 and row['nr_throttled_delta']>=0,row
    measured=rows[-1];ratio=measured['cpu']/measured['wall']
    if limited:
        assert .3<ratio<.75 and measured['nr_throttled_delta']>0,(measured,ratio)
    return ratio
def cpulist(value):
    result=set()
    for piece in value.strip().split(','):
        first,sep,last=piece.partition('-'); result.update(range(int(first),int(last)+1) if sep else [int(first)])
    return result

cpus=sorted(cpulist(Path('/sys/fs/cgroup/cpuset.cpus.effective').read_text()))
assert len(cpus)>=2 and max(cpus)<64,cpus
chosen=cpus[-2:];mask=sum(1<<cpu for cpu in chosen);binding=','.join(map(str,chosen))
results=[]
try:
    (base/'fixture.c').write_text(source);(base/'Containerfile').write_text('FROM scratch\nCOPY fixture /fixture\nENTRYPOINT ["/fixture"]\n')
    for name in ('fixture.c','Containerfile'): (base/name).chmod(0o644)
    out(['gcc','-static','-O2','-pthread','-Wall','-Wextra','-Werror',str(base/'fixture.c'),'-o',str(base/'fixture')])
    (base/'fixture').chmod(0o755)
    for mode,cli in [('rootful',['podman']),('rootless',['podman-rootless'])]:
        if selected_mode not in ('all',mode):continue
        name=token+'-'+mode;image='localhost/'+name+':1';owned=[];built=False
        row={'mode':mode,'cases':{},'cleanup_errors':[]};results.append(row)
        try:
            out(cli+['build','--network=none','-t',image,str(base)],timeout=55);built=True
            for runtime in ('crun','runc'):
                container=name+'-'+runtime;owned.append(container)
                args=cli+['run','--rm','--runtime='+runtime,'--name',container,'--network=none',
                          '--cpus','.5','--cpuset-cpus',binding,'--memory=64m','--pids-limit=32']
                measured=parse(out(args+[image,'family'],timeout=20));ratio=verify(measured,mask,True)
                assert len(measured)==3 and measured[-1]['mode']=='family',measured
                row['cases'][runtime+'-fork-exec']={'payloads':measured,'used_cores':ratio}
                print(json.dumps({'mode':mode,'case':runtime+'-fork-exec',**row['cases'][runtime+'-fork-exec']}),flush=True)
            container=name+'-exec';owned.append(container)
            out(cli+['run','-d','--name',container,'--network=none','--cpus','.5',
                     '--cpuset-cpus',binding,'--memory=64m','--pids-limit=32',image,'hold'])
            measured=parse(out(cli+['exec',container,'/fixture','burn','4','4'],timeout=20))
            row['cases']['live-exec']={'payloads':measured,'used_cores':verify(measured,mask,True)}
            print(json.dumps({'mode':mode,'case':'live-exec',**row['cases']['live-exec']}),flush=True)
            out(cli+['rm','-f','--time','0',container])

            # Same parent, same core and no quota: native weights must change CPU time.
            competitors=[]
            control=base/('control-'+mode);control.mkdir(mode=0o777);control.chmod(0o777)
            hierarchy=[]
            task_debug=[];group_debug=[]
            for shares in (256,1024):
                container=name+'-weight-'+str(shares);owned.append(container)
                argv=cli+['run','--rm','--name',container,'--network=none','--cpu-shares',str(shares),
                          '--cpuset-cpus',str(chosen[-1]),'--memory=64m','--pids-limit=32',
                          '--volume',str(control)+':/control:rw',image,'burn-gated','8','1','/control',str(shares)]
                competitors.append((shares,subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)))
            weights=[]
            try:
                deadline=time.monotonic()+35
                while not all((control/('ready-'+str(shares))).exists() for shares,_ in competitors):
                    assert time.monotonic()<deadline,'Weight workloads did not reach the start barrier'
                    assert all(process.poll() is None for _,process in competitors),'Weight workload exited before barrier'
                    time.sleep(.02)
                for shares,_ in competitors:
                    container=name+'-weight-'+str(shares)
                    pid=int(out(cli+['inspect','--format','{{.State.Pid}}',container]))
                    memberships=Path('/proc',str(pid),'cgroup').read_text().splitlines()
                    cg=next(line[3:] for line in memberships if line.startswith('0::'))
                    ancestors=[];path=Path('/sys/fs/cgroup')/cg.lstrip('/')
                    while path!=Path('/sys/fs/cgroup'):
                        ancestors.append({'path':str(path.relative_to('/sys/fs/cgroup')),
                            'weight':(path/'cpu.weight').read_text().strip() if (path/'cpu.weight').exists() else None,
                            'max':(path/'cpu.max').read_text().strip() if (path/'cpu.max').exists() else None})
                        path=path.parent
                    hierarchy.append({'shares':shares,'memberships':memberships,'ancestors':ancestors})
                (control/'fire').write_text('start\n')
                time.sleep(4)
                ids=[]
                for shares,_ in competitors:
                    container=name+'-weight-'+str(shares)
                    record=json.loads(out(cli+['inspect',container]))[0];pid=record['State']['Pid'];ids.append(record['Id'])
                    threads=[]
                    for task in sorted(Path('/proc',str(pid),'task').iterdir()):
                        sched=[line.strip() for line in (task/'sched').read_text().splitlines() if any(key in line for key in ('se.load.weight','policy','prio','se.sum_exec_runtime'))]
                        threads.append({'tid':int(task.name),'affinity':sorted(__import__('os').sched_getaffinity(int(task.name))),
                                        'membership':(task/'cgroup').read_text().splitlines(),'sched':sched})
                    task_debug.append({'shares':shares,'threads':threads})
                debug=Path('/proc/sched_debug')
                if debug.exists():
                    text=debug.read_text()
                    for block in text.split('\ncfs_rq[')[1:]:
                        section=block.split('\ncfs_rq[',1)[0].split('\nrt_rq[',1)[0].split('\ndl_rq[',1)[0]
                        if any(cid in section.splitlines()[0] for cid in ids):
                            group_debug.append('cfs_rq['+section)
                for shares,process in competitors:
                    stdout,stderr=process.communicate(timeout=25)
                    assert process.returncode==0,(shares,process.returncode,stdout,stderr)
                    measured=parse(stdout);verify(measured,1<<chosen[-1],False)
                    weights.append({'shares':shares,**measured[-1]})
            finally:
                for _,process in competitors:
                    if process.poll() is None: process.terminate();process.wait(timeout=5)
                for path in control.iterdir():
                    assert path.name in ('ready-256','ready-1024','fire'),path
                    path.unlink()
                control.rmdir()
            ratio=weights[1]['cpu']/weights[0]['cpu']
            row['cases']['weight-competition']={'workloads':weights,'hierarchy':hierarchy,'task_debug':task_debug,'group_debug':group_debug,'high_low_cpu_ratio':ratio}
            print(json.dumps({'mode':mode,'case':'weight-competition',**row['cases']['weight-competition']}),flush=True)
            row['weight_passed']=bool(abs(weights[0]['start_monotonic']-weights[1]['start_monotonic'])<.25 and 2<ratio<7 and weights[1]['cpu_weight']>weights[0]['cpu_weight'])
            row['passed']=row['weight_passed'];print(json.dumps(row),flush=True)
        finally:
            for container in owned:
                r=run(cli+['rm','-f','--time','0',container],check=False)
                if r.returncode and 'not found' not in r.stderr and 'no container with name or ID' not in r.stderr:
                    row['cleanup_errors'].append(r.stderr)
            if built:
                r=run(cli+['rmi',image],check=False)
                if r.returncode: row['cleanup_errors'].append(r.stderr)
finally:
    for path in base.iterdir():
        assert path.name in ('fixture.c','fixture','Containerfile'),path
        path.unlink()
    base.rmdir()
assert all(row.get('passed') and not row['cleanup_errors'] for row in results),results
print(json.dumps({'binding':binding,'modes':results,'passed':True}),flush=True)
print('NATIVE_CPU_PODMAN_PASS',flush=True)
PY
