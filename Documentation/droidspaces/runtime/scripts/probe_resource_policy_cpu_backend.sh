#!/bin/sh
# Actual policy CPU pressure on both legacy and native kernels; cleans its fixtures.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
python3 - <<'PY'
import json, subprocess, time, uuid
from pathlib import Path

token='rmx1931-policy-cpu-'+uuid.uuid4().hex[:10]
base=Path('/var/tmp')/token
base.mkdir(mode=0o755)
source=r'''
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
static atomic_int done;
static double now(clockid_t c){struct timespec t;clock_gettime(c,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void *burn(void *unused){(void)unused;volatile unsigned long x=1;while(!atomic_load(&done))x=x*1664525+1013904223;return 0;}
int main(void){
 char limit[128]="absent";FILE *f=fopen("/sys/fs/cgroup/cpu.max","r");
 if(f){if(!fgets(limit,sizeof(limit),f))return 2;fclose(f);limit[strcspn(limit,"\n")]=0;}
 pthread_t t[4];double c=now(CLOCK_PROCESS_CPUTIME_ID),w=now(CLOCK_MONOTONIC);
 for(int i=0;i<4;i++)if(pthread_create(&t[i],0,burn,0))return 3;
 struct timespec delay={4,0};nanosleep(&delay,0);atomic_store(&done,1);
 for(int i=0;i<4;i++)pthread_join(t[i],0);
 printf("{\"cpu_max_first_instruction\":\"%s\",\"cpu\":%.6f,\"wall\":%.6f,\"seccomp\":%d}\n",limit,now(CLOCK_PROCESS_CPUTIME_ID)-c,now(CLOCK_MONOTONIC)-w,prctl(PR_GET_SECCOMP));
 return 0;
}
'''

def run(argv,check=True,timeout=35):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
 if check and r.returncode:
  raise RuntimeError(json.dumps({'argv':argv,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
 return r

def out(argv,timeout=35):return run(argv,timeout=timeout).stdout.strip()

(base/'fixture.c').write_text(source)
(base/'Containerfile').write_text('FROM scratch\nCOPY fixture /fixture\nENTRYPOINT ["/fixture"]\n')
for name in ('fixture.c','Containerfile'):(base/name).chmod(0o644)
out(['gcc','-static','-O2','-pthread','-Wall','-Wextra','-Werror',str(base/'fixture.c'),'-o',str(base/'fixture')])
(base/'fixture').chmod(0o755)
health=json.loads(out(['rmx1931-policy','ping']))
backend=health.get('cpu_backend','v1')
assert backend in ('v1','v2'),health
results=[]
try:
 for mode,cli in [('rootful',['podman']),('rootless',['podman-rootless'])]:
  name=token+'-'+mode;image='localhost/'+name+':1';profile=False;built=False
  row={'mode':mode,'cpu_backend':backend,'cleanup_errors':[]};results.append(row)
  try:
   out(cli+['build','--network=none','-t',image,str(base)],timeout=55);built=True
   ordinary=json.loads(out(cli+['run','--rm','--name',name+'-ordinary','--network=none','--memory=64m','--pids-limit=32',image]))
   ratio=ordinary['cpu']/ordinary['wall'];assert ordinary['seccomp']==2 and ratio>1.2,ordinary
   row['ordinary']={**ordinary,'used_cores':ratio}
   out(['rmx1931-policy','set',name,'--mode',mode,'--cpus','.5','--memory-mib','64','--pids','32',
        '--read-bps','2097152','--write-bps','2097152','--oom-group']);profile=True
   limited=json.loads(out(cli+['run','--rm','--name',name,'--network=none',
                            '--annotation','io.rmx1931.resource-policy='+name,image]))
   ratio=limited['cpu']/limited['wall'];assert limited['seccomp']==2 and .3<ratio<.75,limited
   if backend=='v2':assert limited['cpu_max_first_instruction']=='50000 100000',limited
   else:assert limited['cpu_max_first_instruction']=='absent',limited
   row['limited']={**limited,'used_cores':ratio};row['pressure_passed']=True
   print(json.dumps(row),flush=True)
  finally:
   for container in (name,name+'-ordinary'):
    r=run(cli+['rm','-f','--time','0',container],check=False)
    if r.returncode and 'no container with name or ID' not in r.stderr and 'not found' not in r.stderr:
     row['cleanup_errors'].append(r.stderr)
   if built:
    r=run(cli+['rmi',image],check=False)
    if r.returncode:row['cleanup_errors'].append(r.stderr)
   if profile:
    r=run(['rmx1931-policy','remove',name],check=False)
    if r.returncode:row['cleanup_errors'].append(r.stderr)
finally:
 for p in base.iterdir():
  assert p.name in ('fixture.c','fixture','Containerfile'),p
  p.unlink()
 base.rmdir()
assert all(r.get('pressure_passed') and not r['cleanup_errors'] for r in results),results
for _ in range(30):
 rows=json.loads(out(['rmx1931-policy','status']))['containers']
 if not any(str(r.get('profile','')).startswith(token) for r in rows):break
 time.sleep(.1)
else:raise RuntimeError('Policy CPU fixture state did not retire')
print(json.dumps({'cpu_backend':backend,'modes':results,'passed':True}),flush=True)
print('POLICY_CPU_BACKEND_PRESSURE_PASS',flush=True)
PY
