#!/bin/sh
# Exercise runnable memstall transfer between owned descendants under reclaim.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
test "$(uname -r)" = 4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf
python3 - <<'PY'
import json,os,subprocess,time,uuid
from pathlib import Path

token='rmx1931-psi-migrate-'+uuid.uuid4().hex[:10]
base=Path('/var/tmp')/token;base.mkdir(mode=0o755)
source=r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static long limit(const char *name){char p[128];snprintf(p,sizeof(p),"/sys/fs/cgroup/%s",name);FILE *f=fopen(p,"r");long v=-1;if(!f||fscanf(f,"%ld",&v)!=1)_exit(2);fclose(f);return v;}
int main(void){
 alarm(30);printf("{\"phase\":\"ready\",\"max\":%ld,\"high\":%ld,\"seccomp\":%d}\n",limit("memory.max"),limit("memory.high"),prctl(PR_GET_SECCOMP));fflush(stdout);
 /* Give the controller time to open the original group before reclaim. */
 usleep(500000);size_t size=48*1024*1024;volatile unsigned char *p=mmap(0,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)return 3;
 double start=now();unsigned int rounds=0;
 do{for(size_t i=0;i<size;i+=4096)p[i]=(unsigned char)rounds;if(madvise((void *)(p+32*1024*1024),16*1024*1024,MADV_DONTNEED))return 4;rounds++;usleep(1000);}while(now()-start<9);
 munmap((void *)p,size);printf("{\"phase\":\"done\",\"seconds\":%.6f,\"rounds\":%u,\"seccomp\":%d}\n",now()-start,rounds,prctl(PR_GET_SECCOMP));fflush(stdout);for(;;)pause();
}
'''
def run(argv,check=True,timeout=40):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
 if check and r.returncode:raise RuntimeError(json.dumps({'argv':argv,'rc':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
 return r
def out(argv,**kw):return run(argv,**kw).stdout.strip()
def inspect(cli,name):return json.loads(out(cli+['inspect',name]))[0]
def group(pid):
 rows=[line[3:] for line in Path('/proc',str(pid),'cgroup').read_text().splitlines() if line.startswith('0::')]
 assert len(rows)==1 and '..' not in rows[0].split('/'),rows
 return Path('/sys/fs/cgroup'+rows[0])
def stat(pid):
 value=Path('/proc',str(pid),'stat').read_text();fields=value[value.rindex(')')+2:].split()
 return int(fields[6]),fields[19]
def pressure(path):
 values={line.split()[0]:int(line.split('total=')[1]) for line in (path/'memory.pressure').read_text().splitlines()}
 assert set(values)=={'some','full'} and values['some']>=values['full'],values
 return values
def events(path):return dict((k,int(v)) for k,v in (line.split() for line in (path/'memory.events').read_text().splitlines()))
def logs(cli,name):return [json.loads(line) for line in out(cli+['logs',name]).splitlines()]
results=[];cleanup_errors=[]
try:
 (base/'fixture.c').write_text(source);(base/'fixture.c').chmod(0o644)
 (base/'Containerfile').write_text('FROM scratch\nCOPY fixture /fixture\nENTRYPOINT ["/fixture"]\n');(base/'Containerfile').chmod(0o644)
 out(['gcc','-static','-O2','-Wall','-Wextra','-Werror',str(base/'fixture.c'),'-o',str(base/'fixture')]);(base/'fixture').chmod(0o755)
 for mode,cli in [('rootful',['podman']),('rootless',['podman-rootless'])]:
  image='localhost/'+token+'-'+mode+':1';owned=[];built=False
  try:
   out(cli+['build','--network=none','-t',image,str(base)],timeout=60);built=True
   for runtime in ('crun','runc'):
    name=token+'-'+mode+'-'+runtime;children=[];parent=None;pid=None;owned.append(name)
    try:
     out(['rmx1931-policy','set',name,'--mode',mode,'--cpus','.5','--memory-mib','64','--memory-high-mib','32','--pids','32','--read-bps','2097152','--write-bps','2097152','--oom-group'])
     out(cli+['run','-d','--name',name,'--runtime='+runtime,'--network=none','--memory=96m',
       '--annotation','io.rmx1931.resource-policy='+name,image])
     initial=inspect(cli,name);pid=initial['State']['Pid'];starttime=stat(pid)[1];parent=group(pid)
     assert initial['Id'] in str(parent) and parent.is_dir() and not parent.is_symlink()
     deadline=time.monotonic()+8
     while not logs(cli,name):
      assert time.monotonic()<deadline and inspect(cli,name)['State']['Running'];time.sleep(.05)
     ready=logs(cli,name)[0];assert ready=={'phase':'ready','max':67108864,'high':33554432,'seccomp':2},ready
     before=pressure(parent);ev_before=events(parent)
     for suffix in ('a','b'):
      child=parent/(token+'-'+suffix);assert not child.exists();child.mkdir();children.append(child)
     moves=0;memstall_observed_moves=0;sleeping_observations=0;limit=time.monotonic()+6
     while time.monotonic()<limit:
      flags,observed_start=stat(pid);assert observed_start==starttime
      target=children[moves%2]
      # PF_MEMSTALL=0x01000000 in this exact source tree. Sampling before
      # a move is evidence of overlap, not an atomic kernel flag snapshot.
      if flags&0x01000000:memstall_observed_moves+=1
      if Path('/proc',str(pid),'stat').read_text().split(') ',1)[1].startswith(('S ','D ')):sleeping_observations+=1
      (target/'cgroup.procs').write_text(str(pid)+'\n');assert group(pid)==target
      moves+=1;time.sleep(.003)
     (parent/'cgroup.procs').write_text(str(pid)+'\n');assert group(pid)==parent
     deadline=time.monotonic()+12
     while len(logs(cli,name))<2:
      assert time.monotonic()<deadline and inspect(cli,name)['State']['Running'];time.sleep(.1)
     done=logs(cli,name)[1];assert done['phase']=='done' and done['rounds']>0 and done['seccomp']==2
     after=pressure(parent);ev_after=events(parent);descendants=[pressure(path) for path in children]
     assert moves>=128 and memstall_observed_moves>=8,(moves,memstall_observed_moves)
     assert all(row['some']>=1000 and row['full']>=1000 for row in descendants),descendants
     assert after['some']>before['some'] and after['full']>before['full']
     assert ev_after['high']>ev_before['high'] and ev_after['oom_kill']==ev_before['oom_kill']==0
     assert (parent/'memory.max').read_text().strip()=='67108864' and (parent/'memory.high').read_text().strip()=='33554432'
     for child in children:assert not (child/'cgroup.procs').read_text().strip();child.rmdir()
     children=[]
     row={'mode':mode,'runtime':runtime,'container_id':initial['Id'],'pid':pid,'starttime':starttime,
       'moves':moves,'memstall_observed_moves':memstall_observed_moves,'sleeping_observations':sleeping_observations,
       'pf_memstall_mask':'0x01000000','initial_payload':ready,'payload':done,
       'before':before,'after':after,'descendants':descendants,'events_before':ev_before,'events_after':ev_after,
       'restored_original_group':True,'owned_descendants_removed':True,'passed':True}
     results.append(row);print(json.dumps(row),flush=True)
    finally:
     if pid is not None and parent is not None and Path('/proc',str(pid)).exists() and stat(pid)[1]==starttime:
      (parent/'cgroup.procs').write_text(str(pid)+'\n')
     for child in children:
      if child.exists():child.rmdir()
     r=run(cli+['rm','-f','--time','0',name],check=False)
     if r.returncode and 'no such container' not in r.stderr.lower():cleanup_errors.append(r.stderr)
     r=run(['rmx1931-policy','remove',name],check=False)
     if r.returncode:cleanup_errors.append(r.stderr)
  finally:
   for name in owned:
    r=run(cli+['rm','-f','--time','0',name],check=False)
    if r.returncode and 'no such container' not in r.stderr.lower():cleanup_errors.append(r.stderr)
   if built:out(cli+['image','rm','-f',image])
 assert len(results)==4 and not cleanup_errors
 assert not out(['podman','ps','-q']) and not out(['podman-rootless','ps','-q'])
 assert json.loads(out(['rmx1931-policy','validate']))['profiles']=={}
 print('GROUP_PSI_RECLAIM_MIGRATION_PASS',flush=True)
finally:
 print(json.dumps({'cleanup_errors':cleanup_errors,'fixture_directory':str(base),'fixture_source_retained':True}),flush=True)
PY
