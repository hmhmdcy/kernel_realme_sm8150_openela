#!/bin/sh
# Real per-container memory pressure and pre-execution memory.high policy.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
test "$(uname -r)" = 4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf
python3 - "$@" <<'PY'
import contextlib,errno,json,os,select,subprocess,sys,time,uuid
from pathlib import Path
assert len(sys.argv)<=2
stall=sys.argv[1] if len(sys.argv)==2 else 'some'
assert stall in ('some','full')
token='rmx1931-psi-'+uuid.uuid4().hex[:10]
base=Path('/var/tmp')/token;base.mkdir(mode=0o755)
source=r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static long value(const char *n){char path[128];snprintf(path,sizeof(path),"/sys/fs/cgroup/%s",n);FILE *f=fopen(path,"r");long v=-1;if(!f||fscanf(f,"%ld",&v)!=1)exit(2);fclose(f);return v;}
static unsigned long long starttime(void){char line[4096];FILE *f=fopen("/proc/self/stat","r");if(!f||!fgets(line,sizeof(line),f))exit(7);fclose(f);char *p=strrchr(line,')');if(!p)exit(8);p+=2;for(int i=0;i<19;i++){p=strchr(p,' ');if(!p)exit(9);p++;}return strtoull(p,0,10);}
int main(int argc,char **argv){
 if(argc!=2)return 3;
 if(!strcmp(argv[1],"hold")){long max=value("memory.max"),high=value("memory.high");int filter=prctl(PR_GET_SECCOMP);printf("{\"max\":%ld,\"high\":%ld,\"seccomp\":%d,\"starttime\":%llu}\n",max,high,filter,starttime());fflush(stdout);for(;;)pause();}
 if(strcmp(argv[1],"pressure"))return 4;
 alarm(30);size_t bytes=48*1024*1024;volatile unsigned char *p=mmap(0,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)return 5;
 double start=now();unsigned int rounds=0;
 do{for(size_t i=0;i<bytes;i+=4096)p[i]=(unsigned char)rounds;if(madvise((void *)(p+32*1024*1024),16*1024*1024,MADV_DONTNEED))return 6;rounds++;}while(now()-start<8);
 printf("{\"seconds\":%.6f,\"rounds\":%u,\"seccomp\":%d}\n",now()-start,rounds,prctl(PR_GET_SECCOMP));munmap((void *)p,bytes);return 0;
}
'''

def run(argv,check=True,timeout=40):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
 if check and r.returncode:raise RuntimeError(json.dumps({'argv':argv,'rc':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
 return r
def out(argv,**kwargs):return run(argv,**kwargs).stdout.strip()
def inspect(cli,name):return json.loads(out(cli+['inspect',name]))[0]
def first_payload(cli,name):
 data=inspect(cli,name);pid=data['State']['Pid'];stat=Path('/proc',str(pid),'stat').read_text()
 started=int(stat[stat.rindex(')')+2:].split()[19]);deadline=time.monotonic()+8
 while True:
  logs=[json.loads(line) for line in out(cli+['logs',name]).splitlines()]
  logs=[row for row in logs if row.get('starttime')==started]
  if logs or time.monotonic()>=deadline:break
  current=inspect(cli,name)
  assert current['State']['Running'] and current['Id']==data['Id'] and current['State']['Pid']==pid
  stat=Path('/proc',str(pid),'stat').read_text();assert int(stat[stat.rindex(')')+2:].split()[19])==started
  time.sleep(.05)
 assert len(logs)==1,logs
 return logs[0]
def group(cli,name):
 data=inspect(cli,name);pid=data['State']['Pid'];cid=data['Id']
 rows=[s[3:] for s in Path('/proc',str(pid),'cgroup').read_text().splitlines() if s.startswith('0::')]
 assert len(rows)==1 and cid in rows[0] and '..' not in rows[0].split('/'),rows
 return Path('/sys/fs/cgroup'+rows[0]),data
def pressure(path):
 text=(path/'memory.pressure').read_text()
 values={line.split()[0]:int(line.split('total=')[1]) for line in text.splitlines()}
 assert set(values)=={'some','full'} and values['some']>=values['full'],text
 return values
def events(path):return dict((k,int(v)) for k,v in (line.split() for line in (path/'memory.events').read_text().splitlines()))
@contextlib.contextmanager
def trigger(path):
 fd=os.open(path/'memory.pressure',os.O_RDWR|os.O_NONBLOCK)
 try:
  os.write(fd,(stall+' 1000 1000000\0').encode())
  poller=select.poll();poller.register(fd,select.POLLPRI|select.POLLERR|select.POLLHUP)
  yield poller
 finally:os.close(fd)
def ready(process,log):
 deadline=time.monotonic()+12
 while time.monotonic()<deadline:
  if log.exists():
   rows=[json.loads(s) for s in log.read_text().splitlines() if s.startswith('{')]
   if rows and rows[0]['event']=='ready':return rows[0]
  if process.poll() is not None:raise RuntimeError('Pressure monitor exited before readiness: '+log.read_text())
  time.sleep(.05)
 raise RuntimeError('Pressure monitor not ready')

results=[];cleanup_errors=[]
try:
 (base/'fixture.c').write_text(source);(base/'Containerfile').write_text('FROM scratch\nCOPY fixture /fixture\nENTRYPOINT ["/fixture"]\n')
 (base/'fixture.c').chmod(0o644);(base/'Containerfile').chmod(0o644)
 out(['gcc','-static','-O2','-Wall','-Wextra','-Werror',str(base/'fixture.c'),'-o',str(base/'fixture')]);(base/'fixture').chmod(0o755)
 for mode,cli in [('rootful',['podman']),('rootless',['podman-rootless'])]:
  image='localhost/'+token+'-'+mode+':1';owned=[];profiles=[];built=False
  try:
   out(cli+['build','--network=none','-t',image,str(base)],timeout=60);built=True
   for runtime in ('crun','runc'):
    name=token+'-'+mode+'-'+runtime;neighbor=name+'-idle';profiles.append(name);owned.extend([name,neighbor])
    out(['rmx1931-policy','set',name,'--mode',mode,'--cpus','.5','--memory-mib','64','--memory-high-mib','32','--pids','32','--read-bps','2097152','--write-bps','2097152','--oom-group'])
    common=['run','-d','--runtime='+runtime,'--network=none','--memory=96m','--pids-limit=48']
    out(cli+common+['--name',name,'--annotation','io.rmx1931.resource-policy='+name,image,'hold'])
    # Idle neighbor has no managed policy: memory.high must remain max.
    # Use the existing shell probe to keep this neighbor idle with no high limit.
    out(cli+common+['--name',neighbor,'--entrypoint=/bin/sh','localhost/rmx1931-probe:1','-c','exec sleep 90'])
    g,meta=group(cli,name);ng,nmeta=group(cli,neighbor)
    startup=first_payload(cli,name)
    limits={'max':67108864,'high':33554432,'seccomp':2}
    assert {k:startup[k] for k in limits}==limits,startup
    assert (ng/'memory.high').read_text().strip()=='max'
    for resource in ('cpu','memory','io'):
     text=(g/(resource+'.pressure')).read_text();assert 'some avg10=' in text and 'total=' in text
    # Reject malformed triggers and a second subscription on the same FD.
    fd=os.open(g/'memory.pressure',os.O_RDWR|os.O_NONBLOCK)
    try:
     for bad in (b'some 0 1000000\0',b'some 2000000 1000000\0',b'some 1000 1000\0',b'invalid\0'):
      try:os.write(fd,bad)
      except OSError as e:assert e.errno==errno.EINVAL,e
      else:raise AssertionError('Invalid PSI trigger accepted')
     os.write(fd,b'some 1000 1000000\0')
     try:os.write(fd,b'some 1000 1000000\0')
     except OSError as e:assert e.errno==errno.EBUSY,e
     else:raise AssertionError('Duplicate PSI trigger accepted')
    finally:os.close(fd)
    for _ in range(32):
     fd=os.open(g/'memory.pressure',os.O_RDWR|os.O_NONBLOCK)
     try:os.write(fd,b'full 1000 1000000\0')
     finally:os.close(fd)
    parent_before=pressure(g.parent);before=pressure(g);neighbor_before=pressure(ng);ev_before=events(g)
    log=base/(name+'.monitor');err=base/(name+'.monitor-err');monitor=None
    with trigger(g.parent) as parent_poll,log.open('w') as stdout,err.open('w') as stderr:
     try:
      monitor=subprocess.Popen(['rmx1931-pressure','--mode',mode,'--name',name,'--stall',stall,'--threshold-us','1000','--window-us','1000000','--timeout','28'],stdout=stdout,stderr=stderr)
      subscription=ready(monitor,log);assert subscription['container_id']==meta['Id'] and subscription['memory_high']=='33554432'
      payload=json.loads(out(cli+['exec',name,'/fixture','pressure'],timeout=35));assert payload['seccomp']==2 and payload['rounds']>0,payload
      print(json.dumps({'event':'payload-finished','mode':mode,'runtime':runtime,'stall':stall,
        'payload':payload,'before':before,'after':pressure(g),
        'parent_before':parent_before,'parent_after':pressure(g.parent),
        'events_before':ev_before,'events_after':events(g)}),flush=True)
      assert monitor.wait(timeout=30)==0,err.read_text()
      parent_poll_events=parent_poll.poll(0)
     except BaseException:
      stdout.flush();stderr.flush()
      print(json.dumps({'monitor_stdout':log.read_text(),'monitor_stderr':err.read_text()}),flush=True)
      raise
     finally:
      if monitor is not None and monitor.poll() is None:monitor.terminate();monitor.wait(timeout=5)
    after=pressure(g);parent_after=pressure(g.parent);neighbor_after=pressure(ng);ev_after=events(g)
    notifications=[json.loads(s) for s in log.read_text().splitlines()]
    delta={k:after[k]-before[k] for k in before}
    parent_delta={k:parent_after[k]-parent_before[k] for k in parent_before}
    # collect_percpu_times weights each group's CPUs by its own non-idle
    # time. Ancestors propagate task states but are not additive counters;
    # parent total need not exceed child total. Prove ancestor accounting
    # and a separate ancestor trigger instead of that invalid inequality.
    parent_notified=any(event&select.POLLPRI for _,event in parent_poll_events)
    parent_poll_errors=any(event&(select.POLLERR|select.POLLHUP|select.POLLNVAL) for _,event in parent_poll_events)
    row={'mode':mode,'runtime':runtime,'stall':stall,'container_id':meta['Id'],'initial_payload':startup,
         'pressure_before':before,'pressure_after':after,'delta':delta,
         'parent_before':parent_before,'parent_after':parent_after,'parent_delta':parent_delta,
         'parent_trigger_notified':parent_notified,'parent_trigger_errors':parent_poll_errors,
         'cgroup':str(g),'parent_cgroup':str(g.parent),
         'neighbor_before':neighbor_before,'neighbor_after':neighbor_after,'events_before':ev_before,'events_after':ev_after,
         'notifications':notifications,'payload':payload,'invalid_trigger_cases':4,'duplicate_trigger_rejected':True,'trigger_close_cycles':32}
    print(json.dumps({'event':'pressure-measurement',**row}),flush=True)
    assert delta['some']>=1000 and delta['full']>=0 and parent_delta['some']>=1000 and parent_delta['full']>=0,row
    assert delta[stall]>=1000 and parent_delta[stall]>=1000,row
    assert parent_notified and not parent_poll_errors,row
    assert neighbor_after==neighbor_before,(neighbor_before,neighbor_after)
    assert ev_after['high']>ev_before['high'] and ev_after['oom_kill']==ev_before['oom_kill']==0
    assert len([r for r in notifications if r['event']=='memory-pressure'])==1 and not err.read_text(),notifications
    # Stop/start keeps identity and reapplies high before the first instruction.
    out(cli+['stop','--time','0',name]);out(cli+['start',name]);restarted=inspect(cli,name)
    restart_payload=first_payload(cli,name)
    assert restarted['Id']==meta['Id'] and {k:restart_payload[k] for k in limits}==limits and restart_payload['starttime']!=startup['starttime']
    out(cli+['rm','-f','--time','0',name])
    out(cli+common+['--name',name,'--annotation','io.rmx1931.resource-policy='+name,image,'hold'])
    recreated=inspect(cli,name);recreate_payload=first_payload(cli,name)
    assert recreated['Id']!=meta['Id'] and {k:recreate_payload[k] for k in limits}==limits
    row.update(stop_start_passed=True,recreate_passed=True,recreated_container_id=recreated['Id'],restart_payload=restart_payload,recreate_payload=recreate_payload);results.append(row)
    print(json.dumps(row),flush=True)
    for container in (name,neighbor):out(cli+['rm','-f','--time','0',container])
    # Group teardown with all monitor FDs closed must leave no original leaf.
    for _ in range(50):
     if not g.exists() and not ng.exists():break
     time.sleep(.05)
    assert not g.exists() and not ng.exists()
    out(['rmx1931-policy','remove',name]);profiles.remove(name)
  finally:
   for container in owned:
    r=run(cli+['rm','-f','--time','0',container],check=False)
    if r.returncode and 'no such container' not in r.stderr.lower():cleanup_errors.append(r.stderr)
   for name in profiles:
    r=run(['rmx1931-policy','remove',name],check=False)
    if r.returncode:cleanup_errors.append(r.stderr)
   if built:run(cli+['image','rm','-f',image],check=True)
 assert len(results)==4 and not cleanup_errors,(len(results),cleanup_errors)
 assert not out(['podman','ps','-q']) and not out(['podman-rootless','ps','-q'])
 assert json.loads(out(['rmx1931-policy','validate']))['profiles']=={}
 print('GROUP_PSI_POLICY_ROOTFUL_ROOTLESS_CRUN_RUNC_PASS',flush=True)
finally:
 print(json.dumps({'cleanup_errors':cleanup_errors}),flush=True)
 # Keep bounded fixture source/log diagnostics; no running workload remains.
 print(json.dumps({'fixture_directory':str(base),'fixture_source_retained':True}),flush=True)
PY
