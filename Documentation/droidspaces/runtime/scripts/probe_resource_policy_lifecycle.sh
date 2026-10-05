#!/bin/sh
# Real CPU/IO/memory/pids limits across creation, exec and container lifecycle.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
action=${1:?prepare, verify, stop, outage or cleanup}
base=${2:?unique /var/tmp/rmx1931-policy-test-* directory}
case "$base" in /var/tmp/rmx1931-policy-test-*) ;; *) exit 2 ;; esac
case "$base" in *[!a-zA-Z0-9/-]*|*/../* ) exit 2 ;; esac
if test "$action" = prepare; then
    test ! -e "$base"
    mkdir -m 755 "$base"
    cat > "$base/fixture.c" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static atomic_int done;
static double now(clockid_t c){struct timespec t;clock_gettime(c,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void *burn(void *arg){(void)arg;volatile unsigned long x=1;while(!atomic_load(&done))x=x*1664525+1013904223;return 0;}
static long value(const char *name){char path[256];snprintf(path,sizeof(path),"/sys/fs/cgroup/%s",name);FILE *f=fopen(path,"r");long n=-1;if(f){if(fscanf(f,"%ld",&n)!=1)n=-1;fclose(f);}return n;}
int main(int argc,char **argv){
 if(argc<2)return 2;
 if(!strcmp(argv[1],"hold")){
  if(argc!=3)return 3;
  char io[512]="";FILE *f=fopen("/sys/fs/cgroup/io.max","r");if(f){if(!fgets(io,sizeof(io),f))io[0]=0;fclose(f);}io[strcspn(io,"\n")]=0;
  char cpu[128]="absent";f=fopen("/sys/fs/cgroup/cpu.max","r");if(f){if(!fgets(cpu,sizeof(cpu),f))return 17;fclose(f);}cpu[strcspn(cpu,"\n")]=0;
  f=fopen(argv[2],"w");if(!f)return 4;
  fprintf(f,"{\"memory\":%ld,\"pids\":%ld,\"oom_group\":%ld,\"io\":\"%s\",\"cpu_max\":\"%s\",\"seccomp\":%d}\n",value("memory.max"),value("pids.max"),value("memory.oom.group"),io,cpu,prctl(PR_GET_SECCOMP));fclose(f);for(;;)pause();
 }
 if(!strcmp(argv[1],"cpu")){
  pthread_t t[4];double wall=now(CLOCK_MONOTONIC),cpu=now(CLOCK_PROCESS_CPUTIME_ID);
  for(int i=0;i<4;i++)if(pthread_create(&t[i],0,burn,0))return 5;
  struct timespec delay={3,0};nanosleep(&delay,0);atomic_store(&done,1);
  for(int i=0;i<4;i++)pthread_join(t[i],0);
  printf("{\"wall\":%.6f,\"cpu\":%.6f,\"seccomp\":%d}\n",now(CLOCK_MONOTONIC)-wall,now(CLOCK_PROCESS_CPUTIME_ID)-cpu,prctl(PR_GET_SECCOMP));return 0;
 }
 if(!strcmp(argv[1],"read")||!strcmp(argv[1],"write")){
  if(argc!=3){return 6;}
  int writing=!strcmp(argv[1],"write");
  int fd=open(argv[2],O_DIRECT|O_RDWR|(writing?O_CREAT:0),0666);if(fd<0){perror("open");return 7;}
  void *buf;if(posix_memalign(&buf,4096,1048576))return 8;memset(buf,0x5a,1048576);
  struct stat st;if(fstat(fd,&st))return 9;double start=now(CLOCK_MONOTONIC);
  for(int i=0;i<8;i++){ssize_t n=writing?write(fd,buf,1048576):read(fd,buf,1048576);if(n!=1048576)return 10;if(!writing&&((unsigned char*)buf)[1048575]!=0x5a)return 11;}
  if(writing&&fdatasync(fd))return 12;
  printf("{\"seconds\":%.6f,\"bytes\":8388608,\"device\":\"%u:%u\",\"seccomp\":%d}\n",now(CLOCK_MONOTONIC)-start,major(st.st_dev),minor(st.st_dev),prctl(PR_GET_SECCOMP));close(fd);free(buf);return 0;
 }
 if(!strcmp(argv[1],"pids")){
  pid_t kids[128];int count=0,error=0;
  for(;count<128;count++){pid_t pid=fork();if(pid<0){error=errno;break;}if(!pid){for(;;)pause();}kids[count]=pid;}
  for(int i=0;i<count;i++){kill(kids[i],SIGKILL);}
  for(int i=0;i<count;i++){waitpid(kids[i],0,0);}
  printf("{\"children\":%d,\"errno\":%d,\"seccomp\":%d}\n",count,error,prctl(PR_GET_SECCOMP));return count<128&&error==EAGAIN?0:13;
 }
 if(!strcmp(argv[1],"oom")){
  for(int i=0;i<32;i++){void *p=malloc(4194304);if(!p)return 14;memset(p,0x5a,4194304);__asm__ volatile("" : : "r"(p) : "memory");struct timespec t={0,5000000};nanosleep(&t,0);}return 15;
 }
 return 16;
}
C
    gcc -static -O2 -pthread -Wall -Wextra -Werror "$base/fixture.c" -o "$base/fixture"
    cat > "$base/Containerfile" <<'CF'
FROM scratch
COPY fixture /fixture
ENTRYPOINT ["/fixture"]
CF
    chmod 644 "$base/fixture.c" "$base/Containerfile"
    chmod 755 "$base/fixture"
fi
python3 - "$action" "$base" <<'PY'
import json,os,re,subprocess,sys,time
from pathlib import Path
action=sys.argv[1];base=Path(sys.argv[2]);state=base/'state.json'
def run(argv,check=True,timeout=40):
    r=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
    if check and r.returncode:raise RuntimeError(json.dumps({'argv':argv,'rc':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
    return r
def out(argv,**kw):return run(argv,**kw).stdout.strip()
token=base.name.lower();rows=[]
if action=='prepare':
    assert not state.exists()
    backend=json.loads(out(['rmx1931-policy','ping']))['cpu_backend']
    assert backend in ('v1','v2')
    report={'base':str(base),'kernel':out(['uname','-r']),'cpu_backend':backend,'modes':[],'cleanup_errors':[],'passed':False}
    for mode in ('rootful','rootless'):
        row={'mode':mode,'name':token+'-'+mode,'profile':token+'-'+mode,'image':'localhost/'+token+'-'+mode+':1','measurements':[]}
        report['modes'].append(row)
else:report=json.loads(state.read_text())
def launcher(row):return ['podman-rootless'] if row['mode']=='rootless' else ['podman']
def inspect(row,neighbor=False):return json.loads(out(launcher(row)+['inspect',row['name']+('-neighbor' if neighbor else '')]))[0]
def create(row,neighbor=False):
    name=row['name']+('-neighbor' if neighbor else '');data=base/name
    if not data.exists():data.mkdir(mode=0o777);os.chmod(data,0o777)
    (data/'startup.json').unlink(missing_ok=True)
    args=launcher(row)+['run','-d','--name',name,'--network=none','--memory=96m','--pids-limit=48','-v',str(data)+':/data']
    if not neighbor:args+=['--annotation','io.rmx1931.resource-policy='+row['profile']]
    out(args+[row['image'],'hold','/data/startup.json'])
    return inspect(row,neighbor)['Id']
def snapshot(row,phase,neighbor=False):
    record=inspect(row,neighbor);name=row['name']+('-neighbor' if neighbor else '');data=base/name
    for _ in range(50):
        if (data/'startup.json').exists():break
        time.sleep(.1)
    payload=json.loads((data/'startup.json').read_text());pid=record['State']['Pid'];cid=record['Id']
    groups=Path('/proc',str(pid),'cgroup').read_text().splitlines()
    cpu=[line.split(':',2)[2] for line in groups if {'cpu','cpu_legacy'} & set(line.split(':',2)[1].split(','))]
    v2=[line.split(':',2)[2] for line in groups if line.startswith('0::')]
    assert len(cpu)==len(v2)==1 and '/libpod-'+cid+'.scope' in v2[0]
    group=Path('/sys/fs/cgroup'+v2[0]);assert '..' not in group.parts
    backend=report.get('cpu_backend','v1')
    if backend=='v2':
        assert cpu[0]=='/',cpu
        expected='max 100000' if neighbor else '50000 100000'
        assert payload['cpu_max']==expected and (group/'cpu.max').read_text().strip()==expected,payload
    else:assert payload['cpu_max']=='absent',payload
    if neighbor:
        assert payload['memory']==100663296 and payload['pids']==48 and payload['oom_group']==0 and payload['io']=='',payload
        assert 'rmx1931-policy-' not in cpu[0]
    else:
        assert payload['memory']==67108864 and payload['pids']==32 and payload['oom_group']==1,payload
        dev=os.stat('/').st_dev;device=str(os.major(dev))+':'+str(os.minor(dev))
        assert payload['io']==device+' rbps=2097152 wbps=2097152 riops=max wiops=max',payload
        if backend=='v1':assert cpu[0]=='/rmx1931-policy-'+cid,cpu
        assert (group/'memory.max').read_text().strip()=='67108864' and (group/'pids.max').read_text().strip()=='32'
    assert payload['seccomp']==2
    result={'phase':phase,'neighbor':neighbor,'cid':cid,'pid':pid,'cpu_backend':backend,
            'cpu_group':v2[0] if backend=='v2' else cpu[0],'legacy_cpu_group':cpu[0],
            'v2_group':v2[0],'first_payload':payload}
    row.setdefault('snapshots',[]).append(result)
    return group
def pressure(row,phase,neighbor=False):
    name=row['name']+('-neighbor' if neighbor else '');group=snapshot(row,phase,neighbor)
    cpu=json.loads(out(launcher(row)+['exec',name,'/fixture','cpu'],timeout=15));ratio=cpu['cpu']/cpu['wall']
    assert cpu['seccomp']==2 and (ratio>2 if neighbor else .3<ratio<.75),cpu
    result={'phase':phase,'neighbor':neighbor,'cpu':cpu,'used_cores':ratio,'io':[]}
    for operation in ('write','read'):
        io=json.loads(out(launcher(row)+['exec',name,'/fixture',operation,'/data/payload.bin'],timeout=15))
        assert io['bytes']==8388608 and io['seccomp']==2 and (io['seconds']<2 if neighbor else 2.8<io['seconds']<12),io
        result['io'].append({'operation':operation,**io})
    if not neighbor:
        before=(group/'pids.events').read_text()
        pids=json.loads(out(launcher(row)+['exec',name,'/fixture','pids'],timeout=15))
        assert 8<=pids['children']<32 and pids['errno']==11 and pids['seccomp']==2,pids
        after=(group/'pids.events').read_text();assert int(after.split()[1])>int(before.split()[1]),(before,after)
        result['pids']={**pids,'events_before':before,'events_after':after}
    row['measurements'].append(result)
    print(json.dumps({'completed_pressure':phase,'mode':row['mode'],'neighbor':neighbor,'used_cores':ratio}),flush=True)
try:
  if action=='prepare':
    assert not json.loads(out(['rmx1931-policy','validate']))['profiles'],'Fixture requires an empty policy registry'
    for row in report['modes']:
        out(launcher(row)+['build','--network=none','-t',row['image'],str(base)],timeout=50)
        out(['rmx1931-policy','set',row['profile'],'--mode',row['mode'],'--cpus','.5','--memory-mib','64','--pids','32','--read-bps','2097152','--write-bps','2097152','--oom-group'])
        row['initial_cid']=create(row);row['neighbor_cid']=create(row,True)
        pressure(row,'create');pressure(row,'unmanaged',True)
        out(launcher(row)+['stop','--time','0',row['name']]);(base/row['name']/'startup.json').unlink()
        out(launcher(row)+['start',row['name']]);assert inspect(row)['Id']==row['initial_cid'];pressure(row,'stop-start')
        out(launcher(row)+['rm','-f','--time','0',row['name']]);row['recreated_cid']=create(row)
        assert row['recreated_cid']!=row['initial_cid'];pressure(row,'recreate')
        # Bound the allocator to 128 MiB; the policy must kill the 64 MiB group.
        oom=run(launcher(row)+['exec',row['name'],'/fixture','oom'],check=False,timeout=20)
        status=out(launcher(row)+['wait',row['name']],timeout=20)
        assert oom.returncode==137 and status=='137',(oom.returncode,status,oom.stderr)
        row['oom']={'exec_exit':oom.returncode,'container_exit':status,'state':inspect(row)['State']}
        (base/row['name']/'startup.json').unlink();out(launcher(row)+['start',row['name']]);snapshot(row,'after-oom')
        snapshot(row,'neighbor-after-oom',True)
    report['prepare_passed']=True
  elif action=='verify':
    assert report['prepare_passed']
    for row in report['modes']:
        if not inspect(row)['State']['Running']:
            (base/row['name']/'startup.json').unlink(missing_ok=True);out(launcher(row)+['start',row['name']])
        if not inspect(row,True)['State']['Running']:
            (base/(row['name']+'-neighbor')/'startup.json').unlink(missing_ok=True);out(launcher(row)+['start',row['name']+'-neighbor'])
        pressure(row,'resume');snapshot(row,'neighbor-resume',True)
        assert inspect(row)['Id']==row['recreated_cid']
    report.setdefault('resume_passes',[]).append({'pid_namespace':os.readlink('/proc/self/ns/pid'),'device':out(['findmnt','-n','-o','MAJ:MIN','/'])})
  elif action=='stop':
    for row in report['modes']:
        for name in (row['name'],row['name']+'-neighbor'):
            out(launcher(row)+['stop','--time','0',name])
    report['stopped_for_guest_restart']=True
  elif action=='outage':
    for row in report['modes']:
        denied=run(launcher(row)+['exec',row['name'],'/fixture','cpu'],check=False)
        assert denied.returncode!=0 and 'policy service unavailable' in denied.stderr,denied.stderr
        snapshot(row,'still-limited-during-outage');snapshot(row,'neighbor-outage',True)
        out(launcher(row)+['exec',row['name']+'-neighbor','/fixture','cpu'],timeout=15)
        out(launcher(row)+['stop','--time','0',row['name']])
        denied_start=run(launcher(row)+['start',row['name']],check=False)
        assert denied_start.returncode!=0 and 'policy service unavailable' in denied_start.stderr,denied_start.stderr
        fresh=row['name']+'-denied';denied_run=run(launcher(row)+['run','--name',fresh,'--network=none','--annotation','io.rmx1931.resource-policy='+row['profile'],row['image'],'hold','/never'],check=False)
        assert denied_run.returncode!=0 and 'policy service unavailable' in denied_run.stderr,denied_run.stderr
        out(launcher(row)+['rm','-f','--time','0',fresh])
        row['outage']={'exec_exit':denied.returncode,'start_exit':denied_start.returncode,'create_exit':denied_run.returncode,'diagnostic':denied.stderr}
    report['outage_passed']=True
  elif action=='cleanup':
    for row in report['modes']:
        for name in (row['name'],row['name']+'-neighbor'):
            out(launcher(row)+['rm','-f','--time','0',name])
        out(launcher(row)+['rmi',row['image']]);out(['rmx1931-policy','remove',row['profile']])
        for name in (row['name'],row['name']+'-neighbor'):
            for file in (base/name).iterdir():assert file.name in ('startup.json','payload.bin');file.unlink()
            (base/name).rmdir()
    for _ in range(30):
        if not list(Path('/var/lib/rmx1931-policy/containers').glob('*.json')):break
        time.sleep(.1)
    assert not list(Path('/var/lib/rmx1931-policy/containers').glob('*.json'))
    report['cleanup_passed']=True
    report['passed']=bool(report.get('prepare_passed') and report.get('outage_passed') and len(report.get('resume_passes',[]))>=2)
  else:raise RuntimeError('Unknown probe phase')
except Exception as error:
    report['error']=str(error);raise
finally:
    state.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
print('RESOURCE_POLICY_'+action.upper()+'_PASS',flush=True)
PY
