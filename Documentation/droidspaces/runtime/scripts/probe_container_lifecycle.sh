#!/bin/sh
# Bounded lifecycle tests. Run through privileged_guest for the -1000 exception.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
test "$(uname -r)" = 4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-harden1
test "$(sed -n 's/^Seccomp:[[:space:]]*//p' /proc/self/status)" = 0
base=$(mktemp -d /var/tmp/rmx1931-lifecycle-XXXXXXXX)
chmod 755 "$base"
cat > "$base/fixture.c" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void hog(void){
 for(int i=0;i<96;i++){
  void *p=malloc(1048576);if(!p)exit(30);memset(p,0xa5,1048576);
  __asm__ __volatile__("" : : "r"(p) : "memory");
 }
 exit(31);
}
static void *hold(void *unused){(void)unused;for(;;)pause();return NULL;}
int main(int argc,char **argv){
 if(argc!=2)return 2;
 printf("READY %d SECCOMP %d\n",getpid(),prctl(PR_GET_SECCOMP));fflush(stdout);
 if(!strcmp(argv[1],"hold")){for(;;)pause();}
 if(!strcmp(argv[1],"hog")){hog();}
 if(!strcmp(argv[1],"threads")){
  pthread_t threads[3];for(int i=0;i<3;i++)if(pthread_create(&threads[i],NULL,hold,NULL))return 4;
  for(;;)pause();
 }
 if(!strcmp(argv[1],"forks")){
  double end=now()+2;for(int i=0;i<4096&&now()<end;i++){
   pid_t p=fork();if(p==0){sleep(6);_exit(0);}if(p<0&&errno!=EAGAIN)return 5;
   usleep(500);
  }
  sleep(6);return 0;
 }
 if(!strcmp(argv[1],"tree")){
  pid_t sleeper=fork();if(sleeper<0)return 6;if(sleeper==0){for(;;)pause();}
  pid_t child=fork();if(child<0)return 7;if(child==0)hog();
  int status;if(waitpid(child,&status,0)!=child)return 8;
  if(!WIFSIGNALED(status)||WTERMSIG(status)!=9)return 9;
  printf("OOM_CHILD_KILLED_PARENT_SURVIVED\n");fflush(stdout);
  kill(sleeper,9);waitpid(sleeper,NULL,0);return 0;
 }
 return 3;
}
C
gcc -static -pthread -O2 -Wall -Wextra -Werror "$base/fixture.c" -o "$base/fixture"
chmod 755 "$base/fixture"
cat > "$base/Containerfile" <<'CF'
FROM scratch
COPY fixture /fixture
ENTRYPOINT ["/fixture"]
CMD ["tree"]
CF
chmod 644 "$base/fixture.c" "$base/Containerfile"
python3 - "$base" <<'PY'
import errno,json,os,re,selectors,subprocess,sys,time
from pathlib import Path
base=Path(sys.argv[1]); fixture=str(base/'fixture'); token=base.name.lower()
root=Path('/sys/fs/cgroup'); groups=[]; processes=[]; containers=[]; images=[]
report={'passed':False,'cases':[],'cleanup_errors':[],'android_processes_moved':False}
before=Path('/proc/self/cgroup').read_text()
testroot=root/token
assert not testroot.exists()
assert 'memory' in (root/'cgroup.controllers').read_text().split()

def run(argv,timeout=45,check=True):
 result=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
 if check and result.returncode:raise RuntimeError(json.dumps({'command':argv,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}))
 return result

def create(name,parent=testroot,memory=64*1048576,pids=32,oom=0):
 path=parent/name;path.mkdir();groups.append(path)
 for key,value in [('memory.max',memory),('memory.swap.max',0),('pids.max',pids),('memory.oom.group',oom)]:
  (path/key).write_text(str(value)+'\n')
 return path

def launch(group,mode='hold',protect=False):
 def enter():
  (group/'cgroup.procs').write_text(str(os.getpid())+'\n')
  if protect:Path('/proc/self/oom_score_adj').write_text('-1000\n')
 process=subprocess.Popen([fixture,mode],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,preexec_fn=enter)
 processes.append(process)
 selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
 try:
  assert selector.select(3),'Fixture did not become ready'
  line=process.stdout.readline();assert line.startswith('READY '),line
 finally:selector.close()
 return process

def wait_empty(path,timeout=5):
 deadline=time.monotonic()+timeout
 while time.monotonic()<deadline:
  if 'populated 0' in (path/'cgroup.events').read_text():return
  time.sleep(.02)
 raise RuntimeError('Cgroup not empty: '+str(path))

def killed(process):
 assert process.wait(timeout=6)==-9,'Fixture was not killed by SIGKILL'

def mark(name,**details):
 report['cases'].append({'name':name,'passed':True,**details});print('LIFECYCLE_CASE_PASS '+name,flush=True)

try:
 testroot.mkdir();groups.append(testroot)
 (testroot/'cgroup.subtree_control').write_text('+memory +pids\n')
 # This mount is a delegated subtree; check the actual hierarchy root from Android.
 report['delegated_root_has_kill']=(root/'cgroup.kill').exists()
 invalid=create('invalid')
 assert (invalid/'memory.oom.group').read_text().strip()=='0'
 for file,value,wanted in [('cgroup.kill','0',errno.ERANGE),('cgroup.kill','2',errno.ERANGE),('memory.oom.group','2',errno.EINVAL)]:
  try:(invalid/file).write_text(value+'\n')
  except OSError as error:assert error.errno==wanted,(file,error)
  else:raise AssertionError('Invalid value accepted')
 mark('default_and_invalid_values')

 control=create('oom-control',memory=32*1048576)
 keep=[launch(control),launch(control)]
 hog=launch(control,'hog');killed(hog)
 assert all(p.poll() is None for p in keep)
 (control/'cgroup.kill').write_text('1\n')
 for p in keep:killed(p)
 wait_empty(control);mark('oom_group_disabled_control')

 grouped=create('oom-group',memory=32*1048576,oom=1)
 keep=[launch(grouped),launch(grouped,'threads')]
 protected=launch(grouped,protect=True)
 hog=launch(grouped,'hog');killed(hog)
 for p in keep:killed(p)
 assert protected.poll() is None
 assert Path('/proc/'+str(protected.pid)+'/oom_score_adj').read_text().strip()=='-1000'
 (grouped/'cgroup.kill').write_text('1\n');killed(protected)
 wait_empty(grouped);mark('oom_group_and_protected_exception')

 parent=create('oom-parent',memory=48*1048576,oom=1)
 (parent/'cgroup.subtree_control').write_text('+memory +pids\n')
 a=create('a',parent,memory=64*1048576);b=create('b',parent,memory=64*1048576)
 neighbor=create('oom-neighbor');outside=launch(neighbor)
 children=[launch(a),launch(b)];hog=launch(a,'hog');killed(hog)
 for p in children:killed(p)
 wait_empty(parent);assert outside.poll() is None
 (neighbor/'cgroup.kill').write_text('1\n');killed(outside)
 mark('parent_oom_group_reaches_descendants_only')

 parent=create('domain-parent',memory=64*1048576,oom=1)
 (parent/'cgroup.subtree_control').write_text('+memory +pids\n')
 leaf=create('limited',parent,memory=32*1048576,oom=1)
 sibling=create('sibling',parent);outside=launch(sibling);inside=launch(leaf)
 hog=launch(leaf,'hog');killed(hog);killed(inside)
 wait_empty(leaf);assert outside.poll() is None
 (parent/'cgroup.kill').write_text('1\n');killed(outside)
 wait_empty(parent);mark('leaf_oom_does_not_kill_ancestor_or_sibling')

 parent=create('kill-parent')
 (parent/'cgroup.subtree_control').write_text('+memory +pids\n')
 children=[launch(create('a',parent)),launch(create('b',parent),'threads')]
 neighbor=create('kill-neighbor');outside=launch(neighbor)
 (parent/'cgroup.kill').write_text('1\n')
 for p in children:killed(p)
 wait_empty(parent);assert outside.poll() is None
 (neighbor/'cgroup.kill').write_text('1\n');killed(outside)
 mark('recursive_kill_and_sibling_isolation')

 frozen=create('frozen');process=launch(frozen,'threads')
 (frozen/'cgroup.freeze').write_text('1\n')
 deadline=time.monotonic()+3
 while 'frozen 1' not in (frozen/'cgroup.events').read_text():
  assert time.monotonic()<deadline,'Freeze did not complete';time.sleep(.02)
 (frozen/'cgroup.kill').write_text('1\n');killed(process);wait_empty(frozen)
 mark('kill_frozen_group')

 threaded_parent=create('threaded-parent')
 threaded=threaded_parent/'threaded';threaded.mkdir();groups.append(threaded)
 (threaded/'cgroup.type').write_text('threaded\n')
 try:(threaded/'cgroup.kill').write_text('1\n')
 except OSError as error:assert error.errno==errno.EOPNOTSUPP,error
 else:raise AssertionError('Threaded cgroup accepted process-directed kill')
 mark('threaded_kill_refused')

 for iteration in range(12):
  forkgroup=create('fork-race-'+str(iteration),pids=32)
  process=launch(forkgroup,'forks');time.sleep(.01+iteration*.001)
  (forkgroup/'cgroup.kill').write_text('1\n');killed(process);wait_empty(forkgroup)
 mark('bounded_fork_race',iterations=12,pids_limit=32)

 # Guest PID 1 retains DroidSpaces' filter. Request ordinary services from it;
 # do not inherit this operator's unfiltered entry for Podman payloads.
 service=['systemd-run','--quiet','--wait','--pipe','--collect','--property=OOMScoreAdjust=0']
 for mode,launcher in [('rootful',service+['podman']),('rootless',service+['podman-rootless'])]:
  image='localhost/'+token+'-'+mode+':1'
  assert run(launcher+['image','exists',image],check=False).returncode==1,'Fixture image collision'
  images.append((launcher,image))
  run(launcher+['build','--network=none','-t',image,str(base)],timeout=90)
  for oom in (0,1):
   name=token+'-'+mode+'-'+str(oom)
   assert not run(launcher+['ps','-a','--filter','name=^'+name+'$','--format','{{.Id}}']).stdout.strip()
   containers.append((launcher,name))
   result=run(launcher+['run','--name',name,'--network=none','--memory=32m','--memory-swap=32m',
               '--pids-limit=32','--cgroup-conf=memory.oom.group='+str(oom),image],timeout=35,check=False)
   expected=137 if oom else 0
   assert result.returncode==expected,{'mode':mode,'oom':oom,'result':result.__dict__}
   assert 'SECCOMP 2' in result.stdout,'Ordinary container lost filtering'
   if not oom:assert 'OOM_CHILD_KILLED_PARENT_SURVIVED' in result.stdout
   else:assert 'OOM_CHILD_KILLED_PARENT_SURVIVED' not in result.stdout
   state=json.loads(run(launcher+['inspect',name]).stdout)[0]
   assert state['State']['ExitCode']==expected
   mark(mode+'_actual_container_oom_group_'+str(oom),exit_code=expected,payload_seccomp=2,
        launch='ordinary guest systemd service')
 assert Path('/proc/self/cgroup').read_text()==before,'Operator unexpectedly migrated'
 report['passed']=True
finally:
 for launcher,name in reversed(containers):
  result=run(launcher+['rm','-f',name],check=False)
  if result.returncode:report['cleanup_errors'].append(result.stderr)
 for launcher,image in reversed(images):
  result=run(launcher+['rmi',image],check=False)
  if result.returncode:report['cleanup_errors'].append(result.stderr)
 for group in reversed(groups):
  try:
   if (group/'cgroup.kill').exists() and (group/'cgroup.type').read_text().strip()!='threaded':
    (group/'cgroup.kill').write_text('1\n')
  except OSError as error:report['cleanup_errors'].append(str(error))
 for process in processes:
  if process.poll() is None:process.kill()
  try:process.wait(timeout=6)
  except subprocess.TimeoutExpired as error:report['cleanup_errors'].append(str(error))
  process.stdout.close();process.stderr.close()
 for group in reversed(groups):
  try:wait_empty(group);group.rmdir()
  except (OSError,RuntimeError) as error:report['cleanup_errors'].append(str(error))
 report['passed']=report['passed'] and not report['cleanup_errors']
 (base/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report),flush=True)
assert report['passed'],report
print('CONTAINER_LIFECYCLE_ACCEPTANCE_PASS')
PY
