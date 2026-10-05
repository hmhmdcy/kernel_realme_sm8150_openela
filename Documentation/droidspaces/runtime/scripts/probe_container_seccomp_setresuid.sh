#!/bin/sh
# Native syscall denial before/after setresuid, in scoped disposable children.
set -eu
test -f /etc/droidspaces
python3 - <<'PY'
import json,os,subprocess,tempfile,shutil
from pathlib import Path
base=Path(tempfile.mkdtemp(prefix='rmx1931-seccomp-setuid-',dir='/var/tmp'));base.chmod(0o755)
source=r'''
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
int main(void) {
 struct sock_filter instructions[]={BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_getppid,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
 struct sock_fprog program={sizeof(instructions)/sizeof(instructions[0]),instructions};
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))return 2;
 int before=prctl(PR_GET_SECCOMP);errno=0;long before_result=syscall(__NR_getppid);int before_errno=errno;
 int setresuid_result=setresuid(0,0,0);int after=prctl(PR_GET_SECCOMP);errno=0;long after_result=syscall(__NR_getppid);int after_errno=errno;
 printf("{\"before_seccomp\":%d,\"before_syscall_result\":%ld,\"before_errno\":%d,\"setresuid_result\":%d,\"after_seccomp\":%d,\"after_syscall_result\":%ld,\"after_errno\":%d}\n",before,before_result,before_errno,setresuid_result,after,after_result,after_errno);
 return 0;
}
'''
try:
 (base/'probe.c').write_text(source)
 r=subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror',str(base/'probe.c'),'-o',str(base/'probe')],capture_output=True,text=True);assert r.returncode==0,r.stderr
 (base/'probe').chmod(0o755)
 results={}
 for name,args in [('guest_pidns',['/usr/bin/env']),('private_userns',['unshare','--user','--map-root-user','--'])]:
  r=subprocess.run(args+[str(base/'probe')],capture_output=True,text=True,timeout=10);assert r.returncode==0,(r.stdout,r.stderr)
  data=json.loads(r.stdout);assert data['before_seccomp']==2 and data['before_syscall_result']==-1 and data['before_errno']==1 and data['setresuid_result']==0
  data['preserved']=data['after_seccomp']==2 and data['after_syscall_result']==-1 and data['after_errno']==1;results[name]=data
 ordinary=int(next(x.split(':')[1] for x in Path('/proc/1/status').read_text().splitlines() if x.startswith('Seccomp:')));assert ordinary==2
 passed=all(v['preserved'] for v in results.values())
 print(json.dumps({'passed':passed,'cases':results,'guest_pid_namespace':os.readlink('/proc/self/ns/pid'),'operator_user_namespace':os.readlink('/proc/self/ns/user'),'ordinary_guest_seccomp':ordinary,'cleanup_errors':[]}))
 print('CONTAINER_SECCOMP_SETRESUID_PASS' if passed else 'BINFMT_SECCOMP_PRESERVATION_FAILED')
 if not passed:raise SystemExit(1)
finally:shutil.rmtree(base)
PY
