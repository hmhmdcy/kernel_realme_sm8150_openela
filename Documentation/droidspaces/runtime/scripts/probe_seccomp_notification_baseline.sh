#!/bin/sh
# Diagnose missing notify APIs without installing a USER_NOTIF rule.
set -eu
test -f /etc/droidspaces
cd /var/tmp
base=$(mktemp -d /var/tmp/rmx1931-notify-baseline-XXXXXXXX)
trap 'rm -f "$base/fixture" "$base/fixture.c"; rmdir "$base"' EXIT
cat > "$base/fixture.c" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
 unsigned int action=0x7fc00000U;
 struct {unsigned short notif,resp,data;} sizes={0};
 int before=prctl(PR_GET_SECCOMP),a,s,l,ae,se,le;
 errno=0;a=syscall(SYS_seccomp,2,0,&action);ae=errno;
 errno=0;s=syscall(SYS_seccomp,3,0,&sizes);se=errno;
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return 2;
 struct sock_filter instruction=BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
 struct sock_fprog program={.len=1,.filter=&instruction};
 errno=0;l=syscall(SYS_seccomp,1,8,&program);le=errno;
 if(l>=0)close(l);
 int after=prctl(PR_GET_SECCOMP);
 printf("{\"action_query\":%d,\"action_errno\":%d,\"sizes_query\":%d,\"sizes_errno\":%d,\"listener_install\":%d,\"listener_errno\":%d,\"seccomp_before\":%d,\"seccomp_after\":%d}\n",a,ae,s,se,l,le,before,after);
 if(a==-1&&ae==EOPNOTSUPP&&s==-1&&se==EINVAL&&l==-1&&le==EINVAL&&before==2&&after==2){puts("SECCOMP_NOTIFY_BASELINE_MISSING");return 0;}
 return 1;
}
C
gcc -static -O2 -Wall -Wextra -Werror "$base/fixture.c" -o "$base/fixture"
"$base/fixture"
