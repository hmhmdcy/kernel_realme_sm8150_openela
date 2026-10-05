#!/bin/sh
# Bounded CPU fixture for the separate Android-root quota management entry.
set -eu
action=${1:?action}
name=${2:?name}
mode=${3:?rootful or rootless}
case "$name" in rmx1931-cpu-* ) ;; *) exit 2 ;; esac
case "$name" in *[!a-z0-9-]* ) exit 2 ;; esac
case "$mode" in rootful) launcher=podman ;; rootless) launcher=podman-rootless ;; *) exit 2 ;; esac
base=/var/tmp/$name
image=localhost/$name:1
cd /var/tmp
case "$action" in
prepare)
    test ! -e "$base"
    test -z "$($launcher ps -a --filter name="^$name$" --format '{{.Names}}')"
    mkdir -m 755 "$base"
    cat > "$base/fixture.c" <<'C'
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>
static atomic_int stopped;
static double now(clockid_t c){struct timespec t;clock_gettime(c,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void *work(void *unused){(void)unused;volatile unsigned long x=1;while(!atomic_load(&stopped))x=x*1664525+1013904223;return 0;}
int main(int argc,char **argv){
 if(argc!=2)return 2;
 if(!strcmp(argv[1],"hold")){for(;;)pause();}
 if(strcmp(argv[1],"measure"))return 3;
 pthread_t t[4];double cpu=now(CLOCK_PROCESS_CPUTIME_ID),wall=now(CLOCK_MONOTONIC);
 for(int i=0;i<4;i++)if(pthread_create(&t[i],0,work,0))return 4;
 struct timespec delay={4,0};nanosleep(&delay,0);atomic_store(&stopped,1);
 for(int i=0;i<4;i++)pthread_join(t[i],0);
 printf("{\"wall_seconds\":%.6f,\"cpu_seconds\":%.6f,\"threads\":4,\"seccomp\":%d}\n",now(CLOCK_MONOTONIC)-wall,now(CLOCK_PROCESS_CPUTIME_ID)-cpu,prctl(PR_GET_SECCOMP));
 return 0;
}
C
    gcc -static -O2 -pthread -Wall -Wextra -Werror "$base/fixture.c" -o "$base/fixture"
    cat > "$base/Containerfile" <<'CF'
FROM scratch
COPY fixture /fixture
ENTRYPOINT ["/fixture"]
CMD ["hold"]
CF
    chmod 644 "$base/fixture.c" "$base/Containerfile"
    chmod 755 "$base/fixture"
    cd "$base"
    timeout 45 "$launcher" build --network=none -t "$image" . >/dev/null
    "$launcher" run -d --name "$name" --network=none --memory=64m --pids-limit=32 "$image" >/dev/null
    "$launcher" inspect --format '{{.Id}}' "$name"
    ;;
measure)
    cd /var/tmp
    timeout 15 "$launcher" exec "$name" /fixture measure
    ;;
cleanup)
    cd /var/tmp
    "$launcher" rm -f --time 0 "$name" >/dev/null
    "$launcher" rmi "$image" >/dev/null
    test -z "$($launcher ps -a --filter name="^$name$" --format '{{.Names}}')"
    echo CONTAINER_CPU_FIXTURE_CLEANUP_PASS
    ;;
*) exit 2 ;;
esac
