#!/bin/sh
# Real OCI process-tree checkpoint/restore with memory, socket, overlay and volume state.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
base=$(mktemp -d /var/tmp/rmx1931-checkpoint-XXXXXXXX)
token=$(basename "$base" | tr '[:upper:]' '[:lower:]')
name=$token
volume=$token
image=localhost/$token:1
control=${1:-}
control_label=${2:-}
if test -n "$control"; then
    test "$control" = external-operator
    case "$control_label" in ''|*[!a-zA-Z0-9_-]*) exit 2 ;; esac
fi
existing=$(podman ps -a --filter name="^$name$" --format '{{.Names}}')
test -z "$existing"
volume_created=0
container_created=0
cleanup() {
    if [ "$container_created" = 1 ]; then
        storage=$(podman inspect --format '{{.StaticDir}}' "$name" 2>/dev/null || true)
        if [ -n "$storage" ] && [ -d "$storage" ]; then
            find "$storage" -maxdepth 3 -type f \( -name '*log*' -o -name '*stats*' \) -exec cp --parents '{}' "$base" \; 2>/dev/null || true
        fi
        podman rm -f "$name" >/dev/null 2>&1 || true
    fi
    if [ "$volume_created" = 1 ]; then podman volume rm "$volume" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT HUP INT TERM
cat > "$base/fixture.c" <<'C'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
struct message { unsigned long counter; int memory_ok; };
static void delay(void) { struct timespec t={0,100000000}; nanosleep(&t,0); }
int main(int argc,char **argv) {
    if(getpid()!=1 || argc!=2) return 10;
    unsigned char *memory=malloc(4*1024*1024);
    if(!memory) return 11;
    memset(memory,0xa5,4*1024*1024);
    FILE *f=fopen("/startup-count","r"); int startups=0;
    if(f){ if(fscanf(f,"%d",&startups)!=1) return 12; fclose(f); }
    f=fopen("/startup-count","w"); if(!f)return 13; fprintf(f,"%d\n",++startups); fclose(f);
    f=fopen("/overlay-proof","w"); if(!f)return 14; fprintf(f,"%s\n",argv[1]); fclose(f);
    f=fopen("/data/persisted","w"); if(!f)return 15; fprintf(f,"%s\n",argv[1]); fclose(f);
    int sockets[2]; if(socketpair(AF_UNIX,SOCK_STREAM,0,sockets)!=0)return 16;
    pid_t child=fork(); if(child<0)return 17;
    if(child==0) {
        close(sockets[0]); unsigned long counter=90000;
        for(;;) {
            struct message m={++counter,memory[4*1024*1024-1]==0xa5};
            if(write(sockets[1],&m,sizeof(m))!=sizeof(m))return 18;
            delay();
        }
    }
    close(sockets[1]); unsigned long counter=100000;
    for(;;) {
        struct message m; if(read(sockets[0],&m,sizeof(m))!=sizeof(m))return 19;
        int memory_ok=1; for(unsigned i=0;i<4*1024*1024;i+=4096)if(memory[i]!=0xa5)memory_ok=0;
        f=fopen("/state.json","w"); if(!f)return 20;
        fprintf(f,"{\"parent\":1,\"child\":%d,\"counter\":%lu,\"child_counter\":%lu,\"memory_ok\":%d,\"child_memory_ok\":%d,\"startups\":%d}\n",
                child,++counter,m.counter,memory_ok,m.memory_ok,startups);
        fclose(f);
    }
}
C
gcc -static -O2 -Wall -Wextra -Werror "$base/fixture.c" -o "$base/fixture"
cat > "$base/Containerfile" <<'CF'
FROM scratch
COPY fixture /fixture
ENTRYPOINT ["/fixture"]
CF
timeout 45 podman build --network=none -t "$image" "$base"
podman volume create "$volume" >/dev/null
volume_created=1
podman --runtime=runc run -d --name "$name" --network=none --memory=64m --pids-limit=32 -v "$volume:/data" "$image" "$token"
container_created=1
python3 - "$name" "$token" "$base" "$control" "$control_label" <<'PY'
import json, subprocess, sys, time
from pathlib import Path
name,token,base,control,control_label=sys.argv[1:]
def run(arguments,timeout=45):
    if control and arguments[:2] in (['container','checkpoint'],['container','restore']):
        action=arguments[1]
        path=Path('/tmp/rmx1931-tests')/('checkpoint-control-'+control_label+'.'+action+'.json')
        assert not path.exists()
        identity=json.loads(subprocess.check_output(['podman','inspect',name]))[0]['Id']
        request={'action':action,'container_name':name,'container_id':identity,'base':base,
                 'export':str(Path(base)/'checkpoint.tar') if action=='checkpoint' else None}
        path.write_text(json.dumps(request))
        done=path.with_suffix('.done')
        for attempt in range(900):
            if done.exists():return ''
            time.sleep(.1)
        raise RuntimeError('External operator action never completed: '+action)
    result=subprocess.run(['podman',*arguments],capture_output=True,text=True,timeout=timeout)
    if result.returncode:
        print(json.dumps({'command':arguments,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}),flush=True)
        raise RuntimeError('Podman fixture operation failed')
    return result.stdout.strip()
# Read through the mounted root; the scratch fixture deliberately has no exec shell.
mounted=run(['mount',name])
state=Path(mounted)/'state.json'
for attempt in range(100):
    try:
        before=json.loads(state.read_text())
        if before['counter']>=100005:break
    except (FileNotFoundError,json.JSONDecodeError): pass
    time.sleep(.1)
else: raise RuntimeError('Process tree never became ready')
assert before['child']>1 and before['memory_ok']==before['child_memory_ok']==before['startups']==1,before
assert (Path(mounted)/'overlay-proof').read_text().strip()==token
Path(base,'before.json').write_text(json.dumps(before))
print(json.dumps({'phase':'before','state':before}),flush=True)
archive=str(Path(base)/'checkpoint.tar')
run(['container','checkpoint','--keep','--compress=none','--export',archive,name])
assert run(['inspect','--format','{{.State.Running}}',name])=='false'
assert Path(archive).stat().st_size>1048576
print('OCI_CONTAINER_PROCESS_TREE_CHECKPOINT_STOP_PASS',flush=True)
time.sleep(1)
run(['container','restore','--keep',name])
assert run(['inspect','--format','{{.State.Running}}',name])=='true'
for attempt in range(100):
    try:
        after=json.loads(state.read_text())
        if after['counter']>before['counter'] and after['child_counter']>before['child_counter']:break
    except (FileNotFoundError,json.JSONDecodeError):pass
    time.sleep(.1)
else: raise RuntimeError('Restored state did not advance')
assert after['child']==before['child'] and after['memory_ok']==after['child_memory_ok']==after['startups']==1,after
assert (Path(mounted)/'overlay-proof').read_text().strip()==token
assert (Path(mounted)/'startup-count').read_text().strip()=='1'
volume=run(['volume','inspect','--format','{{.Mountpoint}}',name])
assert Path(volume,'persisted').read_text().strip()==token
inspection=json.loads(run(['inspect',name]))[0]
assert inspection['HostConfig']['Memory']==67108864 and inspection['HostConfig']['PidsLimit']==32
Path(base,'after.json').write_text(json.dumps(after))
print(json.dumps({'phase':'after','state':after,'memory_limit':67108864,'pids_limit':32,
                  'archive_bytes':Path(archive).stat().st_size}),flush=True)
run(['unmount',name])
print('OCI_CONTAINER_TREE_MEMORY_SOCKET_OVERLAY_VOLUME_RESTORE_PASS',flush=True)
PY
cleanup
test -z "$(podman ps -a --filter name="^$name$" --format '{{.Names}}')"
test -z "$(podman volume ls --filter name="^$volume$" --format '{{.Name}}')"
container_created=0
volume_created=0
trap - EXIT HUP INT TERM
printf 'PODMAN_CHECKPOINT_FIXTURE_CLEANUP_PASS diagnostics=%s\n' "$base"
