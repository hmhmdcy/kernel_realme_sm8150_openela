#!/bin/sh
# Actual cgroup2 device BPF allow/deny, including an alias with the same major/minor.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
printf 'PREVIOUS_MEMLOCK_KIB=%s\n' "$(ulimit -l)"
launcher_command=${1:-lxc-start}
case "$launcher_command" in
    lxc-start) ulimit -l 65536 ;;
    lxc-start-bpf) command -v lxc-start-bpf ;;
    *) exit 2 ;;
esac
base=$(mktemp -d /var/tmp/rmx1931-lxc-device-XXXXXXXX)
mkdir -p "$base/rootfs/bin" "$base/rootfs/dev" "$base/rootfs/proc" "$base/rootfs/sys" "$base/rootfs/tmp" "$base/rootfs/run"
cp /usr/bin/busybox "$base/rootfs/bin/busybox"
ln -s busybox "$base/rootfs/bin/sh"
cat > "$base/device.c" <<'C'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (getpid()!=1 || getuid()!=0 || argc!=2) return 20;
    int denied=atoi(argv[1]);
    int fd=open("/dev/null",O_WRONLY);
    if(fd<0 || write(fd,"x",1)!=1) return 21;
    close(fd);
    if(mknod("/dev/zero-alias",S_IFCHR|0600,makedev(1,5))!=0) return 22;
    const char *paths[]={"/dev/zero","/dev/zero-alias"};
    for(unsigned i=0;i<2;i++) {
        struct stat s;
        if(stat(paths[i],&s)!=0 || !S_ISCHR(s.st_mode) || major(s.st_rdev)!=1 || minor(s.st_rdev)!=5) return 23;
        errno=0; fd=open(paths[i],O_RDONLY);
        if(denied) { if(fd>=0 || errno!=EPERM) return 24; }
        else { char c=1; if(fd<0 || read(fd,&c,1)!=1 || c!=0) return 25; close(fd); }
    }
    FILE *f=fopen("/tmp/result","w"); if(!f) return 26;
    fprintf(f,"LXC_DEVICE_POLICY_%s_PASS\n",denied?"DENY":"ALLOW"); fclose(f);
    for(int i=0;i<100;i++) {
        if(access("/tmp/finish",F_OK)==0) return 0;
        struct timespec t={0,100000000}; nanosleep(&t,0);
    }
    return 27;
}
C
gcc -static -O2 -Wall -Wextra -Werror "$base/device.c" -o "$base/rootfs/bin/device-probe"
active=''
cleanup() { if [ -n "$active" ]; then lxc-stop -n "$active" -P "$base" -k >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT HUP INT TERM
for mode in 0 1; do
    name=rmx1931-device-$$-$mode
    mkdir "$base/$name"
    rm -f "$base/rootfs/tmp/result" "$base/rootfs/tmp/finish"
    cat > "$base/$name/config" <<CONFIG
lxc.rootfs.path = dir:$base/rootfs
lxc.uts.name = rmx1931-device-probe
lxc.net.0.type = empty
lxc.mount.auto = proc:rw sys:ro
lxc.autodev = 1
lxc.init.cmd = /bin/device-probe $mode
lxc.cgroup2.devices.allow = a
lxc.log.file = $base/$name/lxc.log
lxc.log.level = TRACE
CONFIG
    if [ "$mode" = 1 ]; then printf 'lxc.cgroup2.devices.deny = c 1:5 r\n' >> "$base/$name/config"; fi
    active=$name
    timeout 25 "$launcher_command" -n "$name" -P "$base" -F > "$base/$name/stdout" 2> "$base/$name/stderr" &
    launcher=$!
    for attempt in $(seq 1 50); do
        if [ -f "$base/rootfs/tmp/result" ]; then break; fi
        sleep 0.1
    done
    if [ ! -f "$base/rootfs/tmp/result" ]; then cat "$base/$name/stderr"; tail -n 35 "$base/$name/lxc.log"; exit 1; fi
    pid=$(lxc-info -n "$name" -P "$base" -pH)
    python3 - "$pid" "$mode" <<'PY'
import ctypes, json, os, struct, sys
from pathlib import Path
pid=int(sys.argv[1])
path=next(row.split(':',2)[2] for row in Path('/proc/%s/cgroup'%pid).read_text().splitlines() if row.startswith('0::'))
group=Path('/sys/fs/cgroup'+path)
descriptor=os.open(group,os.O_RDONLY|os.O_DIRECTORY)
ids=(ctypes.c_uint32*32)()
attribute=ctypes.create_string_buffer(32)
struct.pack_into('<IIIIQI',attribute,0,descriptor,6,1,0,ctypes.addressof(ids),32)
libc=ctypes.CDLL(None,use_errno=True)
status=libc.syscall(280,16,ctypes.byref(attribute),32)
error=ctypes.get_errno()
count=struct.unpack_from('<I',attribute,24)[0]
os.close(descriptor)
assert status==0 and 0<=count<=32,(status,error,count)
if sys.argv[2]=='1': assert count>0, 'No device BPF filter attached to the restricted container'
print(json.dumps({'device_bpf_programs':list(ids)[:count],'container_cgroup':path,'query_effective':True}))
PY
    cat "$base/rootfs/tmp/result"
    touch "$base/rootfs/tmp/finish"
    wait "$launcher"
    test "$(lxc-info -n "$name" -P "$base" -sH)" = STOPPED
    if grep -q 'Failed to load bpf program' "$base/$name/lxc.log"; then exit 1; fi
    active=''
done
trap - EXIT HUP INT TERM
printf 'LXC_DEVICE_BPF_ALLOW_DENY_ALIAS_CLEANUP_PASS diagnostics=%s\n' "$base"
