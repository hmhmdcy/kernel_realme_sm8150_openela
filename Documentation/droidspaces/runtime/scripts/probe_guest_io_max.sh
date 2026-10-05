#!/bin/sh
# Native V2 io.max on guest processes and actual rootful/rootless payloads.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
case "$(uname -r)" in
  4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-dualio|4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-harden1) ;;
  *) exit 1 ;;
esac
grep -qw io /sys/fs/cgroup/cgroup.controllers
base=$(mktemp -d /var/tmp/rmx1931-v2io-XXXXXXXX)
chmod 755 "$base"
cd "$base"
cat > fixture.c <<'C'
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"hold")){for(;;)pause();}
 if(argc!=3)return 2;
 int writing=!strcmp(argv[1],"write");if(!writing&&strcmp(argv[1],"read"))return 3;
 int fd=open(argv[2],O_DIRECT|O_RDWR|(writing?O_CREAT:0),0666);if(fd<0){perror("open");return 4;}
 void *buf;if(posix_memalign(&buf,4096,1048576))return 5;memset(buf,0xa5,1048576);
 struct stat st;if(fstat(fd,&st))return 6;double start=now();
 for(int i=0;i<16;i++){
  ssize_t done=writing?write(fd,buf,1048576):read(fd,buf,1048576);
  if(done!=1048576){perror("direct IO");return 7;}
  if(!writing&&((unsigned char*)buf)[1048575]!=0xa5)return 8;
 }
 if(writing&&fdatasync(fd))return 9;
 printf("{\"seconds\":%.6f,\"bytes\":16777216,\"operation\":\"%s\",\"device\":\"%u:%u\",\"seccomp\":%d}\n",now()-start,argv[1],major(st.st_dev),minor(st.st_dev),prctl(PR_GET_SECCOMP));
 close(fd);free(buf);return 0;
}
C
gcc -static -O2 -Wall -Wextra -Werror fixture.c -o fixture
cat > Containerfile <<'CF'
FROM scratch
COPY fixture /fixture
ENTRYPOINT ["/fixture"]
CMD ["hold"]
CF
chmod 644 fixture.c Containerfile
chmod 755 fixture
python3 - "$base" <<'PY'
import json,os,re,shlex,subprocess,sys,time
from pathlib import Path
base=Path(sys.argv[1]);token=base.name.lower();report={'modes':[],'passed':False,'cleanup_errors':[]}
def run(argv,timeout=45):
    result=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
    if result.returncode:
        raise RuntimeError(json.dumps({'command':argv,'stdout':result.stdout,'stderr':result.stderr,'status':result.returncode}))
    return result.stdout.strip()
source=run(['findmnt','-n','-o','SOURCE','/'])
assert re.fullmatch('/dev/block/loop[0-9]+',source),source
dev=run(['findmnt','-n','-o','MAJ:MIN','/'])
assert re.fullmatch('7:[0-9]+',dev),dev
report.update(rootfs_source=source,major_minor=dev,limit_bps=2097152,fixture_bytes=16777216)
def stat(group):
    text=(group/'io.stat').read_text();values={}
    for line in text.splitlines():
        fields=line.split()
        if fields[0]==dev:values={k:int(v) for k,v in (entry.split('=') for entry in fields[1:])}
    return text,values
try:
  for mode in ('guest','rootful','rootless'):
    name=token+'-'+mode;image='localhost/'+name+':1';launcher=['podman-rootless'] if mode=='rootless' else ['podman']
    data=base/mode;data.mkdir(mode=0o777);os.chmod(data,0o777)
    row={'mode':mode,'measurements':[]};report['modes'].append(row)
    created=False;group_created=False;image_created=False
    try:
      if mode=='guest':
        group=Path('/sys/fs/cgroup')/name;assert not group.exists();group.mkdir();group_created=True
      else:
        run(launcher+['build','--network=none','-t',image,str(base)]);image_created=True
        run(launcher+['run','-d','--name',name,'--network=none','--memory=64m','--pids-limit=32','-v',str(data)+':/data',image]);created=True
        inspection=json.loads(run(launcher+['inspect',name]))[0];pid=inspection['State']['Pid'];ident=inspection['Id']
        unified=[line.split(':',2)[2] for line in Path('/proc',str(pid),'cgroup').read_text().splitlines() if line.startswith('0::')]
        assert len(unified)==1 and '/libpod-'+ident+'.scope' in unified[0]
        assert '..' not in unified[0].split('/')
        group=Path('/sys/fs/cgroup'+unified[0]);row['container_id']=ident
      assert (group/'io.max').is_file() and (group/'io.stat').is_file()
      row['cgroup']=str(group)
      def setlimit(limited):
        value=dev+' rbps='+('2097152' if limited else 'max')+' wbps='+('2097152' if limited else 'max')+' riops=max wiops=max\n'
        if mode=='rootless':
            code='from pathlib import Path;import sys;Path(sys.argv[1]).write_text(sys.argv[2])'
            run(['runuser','-u','podmantest','--','python3','-c',code,str(group/'io.max'),value])
        else:(group/'io.max').write_text(value)
        row.setdefault('settings',[]).append((group/'io.max').read_text())
      def measure(operation,phase):
        before_text,before=stat(group)
        if mode=='guest':
            inner='printf "%s\\n" $$ > '+shlex.quote(str(group/'cgroup.procs'))+'; exec '+shlex.join([str(base/'fixture'),operation,str(data/'payload.bin')])
            output=run(['/bin/sh','-ec',inner],timeout=25)
        else:output=run(launcher+['exec',name,'/fixture',operation,'/data/payload.bin'],timeout=25)
        result=json.loads(output);after_text,after=stat(group)
        key='wbytes' if operation=='write' else 'rbytes'
        accounted=after.get(key,0)-before.get(key,0)
        assert result['device']==dev and result['bytes']==16777216 and result['seccomp']==2,result
        assert accounted>=16777216,(mode,phase,operation,before_text,after_text)
        result.update(phase=phase,accounted_bytes=accounted,stat_before=before_text,stat_after=after_text)
        row['measurements'].append(result)
        return result
      setlimit(False);baseline={op:measure(op,'baseline') for op in ('write','read')}
      setlimit(True);limited={op:measure(op,'limited') for op in ('write','read')}
      setlimit(False);restored={op:measure(op,'restored') for op in ('write','read')}
      for op in ('write','read'):
        assert limited[op]['seconds']>=6 and limited[op]['seconds']>2*baseline[op]['seconds']
        assert restored[op]['seconds']<limited[op]['seconds']/2
      row['rootless_self_service_io_max']=mode=='rootless';row['passed']=True
    finally:
      try:
        if created:run(launcher+['rm','-f','--time','0',name])
        if image_created:run(launcher+['rmi',image])
        if group_created:group.rmdir()
        # Files belong solely to this unique fixture directory.
        payload=data/'payload.bin'
        if payload.exists():payload.unlink()
        data.rmdir()
      except Exception as error:report['cleanup_errors'].append(str(error))
  report['passed']=all(row.get('passed') for row in report['modes']) and not report['cleanup_errors']
except Exception as error:
  report['error']=str(error);raise
finally:
  (base/'result.json').write_text(json.dumps(report,indent=2)+'\n')
  print(json.dumps(report,indent=2),flush=True)
assert report['passed']
print('GUEST_ROOTFUL_ROOTLESS_NATIVE_IO_MAX_READ_WRITE_PASS',flush=True)
PY
