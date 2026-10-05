#!/bin/sh
# Preserve memory.high profiles across a real, controlled guest restart.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
test "$(uname -r)" = 4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf
python3 - "$@" <<'PY'
import hashlib,json,os,re,subprocess,sys,time
from pathlib import Path

assert len(sys.argv)==3
phase,location=sys.argv[1:]
assert phase in ('prepare','resume','recover','cleanup') and re.fullmatch(r'/var/tmp/rmx1931-psi-persist-[A-Za-z0-9-]+',location)
base=Path(location);state=base/'state.json'
def run(argv,check=True):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=40)
 if check and r.returncode:raise RuntimeError(json.dumps({'argv':argv,'rc':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
 return r
def out(argv):return run(argv).stdout.strip()
def cli(row):return ['podman-rootless'] if row['mode']=='rootless' else ['podman']
def inspect(row):return json.loads(out(cli(row)+['inspect',row['name']]))[0]
def source_hashes():
 return {path:hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in
  ('/usr/local/libexec/rmx1931_resource_policy.py','/usr/local/libexec/rmx1931-oci-crun',
   '/usr/local/libexec/rmx1931-oci-runc','/usr/local/bin/rmx1931-pressure')}
registry=Path('/etc/rmx1931/resource-policies.json')
snapshot_command='cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.high; sed -n "s/^Seccomp:[[:space:]]*//p" /proc/self/status'
first_command=snapshot_command+"; awk '{print $22}' /proc/$$/stat"
expected=['67108864','33554432','2']

def first_payload(row,current):
 pid=current['State']['Pid'];stat=Path('/proc',str(pid),'stat').read_text()
 start=stat[stat.rindex(')')+2:].split()[19];deadline=time.monotonic()+8
 while True:
  lines=out(cli(row)+['logs',row['name']]).splitlines()
  matching=[lines[i:i+4] for i in range(0,len(lines)-3,4) if lines[i+3]==start]
  if matching or time.monotonic()>=deadline:break
  observed=inspect(row)
  assert observed['Id']==current['Id'] and observed['State']['Pid']==pid and observed['State']['Running']
  time.sleep(.05)
 assert matching==[expected+[start]],matching
 return matching[0][:3],start

if phase=='prepare':
 assert not base.exists() and not out(['podman','ps','-q']) and not out(['podman-rootless','ps','-q'])
 assert json.loads(out(['rmx1931-policy','validate']))['profiles']=={}
 base.mkdir(mode=0o700)
 report={'before_namespace':os.readlink('/proc/self/ns/pid'),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
   'sources_before':source_hashes(),'modes':[],'prepare_passed':False,'resume_passed':False,'cleanup_passed':False}
else:
 report=json.loads(state.read_text())

def cleanup():
 for row in report['modes']:
  r=run(cli(row)+['rm','-f','--time','0',row['name']],check=False)
  assert not r.returncode or 'no such container' in r.stderr.lower(),r.stderr
  out(['rmx1931-policy','remove',row['name']])
 assert not out(['podman','ps','-q']) and not out(['podman-rootless','ps','-q'])
 assert json.loads(out(['rmx1931-policy','validate']))['profiles']=={}
 report['cleanup_passed']=True

try:
 if phase=='prepare':
  for mode in ('rootful','rootless'):
   for runtime in ('crun','runc'):
    name=base.name+'-'+mode+'-'+runtime;row={'mode':mode,'runtime':runtime,'name':name};report['modes'].append(row)
    out(['rmx1931-policy','set',name,'--mode',mode,'--cpus','.5','--memory-mib','64','--memory-high-mib','32',
     '--pids','32','--read-bps','2097152','--write-bps','2097152','--oom-group'])
    out(cli(row)+['run','-d','--name',name,'--runtime='+runtime,'--network=none','--memory=96m','--pids-limit=48',
     '--annotation','io.rmx1931.resource-policy='+name,'--entrypoint=/bin/sh','localhost/rmx1931-probe:1',
     '-c',first_command+'; exec sleep 300'])
    initial=inspect(row);row['container_id']=initial['Id']
    row['first_payload_before'],row['first_starttime_before']=first_payload(row,initial)
    out(cli(row)+['stop','--time','0',name]);assert not inspect(row)['State']['Running']
  report.update(registry_sha256=hashlib.sha256(registry.read_bytes()).hexdigest(),profiles=json.loads(registry.read_text()),prepare_passed=True)
  print('GROUP_PSI_PERSISTENCE_PREPARE_PASS',flush=True)
 elif phase in ('resume','recover'):
  assert report['prepare_passed'] and report['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  if phase=='recover':
   assert not report['resume_passed']
   original_error=report.pop('error')
   assert original_error=='AssertionError([])' or (original_error=='AssertionError()' and report.get('original_resume_error')=='AssertionError([])')
   report.setdefault('original_resume_error',original_error)
   report.setdefault('collection_errors',[]).append(original_error)
  after_ns=os.readlink('/proc/self/ns/pid');assert after_ns!=report['before_namespace'],'Real guest restart is required'
  assert hashlib.sha256(registry.read_bytes()).hexdigest()==report['registry_sha256']
  assert source_hashes()==report['sources_before']
  server=json.loads(out(['rmx1931-policy','ping']));assert server['cpu_backend']=='v2' and server['pid_namespace']==after_ns
  for row in report['modes']:
   initial=inspect(row);assert initial['Id']==row['container_id']
   if initial['State']['Running']:
    assert phase=='recover' and row is report['modes'][0],'Only the observed original start may be collected'
    row['original_started_process_collected']=True
   else:
    row['start_issued_once']=True;state.write_text(json.dumps(report,indent=2)+'\n')
    out(cli(row)+['start',row['name']])
   started=inspect(row);assert started['Id']==row['container_id'] and started['State']['Running']
   backend=started['HostConfig']['LogConfig']['Type'];assert backend in ('journald','k8s-file'),backend
   started_at=started['State']['StartedAt'];assert re.match(r'^2026-\d\d-\d\dT',started_at),started_at
   # Bind first output to /proc starttime; backend timestamp filtering may
   # exclude a very early first instruction. Do not replay a successful start.
   logs,first_start=first_payload(row,started)
   assert first_start!=row['first_starttime_before']
   executed=out(cli(row)+['exec',row['name'],'/bin/sh','-c',snapshot_command]).splitlines();assert executed==expected,executed
   observed=run(['rmx1931-pressure','--mode',row['mode'],'--name',row['name'],'--threshold-us','50000','--timeout','1'],check=False)
   notices=[json.loads(s) for s in observed.stdout.splitlines()]
   assert observed.returncode==3 and not observed.stderr and notices[0]['memory_high']=='33554432' and notices[0]['memory_max']=='67108864'
   assert notices[0]['container_id']==row['container_id'] and notices[-1]['reason']=='deadline',notices
   row.update(first_payload_after=logs,first_starttime_after=first_start,started_at_after=started_at,log_backend=backend,exec_payload_after=executed,monitor_after=notices,passed=True)
   out(cli(row)+['stop','--time','0',row['name']])
  report.update(after_namespace=after_ns,server_after=server,sources_after=source_hashes(),registry_preserved=True,resume_passed=True)
  cleanup();print('GROUP_PSI_PERSISTENCE_RESUME_PASS',flush=True)
 else:
  cleanup();print('GROUP_PSI_PERSISTENCE_CLEANUP_PASS',flush=True)
except BaseException as error:
 report['error']=repr(error);raise
finally:
 state.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
PY
