#!/usr/bin/env python3
"""Offline one verified secondary CPU, verify native masks, and always restore it."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root, collect_service

GUEST = r'''
import json,os,subprocess,sys,time
from pathlib import Path
work=Path(sys.argv[1]);core=int(sys.argv[2]);other=int(sys.argv[3]);label=sys.argv[4]
cg=Path('/sys/fs/cgroup');base=cg/label;worker=None;created=[];result={};cleanup=[]
def write(path,value):
 with path.open('w') as f:f.write(str(value)+'\n')
def cpus(value):
 answer=set()
 for piece in value.strip().split(','):
  if not piece:continue
  a,sep,b=piece.partition('-');answer.update(range(int(a),int(b)+1) if sep else [int(a)])
 return answer
def snapshot():
 return {'requested':(base/'worker/cpuset.cpus').read_text().strip(),
  'effective':sorted(cpus((base/'worker/cpuset.cpus.effective').read_text())),
  'affinity':sorted(os.sched_getaffinity(worker.pid))}
def wait(expected):
 deadline=time.monotonic()+25
 while time.monotonic()<deadline:
  if worker.poll() is not None:raise RuntimeError('Hotplug worker exited')
  s=snapshot()
  if s['effective']==expected and s['affinity']==expected:return s
  time.sleep(.05)
 raise RuntimeError('Hotplug mask/affinity did not converge: '+json.dumps(snapshot()))
try:
 assert Path('/etc/droidspaces').exists() and os.getuid()==0
 assert 'cpuset' in (cg/'cgroup.controllers').read_text().split()
 base.mkdir();created.append(base);write(base/'cpuset.cpus',f'{other},{core}');write(base/'cpuset.mems',0)
 write(base/'cgroup.subtree_control','+cpuset');child=base/'worker';child.mkdir();created.append(child)
 write(child/'cpuset.cpus',f'{other},{core}')
 worker=subprocess.Popen([sys.executable,'-c','import time;time.sleep(90)'])
 write(child/'cgroup.procs',worker.pid);initial=wait(sorted([other,core]))
 status=Path('/proc',str(worker.pid),'status').read_text()
 assert int(next(l.split(':')[1] for l in status.splitlines() if l.startswith('Seccomp:')))==2
 result['initial']=initial;(work/'ready').write_text(json.dumps(initial))
 result['offline']=wait([other]);assert cpus(result['offline']['requested'])=={other,core}
 (work/'offline').write_text(json.dumps(result['offline']))
 result['online']=wait(sorted([other,core]));assert cpus(result['online']['requested'])=={other,core}
 result['passed']=True
finally:
 if worker is not None:
  if worker.poll() is None:worker.terminate()
  worker.wait(timeout=5)
 for path in reversed(created):
  for attempt in range(30):
   try:path.rmdir();break
   except OSError as e:
    if attempt==29:cleanup.append(str(e))
    time.sleep(.1)
 result['cleanup_errors']=cleanup;print(json.dumps(result),flush=True)
assert result.get('passed') and not cleanup
print('NATIVE_CPUSET_HOTPLUG_PASS',flush=True)
'''


def cpulist(value):
    answer=set()
    for piece in value.strip().split(','):
        a, sep, b=piece.partition('-')
        answer.update(range(int(a),int(b)+1) if sep else [int(a)])
    return answer


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label',required=True)
    args=parser.parse_args()
    assert re.fullmatch(r'native-cpuset-hotplug-[A-Za-z0-9_-]+',args.label)
    report_path=ROOT/'artifacts/droidspaces/runtime'/f'{args.label}.json'
    assert not report_path.exists(),'Keep hotplug evidence immutable'
    compile(GUEST,'hotplug-guest','exec')
    adb=device();identity=read_identity(adb)
    stages={'4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp':'harden2-cpuset',
            '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp2':'harden2-cpuset-fix',
            '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp3':'harden2-cpuset-decay',
            '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp4':'harden2-cpuset-stats'}
    assert identity['kernel'] in stages
    verified=json.loads((ROOT/f'artifacts/droidspaces/extensions-{stages[identity["kernel"]]}-boot-result.json').read_text(encoding='utf-8'))
    assert verified['running_config_matches'] and verified['kernel']==identity['kernel']
    assert read_root(adb,'sha256sum /dev/block/by-name/boot').decode().split()[0]==verified['boot_sha256']
    assert read_root(adb,'getenforce').strip()==b'Enforcing'
    info=guest_info(adb);init=info['pid'];guest_root=f'/proc/{init}/root'
    target=f'/sys/fs/cgroup/droidspaces/{NAME}'
    before=read_root(adb,'cat /sys/devices/system/cpu/online').decode().strip()
    candidates=sorted(cpulist(read_root(adb,f'cat {target}/cpuset.cpus.effective').decode()) & cpulist(before))
    assert len(candidates)>=2 and max(candidates)>0,candidates
    core=candidates[-1];other=candidates[-2];online=f'/sys/devices/system/cpu/cpu{core}/online'
    assert read_root(adb,'cat '+online).strip()==b'1'
    report={'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),**identity,
            'cpu':core,'other_cpu':other,'online_before':before,'passed':False,
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n',b'\n')).hexdigest(),
            'guest_source_sha256':hashlib.sha256(GUEST.encode()).hexdigest()}
    work=f'/tmp/rmx1931-tests/service-{args.label}';host_work=guest_root+work
    normalized=ROOT/'tools/droidspaces'/f'{args.label}.py';normalized.write_text(GUEST,encoding='utf-8',newline='\n')
    remote=f'/data/local/tmp/{args.label}.py';script=f'/tmp/rmx1931-tests/{args.label}.py'
    subprocess.run(adb+['push',str(normalized),remote],capture_output=True,check=True,timeout=20)
    def mutation(command,timeout=25):
        r=subprocess.run(adb+['exec-out','su','-c',command],capture_output=True,timeout=timeout)
        if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace') or r.stdout.decode(errors='replace'))
        return r.stdout.decode(errors='replace').strip()
    def wait_file(name,limit=25):
        deadline=time.monotonic()+limit
        while time.monotonic()<deadline:
            data=read_root(adb,f'if test -f {host_work}/{name}; then cat {host_work}/{name}; elif test -f {host_work}/status; then cat {host_work}/stderr; exit 1; fi').decode().strip()
            if data:return json.loads(data)
            time.sleep(.2)
        raise RuntimeError('Hotplug phase did not finish: '+name)
    guard=f'test "$(uname -r)" = {shlex.quote(identity["kernel"])}; test "$(cat /proc/sys/kernel/random/boot_id)" = {identity["boot_id"]}; test "$(cat /sys/devices/system/cpu/cpu0/online 2>/dev/null || echo 1)" = 1; '
    offline_attempted=False;launched=False
    try:
        mutation(f'set -e; test -f {guest_root}/etc/droidspaces; test ! -L {guest_root}/tmp/rmx1931-tests; mkdir -p {guest_root}/tmp/rmx1931-tests; test ! -e {host_work}; mkdir -m 700 {host_work}; test ! -e {guest_root}{script}; cp {remote} {guest_root}{script}; chmod 600 {guest_root}{script}')
        assert read_root(adb,f'sha256sum {guest_root}{script}').decode().split()[0]==report['guest_source_sha256']
        payload=shlex.join(['python3',script,work,str(core),str(other),args.label])+f' > {work}/stdout 2> {work}/stderr; code=$?; printf "%s\\n" "$code" > {work}/status; exit "$code"'
        service=['systemd-run','--quiet','--no-block','--collect','--unit=rmx1931-test-'+args.label,'--property=OOMScoreAdjust=0','/bin/sh','-c',payload]
        mutation(shlex.join([DS,'--name='+NAME,'run',*service]));launched=True
        report['initial']=wait_file('ready')
        offline_attempted=True
        mutation('set -e; '+guard+f'echo 0 > {online}')
        report['offline']=wait_file('offline')
    except Exception as error:
        report['error']=str(error)
    finally:
        if offline_attempted:
            try:
                mutation('set -e; '+guard+f'echo 1 > {online}')
                report['online_after']=read_root(adb,'cat /sys/devices/system/cpu/online').decode().strip()
                report['cpu_restored']=report['online_after']==before
            except Exception as error:report['restore_error']=str(error)
        if launched:
            result=collect_service(adb,args.label,35)
            report.update(returncode=result.returncode,stdout=result.stdout.decode(errors='replace'),stderr=result.stderr.decode(errors='replace'))
        report['end_identity']=read_identity(adb)
        report['passed']=bool(report.get('cpu_restored') and report.get('returncode')==0 and 'NATIVE_CPUSET_HOTPLUG_PASS' in report.get('stdout','') and not report.get('error') and report['end_identity']==identity)
        report_path.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
        print(json.dumps(report,indent=2,ensure_ascii=False),flush=True)
    if not report['passed']:raise SystemExit(1)


if __name__=='__main__':main()
