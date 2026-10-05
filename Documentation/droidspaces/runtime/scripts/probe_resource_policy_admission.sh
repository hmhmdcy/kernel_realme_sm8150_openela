#!/bin/sh
# Verify rejected admission, immutable referenced profiles and actual OOM events.
set -eu
test -f /etc/droidspaces
base=${1:?owned lifecycle fixture}
case "$base" in /var/tmp/rmx1931-policy-test-*) ;; *) exit 2 ;; esac
python3 - "$base" <<'PY'
import errno,json,subprocess,sys,time
from pathlib import Path
base=Path(sys.argv[1]);state=base/'state.json';report=json.loads(state.read_text())
def run(argv,check=True):
    r=subprocess.run(argv,capture_output=True,text=True,timeout=30)
    if check and r.returncode:raise RuntimeError(json.dumps({'argv':argv,'rc':r.returncode,'stderr':r.stderr}))
    return r
def out(argv):return run(argv).stdout.strip()
def values(text):return {k:int(v) for k,v in (line.split() for line in text.splitlines())}
try:
    for row in report['modes']:
        cli=['podman-rootless'] if row['mode']=='rootless' else ['podman'];other=next(r for r in report['modes'] if r['mode']!=row['mode'])
        out(cli+['ps','-a','--sync','--filter','name=^'+row['name']+'$'])
        current=json.loads(out(cli+['inspect',row['name']]))[0]
        if not current['State']['Running']:
            (base/row['name']/'startup.json').unlink(missing_ok=True);out(cli+['start',row['name']])
        negative=[]
        for tag,profile in [('unknown','rmx1931-policy-does-not-exist'),('wrong-user',other['profile'])]:
            name=row['name']+'-'+tag
            rejected=run(cli+['run','--name',name,'--network=none','--annotation','io.rmx1931.resource-policy='+profile,row['image'],'hold','/never'],False)
            assert rejected.returncode!=0 and 'Unknown policy or policy belongs to a different user' in rejected.stderr,rejected.stderr
            out(cli+['rm','-f','--time','0',name]);negative.append({'case':tag,'exit':rejected.returncode,'diagnostic':rejected.stderr})
        changed=run(['rmx1931-policy','set',row['profile'],'--mode',row['mode'],'--cpus','.75','--memory-mib','64','--pids','32','--read-bps','2097152','--write-bps','2097152','--oom-group'],False)
        removed=run(['rmx1931-policy','remove',row['profile']],False)
        assert changed.returncode==removed.returncode==125 and 'referenced by an existing container' in changed.stderr and 'referenced by an existing container' in removed.stderr
        denied=run(['runuser','-u','podmantest','--','rmx1931-policy','remove',row['profile']],False)
        assert denied.returncode==125 and 'requires isolated guest root' in denied.stderr
        record=json.loads(out(cli+['inspect',row['name']]))[0];pid=record['State']['Pid']
        unified=next(line.split(':',2)[2] for line in Path('/proc',str(pid),'cgroup').read_text().splitlines() if line.startswith('0::'))
        group=Path('/sys/fs/cgroup'+unified)
        with (group/'memory.events').open() as events:
            before=events.read();oom=run(cli+['exec',row['name'],'/fixture','oom'],False);status=out(cli+['wait',row['name']])
            try:
                events.seek(0);after=events.read()
            except OSError as error:
                if error.errno!=errno.ENODEV:raise
                after=None
        assert oom.returncode==137 and status=='137'
        if after is not None:assert values(after)['oom_kill']>values(before)['oom_kill'],(before,after)
        row['admission']={'negative':negative,'profile_change_exit':changed.returncode,'profile_remove_exit':removed.returncode,'rootless_admin_exit':denied.returncode,'memory_events_before':before,'memory_events_after':after,'event_file_removed_by_runtime':after is None,'kernel_oom_log_required':True,'oom_exec_exit':oom.returncode,'oom_container_id':record['Id']}
        out(cli+['ps','-a','--sync','--filter','name=^'+row['name']+'$'])
        assert not json.loads(out(cli+['inspect',row['name']]))[0]['State']['Running']
        (base/row['name']/'startup.json').unlink();out(cli+['start',row['name']])
        for _ in range(30):
            if (base/row['name']/'startup.json').exists():break
            time.sleep(.1)
        startup=json.loads((base/row['name']/'startup.json').read_text())
        assert startup['memory']==67108864 and startup['pids']==32 and startup['oom_group']==1 and startup['seccomp']==2
    report['admission_passed']=True
finally:
    state.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'admission_passed':report.get('admission_passed',False),'modes':[{'mode':r['mode'],'admission':r.get('admission')} for r in report['modes']]},indent=2),flush=True)
print('RESOURCE_POLICY_ADMISSION_PASS_KERNEL_OOM_LOG_REQUIRED',flush=True)
PY
