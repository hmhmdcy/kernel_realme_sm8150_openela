#!/bin/sh
# Verify parent enforcement, sibling isolation and buffered cgroup writeback.
set -eu
test -f /etc/droidspaces
grep -qw io /sys/fs/cgroup/cgroup.controllers
python3 - <<'PY'
import errno,json,shlex,subprocess,tempfile,time
from pathlib import Path
base=Path(tempfile.mkdtemp(prefix='rmx1931-io-wb-',dir='/var/tmp'))
parent=Path('/sys/fs/cgroup')/base.name
child=parent/'worker'
peer=Path('/sys/fs/cgroup')/(base.name+'-peer')
report={'passed':False,'cleanup_errors':[],'measurements':[]}
source=subprocess.check_output(['findmnt','-n','-o','SOURCE','/'],text=True).strip()
dev=subprocess.check_output(['findmnt','-n','-o','MAJ:MIN','/'],text=True).strip()
report.update(device=source,major_minor=dev,limit_bps=2097152,fixture_bytes=16777216)
assert source.startswith('/dev/block/loop') and dev.startswith('7:')
made=[]
def measure(group,args,phase):
    command='printf "%s\\n" $$ > '+shlex.quote(str(group/'cgroup.procs'))+'; exec '+shlex.join(args)
    before=(group/'io.stat').read_text();start=time.monotonic()
    output=subprocess.run(['/bin/sh','-ec',command],capture_output=True,text=True,timeout=30)
    elapsed=time.monotonic()-start
    assert output.returncode==0,output.stderr
    row={'phase':phase,'seconds':elapsed,'cgroup':str(group),
         'stat_before':before,'stat_after':(group/'io.stat').read_text()}
    report['measurements'].append(row)
    return row
try:
    assert not parent.exists() and not peer.exists()
    parent.mkdir();made.append(parent)
    (parent/'cgroup.subtree_control').write_text('+io +memory +pids\n')
    child.mkdir();made.append(child)
    peer.mkdir();made.append(peer)
    assert all((group/'io.max').exists() for group in made)
    baseline=base/'baseline.bin';limited=base/'limited.bin'
    arguments=lambda path:['dd','if=/dev/zero','of='+str(path),'bs=1M','count=16','conv=fsync','status=none']
    fast=measure(child,arguments(baseline),'buffered-write-baseline')
    (parent/'io.max').write_text(dev+' rbps=2097152 wbps=2097152\n')
    (child/'io.max').write_text(dev+' rbps=max wbps=max riops=max wiops=max\n')
    try:(child/'io.v2_delegate').write_text('0\n')
    except OSError as error:
        assert error.errno==errno.EINVAL
        report['disable_selection_rejected_errno']=error.errno
    else:raise RuntimeError('A child disabled the one-way IO selection')
    slow=measure(child,arguments(limited),'buffered-write-parent-limit')
    read=['dd','if='+str(limited),'of=/dev/null','bs=1M','count=16','iflag=direct','status=none']
    slow_read=measure(child,read,'direct-read-parent-limit')
    sibling=measure(peer,read,'unlimited-sibling-read')
    assert slow['seconds']>=6 and slow['seconds']>2*fast['seconds']
    assert slow_read['seconds']>=6 and sibling['seconds']<slow_read['seconds']/2
    report['parent_io_stat']=(parent/'io.stat').read_text()
    assert dev+' ' in report['parent_io_stat']
    (parent/'io.max').write_text(dev+' rbps=max wbps=max\n')
    restored=measure(child,read,'released-parent-read')
    assert restored['seconds']<slow_read['seconds']/2
    report['passed']=True
finally:
    for group in reversed(made):
        try:group.rmdir()
        except Exception as error:report['cleanup_errors'].append(str(error))
    for name in ('baseline.bin','limited.bin'):
        path=base/name
        if path.exists():path.unlink()
    (base/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    if report['cleanup_errors']:report['passed']=False
    print(json.dumps(report,indent=2),flush=True)
assert report['passed']
print('V2_IO_PARENT_SIBLING_BUFFERED_WRITEBACK_ENFORCEMENT_PASS')
PY
