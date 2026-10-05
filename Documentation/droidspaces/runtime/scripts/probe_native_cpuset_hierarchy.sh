#!/bin/sh
# Native cpuset requests/effective masks, affinity, migration and task inheritance.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
python3 - <<'PY'
import errno,json,os,select,subprocess,sys,time,uuid
from pathlib import Path

cg=Path('/sys/fs/cgroup')
assert 'cpuset' in (cg/'cgroup.controllers').read_text().split()
token='rmx1931-native-cpuset-'+uuid.uuid4().hex[:10]
base=cg/token;created=[];worker=None;results={};cleanup=[]

def read(path):return path.read_text().strip()
def write(path,value):
    with path.open('w') as stream:stream.write(value+'\n')
def mkdir(path):path.mkdir();created.append(path);return path
def cpus(value):
    result=set()
    for piece in value.split(','):
        if not piece:continue
        first,sep,last=piece.partition('-')
        result.update(range(int(first),int(last)+1) if sep else [int(first)])
    return result
def mask(path):return cpus(read(path/'cpuset.cpus.effective'))
def text(values):return ','.join(map(str,sorted(values)))

worker_code=r'''
import json,os,subprocess,sys,threading
def report(mode):
    status=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
    row={'mode':mode,'affinity':sorted(os.sched_getaffinity(0)),'seccomp':int(status['Seccomp']),
         'pid':os.getpid(),'tid':threading.get_native_id()}
    os.write(1,(json.dumps(row)+'\n').encode())
for operation in sys.stdin:
    if operation.strip()!='family':raise RuntimeError('Unexpected worker command')
    report('parent')
    pid=os.fork()
    if pid==0:report('fork');os._exit(0)
    _,status=os.waitpid(pid,0)
    if status:raise RuntimeError('Fork child failed')
    command='import os,json; print(json.dumps({"mode":"exec","affinity":sorted(os.sched_getaffinity(0)),"seccomp":int(next(line.split(":")[1] for line in open("/proc/self/status") if line.startswith("Seccomp:")))}),flush=True)'
    subprocess.run([sys.executable,'-c',command],check=True)
    thread=threading.Thread(target=lambda:report('thread'));thread.start();thread.join()
'''

def family(expected):
    worker.stdin.write('family\n');worker.stdin.flush();rows=[]
    # Read raw bytes to avoid buffered TextIO hiding the remaining lines from select.
    data=b'';deadline=time.monotonic()+8
    while len(rows)<4 and time.monotonic()<deadline:
        ready,_,_=select.select([worker.stdout],[],[],.2)
        if not ready:continue
        part=os.read(worker.stdout.fileno(),4096)
        if not part:raise RuntimeError('Worker exited before reporting inheritance')
        data+=part
        while b'\n' in data:
            line,data=data.split(b'\n',1);rows.append(json.loads(line))
    assert len(rows)==4 and {row['mode'] for row in rows}=={'parent','fork','exec','thread'},rows
    assert all(set(row['affinity'])==expected and row['seccomp']==2 for row in rows),rows
    return rows

root_before=read(cg/'cgroup.subtree_control')
available=mask(cg);assert len(available)>=2,available
selected=set(sorted(available)[-2:]);single={max(selected)};outside=available-single
original=next(line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
assert '..' not in Path(original).parts
original_group=cg/original.lstrip('/')
assert (original_group/'cgroup.procs').exists(),original
try:
    mkdir(base);write(base/'cpuset.cpus',text(selected));write(base/'cpuset.mems','0')
    write(base/'cgroup.subtree_control','+cpuset')
    child=mkdir(base/'child')
    assert read(child/'cpuset.cpus')=='' and mask(child)==selected
    assert read(child/'cpuset.mems')=='' and read(child/'cpuset.mems.effective')=='0'
    results['empty_requests_inherit_parent']=True
    write(child/'cpuset.cpus',text(available))
    assert cpus(read(child/'cpuset.cpus'))==available and mask(child)==selected
    results['request_retained_and_parent_cap_applied']=True
    worker=subprocess.Popen([sys.executable,'-u','-c',worker_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    write(child/'cgroup.procs',str(worker.pid))
    results['initial_family']=family(selected)
    write(base/'cpuset.cpus',text(single));assert mask(child)==single
    results['parent_narrowing_updates_tasks']=family(single)
    os.sched_setaffinity(worker.pid,available)
    assert set(os.sched_getaffinity(worker.pid))==single
    try:os.sched_setaffinity(worker.pid,outside)
    except OSError as error:assert error.errno==errno.EINVAL
    else:raise AssertionError('Affinity escaped the native cpuset')
    results['affinity_cannot_escape']=True
    write(child/'cpuset.cpus',text(outside))
    assert cpus(read(child/'cpuset.cpus'))==outside and mask(child)==single
    results['unusable_request_inherits_parent']=family(single)
    write(child/'cpuset.cpus','');assert mask(child)==single
    write(base/'cpuset.cpus',text(selected));assert mask(child)==selected
    results['empty_request_and_parent_expansion']=family(selected)
    write(original_group/'cgroup.procs',str(worker.pid))
    restored=set(os.sched_getaffinity(worker.pid))
    assert restored and restored<=mask(original_group),restored
    results['migration_out_restores_destination_grant']=sorted(restored)
finally:
    if worker is not None:
        if worker.poll() is None:worker.terminate()
        worker.wait(timeout=5)
    for path in reversed(created):
        for attempt in range(30):
            try:path.rmdir();break
            except OSError as error:
                if error.errno not in (errno.EBUSY,errno.ENOTEMPTY) or attempt==29:
                    cleanup.append({'path':str(path),'error':str(error)});break
                time.sleep(.1)
assert not cleanup,cleanup
assert read(cg/'cgroup.subtree_control')==root_before
print(json.dumps({'cases':results,'selected':sorted(selected),'cleanup_errors':cleanup,'passed':True}),flush=True)
print('NATIVE_CPUSET_HIERARCHY_PASS',flush=True)
PY
