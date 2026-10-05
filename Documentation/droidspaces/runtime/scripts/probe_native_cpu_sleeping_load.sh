#!/bin/sh
# Diagnostic only: compare clean nested weights with sleeping scope migration.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
python3 - <<'PY'
import json, os, select, subprocess, sys, time, uuid
from pathlib import Path
cg = Path('/sys/fs/cgroup')
assert {'cpu', 'cpuset'} <= set((cg / 'cgroup.controllers').read_text().split())
token = 'rmx1931-sleeping-load-' + uuid.uuid4().hex[:10]
base = cg / token
created, workers, cases, cleanup = [], [], [], []
root_before = (cg / 'cgroup.subtree_control').read_text()

def cpus(text):
    out = set()
    for item in text.strip().split(','):
        a, sep, b = item.partition('-')
        out.update(range(int(a), int(b) + 1) if sep else [int(a)])
    return out

available = cpus((cg / 'cpuset.cpus.effective').read_text())
old_cpu, target_cpu = min(available), max(available)
assert old_cpu != target_cpu

def write(path, value): path.write_text(str(value) + '\n')
def mkdir(path): path.mkdir(); created.append(path); return path

source = r'''
import json, os, resource, sys, time
from pathlib import Path
print('ready', flush=True)
command = json.loads(sys.stdin.readline())
start = command['start']; warm = start + command['warm']; end = warm + command['seconds']
while time.monotonic() < start: time.sleep(.001)
before = None; value = 1
while time.monotonic() < end:
    if before is None and time.monotonic() >= warm:
        r = resource.getrusage(resource.RUSAGE_SELF); before = (r.ru_utime + r.ru_stime, time.monotonic())
    for _ in range(4096): value = (value * 1664525 + 1013904223) & 0xffffffff
r = resource.getrusage(resource.RUSAGE_SELF)
assert before
print(json.dumps({'cpu': r.ru_utime + r.ru_stime - before[0], 'wall': time.monotonic() - before[1],
    'start': before[1], 'affinity': sorted(os.sched_getaffinity(0)),
    'membership': Path('/proc/self/cgroup').read_text().splitlines(),
    'seccomp': int(next(line.split(':')[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('Seccomp:')))}), flush=True)
'''

def spawn(cpu):
    p = subprocess.Popen([sys.executable, '-u', '-c', source], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        preexec_fn=lambda: os.sched_setaffinity(0, {cpu}))
    workers.append(p)
    assert select.select([p.stdout], [], [], 10)[0] and p.stdout.readline().strip() == 'ready'
    time.sleep(.05)
    assert Path('/proc/' + str(p.pid) + '/stat').read_text().rsplit(')', 1)[1].split()[0] == 'S'
    return p

def fire(p, start, warm=2, seconds=8):
    p.stdin.write(json.dumps({'start': start, 'warm': warm, 'seconds': seconds}) + '\n'); p.stdin.flush()

def collect(p):
    stdout, stderr = p.communicate(timeout=20)
    assert p.returncode == 0, (p.returncode, stdout, stderr)
    return json.loads(stdout)

def debug():
    output = []
    for block in Path('/proc/sched_debug').read_text().split('\ncfs_rq[')[1:]:
        section = block.split('\nrt_rq[', 1)[0].split('\ndl_rq[', 1)[0]
        if token in section.splitlines()[0]: output.append('cfs_rq[' + section)
    return output

try:
    mkdir(base); write(base / 'cgroup.subtree_control', '+cpu +cpuset')
    for tag, dormant, witness in [('clean-nested-target-cpu', False, False),
            ('target-only-sleeping-attach-old-cpu', False, False),
            ('sleeping-parent-before-delegate', True, False),
            ('sleeping-startup-migration', True, False), ('sleeping-migration-with-enqueue', True, True)]:
        round_group = mkdir(base / tag); write(round_group / 'cgroup.subtree_control', '+cpu +cpuset')
        pair, paths, witnesses = [], [], []
        for index, weight in enumerate((10, 39)):
            parent = mkdir(round_group / str(index))
            parent_attach = tag == 'sleeping-parent-before-delegate'
            old_attach = tag == 'target-only-sleeping-attach-old-cpu'
            if not dormant:
                write(parent / 'cpuset.cpus', target_cpu); write(parent / 'cpu.weight', weight)
            if parent_attach:
                p = spawn(old_cpu)
                write(parent / 'cgroup.procs', p.pid)
                payload = mkdir(parent / 'payload')
                write(payload / 'cgroup.procs', p.pid)
                write(parent / 'cgroup.subtree_control', '+cpu +cpuset')
                write(payload / 'cpuset.cpus', target_cpu)
                startup = None
            else:
                write(parent / 'cgroup.subtree_control', '+cpu +cpuset')
                payload = mkdir(parent / 'payload'); write(payload / 'cpuset.cpus', target_cpu)
                if not dormant: write(payload / 'cpu.weight', weight)
                startup = mkdir(parent / 'startup') if dormant else None
                p = spawn(old_cpu if dormant or old_attach else target_cpu)
            if startup is not None: write(startup / 'cpuset.cpus', old_cpu)
            if startup is not None: write(startup / 'cgroup.procs', p.pid)
            if not parent_attach: write(payload / 'cgroup.procs', p.pid)
            if dormant:
                write(payload / 'cpu.weight', weight); write(parent / 'cpu.weight', weight)
            assert os.sched_getaffinity(p.pid) == {target_cpu}
            pair.append(p); paths.append((parent, payload))
        if witness:
            for parent, payload in paths:
                write(payload / 'cpuset.cpus', str(old_cpu) + ',' + str(target_cpu))
                p = spawn(old_cpu); write(payload / 'cgroup.procs', p.pid)
                os.sched_setaffinity(p.pid, {old_cpu})
                fire(p, time.monotonic() + .1, warm=0, seconds=.25)
                witnesses.append(collect(p))
                write(payload / 'cpuset.cpus', target_cpu)
            time.sleep(.5)
        before = debug(); start = time.monotonic() + .3
        for p in pair: fire(p, start)
        time.sleep(6)
        during = debug(); rows = [collect(p) for p in pair]
        assert all(row['affinity'] == [target_cpu] and row['seccomp'] == 2 for row in rows), rows
        ratio = rows[1]['cpu'] / rows[0]['cpu']
        case = {'case': tag, 'workloads': rows, 'old_cpu': old_cpu, 'target_cpu': target_cpu,
            'high_low_cpu_ratio': ratio, 'expected_weight_ratio': 3.9, 'weight_in_acceptance_range': 2 < ratio < 7,
            'enqueue_witnesses': witnesses, 'before_debug': before, 'during_debug': during}
        cases.append(case); print(json.dumps(case), flush=True)
finally:
    for p in workers:
        if p.poll() is None: p.terminate()
        p.wait(timeout=5)
    for path in reversed(created):
        for attempt in range(30):
            try: path.rmdir(); break
            except OSError as error:
                if attempt == 29: cleanup.append({'path': str(path), 'error': str(error)})
                time.sleep(.1)
assert not cleanup, cleanup
assert (cg / 'cgroup.subtree_control').read_text() == root_before
print(json.dumps({'cases': [{'case': row['case'], 'ratio': row['high_low_cpu_ratio'],
    'weight_in_acceptance_range': row['weight_in_acceptance_range']} for row in cases],
    'cleanup_errors': cleanup, 'scope': 'diagnostic reproduction only; not Podman acceptance'}), flush=True)
print('NATIVE_CPU_SLEEPING_LOAD_DIAGNOSTIC_COMPLETE', flush=True)
PY
