#!/bin/sh
# Reviewed privileged fixture: private mounts, owned legacy leaves and worker only.
# Run through privileged_guest.py; ordinary guest filters stay in place.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
test "$(sed -n 's/^Seccomp:[[:space:]]*//p' /proc/self/status)" = 0
if test "${1:-}" != private-mount-namespace; then
    exec unshare --mount --propagation private -- /bin/sh "$0" private-mount-namespace
fi
python3 - <<'PY'
import json, os, select, subprocess, sys, tempfile, time, uuid
from pathlib import Path

assert os.getpid() > 1
assert os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt')
assert int(next(line.split(':')[1] for line in Path('/proc/1/status').read_text().splitlines() if line.startswith('Seccomp:'))) == 2
cg = Path('/sys/fs/cgroup')
assert {'cpu', 'cpuset'} <= set((cg / 'cgroup.controllers').read_text().split())
assert {'cpu', 'cpuset'} <= set((cg / 'cgroup.subtree_control').read_text().split())
token = 'rmx1931-coexist-' + uuid.uuid4().hex[:10]
base = Path(tempfile.mkdtemp(prefix=token + '-', dir='/var/tmp'))
v1cpu, v1set = base / 'cpu', base / 'cpuset'
native = cg / token
mounts, leaves, workers, results, errors = [], [], [], [], []
profile = False
operator_moved = False
root_state = {}

def run(argv, check=True):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=35)
    if check and r.returncode:
        raise RuntimeError(json.dumps({'argv': argv, 'returncode': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr}))
    return r

def write(path, value):
    path.write_text(str(value) + '\n')

def cpus(text):
    out = set()
    for item in text.strip().split(','):
        a, sep, b = item.partition('-')
        out.update(range(int(a), int(b) + 1) if sep else [int(a)])
    return out

def legacy_membership(pid, controller):
    for line in Path('/proc/' + str(pid) + '/cgroup').read_text().splitlines():
        _, names, path = line.split(':', 2)
        if {controller, controller + '_legacy'} & set(names.split(',')):
            return path
    raise AssertionError('Missing legacy controller: ' + controller)

worker_source = r'''
import json, os, resource, sys, time
from pathlib import Path
print('ready', flush=True)
for text in sys.stdin:
    command = json.loads(text)
    before = resource.getrusage(resource.RUSAGE_SELF)
    start = time.monotonic()
    end = start + command.get('seconds', 0)
    value = 1
    while time.monotonic() < end:
        for _ in range(4096):
            value = (value * 1664525 + 1013904223) & 0xffffffff
    after = resource.getrusage(resource.RUSAGE_SELF)
    print(json.dumps({'cpu': (after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime),
        'wall': time.monotonic() - start, 'affinity': sorted(os.sched_getaffinity(0)),
        'membership': Path('/proc/self/cgroup').read_text().splitlines(),
        'seccomp': int(next(line.split(':')[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('Seccomp:')))}), flush=True)
'''

def measure(p, label, seconds=0, expected_mask=None, limits=None):
    p.stdin.write(json.dumps({'seconds': seconds}) + '\n')
    p.stdin.flush()
    assert select.select([p.stdout], [], [], seconds + 10)[0], label
    line = p.stdout.readline()
    assert line, (label, p.poll())
    row = json.loads(line)
    row['case'] = label
    if seconds:
        row['used_cores'] = row['cpu'] / row['wall']
    results.append(row)
    print(json.dumps(row), flush=True)
    if expected_mask is not None:
        assert row['affinity'] == sorted(expected_mask), row
    if limits is not None:
        assert limits[0] < row['used_cores'] < limits[1], row
    return row

try:
    for mountpoint, options in [(v1cpu, 'cpu'), (v1set, 'cpuset,noprefix,cpuset_v2_mode')]:
        mountpoint.mkdir()
        run(['mount', '-t', 'cgroup', '-o', options, 'none', str(mountpoint)])
        mounts.append(mountpoint)
    assert legacy_membership(os.getpid(), 'cpu') == '/'
    assert legacy_membership(os.getpid(), 'cpuset') == '/'
    root_state = {str(p): p.read_text() for p in [v1cpu / 'cpu.cfs_quota_us', v1cpu / 'cpu.cfs_period_us',
        v1cpu / 'cpu.shares', v1set / 'cpus', v1set / 'mems', cg / 'cgroup.subtree_control']}
    available = cpus((cg / 'cpuset.cpus.effective').read_text()) & cpus((v1set / 'cpus').read_text())
    assert len(available) >= 3
    chosen = set(sorted(available)[-2:])
    outside = min(available - chosen)
    native.mkdir(); leaves.append(native)
    write(native / 'cpuset.cpus', ','.join(map(str, sorted(chosen))))
    write(native / 'cpuset.mems', (cg / 'cpuset.mems.effective').read_text().strip())
    write(native / 'cpu.max', '50000 100000')
    legacy_cpu, legacy_set = v1cpu / token, v1set / token
    for leaf in (legacy_cpu, legacy_set):
        leaf.mkdir(); leaves.append(leaf)
    write(legacy_cpu / 'cpu.cfs_period_us', 100000)
    write(legacy_cpu / 'cpu.cfs_quota_us', 25000)
    write(legacy_set / 'mems', (v1set / 'mems').read_text().strip())
    write(legacy_set / 'sched_load_balance', 0)
    write(legacy_set / 'cpus', ','.join(map(str, sorted(chosen))))
    p = subprocess.Popen([sys.executable, '-u', '-c', worker_source], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    workers.append(p)
    assert select.select([p.stdout], [], [], 10)[0] and p.stdout.readline().strip() == 'ready'
    write(native / 'cgroup.procs', p.pid)
    measure(p, 'legacy-root-selects-native-half-cpu', 4, chosen, (.32, .68))
    write(legacy_cpu / 'cgroup.procs', p.pid)
    assert legacy_membership(p.pid, 'cpu') == '/' + token
    measure(p, 'nonroot-legacy-selects-quarter-cpu', 4, chosen, (.15, .37))
    write(legacy_cpu / 'cpu.cfs_quota_us', 100000)
    measure(p, 'legacy-one-cpu-native-half-not-combined', 4, chosen, (.75, 1.1))
    write(v1cpu / 'cgroup.procs', p.pid)
    assert legacy_membership(p.pid, 'cpu') == '/'
    measure(p, 'legacy-root-restores-native-half-cpu', 4, chosen, (.32, .68))
    first, second = sorted(chosen)
    write(legacy_set / 'cpus', first)
    write(legacy_set / 'cgroup.procs', p.pid)
    measure(p, 'cpuset-intersection', expected_mask={first})
    write(legacy_set / 'cpus', outside)
    measure(p, 'disjoint-cpuset-native-fallback', expected_mask=chosen)
    write(legacy_set / 'cpus', second)
    measure(p, 'cpuset-intersection-after-conflict', expected_mask={second})
    write(v1set / 'cgroup.procs', p.pid)
    measure(p, 'legacy-cpuset-root-restores-native-mask', expected_mask=chosen)
    # A real OCI admission request must reject an inherited non-root V1 CPU peer.
    run(['podman', 'image', 'exists', 'localhost/rmx1931-probe:1'])
    run(['rmx1931-policy', 'set', token, '--mode', 'rootful', '--cpus', '.5',
        '--memory-mib', '64', '--pids', '32', '--read-bps', '2097152', '--write-bps', '2097152', '--oom-group'])
    profile = True
    write(legacy_cpu / 'cgroup.procs', os.getpid())
    operator_moved = True
    try:
        rejected = run(['podman', 'run', '--runtime=crun', '--name', token, '--network=none',
            '--annotation', 'io.rmx1931.resource-policy=' + token, 'localhost/rmx1931-probe:1',
            '/bin/sh', '-c', 'echo COEXIST_PAYLOAD_MUST_NOT_RUN'], check=False)
        row = {'case': 'native-policy-refuses-nonroot-legacy-peer', 'returncode': rejected.returncode,
            'stdout': rejected.stdout, 'stderr': rejected.stderr}
        results.append(row); print(json.dumps(row), flush=True)
        assert rejected.returncode != 0 and 'peer still belongs to a non-root legacy CPU group' in rejected.stderr, row
        assert 'COEXIST_PAYLOAD_MUST_NOT_RUN' not in rejected.stdout, row
    finally:
        write(v1cpu / 'cgroup.procs', os.getpid())
        operator_moved = False
finally:
    if operator_moved:
        write(v1cpu / 'cgroup.procs', os.getpid())
    if profile:
        removed = run(['podman', 'rm', '-f', '--time', '0', token], check=False)
        if removed.returncode and 'no such container' not in removed.stderr.lower():
            errors.append({'container_cleanup': removed.stderr})
        try: run(['rmx1931-policy', 'remove', token])
        except Exception as error: errors.append({'profile_cleanup': str(error)})
    for p in workers:
        if p.poll() is None: p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait(timeout=5)
    for leaf in reversed(leaves):
        for attempt in range(30):
            try: leaf.rmdir(); break
            except OSError as error:
                if attempt == 29: errors.append({'cgroup': str(leaf), 'error': str(error)})
                time.sleep(.1)
    for path, text in root_state.items():
        if Path(path).read_text() != text: errors.append({'root_state_changed': path})
    for mountpoint in reversed(mounts):
        r = run(['umount', str(mountpoint)], check=False)
        if r.returncode: errors.append({'unmount': str(mountpoint), 'error': r.stderr})
    if not errors:
        for mountpoint in (v1cpu, v1set):
            if mountpoint.exists(): mountpoint.rmdir()
        base.rmdir()
    print(json.dumps({'cases': results, 'cleanup_errors': errors, 'ordinary_guest_seccomp':
        int(next(line.split(':')[1] for line in Path('/proc/1/status').read_text().splitlines() if line.startswith('Seccomp:')))}), flush=True)
    assert not errors, errors
assert len(results) == 9
print('NATIVE_CPU_CPUSET_COEXIST_PASS', flush=True)
PY
