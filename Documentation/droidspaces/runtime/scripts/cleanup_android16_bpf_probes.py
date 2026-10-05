#!/usr/bin/env python3
"""Remove only the two verified, completed native-probe fixture directories."""
import hashlib
import json
import shlex
import subprocess
from device_runtime import ROOT, device, guest_info, read_identity, read_root

ART = ROOT / 'artifacts/droidspaces/runtime'
label = 'android16-bpf-workload-a16pf-20261005'
target = ART / (label + '-cleanup.json')
assert not target.exists(), 'Inspect original cleanup state before any retry'
load = lambda p: json.loads(p.read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
result_path = ART / (label + '-result.json')
result = load(result_path)
assert result['passed'] and result['runtime_acceptance']
adb = device()
identity = read_identity(adb)
assert identity == {k: result[k] for k in ('kernel', 'boot_id')}
init = guest_info(adb)['pid']
directories = []
bindings = {}
for kind in ('readonly', 'workload'):
    name = 'android16-bpf-' + kind + '-a16pf-20261005'
    p = ART / (name + '-build.json')
    build = load(p)
    assert build['completed'] and build['guest_pid'] == init
    assert build['host_dir'] == '/data/local/tmp/' + name and build['guest_dir'] == '/tmp/rmx1931-tests/' + name
    host = build['host_dir']
    guest = '/proc/' + str(init) + '/root' + build['guest_dir']
    observed = read_root(adb, 'set -e; test -d ' + host + '; test ! -L ' + host +
        '; test -d ' + guest + '; test ! -L ' + guest + '; sha256sum ' + host + '/probe ' + guest + '/probe').decode().splitlines()
    assert len(observed) == 2 and all(line.split()[0] == build['binary_sha256'] for line in observed)
    directories += [host, guest]
    bindings[p.name] = sha(p)
report = {**identity, 'guest_pid': init, 'directories': directories, 'build_result_sha256': bindings,
    'workload_result_sha256': sha(result_path), 'cleanup_passed': False, 'phase': 'issuing once'}
target.write_text(json.dumps(report, indent=2) + '\n')
reply = subprocess.run(adb + ['exec-out', 'su', '-c', shlex.join(['rm', '-rf', '--', *directories])], capture_output=True, timeout=20)
report.update(returncode=reply.returncode, stderr=reply.stderr.decode(errors='replace'))
report['remaining'] = read_root(adb, '\n'.join('if test -e ' + p + '; then echo ' + p + '; fi' for p in directories)).decode().splitlines()
report['end_identity'] = read_identity(adb)
report['cleanup_passed'] = not report['remaining'] and report['end_identity'] == identity
report['phase'] = 'observed after cleanup'
target.write_text(json.dumps(report, indent=2) + '\n')
assert report['cleanup_passed']
print(json.dumps({'cleanup_passed': True, 'directories_removed': len(directories)}))
