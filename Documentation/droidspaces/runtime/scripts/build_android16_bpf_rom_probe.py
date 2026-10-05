#!/usr/bin/env python3
"""Compile a bounded read-only native BPF probe using the actual kernel UAPI."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root

ART = ROOT / 'artifacts/droidspaces'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kind', choices=('readonly', 'workload'), default='readonly')
parser.add_argument('--resume-push-failure', action='store_true', help='Resume only the recorded first push permission failure after checking remote state')
args = parser.parse_args()
label = 'android16-bpf-' + args.kind + '-a16pf-20261005'
report_path = ART / 'runtime' / (label + '-build.json')
assert report_path.exists() == args.resume_push_failure, 'Inspect original state; use the exact recovery option only for the recorded push failure'
source = ROOT / ('references/runtime-probes/android16-bpf/bpf_rom_' + args.kind + '.c')
ref = ROOT / 'references/android16-bpf-current-kernel'
lock = json.loads((ref / 'source-lock.json').read_text())
header = ref / 'include/uapi/linux/bpf.h'
assert hashlib.sha256(header.read_bytes()).hexdigest() == lock['files']['include/uapi/linux/bpf.h']
boot = json.loads((ART / 'extensions-android16-group-psi-reclaim-fix-boot-result.json').read_text())
adb = device()
identity = read_identity(adb)
assert identity == {k: boot[k] for k in ('kernel', 'boot_id')}
init = guest_info(adb)['pid']
guest_dir = '/tmp/rmx1931-tests/' + label
root = '/proc/' + str(init) + '/root'
host_dir = '/data/local/tmp/' + label
report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
    'guest_pid': init, 'guest_dir': guest_dir, 'host_dir': host_dir,
    'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    'kernel_uapi_sha256': hashlib.sha256(header.read_bytes()).hexdigest(),
    'source_lock_sha256': hashlib.sha256((ref / 'source-lock.json').read_bytes()).hexdigest(),
    'completed': False, 'runtime_acceptance': False, 'phases': []}
if args.resume_push_failure:
    previous = json.loads(report_path.read_text())
    assert not previous['completed'] and previous['phase'] == 'pushing once: probe.c'
    assert len(previous['phases']) == 1 and previous['phases'][0]['returncode'] == 0
    for key in ('kernel', 'boot_id', 'guest_pid', 'guest_dir', 'host_dir', 'source_sha256', 'kernel_uapi_sha256', 'source_lock_sha256'):
        assert previous[key] == report[key], key
    read_root(adb, 'set -e; test -d ' + host_dir + '; test -d ' + root + guest_dir +
        '; test ! -e ' + host_dir + '/probe.c; test ! -e ' + root + guest_dir + '/probe')
    archive = report_path.with_name(label + '-build-first-push-failure.json')
    assert not archive.exists()
    archive.write_bytes(report_path.read_bytes())
    report = previous
    report['resumed_from_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
report['builder_source_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def save():
    report_path.write_text(json.dumps(report, indent=2) + '\n')


def mutate(command):
    report['phase'] = 'issuing once: ' + command
    save()
    result = subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=60)
    report['phases'].append({'command': command, 'returncode': result.returncode,
        'stdout': result.stdout.decode(errors='replace'), 'stderr': result.stderr.decode(errors='replace')})
    save()
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    return result.stdout.decode(errors='replace')


try:
    if not args.resume_push_failure:
        mutate('set -e; test ! -e ' + host_dir + '; test ! -e ' + root + guest_dir +
            '; test -f ' + root + '/etc/droidspaces; mkdir -m 755 ' + host_dir + ' ' + root + guest_dir)
    # adb push runs as Android shell, not the root process that made the directory.
    mutate('chown 2000:2000 ' + host_dir)
    for local, name in ((source, 'probe.c'), (header, 'kernel-bpf.h')):
        remote = host_dir + '/' + name
        report['phase'] = 'pushing once: ' + name
        save()
        result = subprocess.run(adb + ['push', str(local), remote], capture_output=True, timeout=30)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        assert read_root(adb, 'sha256sum ' + remote).decode().split()[0] == hashlib.sha256(local.read_bytes()).hexdigest()
        mutate('set -e; cp ' + remote + ' ' + root + guest_dir + '/' + name + '; chmod 644 ' + root + guest_dir + '/' + name)
    report['compiler'] = mutate(shlex.join([DS, '--name=' + NAME, 'run', 'gcc', '--version']))
    mutate(shlex.join([DS, '--name=' + NAME, 'run', 'gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
        '-I' + guest_dir, guest_dir + '/probe.c', '-o', guest_dir + '/probe']))
    report['binary_info'] = mutate(shlex.join([DS, '--name=' + NAME, 'run', 'file', guest_dir + '/probe']))
    assert 'ARM aarch64' in report['binary_info'] and 'statically linked' in report['binary_info']
    mutate('set -e; cp ' + root + guest_dir + '/probe ' + host_dir + '/probe; chown 0:0 ' +
        ' '.join(host_dir + suffix for suffix in ('', '/probe', '/probe.c', '/kernel-bpf.h')) + '; chmod 755 ' + host_dir + '/probe')
    report['binary_sha256'] = read_root(adb, 'sha256sum ' + host_dir + '/probe').decode().split()[0]
    report['end_identity'] = read_identity(adb)
    assert report['end_identity'] == identity
    report.update(completed=True, phase='compiled; native probe not executed', kind=args.kind)
finally:
    save()
print(json.dumps({'completed': report['completed'], 'native_binary_sha256': report.get('binary_sha256'), 'runtime_acceptance': False}))
