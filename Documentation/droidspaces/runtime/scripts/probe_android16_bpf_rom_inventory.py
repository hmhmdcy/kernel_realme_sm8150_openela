#!/usr/bin/env python3
"""Read actual ROM BPF metadata and effective attachments in one bounded batch."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
from device_runtime import ROOT, device, read_identity, read_root

ART = ROOT / 'artifacts/droidspaces'
label = 'android16-bpf-readonly-a16pf-20261005'
target = ART / 'runtime' / (label + '-inventory.json')
assert not target.exists()
build_path = ART / 'runtime' / (label + '-build.json')
build = json.loads(build_path.read_text())
assert build['completed']
source = ROOT / 'references/runtime-probes/android16-bpf/bpf_rom_readonly.c'
assert hashlib.sha256(source.read_bytes()).hexdigest() == build['source_sha256']
binary = build['host_dir'] + '/probe'
boot = json.loads((ART / 'extensions-android16-group-psi-reclaim-fix-boot-result.json').read_text())
adb = device()
identity = read_identity(adb)
assert identity == {k: boot[k] for k in ('kernel', 'boot_id')}
assert read_root(adb, 'getenforce').strip() == b'Enforcing'
assert read_root(adb, 'sha256sum ' + binary).decode().split()[0] == build['binary_sha256']
pins = sorted(read_root(adb, 'find /sys/fs/bpf -type f').decode().splitlines())
assert 1 <= len(pins) <= 256 and len(pins) == len(set(pins))
assert all(re.fullmatch(r'/sys/fs/bpf/[A-Za-z0-9_./-]+', path) and '/..' not in path for path in pins)
mountinfo = read_root(adb, 'cat /proc/self/mountinfo').decode()
roots = sorted({line.split(' - ')[0].split()[4] for line in mountinfo.splitlines()
    if ' - cgroup2 ' in line and line.split(' - ')[0].split()[4] in ('/sys/fs/cgroup', '/dev/cg2_bpf')})
types = {0: 'cgroupskb-ingress', 1: 'cgroupskb-egress', 2: 'sock-create',
    8: 'bind4', 9: 'bind6', 10: 'connect4', 11: 'connect6', 14: 'udp4-sendmsg',
    15: 'udp6-sendmsg', 19: 'udp4-recvmsg', 20: 'udp6-recvmsg', 21: 'getsockopt', 22: 'setsockopt'}
commands = [shlex.join([binary, 'object', path]) + ' || true' for path in pins]
raw = read_root(adb, '\n'.join(commands), timeout=60).decode()
objects = [json.loads(line) for line in raw.splitlines()]
assert len(objects) == len(commands), 'Incomplete native object batch'
assert [row['path'] for row in objects] == pins
programs = [row for row in objects if row.get('ok') and row.get('kind') == 'program']
maps = [row for row in objects if row.get('ok') and row.get('kind') == 'map']
# Query only attachment families for programs actually loaded by this ROM.
loaded_types = {row['type'] for row in programs}
selected = []
if 8 in loaded_types: selected += [0, 1]  # CGROUP_SKB
if 9 in loaded_types: selected += [2]  # CGROUP_SOCK
if 18 in loaded_types: selected += [8, 9, 10, 11, 14, 15, 19, 20]  # SOCK_ADDR
if 25 in loaded_types: selected += [21, 22]  # SOCKOPT
commands = [shlex.join([binary, 'query', path, str(kind)]) + ' || true' for path in roots for kind in selected]
raw = read_root(adb, '\n'.join(commands), timeout=30).decode() if commands else ''
queries = [json.loads(line) for line in raw.splitlines()]
assert len(queries) == len(commands), 'Incomplete actual-consumer query batch'
failures = [row for row in objects + queries if not row['ok']]
program_names = {row['id']: row['path'] for row in programs}
for row in queries:
    if row['ok']:
        row['attach_name'] = types[row['attach_type']]
        row['pinned_programs'] = [program_names.get(pid) for pid in row['program_ids']]
report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
    'end_identity': read_identity(adb), 'boot_sha256': boot['boot_sha256'],
    'build_result_sha256': hashlib.sha256(build_path.read_bytes()).hexdigest(),
    'runner_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'pins': pins, 'objects': objects, 'effective_cgroup_queries': queries, 'failures': failures,
    'queried_cgroup2_mounts': roots, 'loaded_program_types': sorted(loaded_types), 'selected_attach_types': selected,
    'program_count': len(programs), 'map_count': len(maps), 'metadata_read_success': not failures,
    'bpf_programs_loaded': read_root(adb, 'getprop bpf.progs_loaded').decode().strip(),
    'user_space_kernel_override': read_root(adb, 'getprop ro.bpf.kver_override').decode().strip(),
    'selinux': 'Enforcing', 'runtime_acceptance': False,
    'interpretation': 'Real object info and effective attachment queries; CPU/time-in-state and network accounting workloads remain required. GPU/tethering hardware operation is outside default test scope.'}
assert report['end_identity'] == identity
target.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'program_count': len(programs), 'map_count': len(maps), 'failures': failures,
    'attached_query_count': len([row for row in queries if row.get('program_ids')]), 'runtime_acceptance': False}))
