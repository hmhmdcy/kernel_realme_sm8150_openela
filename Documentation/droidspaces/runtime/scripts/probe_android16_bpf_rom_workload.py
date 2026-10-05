#!/usr/bin/env python3
"""Execute one bounded ROM consumer workload and read existing BPF maps."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess
from device_runtime import ROOT, device, guest_info, read_identity, read_root

ART = ROOT / 'artifacts/droidspaces'
LABEL = 'android16-bpf-workload-a16pf-20261005'
path = ART / 'runtime' / (LABEL + '-result.json')
assert not path.exists(), 'Inspect or collect the original execution; never replay blindly'
load = lambda p: json.loads(p.read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
build_path = ART / 'runtime' / (LABEL + '-build.json')
build = load(build_path)
readonly_path = ART / 'runtime/android16-bpf-readonly-a16pf-20261005-build.json'
readonly = load(readonly_path)
inventory_path = ART / 'runtime/android16-bpf-readonly-a16pf-20261005-inventory.json'
inventory = load(inventory_path)
acceptance_path = ART / 'group-psi-acceptance.json'
acceptance = load(acceptance_path)
assert build['completed'] and readonly['completed'] and inventory['metadata_read_success'] and acceptance['passed']
for record, source in ((build, 'bpf_rom_workload.c'), (readonly, 'bpf_rom_readonly.c')):
    assert sha(ROOT / 'references/runtime-probes/android16-bpf' / source) == record['source_sha256']
adb = device()
identity = read_identity(adb)
assert all({k: record[k] for k in identity} == identity for record in (build, readonly, inventory, acceptance))
assert guest_info(adb)['pid'] == build['guest_pid']
binary = build['host_dir'] + '/probe'
reader = readonly['host_dir'] + '/probe'
actual = read_root(adb, 'sha256sum ' + binary + ' ' + reader + '; getenforce').decode().splitlines()
assert actual[0].split()[0] == build['binary_sha256'] and actual[1].split()[0] == readonly['binary_sha256'] and actual[2] == 'Enforcing'
uid_map = '/sys/fs/bpf/map_timeInState_uid_time_in_state_map'
net_map = '/sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map'
maps = {row['path']: row for row in inventory['objects'] if row.get('kind') == 'map'}
assert (maps[uid_map]['type'], maps[uid_map]['key_size'], maps[uid_map]['value_size']) == (5, 8, 256)
assert (maps[net_map]['type'], maps[net_map]['key_size'], maps[net_map]['value_size']) == (1, 4, 32)
report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
    'passed': False, 'runtime_acceptance': False, 'phase': 'preparing',
    'runner_source_sha256': sha(Path(__file__)), 'inventory_sha256': sha(inventory_path),
    'workload_build_sha256': sha(build_path), 'readonly_build_sha256': sha(readonly_path),
    'accepted_kernel_receipt_sha256': sha(acceptance_path), 'uid': 2000,
    'bpf_maps_manually_modified': False, 'bpf_programs_loaded_or_attached': False,
    'full_desktop': 'paused', 'limitations': ['UID totals may include other UID 2000 activity.',
        'Loopback accounting and syscall compatibility only; no throughput, power, GPU or tethering claim.',
        'No claim that every netd policy/rewrite configuration was exercised.']}


def save():
    path.write_text(json.dumps(report, indent=2) + '\n')


def snapshot():
    keys = [struct.pack('<II', 2000, bucket).hex() for bucket in range(8)]
    commands = [shlex.join([reader, 'lookup', uid_map, key]) + ' || true' for key in keys]
    commands.append(shlex.join([reader, 'lookup', net_map, struct.pack('<I', 2000).hex()]) + ' || true')
    rows = [json.loads(line) for line in read_root(adb, '\n'.join(commands), timeout=20).decode().splitlines()]
    assert len(rows) == 9 and all(row['ok'] or row['errno'] == 2 for row in rows)
    for row in rows:
        if row['ok']:
            assert row['id'] == maps[row['path']]['id'] and row['read_bytes'] == len(bytes.fromhex(row['value_hex']))
    total = sum(sum(struct.unpack('<' + 'Q' * (row['read_bytes'] // 8), bytes.fromhex(row['value_hex'])))
                for row in rows[:8] if row['ok'])
    network = list(struct.unpack('<QQQQ', bytes.fromhex(rows[-1]['value_hex']))) if rows[-1]['ok'] else [0] * 4
    return {'rows': rows, 'uid_cpu_ns': total, 'network': dict(zip(('rxPackets', 'rxBytes', 'txPackets', 'txBytes'), network))}


try:
    report['before'] = snapshot()
    report['phase'] = 'execution issued once'
    save()
    out = build['host_dir'] + '/workload.stdout'
    err = build['host_dir'] + '/workload.stderr'
    status = build['host_dir'] + '/workload.status'
    command = 'set -e; test ! -e ' + out + '; test ! -e ' + err + '; test ! -e ' + status + \
        '; set +e; timeout 12 ' + binary + ' >' + out + ' 2>' + err + \
        '; code=$?; printf "%s\\n" "$code" >' + status
    result = subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=25)
    report['transport_returncode'] = result.returncode
    report['transport_stderr'] = result.stderr.decode(errors='replace')
    report['native_stdout'] = read_root(adb, 'cat ' + out).decode()
    report['native_stderr'] = read_root(adb, 'cat ' + err).decode()
    report['native_returncode'] = int(read_root(adb, 'cat ' + status).strip())
    report['after'] = snapshot()
    report['end_identity'] = read_identity(adb)
    report['selinux'] = read_root(adb, 'getenforce').decode().strip()
    report['phase'] = 'native workload collected'
    save()
    assert report['native_returncode'] == 0 and not report['native_stderr']
    events = [json.loads(line) for line in report['native_stdout'].splitlines()]
    assert len(events) == 3 and all(row['uid'] == 2000 for row in events)
    cpu = events[0]
    assert cpu['event'] == 'cpu' and cpu['cpu_ns'] >= 1000000000
    assert {row['family'] for row in events[1:]} == {2, 10}
    assert all(row['roundtrips'] == 64 and row['passed'] and row['lo_ifindex'] > 0 for row in events[1:])
    cpu_delta = report['after']['uid_cpu_ns'] - report['before']['uid_cpu_ns']
    net_delta = {key: report['after']['network'][key] - report['before']['network'][key] for key in report['before']['network']}
    report.update(events=events, uid_cpu_delta_ns=cpu_delta, network_delta=net_delta)
    assert cpu_delta >= cpu['cpu_ns'] * 0.8, 'Loaded timeInState did not account the owned CPU workload'
    assert net_delta['rxPackets'] >= 256 and net_delta['txPackets'] >= 256
    assert net_delta['rxBytes'] >= 262144 and net_delta['txBytes'] >= 262144
    assert report['end_identity'] == identity and report['selinux'] == 'Enforcing'
    report.update(passed=True, runtime_acceptance=True, phase='functional workload passed')
finally:
    save()
print(json.dumps({'passed': report['passed'], 'uid_cpu_delta_ns': report.get('uid_cpu_delta_ns'),
    'network_delta': report.get('network_delta'), 'report': str(path)}))
