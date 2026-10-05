#!/usr/bin/env python3
"""Bind actual ROM metadata, workload accounting, health and fixture cleanup."""
import datetime as dt
import hashlib
import json
from pathlib import Path
from device_runtime import ROOT

ART = ROOT / 'artifacts/droidspaces'
target = ART / 'android16-bpf-acceptance.json'
assert not target.exists(), 'Acceptance is immutable'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads(p.read_text())
evidence = {}
reports = {}
for key, name in (
    ('psi', 'group-psi-acceptance.json'),
    ('inventory', 'runtime/android16-bpf-readonly-a16pf-20261005-inventory.json'),
    ('workload', 'runtime/android16-bpf-workload-a16pf-20261005-result.json'),
    ('cleanup', 'runtime/android16-bpf-workload-a16pf-20261005-cleanup.json'),
    ('health', 'runtime/bpf-host-final-a16pf-20261005.json')):
    p = ART / name
    reports[key] = load(p)
    evidence[key] = {'path': name, 'sha256': sha(p)}
identity = {k: reports['psi'][k] for k in ('kernel', 'boot_id')}
for key, report in reports.items():
    assert {k: report[k] for k in identity} == identity, key
    if 'end_identity' in report: assert report['end_identity'] == identity, key
inventory, workload, cleanup, health = (reports[k] for k in ('inventory', 'workload', 'cleanup', 'health'))
assert reports['psi']['passed'] and inventory['metadata_read_success'] and not inventory['failures']
assert workload['passed'] and workload['runtime_acceptance'] and workload['native_returncode'] == 0
assert not workload['native_stderr'] and not workload['bpf_maps_manually_modified'] and not workload['bpf_programs_loaded_or_attached']
assert workload['inventory_sha256'] == evidence['inventory']['sha256']
assert workload['accepted_kernel_receipt_sha256'] == evidence['psi']['sha256']
assert cleanup['cleanup_passed'] and not cleanup['remaining']
assert cleanup['workload_result_sha256'] == evidence['workload']['sha256']
assert health['passed'] and all(health['checks'].values()) and not health['fatal_diagnostics']
assert sha(ROOT / 'scripts/probe_android16_bpf_rom_inventory.py') == inventory['runner_source_sha256']
assert sha(ROOT / 'scripts/probe_android16_bpf_rom_workload.py') == workload['runner_source_sha256']
programs = {row['id']: row for row in inventory['objects'] if row.get('kind') == 'program'}
queries = inventory['effective_cgroup_queries']
expected = {0, 1, 2, 8, 9, 10, 11, 14, 15, 19, 20, 21, 22}
assert {row['attach_type'] for row in queries} == expected and len(queries) == len(expected)
assert all(row['ok'] and row['effective'] and row['program_ids'] and
    all(pid in programs for pid in row['program_ids']) for row in queries)
assert {'prog_timeInState_tracepoint_sched_sched_switch', 'prog_timeInState_tracepoint_power_cpu_frequency',
        'prog_timeInState_tracepoint_sched_sched_process_free'} <= {Path(row['path']).name for row in programs.values()}
assert workload['uid_cpu_delta_ns'] >= workload['events'][0]['cpu_ns'] * 0.8
assert all(workload['network_delta'][k] >= 256 for k in ('rxPackets', 'txPackets'))
assert all(workload['network_delta'][k] >= 262144 for k in ('rxBytes', 'txBytes'))
for name, key in (('readonly', 'readonly_build_sha256'), ('workload', 'workload_build_sha256')):
    p = ART / ('runtime/android16-bpf-' + name + '-a16pf-20261005-build.json')
    report = load(p)
    assert sha(p) == workload[key] and report['completed']
    assert sha(ROOT / 'references/runtime-probes/android16-bpf' / ('bpf_rom_' + name + '.c')) == report['source_sha256']
    evidence[name + '-build'] = {'path': p.relative_to(ART).as_posix(), 'sha256': sha(p)}
lock_path = ROOT / 'references/android16-bpf-current-kernel/source-lock.json'
lock = load(lock_path)
for name, digest in lock['files'].items():
    assert sha(lock_path.parent / name) == digest
receipt = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'passed': True,
    'current_rom_bpf_accepted': True, **identity, 'boot_sha256': reports['psi']['boot_sha256'],
    'kernel_source_lock_sha256': sha(lock_path), 'evidence': evidence,
    'loaded_programs': inventory['program_count'], 'loaded_maps': inventory['map_count'],
    'actual_attached_netd_hooks': len(queries), 'uid_cpu_delta_ns': workload['uid_cpu_delta_ns'],
    'network_delta': workload['network_delta'], 'new_bpf_kernel_code_required': False,
    'scope': 'Current ROM actual loaded objects/effective netd attachments; UID timeInState accounting and IPv4/IPv6 bind/connect/sendmsg/recvmsg/get/setsockopt with loopback UID packet/byte accounting.',
    'limitations': workload['limitations'], 'complete_android16_desktop': 'paused by user'}
target.write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({'current_rom_bpf_accepted': True, 'programs': inventory['program_count'], 'maps': inventory['map_count'], 'report': str(target)}))
