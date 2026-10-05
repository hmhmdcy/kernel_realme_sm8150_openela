#!/usr/bin/env python3
"""Accept stage 3 only after all scoped results agree with the current boot."""
import datetime as dt
import hashlib
import json
import re
import shlex
from pathlib import Path
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root

ART = ROOT / 'artifacts/droidspaces'
RELEASE = '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp4'


def read(path): return json.loads(path.read_text(encoding='utf-8'))
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def source_sha(path): return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def main():
    destination = ART / 'native-cpu-cpuset-stage3-h2cp4-acceptance.json'
    runtime_result = ART / 'extensions-harden2-cpuset-stats-runtime-result.json'
    assert not destination.exists() and not runtime_result.exists()
    boot_path = ART / 'extensions-harden2-cpuset-stats-boot-result.json'
    boot = read(boot_path)
    identity = {key: boot[key] for key in ('kernel', 'boot_id')}
    assert identity['kernel'] == RELEASE and boot['running_config_matches']
    evidence = {}
    scoped = {}
    for tag in ('podman', 'statistics', 'android-scheduling', 'policy'):
        path = ART / ('native-' + tag + '-h2cp4-acceptance.json')
        value = read(path)
        assert value['passed'] and all(value[key] == expected for key, expected in identity.items()), tag
        scoped[tag] = value
        evidence[tag] = {'path': path.relative_to(ART).as_posix(), 'sha256': sha(path)}
        if tag != 'policy': assert value['boot_sha256'] == boot['boot_sha256']
        if 'result_path' in value:
            raw_path = ART / value['result_path']
            assert sha(raw_path) == value['result_sha256'], tag
            raw = read(raw_path)
            assert raw['end_identity'] == identity and raw['returncode'] == 0, tag
            assert raw['script_source_sha256'] == value['probe_sha256'], tag
        for entry in value.get('evidence', {}).values():
            raw_path = ART / entry['path']
            assert sha(raw_path) == entry['sha256'], tag
            raw = read(raw_path)
            assert raw['end_identity'] == identity and all(raw[key] == expected for key, expected in identity.items()), tag
            assert raw.get('returncode', 0) == 0, tag
            if 'source_sha256' in entry:
                assert raw['script_source_sha256'] == entry['source_sha256'], tag
    assert scoped['statistics']['boot_verification_sha256'] == sha(boot_path)
    assert scoped['policy']['cleanup_passed'] and scoped['policy']['normal_guest_seccomp'] == 2
    assert scoped['policy']['guest_restart_before'] != scoped['policy']['guest_restart_after']
    probes = [
        ('native-cpu-hierarchy-threads', 'probe_native_cpu_hierarchy_threads.sh', 'NATIVE_CPU_HIERARCHY_THREADED_PASS'),
        ('native-cgroup-systemd', 'probe_cgroup_systemd_compat.sh', 'CGROUP_SYSTEMD_COMPAT_PASS'),
        ('native-cpuset-hierarchy', 'probe_native_cpuset_hierarchy.sh', 'NATIVE_CPUSET_HIERARCHY_PASS'),
        ('native-cpu-cpuset-coexist-fork', 'probe_native_cpu_cpuset_coexist.sh', 'NATIVE_CPU_CPUSET_COEXIST_PASS'),
        ('native-legacy-cpu-weight-regression', 'probe_legacy_cpu_weight_regression.sh', 'LEGACY_CPU_WEIGHT_REGRESSION_PASS'),
        ('native-cpuset-hotplug-semantic', 'probe_native_cpuset_hotplug.py', 'NATIVE_CPUSET_HOTPLUG_PASS'),
    ]
    for tag, script, marker in probes:
        path = ART / 'runtime' / (tag + '-h2cp4-20261004.json')
        value = read(path)
        assert value['returncode'] == 0 and marker in value['stdout'], tag
        assert value['end_identity'] == identity and all(value[key] == expected for key, expected in identity.items()), tag
        assert value.get('script_source_sha256', value.get('source_sha256')) == source_sha(ROOT / 'scripts' / script), tag
        assert not value.get('cleanup_errors', []), tag
        if tag == 'native-cpuset-hotplug-semantic': assert value['passed'] and value['cpu_restored'] and value['online_after'] == '0-7'
        evidence[tag] = {'path': path.relative_to(ART).as_posix(), 'sha256': sha(path)}
    audit_path = ART / 'kernel-ext-harden2-cpuset-stats/audit.json'
    audit = read(audit_path)
    assert audit['build_audit_passed'] and not audit['config_changes'] and not audit['export_crc']['missing']
    assert sha(ART / 'kernel-ext-harden2-cpuset-stats/Image.gz-dtb') == audit['kernel_sha256']
    assert audit['generic_cgroup_core_unchanged_from_harden1']
    assert scoped['statistics']['build_audit_sha256'] == sha(audit_path)
    adb = device()
    assert read_identity(adb) == identity
    assert read_root(adb, 'sha256sum /dev/block/by-name/boot').decode().split()[0] == boot['boot_sha256']
    assert read_root(adb, 'getenforce').strip() == b'Enforcing'
    assert read_root(adb, 'cat /sys/devices/system/cpu/online').strip() == b'0-7'
    ksu = read_root(adb, '/data/adb/ksud debug info').decode()
    assert 'version: 33304' in ksu and 'uapi_version: 4' in ksu
    init = guest_info(adb)['pid']
    guest_root = '/proc/' + str(init) + '/root'
    assert re.search(r'^Seccomp:\s+2$', read_root(adb, 'cat ' + guest_root + '/proc/1/status').decode(), re.M)
    namespace = read_root(adb, 'readlink /proc/' + str(init) + '/ns/pid').decode().strip()
    assert namespace == scoped['policy']['guest_restart_after']
    for launcher in ('podman', 'podman-rootless'):
        assert not read_root(adb, shlex.join([DS, '--name=' + NAME, 'run', launcher, 'ps', '-aq'])).strip()
    assert not json.loads(read_root(adb, 'cat ' + guest_root + '/etc/rmx1931/resource-policies.json'))['profiles']
    fatal = read_root(adb, "dmesg | grep -E 'Kernel panic - not syncing|Oops:|BUG:|Unable to handle kernel|soft lockup' || true").decode()
    assert not fatal, fatal
    assert read_identity(adb) == identity
    result = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
        'passed': True, 'complete_stage_3_accepted': True, 'boot_sha256': boot['boot_sha256'],
        'scope': 'Native V2 CPU/cpuset, accounting, Podman parameters, legacy coexistence, Android profiles and native persistent-policy regression',
        'evidence': evidence, 'build_audit_sha256': sha(audit_path), 'boot_verification_sha256': sha(boot_path),
        'normal_guest_seccomp': 2, 'selinux': 'Enforcing', 'ksu_version': 33304, 'cpu_online': '0-7',
        'guest_pid': init, 'guest_pid_namespace': namespace, 'cleanup_passed': True, 'fatal_kernel_log': False,
        'android_v1_cpu_cpuset_retained': True, 'full_android_v2_migration_accepted': False,
        'limitations': ['Android regression covers actual Settings lifecycle and observable Power HAL boost; no performance gain claim',
            'Coexistence and legacy weight workers use an isolated unfiltered operator; ordinary workloads keep Seccomp=2'],
        'remaining_functional_stages': [4, 5, 6]}
    destination.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    runtime = {**boot, 'runtime_passed': True, 'acceptance_path': destination.name,
        'acceptance_sha256': sha(destination), 'original_boot_verification_sha256': sha(boot_path)}
    runtime_result.write_text(json.dumps(runtime, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'complete_stage_3_accepted': True, 'evidence_reports': len(evidence),
        'remaining_functional_stages': [4, 5, 6]}))


if __name__ == '__main__': main()
