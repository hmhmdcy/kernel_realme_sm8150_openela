#!/usr/bin/env python3
"""Record stage 4 only after same-boot feature and affected-runtime proofs."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
from device_runtime import ROOT, device, guest_info, read_identity, read_root

ART = ROOT / 'artifacts/droidspaces'
STAGE = 'harden3-binfmt-fix'
RELEASE = '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h3bm2'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def rows(text):
    decoder = json.JSONDecoder()
    result = []
    for i, char in enumerate(text):
        if char != '{' or (i and text[i - 1] != '\n'):
            continue
        try:
            value, _ = decoder.raw_decode(text[i:])
            result.append(value)
        except ValueError:
            pass
    return result


def main():
    target = ART / 'binfmt-stage4-acceptance.json'
    assert not target.exists(), 'Do not overwrite joint acceptance'
    boot_path = ART / ('extensions-' + STAGE + '-boot-result.json')
    boot = read(boot_path)
    assert boot['kernel'] == RELEASE and boot['running_config_matches']
    identity = {k: boot[k] for k in ('kernel', 'boot_id')}
    predecessor = ART / 'native-cpu-cpuset-stage3-h2cp4-acceptance.json'
    assert read(predecessor)['complete_stage_3_accepted']
    audit_path = ART / ('kernel-ext-' + STAGE) / 'audit.json'
    audit = read(audit_path)
    assert audit['build_audit_passed'] and audit['generic_cgroup_core_unchanged_from_harden1']
    assert audit['walt_source_sha256'] == read(ART / 'kernel-ext-harden2-cpuset-stats/audit.json')['walt_source_sha256']
    evidence = {}

    def proof(name, label, source, marker):
        path = ART / 'runtime' / (label + '.json')
        data = read(path)
        assert all(data[k] == value for k, value in identity.items()), label
        assert data['end_identity'] == identity and data['returncode'] == 0, label
        assert not data.get('cleanup_errors'), label
        assert marker in data['stdout'], label
        content = (ROOT / source).read_bytes().replace(b'\r\n', b'\n')
        assert hashlib.sha256(content).hexdigest() == data['script_source_sha256'], label
        evidence[name] = {'path': path.relative_to(ART).as_posix(), 'sha256': sha(path),
                          'source_path': source, 'source_sha256': data['script_source_sha256']}
        return data

    prefix = 'scripts/'
    proof('filter-preservation', 'binfmt-seccomp-setresuid-h3bm2-20261004',
          prefix + 'probe_container_seccomp_setresuid.sh', 'CONTAINER_SECCOMP_SETRESUID_PASS')
    proof('namespace-isolation', 'binfmt-isolation-h3bm2-20261004',
          prefix + 'probe_binfmt_namespace_isolation.sh', 'BINFMT_NAMESPACE_ISOLATION_PASS')
    proof('stack-guard', 'binfmt-stack-guard-h3bm2-20261004',
          prefix + 'probe_binfmt_stack_guard.sh', 'BINFMT_STACK_GUARD_PASS')
    proof('ordinary-filtered-mount', 'binfmt-filtered-mount-h3bm2-20261004',
          prefix + 'probe_binfmt_filtered_mount.sh', 'BINFMT_FILTERED_MOUNT_PASS')
    proof('ordinary-crossarch', 'binfmt-crossarch-podman-filtered-h3bm2-20261004',
          'references/runtime-probes/binfmt-crossarch-attempt10-20261004/probe_binfmt_crossarch_podman.sh',
          'BINFMT_CROSSARCH_PODMAN_PASS')
    cross = proof('installed-crossarch-helper', 'binfmt-crossarch-helper-extents-h3bm2-20261004',
                  prefix + 'probe_binfmt_crossarch_podman.sh', 'BINFMT_CROSSARCH_PODMAN_PASS')
    summary = next(x for x in rows(cross['stdout']) if x.get('entry_mode') == 'helper')
    assert summary['passed'] and summary['entry_seccomp'] == summary['ordinary_guest_seccomp'] == 2
    assert summary['global_registration_sha256_before'] == summary['global_registration_sha256_after']
    assert {m['mode'] for m in summary['modes']} == {'rootful', 'rootless'}
    assert len({m['user_namespace'] for m in summary['modes']}) == 2
    for mode in summary['modes']:
        assert mode['passed'] and not mode['cleanup_errors'] and mode['local_revocation_returncode'] != 0
        assert mode['registry_after_revocation'] == ['register', 'status']
        assert set(mode['cases']) == {'amd64', 'arm64'}
        for arch, case in mode['cases'].items():
            assert case['image_architecture'] == arch
            for kind in ('build_payload', 'run_payload', 'nonroot_payload', 'runc_payload'):
                row = case[kind]
                assert row['architecture'] == arch and row['build_marker'] and row['seccomp'] == 2
                assert row['uid'] == row['gid'] == (1000 if kind == 'nonroot_payload' else 0)
    native = proof('native-cpu-cpuset', 'binfmt-native-cpu-regression-h3bm2-20261004',
                   prefix + 'probe_native_cpu_podman.sh', 'NATIVE_CPU_PODMAN_PASS')
    assert next(x for x in rows(native['stdout']) if 'modes' in x)['passed']
    for runtime in ('crun', 'runc'):
        proof('policy-' + runtime, 'binfmt-policy-' + runtime + '-regression-h3bm2-20261004',
              prefix + 'probe_resource_policy_smoke.sh', 'POLICY_FIRST_PAYLOAD_ROOTFUL_ROOTLESS_SMOKE_PASS')
    cpu = proof('policy-cpu', 'binfmt-policy-cpu-regression-h3bm2-20261004',
                prefix + 'probe_resource_policy_cpu_backend.sh', 'POLICY_CPU_BACKEND_PRESSURE_PASS')
    assert next(x for x in rows(cpu['stdout']) if 'modes' in x)['passed']
    prepare = proof('policy-lifecycle-prepare', 'binfmt-policy-lifecycle-prepare-h3bm2-20261004',
                    prefix + 'probe_resource_policy_lifecycle.sh', 'RESOURCE_POLICY_PREPARE_PASS')
    cleaned = proof('policy-lifecycle-cleanup', 'binfmt-policy-lifecycle-cleanup-h3bm2-20261004',
                    prefix + 'probe_resource_policy_lifecycle.sh', 'RESOURCE_POLICY_CLEANUP_PASS')
    lifecycle = next(x for x in rows(cleaned['stdout']) if 'prepare_passed' in x)
    assert lifecycle['prepare_passed'] and lifecycle['cleanup_passed']
    for mode in lifecycle['modes']:
        assert {'create', 'stop-start', 'recreate', 'after-oom', 'neighbor-after-oom'}.issubset(
            {s['phase'] for s in mode['snapshots']})
        assert mode['oom']['exec_exit'] == 137 and mode['oom']['container_exit'] == '137'

    install_path = ART / 'runtime/binfmt-helper-extents-upgrade-h3bm2-20261004.json'
    install = read(install_path)
    assert install['completed'] and install['end_identity'] == identity
    helper_sha = hashlib.sha256((ROOT / 'scripts/rmx1931_binfmt.py').read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    assert summary['helper_source_sha256'] == install['source_sha256'] == helper_sha
    evidence['helper-installation'] = {'path': install_path.relative_to(ART).as_posix(), 'sha256': sha(install_path)}
    adb = device()
    assert read_identity(adb) == identity
    assert read_root(adb, 'getenforce').strip() == b'Enforcing'
    assert read_root(adb, 'getprop sys.boot_completed').strip() == b'1'
    assert b'uid=0(root)' in read_root(adb, 'id')
    ksu = read_root(adb, '/data/adb/ksud debug info').decode()
    assert 'version: 33304' in ksu and 'uapi_version: 4' in ksu
    assert read_root(adb, 'cat /sys/devices/system/cpu/online').strip() == b'0-7'
    expected_config = (ART / ('kernel-ext-' + STAGE) / 'resolved.config').read_bytes()
    assert read_root(adb, 'zcat /proc/config.gz') == expected_config
    pid = guest_info(adb)['pid']
    root = '/proc/' + str(pid) + '/root'
    status = read_root(adb, 'cat /proc/' + str(pid) + '/status').decode()
    assert re.search(r'^Seccomp:\s+2$', status, re.M)
    assert read_root(adb, 'sha256sum ' + root + '/usr/local/bin/rmx1931-binfmt').decode().split()[0] == helper_sha
    profiles = json.loads(read_root(adb, 'cat ' + root + '/etc/rmx1931/resource-policies.json'))
    assert not profiles['profiles']
    leftovers = read_root(adb, 'find ' + root + '/var/lib/rmx1931-policy/containers -name "*.json"; '
                          'find ' + root + '/var/tmp -maxdepth 1 -type d -name "rmx1931-crossarch-*"; '
                          'find /sys/fs/cgroup/droidspaces/rmx1931-podman -maxdepth 1 -type d -name "privileged-binfmt*"; '
                          'printf "RMX1931_CLEANUP_READ_COMPLETE\\n"').decode()
    assert leftovers.strip() == 'RMX1931_CLEANUP_READ_COMPLETE', leftovers
    log = read_root(adb, 'printf "RMX1931_LOG_BEGIN\\n"; dmesg; printf "RMX1931_LOG_END\\n"').decode()
    assert log.startswith('RMX1931_LOG_BEGIN\n') and log.rstrip().endswith('RMX1931_LOG_END')
    assert not re.search(r'Kernel panic - not syncing|Oops:|BUG:|Unable to handle kernel|soft lockup', log)
    assert read_identity(adb) == identity
    receipt = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity, 'stage': STAGE,
               'passed': True, 'complete_stage_4_accepted': True, 'boot_sha256': boot['boot_sha256'],
               'build_audit_sha256': sha(audit_path), 'boot_verification_sha256': sha(boot_path),
               'predecessor_stage3_acceptance_sha256': sha(predecessor), 'evidence': evidence,
               'guest_pid': pid, 'normal_guest_seccomp': 2, 'selinux': 'Enforcing',
               'ksu_version': 33304, 'cpu_online': '0-7', 'cleanup_passed': True, 'fatal_kernel_log': False,
               'scope': 'Userns binfmt isolation and guarded lifetime; actual amd64/ARM64 OCI RUN/build; ordinary filtered guest foreground helper; affected native CPU/cpuset and policy lifecycle regression',
               'limitations': ['QEMU user-mode emulation', 'Foreground helper only; detached namespace lifetime needs a persistent service',
                               'VFS storage in user namespaces on this legacy overlayfs', 'Helper maps UIDs/GIDs 0..65535'],
               'remaining_functional_stages': [5, 6]}
    target.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    runtime = {**boot, 'runtime_passed': True, 'stage4_acceptance_sha256': sha(target),
               'boot_verification_sha256': sha(boot_path), 'scope': receipt['scope']}
    result = ART / ('extensions-' + STAGE + '-runtime-result.json')
    assert not result.exists()
    result.write_text(json.dumps(runtime, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'complete_stage_4_accepted': True, 'receipt_sha256': sha(target), 'evidence_reports': len(evidence)}))


if __name__ == '__main__':
    main()
