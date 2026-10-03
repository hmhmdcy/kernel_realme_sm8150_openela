#!/usr/bin/env python3
"""Record reproducible build inputs and distinguish build readiness from phone acceptance."""
import datetime as dt
import hashlib
import json
from pathlib import Path
from deploy_kernel_extensions import STAGES, candidate, BASE_SHA
from device_runtime import device, read_root

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    builds = {}
    for stage in STAGES:
        image, check, audit, release = candidate(stage)
        directory = ART / f'kernel-ext-{stage}'
        builds[stage] = {'kernel_release': release, 'boot': image.relative_to(ROOT).as_posix(),
                         'boot_sha256': check['candidate_sha256'], 'kernel_sha256': audit['kernel_sha256'],
                         'config_sha256': audit['resolved_config_sha256'],
                         'module_symvers_sha256': audit['module_symvers_sha256'],
                         'system_map_sha256': audit['system_map_sha256'],
                         'config_changes': len(audit['config_changes']),
                         'existing_export_crc_preserved': audit['existing_export_crc_preserved'],
                         'changed_export_crcs': len(audit['export_crc']['changed']),
                         'audit_sha256': sha(directory / 'audit.json'),
                         'build_log_sha256': sha(directory / 'build.log'),
                         'build_passed': True, 'boot_packaging_passed': True,
                         'runtime_acceptance': 'pending'}
        result = ART / f'extensions-{stage}-acceptance.json'
        if result.exists():
            runtime = read(result)
            if runtime.get('runtime_passed') and runtime.get('boot_sha256') == check['candidate_sha256']:
                builds[stage]['runtime_acceptance'] = 'passed'
                builds[stage]['acceptance_sha256'] = sha(result)
        elif stage in ('checkpoint', 'network'):
            builds[stage]['runtime_acceptance'] = 'standalone not accepted; functionality verified in cumulative io image'
    paths = [ROOT / 'configs/kernel-extensions.json', ROOT / 'patches/nft-socket-4.14-compat.patch',
             ROOT / 'patches/criu3.19-gcc13-array-bound.patch', ART / 'criu-source-lock.txt']
    paths += list((ROOT / 'configs').glob('extensions-*.config'))
    paths += [ROOT / 'scripts' / name for name in (
        'audit_kernel_extensions.py', 'build_kernel_extensions.sh', 'prepare_kernel_extensions.py',
        'prepare_boot_candidate.py', 'inspect_kernel_dtb.py', 'crashlog.py', 'test_crashlog.py',
        'probe_kernel_extensions.sh', 'probe_extension_erofs.sh', 'probe_extension_lxc.sh',
        'probe_io_throttling.py', 'prepare_extension_tools.sh', 'prepare_extension_guest.sh',
        'build_extension_criu.sh', 'export_extension_criu.py', 'deploy_kernel_extensions.py',
        'record_kernel_extensions.py', 'device_runtime.py', 'start_podman_guest.py',
        'test_deploy_kernel_extensions.py', 'check_kernel_extensions_syntax.py')]
    paths += [ROOT / 'scripts' / name for name in ('check_kernel_extension_runtime.py',
        'record_extension_acceptance.py', 'reboot_extension_retention.py',
        'install_guest_podman_oom_wrapper.sh', 'probe_lowrisk_wifi.py',
        'prepare_guest_checkpoint.sh', 'probe_checkpoint_privileged.py')]
    paths += [p for p in (ROOT / 'packages/rmx1931-crashlog').iterdir() if p.is_file()]
    inputs = {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(paths)}
    lock = {'recorded_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'base_commit': '7c423d675865bd2642ae5f523d72c64dad5dcd2c',
            'accepted_base_lock_sha256': sha(ROOT / 'ksunext.sources.lock.json'),
            'accepted_boot_sha256': BASE_SHA, 'order': STAGES, 'inputs_sha256': inputs,
            'network_source_patch': read(ART / 'extensions-network-source.json'), 'builds': builds}
    (ROOT / 'kernel-extensions.sources.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
    evidence = {}
    for label, marker in {
        'extensions-qemu-explicit': '"explicit_qemu": true',
        'extensions-wireguard': '"peer_handshakes": [true, true]',
        'extensions-lxc3': 'LXC_CONTAINER_START_EXIT_PASS',
        'extensions-criu-build3': 'CRIU_NATIVE_ARM64_BUILD_PASS',
        'extensions-binfmt-autoreg-guard': 'masked',
        'extensions-module-inventory': '0 /proc/modules',
    }.items():
        path = ART / 'runtime' / (label + '.json')
        item = read(path)
        if item['returncode'] != 0 or marker not in item['stdout']:
            raise RuntimeError('Recorded baseline probe was not successful: ' + label)
        evidence[label] = {'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(path),
                           'observed_at': item['observed_at'], 'scope': 'original running KSU v3 baseline'}
    exports = sorted((ART / 'crashlog/private').glob('*/manifest.json'))
    export = read(exports[-1])
    if export['errors']:
        raise RuntimeError('Crash-log export is incomplete')
    retention_path = ART / 'crashlog/retention-utilities-pmsg-normal.json'
    retention = read(retention_path)
    if not retention['normal_reboot_retention_verified']:
        raise RuntimeError('Normal reboot pmsg retention evidence is incomplete')
    adb = device()
    installed = {}
    for name in ('module.prop', 'post-fs-data.sh', 'service.sh', 'collect.sh'):
        expected = hashlib.sha256((ROOT / 'packages/rmx1931-crashlog' / name).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
        actual = read_root(adb, 'sha256sum /data/adb/modules/rmx1931-crashlog/' + name).decode().split()[0]
        if expected != actual:
            raise RuntimeError('Installed collector differs: ' + name)
        installed[name] = actual
    accepted = read(ART / 'extensions-io-acceptance.json')
    if read_root(adb, 'uname -r').decode().strip() != accepted['kernel'] or not accepted['runtime_passed']:
        raise RuntimeError('Final accepted kernel is not currently running')
    readiness = {'recorded_at': lock['recorded_at'], 'builds': builds, 'baseline_runtime_evidence': evidence,
                 'current_kernel': accepted['kernel'], 'current_boot_sha256': accepted['boot_sha256'],
                 'current_acceptance_sha256': sha(ART / 'extensions-io-acceptance.json'),
                 'crashlog': {'installed_source_verified': True, 'installed_hashes': installed,
                              'export_files': len(export['files']), 'raw_pstore_records': export['pstore_records'],
                              'export_manifest': exports[-1].relative_to(ROOT).as_posix(),
                              'export_manifest_sha256': sha(exports[-1]),
                              'module_zip_sha256': sha(ART / 'crashlog/rmx1931-crashlog-1.1.zip'),
                              'normal_reboot_retention': 'passed; pmsg marker on utilities image',
                              'normal_retention_evidence_sha256': sha(retention_path), 'panic_retention': 'not triggered; unverified'},
                 'limitations': ['I/O changes 1033 existing export CRCs; old external modules require rebuilding',
                                 'Guest V2 io.max has not been made available',
                                 'LXC device BPF filtering was not verified',
                                 'BBR performance/battery and full-container CRIU restore were not certified'],
                 'deployment_authorization': read(ART / 'extensions-io-deployment.json')['authorization'],
                 'combined_deployment': True}
    (ART / 'extensions-readiness.json').write_text(json.dumps(readiness, indent=2) + '\n')
    print(json.dumps({'builds': len(builds), 'locked_inputs': len(inputs),
                      'new_kernel_runtime_acceptance': {k: v['runtime_acceptance'] for k, v in builds.items()},
                      'crashlog_export_files': len(export['files'])}))


if __name__ == '__main__':
    main()
