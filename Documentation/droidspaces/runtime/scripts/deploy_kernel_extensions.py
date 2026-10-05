#!/usr/bin/env python3
"""Separate read-only preflight from authorized boot-only deployment and verification.

Reboot/flash phases must only be called after the human authorizes that stage.
Higher stages require the prior cumulative stage's real runtime acceptance.
ABI changes additionally require explicit authorization and no external modules.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from device_runtime import device, read_root
from group_psi_boot import STAGE as PSI_STAGE, RECLAIM_STAGE as PSI_RECLAIM_STAGE, STAGES as PSI_STAGES, validate_header_change

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
STAGES = ['utilities', 'bbr', 'checkpoint', 'network', 'io', 'resources', 'dualio', 'harden1', 'harden2-cpuset', 'harden2-cpuset-fix', 'harden2-cpuset-decay', 'harden2-cpuset-stats', 'harden3-binfmt', 'harden3-binfmt-fix', 'harden4-seccomp-notify', 'harden5-binder-freeze', 'harden5-binder-freeze-fix']
STAGES.append(PSI_STAGE)
STAGES.append(PSI_RECLAIM_STAGE)
RELEASE_SUFFIX = {'harden2-cpuset': 'h2cp', 'harden2-cpuset-fix': 'h2cp2', 'harden2-cpuset-decay': 'h2cp3', 'harden2-cpuset-stats': 'h2cp4', 'harden3-binfmt': 'h3bm', 'harden3-binfmt-fix': 'h3bm2', 'harden4-seccomp-notify': 'h4sn', 'harden5-binder-freeze': 'h5bf', 'harden5-binder-freeze-fix': 'h5bf2'}  # UTS_RELEASE must fit in 64 characters.
RELEASE_SUFFIX[PSI_STAGE] = 'a16ps'
RELEASE_SUFFIX[PSI_RECLAIM_STAGE] = 'a16pf'
REPAIRS = {'harden2-cpuset-fix': 'harden2-cpuset', 'harden2-cpuset-decay': 'harden2-cpuset-fix', 'harden2-cpuset-stats': 'harden2-cpuset-decay', 'harden3-binfmt-fix': 'harden3-binfmt', 'harden5-binder-freeze-fix': 'harden5-binder-freeze'}
REPAIRS[PSI_RECLAIM_STAGE] = PSI_STAGE
REPAIR_FAILURES = {
    'harden2-cpuset-fix': 'runtime/native-cpu-podman-debug-h2cp-20261004.json',
    'harden2-cpuset-decay': 'runtime/native-cpu-podman-h2cp2-20261004.json',
    'harden2-cpuset-stats': 'runtime/native-cpu-stat-settled-semantics-h2cp3-20261004.json',
    'harden3-binfmt-fix': 'runtime/binfmt-seccomp-setresuid-baseline-h3bm-20261004.json',
    'harden5-binder-freeze-fix': 'runtime/binder-public-api3-h5bf-20261005.json',
}
REPAIR_FAILURE_MARKERS = {'harden2-cpuset-stats': 'NATIVE_CPU_STAT_CONSISTENCY_FAILED', 'harden3-binfmt-fix': 'BINFMT_SECCOMP_PRESERVATION_FAILED', 'harden5-binder-freeze-fix': 'new kernel must support public callback'}
BASE_KERNEL = '4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2-lr2-ksu3'
BASE_SHA = '9588a95055bf35ced553297541a4e703b038451dcdfa775281b1f8c9f7a0bc58'
BACKUP = ART / 'boot-images/RMX1931CN-crDroid16-DroidSpaces-v6.6.0-Podman2-LowRisk2-KSUNext3/boot.img'
CAPACITY = 100663296


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def run(argv, timeout=45):
    result = subprocess.run(argv, capture_output=True, timeout=timeout)
    output = (result.stdout + result.stderr).decode(errors='replace').strip()
    if result.returncode:
        raise RuntimeError(output)
    return output


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def candidate(stage):
    check = read(ART / f'boot-images/ext-{stage}-candidate-check.json')
    # Packaging records originated on Windows; remain usable from Linux tools.
    image = (ROOT / check['candidate'].replace('\\', '/')).resolve()
    if not image.is_relative_to(ART.resolve()) or image.is_symlink():
        raise RuntimeError('Candidate path escaped artifact directory')
    audit = read(ART / f'kernel-ext-{stage}/audit.json')
    if stage == PSI_RECLAIM_STAGE and not audit.get('existing_export_crc_preserved'):
        from audit_group_psi_reclaim_fix import validate_abi_review
        if validate_abi_review(audit) != audit.get('abi_review_sha256'):
            raise RuntimeError('PSI repair ABI review changed')
    header_field = 'non_kernel_header_fields_except_psi_cmdline_preserved' if stage in PSI_STAGES else 'non_kernel_header_fields_preserved'
    for field in ('original_roundtrip_byte_identical', 'ramdisk_preserved',
                  header_field, 'dtb_matches_original', 'avb_hash_verified'):
        if check.get(field) is not True:
            raise RuntimeError('Incomplete boot packaging: ' + field)
    if stage in PSI_STAGES:
        original = (ROOT / check['original_backup'].replace('\\', '/')).resolve()
        if (not original.is_relative_to(ROOT / 'artifacts/device-root') or original.is_symlink() or
                sha(original) != check['original_boot_sha256'] or
                check.get('non_kernel_header_fields_preserved') is not False or
                validate_header_change(original.read_bytes(), image.read_bytes()) != check.get('psi_cmdline_change') or
                audit['config_changes'] != {'CONFIG_CMDLINE': {'before': '"cgroup_disable=pressure"', 'after': '"psi=1"'}}):
            raise RuntimeError('PSI-specific header/config audit changed')
    if sha(image) != check['candidate_sha256'] or image.stat().st_size != CAPACITY:
        raise RuntimeError('Candidate boot changed after packaging')
    directory = ART / f'kernel-ext-{stage}'
    if (not audit.get('build_audit_passed') or
            sha(directory / 'Image.gz-dtb') != audit['kernel_sha256'] or
            sha(directory / 'resolved.config') != audit['resolved_config_sha256'] or
            sha(directory / 'Module.symvers') != audit['module_symvers_sha256'] or
            sha(directory / 'System.map') != audit['system_map_sha256'] or
            check['candidate_kernel_sha256'] != audit['kernel_sha256']):
        raise RuntimeError('Kernel/config audit is stale or failed')
    release = (directory / 'kernel.release').read_text().strip()
    if not re.fullmatch(r'4\.14\.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-' + RELEASE_SUFFIX.get(stage, stage), release):
        raise RuntimeError('Unexpected candidate kernel release: ' + release)
    if sha(BACKUP) != BASE_SHA or BACKUP.stat().st_size != CAPACITY:
        raise RuntimeError('Previously working rollback boot changed')
    return image, check, audit, release


def predecessor(stage):
    if stage == PSI_RECLAIM_STAGE:
        # Repair this deployed PSI iteration; it did not pass full acceptance.
        # Keep the accepted h5bf2 chain and bind the exact a16ps full failure.
        from audit_group_psi_reclaim_fix import provenance
        _, _, bindings = provenance()
        predecessor(PSI_STAGE)
        _, packed, _, release = candidate(PSI_STAGE)
        boot = read(ART / f'extensions-{PSI_STAGE}-boot-result.json')
        source = read(ART / f'kernel-ext-{stage}/source.json')
        if (any(source.get(key) != value for key, value in bindings.items()) or
                source.get('iteration_baseline_runtime_accepted') is not False or
                boot.get('kernel') != release or boot.get('boot_sha256') != packed['candidate_sha256']):
            raise RuntimeError('PSI repair baseline/failure or accepted predecessor chain changed')
        return release, packed['candidate_sha256']
    if stage in REPAIRS:
        # Repair the current functional stage, rather than advance past its
        # failing acceptance. Require both a verified boot and its real failure.
        previous = REPAIRS[stage]
        _, packed, _, release = candidate(previous)
        boot = read(ART / f'extensions-{previous}-boot-result.json')
        failure = read(ART / REPAIR_FAILURES[stage])
        if stage == 'harden5-binder-freeze-fix':
            raw = read(ART / 'runtime/binder-freeze-callbacks2-h5bf-20261005.json')
            if (failure.get('cleanup_errors') or not all(failure.get('owned_pids_removed', {}).values()) or
                    set(failure.get('owned_pids_removed', {})) != {'service', 'listener'} or
                    raw.get('returncode') != 0 or raw.get('end_identity') != failure.get('end_identity') or
                    'BINDER_FREEZE_CALLBACKS_PASS cases=14' not in raw.get('stdout', '') or
                    raw.get('fixture_mount_directory_removed') is not True):
                raise RuntimeError('Binder discovery repair requires native callbacks and clean public-API failure')
        if (boot.get('running_config_matches') is not True or boot.get('kernel') != release or
                boot.get('boot_sha256') != packed['candidate_sha256'] or
                failure.get('returncode') != 1 or failure.get('kernel') != release or
                failure.get('end_identity') != {'kernel': release, 'boot_id': failure.get('boot_id')} or
                REPAIR_FAILURE_MARKERS.get(stage, 'weight-competition') not in (failure.get('stdout', '') + failure.get('listener_stderr', ''))):
            raise RuntimeError('Repair requires verified predecessor boot and matching real failure')
        return release, packed['candidate_sha256']
    index = STAGES.index(stage)
    if not index:
        return BASE_KERNEL, BASE_SHA
    previous = STAGES[index - 1]
    _, check, _, release = candidate(previous)
    if previous == 'harden5-binder-freeze-fix':
        boot_path = ART / f'extensions-{previous}-boot-result.json'
        boot = read(boot_path)
        runtime = read(ART / f'extensions-{previous}-runtime-result.json')
        receipt_path = ART / 'binder-freeze-acceptance.json'
        receipt = read(receipt_path)
        if (runtime.get('runtime_passed') is not True or runtime.get('binder_freeze_callbacks_accepted') is not True or
                runtime.get('boot_verification_sha256') != sha(boot_path) or
                runtime.get('binder_acceptance_sha256') != sha(receipt_path) or
                receipt.get('passed') is not True or receipt.get('binder_freeze_callbacks_accepted') is not True or
                receipt.get('boot_verification_sha256') != sha(boot_path) or
                receipt.get('build_audit_sha256') != sha(ART / f'kernel-ext-{previous}/audit.json') or
                any(row.get('kernel') != release or row.get('boot_id') != boot.get('boot_id') or
                    row.get('boot_sha256') != check['candidate_sha256'] for row in (runtime, receipt)) or
                set(receipt.get('evidence', {})) != {'native-callbacks-and-features', 'android16-public-api',
                    'filter-preservation', 'native-cpu-cpuset', 'policy-crun', 'policy-runc', 'host-health'}):
            raise RuntimeError('Previous stage lacks complete Binder joint acceptance')
        for evidence in receipt['evidence'].values():
            path = (ART / evidence['path']).resolve()
            if not path.is_relative_to(ART.resolve()) or path.is_symlink() or sha(path) != evidence['sha256']:
                raise RuntimeError('Previous Binder evidence changed')
        return release, check['candidate_sha256']
    if previous == 'harden4-seccomp-notify':
        boot_path = ART / f'extensions-{previous}-boot-result.json'
        boot = read(boot_path)
        runtime = read(ART / f'extensions-{previous}-runtime-result.json')
        receipt_path = ART / 'seccomp-notify-stage5-acceptance.json'
        receipt = read(receipt_path)
        if (runtime.get('runtime_passed') is not True or
                runtime.get('kernel') != release or runtime.get('boot_id') != boot.get('boot_id') or
                runtime.get('boot_sha256') != check['candidate_sha256'] or
                runtime.get('boot_verification_sha256') != sha(boot_path) or
                runtime.get('stage5_acceptance_sha256') != sha(receipt_path) or
                receipt.get('passed') is not True or receipt.get('complete_stage_5_accepted') is not True or
                receipt.get('kernel') != release or receipt.get('boot_id') != boot.get('boot_id') or
                receipt.get('boot_sha256') != check['candidate_sha256'] or
                receipt.get('boot_verification_sha256') != sha(boot_path) or
                receipt.get('build_audit_sha256') != sha(ART / f'kernel-ext-{previous}/audit.json') or
                set(receipt.get('evidence', {})) != {'upstream-selftests', 'crun-broker',
                    'installed-broker-target-binding', 'filter-preservation', 'native-cpu-cpuset',
                    'crossarch', 'policy-crun', 'policy-runc', 'policy-cpu', 'broker-installation'}):
            raise RuntimeError('Previous stage lacks complete stage 5 joint acceptance')
        for evidence in receipt['evidence'].values():
            path = (ART / evidence['path']).resolve()
            if not path.is_relative_to(ART.resolve()) or path.is_symlink() or sha(path) != evidence['sha256']:
                raise RuntimeError('Previous stage joint evidence changed')
        return release, check['candidate_sha256']
    if previous == 'harden3-binfmt-fix':
        # Stage 4 hashes its immutable boot-only proof. Use the independent
        # accepted runtime record and validate every joint evidence digest.
        boot_path = ART / f'extensions-{previous}-boot-result.json'
        boot = read(boot_path)
        runtime = read(ART / f'extensions-{previous}-runtime-result.json')
        receipt_path = ART / 'binfmt-stage4-acceptance.json'
        receipt = read(receipt_path)
        if (runtime.get('runtime_passed') is not True or
                runtime.get('kernel') != release or runtime.get('boot_id') != boot.get('boot_id') or
                runtime.get('boot_sha256') != check['candidate_sha256'] or
                runtime.get('boot_verification_sha256') != sha(boot_path) or
                runtime.get('stage4_acceptance_sha256') != sha(receipt_path) or
                receipt.get('passed') is not True or receipt.get('complete_stage_4_accepted') is not True or
                receipt.get('kernel') != release or receipt.get('boot_id') != boot.get('boot_id') or
                receipt.get('boot_sha256') != check['candidate_sha256'] or
                receipt.get('boot_verification_sha256') != sha(boot_path) or
                receipt.get('build_audit_sha256') != sha(ART / f'kernel-ext-{previous}/audit.json') or
                set(receipt.get('evidence', {})) != {'filter-preservation','namespace-isolation',
                    'stack-guard','ordinary-filtered-mount','ordinary-crossarch','installed-crossarch-helper',
                    'native-cpu-cpuset','policy-crun','policy-runc','policy-cpu','policy-lifecycle-prepare',
                    'policy-lifecycle-cleanup','helper-installation'}):
            raise RuntimeError('Previous stage lacks complete stage 4 joint acceptance')
        for evidence in receipt['evidence'].values():
            path = (ART / evidence['path']).resolve()
            if not path.is_relative_to(ART.resolve()) or path.is_symlink() or sha(path) != evidence['sha256']:
                raise RuntimeError('Previous stage joint evidence changed')
        return release, check['candidate_sha256']
    if previous == 'harden2-cpuset-stats':
        # The boot-only result is immutable because existing scoped receipts
        # hash it. Advance only through the separately sealed joint acceptance.
        boot_path = ART / f'extensions-{previous}-boot-result.json'
        runtime = read(ART / f'extensions-{previous}-runtime-result.json')
        boot = read(boot_path)
        receipt_path = (ART / runtime['acceptance_path']).resolve()
        if (not receipt_path.is_relative_to(ART.resolve()) or receipt_path.is_symlink() or
                runtime.get('runtime_passed') is not True or
                runtime.get('kernel') != release or runtime.get('boot_sha256') != check['candidate_sha256'] or
                runtime.get('boot_id') != boot.get('boot_id') or
                runtime.get('original_boot_verification_sha256') != sha(boot_path) or
                runtime.get('acceptance_sha256') != sha(receipt_path)):
            raise RuntimeError('Previous stage lacks matching joint runtime acceptance')
        receipt = read(receipt_path)
        if (receipt.get('passed') is not True or receipt.get('complete_stage_3_accepted') is not True or
                receipt.get('kernel') != release or receipt.get('boot_sha256') != check['candidate_sha256'] or
                receipt.get('boot_id') != boot.get('boot_id') or
                receipt.get('boot_verification_sha256') != sha(boot_path) or
                receipt.get('build_audit_sha256') != sha(ART / f'kernel-ext-{previous}/audit.json') or
                set(receipt.get('evidence', {})) != {'podman', 'statistics', 'android-scheduling', 'policy',
                    'native-cpu-hierarchy-threads', 'native-cgroup-systemd', 'native-cpuset-hierarchy',
                    'native-cpu-cpuset-coexist-fork', 'native-legacy-cpu-weight-regression', 'native-cpuset-hotplug-semantic'}):
            raise RuntimeError('Previous stage lacks complete stage 3 joint acceptance')
        for evidence in receipt['evidence'].values():
            path = (ART / evidence['path']).resolve()
            if not path.is_relative_to(ART.resolve()) or path.is_symlink() or sha(path) != evidence['sha256']:
                raise RuntimeError('Previous stage joint evidence changed')
        return release, check['candidate_sha256']
    acceptance_path = ART / f'extensions-{previous}-acceptance.json'
    if previous == 'dualio' and not acceptance_path.exists():
        acceptance_path = ART / 'extensions-dualio-postpanic20261004-acceptance.json'
    acceptance = read(acceptance_path)
    if (acceptance.get('runtime_passed') is not True or
            acceptance.get('boot_sha256') != check['candidate_sha256'] or
            acceptance.get('kernel') != release):
        raise RuntimeError('Previous stage lacks matching runtime acceptance')
    return release, check['candidate_sha256']


def archive_failed_deployment(report_path, observed):
    """Resume only after Android proves the prior boot is still unchanged."""
    previous = read(report_path)
    if (previous.get('phase') != 'flash failed; inspect device before retry' or
            previous.get('flashed') is not False or previous.get('boot_write_confirmed') is not False or
            not previous.get('preflight_passed') or not previous.get('bootloader_reboot_sent') or
            not previous.get('last_flash_error') or
            any(previous.get(key) != observed[key] for key in
                ('stage', 'candidate_sha256', 'kernel', 'boot_sha256', 'transport_id_sha256'))):
        raise RuntimeError('Failed deployment cannot resume from this device/boot/candidate state')
    directory = ART / 'deployment-attempts' / observed['stage']
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / (dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.json')
    content = report_path.read_bytes()
    with archive.open('xb') as stream:
        stream.write(content)
    assert archive.read_bytes() == content
    return previous.get('previous_failed_deployments', []) + [archive.relative_to(ROOT).as_posix()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['preflight', 'reboot-bootloader', 'flash-reboot', 'verify'])
    parser.add_argument('--stage', choices=STAGES, required=True)
    parser.add_argument('--authorization', help='Exact human instruction authorizing this deployment')
    parser.add_argument('--allow-abi-change', action='store_true', help='Only after explicit ABI-change authorization')
    parser.add_argument('--combined', action='store_true', help='Human explicitly requested one cumulative deployment; accept a matching verified earlier boot')
    parser.add_argument('--resume-failed-deployment', action='store_true', help='After rechecking Android, archive a failed transfer and restart its deployment')
    parser.add_argument('--fastboot-serial', help='Previously observed target serial; flash directly after matching the Android preflight identity')
    args = parser.parse_args()
    if args.resume_failed_deployment and args.phase != 'reboot-bootloader':
        raise RuntimeError('Failed deployment resumes only from the Android preflight phase')
    if args.fastboot_serial and args.phase != 'flash-reboot':
        raise RuntimeError('Pinned fastboot serial is only valid for the flash phase')
    image, check, audit, release = candidate(args.stage)
    report_path = ART / f'extensions-{args.stage}-deployment.json'
    incompatible = not audit['existing_export_crc_preserved']
    if incompatible and args.stage not in {'io', 'resources', 'dualio', 'harden1', 'harden2-cpuset', 'harden2-cpuset-fix', 'harden2-cpuset-decay', 'harden2-cpuset-stats', 'harden3-binfmt', 'harden3-binfmt-fix', PSI_RECLAIM_STAGE}:
        raise RuntimeError('Unreviewed external module ABI change')
    if args.phase in ('reboot-bootloader', 'flash-reboot'):
        if not args.authorization or not args.authorization.strip():
            raise RuntimeError('Human deployment authorization must be recorded')
        if incompatible and not args.allow_abi_change:
            raise RuntimeError('Candidate changes export CRCs; explicit ABI-change authorization required')
    if args.phase in ('preflight', 'reboot-bootloader'):
        adb = device()
        root = lambda text: read_root(adb, text).decode().strip()
        if args.combined:
            current_release = root('uname -r')
            current_sha = root('sha256sum /dev/block/by-name/boot').split()[0]
            known = [(BASE_KERNEL, BASE_SHA)]
            for previous in STAGES[:STAGES.index(args.stage)]:
                path = ART / f'extensions-{previous}-boot-result.json'
                if path.exists():
                    old = read(path)
                    _, packed, _, old_release = candidate(previous)
                    if old.get('running_config_matches') and old['kernel'] == old_release and old['boot_sha256'] == packed['candidate_sha256']:
                        known.append((old_release, old['boot_sha256']))
            if (current_release, current_sha) not in known:
                raise RuntimeError('Combined deployment still requires a matching previously verified boot')
            expected_release, expected_sha = current_release, current_sha
        else:
            expected_release, expected_sha = predecessor(args.stage)
        observed = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                    'kernel': root('uname -r'), 'boot_completed': root('getprop sys.boot_completed'),
                    'selinux': root('getenforce'), 'root': root('id'),
                    'boot_sha256': root('sha256sum /dev/block/by-name/boot').split()[0],
                    'ksu': root('/data/adb/ksud debug info'),
                    'loaded_modules': root('cat /proc/modules'),
                    'available_external_modules': root('set -e; for d in /vendor/lib/modules /odm/lib/modules '
                        '/system/lib/modules /vendor_dlkm/lib/modules /odm_dlkm/lib/modules '
                        '/system_dlkm/lib/modules /data/adb/modules; do if test -d "$d"; then '
                        'find "$d" -type f -name "*.ko"; fi; done'),
                    'transport_id_sha256': hashlib.sha256(adb[-1].encode()).hexdigest()}
        battery = root('dumpsys battery')
        observed['battery_percent'] = int(re.search(r'\blevel: (\d+)', battery)[1])
        if (observed['kernel'] != expected_release or observed['boot_sha256'] != expected_sha or
                observed['boot_completed'] != '1' or observed['selinux'] != 'Enforcing' or
                'uid=0(root)' not in observed['root'] or observed['battery_percent'] < 50 or
                'version: 33304' not in observed['ksu'] or 'uapi_version: 4' not in observed['ksu']):
            raise RuntimeError('Preflight device state does not match the accepted predecessor')
        if incompatible and (observed['loaded_modules'] or observed['available_external_modules']):
            raise RuntimeError('ABI-changing candidate conflicts with external modules; rebuild them first')
        # Verify the exact installed collector, rather than just a module name.
        for name in ('module.prop', 'post-fs-data.sh', 'service.sh', 'collect.sh'):
            expected = hashlib.sha256((ROOT / 'packages/rmx1931-crashlog' / name).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
            if root('sha256sum /data/adb/modules/rmx1931-crashlog/' + name).split()[0] != expected:
                raise RuntimeError('Installed crash collector changed')
        root('test ! -e /data/adb/modules/rmx1931-crashlog/disable')
        observed.update(preflight_passed=True, stage=args.stage, candidate_sha256=check['candidate_sha256'],
                        rollback_sha256=BASE_SHA, existing_export_crc_preserved=not incompatible,
                        combined_deployment=args.combined,
                        changed_existing_export_crcs=len(audit['export_crc']['changed']),
                        phase='read-only preflight', flashed=False)
        if args.stage in REPAIRS:
            observed.update(repairs_stage=REPAIRS[args.stage], predecessor_functional_acceptance=False,
                            same_functional_stage_repair=True)
        save(ART / f'extensions-{args.stage}-preflight.json', observed)
        print(json.dumps({key: observed[key] for key in ('stage', 'preflight_passed', 'battery_percent',
              'existing_export_crc_preserved', 'changed_existing_export_crcs', 'phase')}, ensure_ascii=False))
        if args.phase == 'preflight':
            return
        if args.resume_failed_deployment:
            if not report_path.exists():
                raise RuntimeError('No failed deployment record to resume')
            observed['previous_failed_deployments'] = archive_failed_deployment(report_path, observed)
        elif report_path.exists():
            raise RuntimeError('Deployment record already exists; inspect before another write')
        root('! grep -q /mnt/Droidspaces/rmx1931-podman /proc/mounts')
        # Record a normal-reboot retention marker before the authorized reboot.
        subprocess.run([sys.executable, str(ROOT / 'scripts/crashlog.py'), 'mark',
                        '--reset-path', 'bootloader', '--test-name', args.stage + '-bootloader'], check=True)
        observed.update(authorization=args.authorization, phase='bootloader reboot', bootloader_reboot_sent=False)
        save(report_path, observed)
        run(adb + ['exec-out', 'su', '-c', 'sync; /system/bin/reboot bootloader'])
        observed['bootloader_reboot_sent'] = True
        save(report_path, observed)
    elif args.phase == 'flash-reboot':
        report = read(report_path)
        if (not report.get('preflight_passed') or not report.get('bootloader_reboot_sent') or
                report.get('flashed') or report['candidate_sha256'] != check['candidate_sha256']):
            raise RuntimeError('Unexpected deployment phase or candidate drift')
        fastboot = [str(ROOT / 'tools/platform-tools/fastboot.exe')]
        if args.fastboot_serial:
            serial = args.fastboot_serial
            if not re.fullmatch(r'[A-Za-z0-9._-]+', serial):
                raise RuntimeError('Invalid pinned fastboot serial')
            if hashlib.sha256(serial.encode()).hexdigest() != report['transport_id_sha256']:
                raise RuntimeError('Fastboot target differs from checked ADB target')
            # The human has already observed this target in fastboot. Extra
            # enumeration/getvar requests destabilized this Windows transport.
            fastboot += ['-s', serial]
            report['flash_transport'] = 'previously verified serial; no extra enumeration'
        else:
            rows = [row.split() for row in run(fastboot + ['devices']).splitlines()]
            if len(rows) != 1 or len(rows[0]) != 2 or rows[0][1] != 'fastboot':
                raise RuntimeError('Exactly one fastboot target required')
            if hashlib.sha256(rows[0][0].encode()).hexdigest() != report['transport_id_sha256']:
                raise RuntimeError('Fastboot target differs from checked ADB target')
            fastboot += ['-s', rows[0][0]]
            product = run(fastboot + ['getvar', 'product'])
            unlocked = run(fastboot + ['getvar', 'unlocked']).lower()
            size = run(fastboot + ['getvar', 'partition-size:boot'])
            if 'product: msmnile' not in product or not any(s in unlocked for s in ('unlocked: yes', 'unlocked: true')):
                raise RuntimeError('Unexpected bootloader identity or lock state')
            if int(re.search(r'partition-size:boot:\s*(0x[0-9a-fA-F]+)', size)[1], 16) != CAPACITY:
                raise RuntimeError('Boot partition capacity changed')
        try:
            output = run(fastboot + ['flash', 'boot', str(image)], timeout=60)
        except RuntimeError as error:
            # A terminal fastboot error requires device inspection, not an
            # automatic replay or a claim that the partition was written.
            report.update(phase='flash failed; inspect device before retry',
                          last_flash_error=str(error), boot_write_confirmed=False)
            save(report_path, report)
            raise
        if "Writing 'boot'" not in output or output.count('OKAY') < 2:
            raise RuntimeError('Boot write not confirmed')
        report.update(flashed=True, boot_write_confirmed=True, phase='boot written', fastboot_output=output)
        save(report_path, report)
        run(fastboot + ['reboot'])
        report['android_reboot_sent'] = True
        save(report_path, report)
        print('EXTENSION_BOOT_FLASHED_ANDROID_REBOOT_SENT')
    else:
        adb = device()
        root = lambda text: read_root(adb, text).decode().strip()
        observed = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'stage': args.stage,
                    'kernel': root('uname -r'), 'boot_completed': root('getprop sys.boot_completed'),
                    'boot_id': root('cat /proc/sys/kernel/random/boot_id'),
                    'root': root('id'), 'selinux': root('getenforce'),
                    'boot_sha256': root('sha256sum /dev/block/by-name/boot').split()[0],
                    'kernel_ksu': root('/data/adb/ksud debug info'), 'runtime_passed': False}
        if (observed['kernel'] != release or observed['boot_sha256'] != check['candidate_sha256'] or
                observed['boot_completed'] != '1' or observed['selinux'] != 'Enforcing' or
                'uid=0(root)' not in observed['root'] or 'version: 33304' not in observed['kernel_ksu'] or
                'uapi_version: 4' not in observed['kernel_ksu']):
            raise RuntimeError('Candidate boot validation failed')
        actual = read_root(adb, 'cat /proc/config.gz', timeout=20)
        import gzip
        if gzip.decompress(actual).replace(b'\r\n', b'\n') != (ART / f'kernel-ext-{args.stage}/resolved.config').read_bytes().replace(b'\r\n', b'\n'):
            raise RuntimeError('Running kernel config differs from built config')
        observed['running_config_matches'] = True
        save(ART / f'extensions-{args.stage}-boot-result.json', observed)
        print('EXTENSION_BOOT_VERIFIED (kernel/container functional regression remains pending)')


if __name__ == '__main__':
    main()
