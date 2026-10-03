#!/usr/bin/env python3
"""Separate read-only preflight from authorized boot-only deployment and verification.

Reboot/flash phases must only be called after the human authorizes that stage.
Higher stages require the prior cumulative stage's real runtime acceptance.
I/O additionally requires explicit ABI-change authorization and no external modules.
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

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
STAGES = ['utilities', 'bbr', 'checkpoint', 'network', 'io']
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
    for field in ('original_roundtrip_byte_identical', 'ramdisk_preserved',
                  'non_kernel_header_fields_preserved', 'dtb_matches_original', 'avb_hash_verified'):
        if check.get(field) is not True:
            raise RuntimeError('Incomplete boot packaging: ' + field)
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
    if not re.fullmatch(r'4\.14\.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-' + stage, release):
        raise RuntimeError('Unexpected candidate kernel release: ' + release)
    if sha(BACKUP) != BASE_SHA or BACKUP.stat().st_size != CAPACITY:
        raise RuntimeError('Previously working rollback boot changed')
    return image, check, audit, release


def predecessor(stage):
    index = STAGES.index(stage)
    if not index:
        return BASE_KERNEL, BASE_SHA
    previous = STAGES[index - 1]
    _, check, _, release = candidate(previous)
    acceptance = read(ART / f'extensions-{previous}-acceptance.json')
    if (acceptance.get('runtime_passed') is not True or
            acceptance.get('boot_sha256') != check['candidate_sha256'] or
            acceptance.get('kernel') != release):
        raise RuntimeError('Previous stage lacks matching runtime acceptance')
    return release, check['candidate_sha256']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['preflight', 'reboot-bootloader', 'flash-reboot', 'verify'])
    parser.add_argument('--stage', choices=STAGES, required=True)
    parser.add_argument('--authorization', help='Exact human instruction authorizing this deployment')
    parser.add_argument('--allow-abi-change', action='store_true', help='Only after explicit I/O ABI-change authorization')
    parser.add_argument('--combined', action='store_true', help='Human explicitly requested one cumulative deployment; accept a matching verified earlier boot')
    args = parser.parse_args()
    image, check, audit, release = candidate(args.stage)
    report_path = ART / f'extensions-{args.stage}-deployment.json'
    incompatible = not audit['existing_export_crc_preserved']
    if incompatible and args.stage != 'io':
        raise RuntimeError('Unreviewed external module ABI change')
    if args.phase in ('reboot-bootloader', 'flash-reboot'):
        if not args.authorization or not args.authorization.strip():
            raise RuntimeError('Human deployment authorization must be recorded')
        if incompatible and not args.allow_abi_change:
            raise RuntimeError('I/O changes export CRCs; separate explicit ABI-change authorization required')
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
            raise RuntimeError('ABI-changing I/O candidate conflicts with external modules; rebuild them first')
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
        save(ART / f'extensions-{args.stage}-preflight.json', observed)
        print(json.dumps({key: observed[key] for key in ('stage', 'preflight_passed', 'battery_percent',
              'existing_export_crc_preserved', 'changed_existing_export_crcs', 'phase')}, ensure_ascii=False))
        if args.phase == 'preflight':
            return
        if report_path.exists():
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
        output = run(fastboot + ['flash', 'boot', str(image)], timeout=60)
        if "Writing 'boot'" not in output or output.count('OKAY') < 2:
            raise RuntimeError('Boot write not confirmed')
        report.update(flashed=True, phase='boot written', fastboot_output=output)
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
        print('EXTENSION_BOOT_VERIFIED (functional/hardware regression remains pending)')


if __name__ == '__main__':
    main()
