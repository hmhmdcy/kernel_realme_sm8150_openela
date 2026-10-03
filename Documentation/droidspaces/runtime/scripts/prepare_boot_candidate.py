#!/usr/bin/env python3
"""Repack the verified original boot with the candidate kernel using AOSP tools.

Require a byte-identical original round trip before preparing a test image.
Rebuild the existing unsigned AVB hash footer; never flash or reboot a phone.
"""
import hashlib
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'artifacts/droidspaces'
MKBOOTIMG = ROOT / 'references/mkbootimg'
AVB = ROOT / 'references/avb'
TOOLS = {MKBOOTIMG: '808ecd09666ffe0ff5800f02af693abce56eb395',
         AVB: '5ac0c3a071d811846a62412383dd6e259f341e6e'}
sys.path.insert(0, str(AVB))
import avbtool


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(script, *args):
    environment = {**os.environ, 'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8'}
    result = subprocess.run([sys.executable, str(script), *map(str, args)],
                            capture_output=True, env=environment)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace'))
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variant', choices=['droidspaces', 'podman', 'podman2', 'lowrisk', 'ksunext',
                        'ext-utilities', 'ext-bbr', 'ext-checkpoint', 'ext-network', 'ext-io'], default='droidspaces')
    variant = parser.parse_args().variant
    for directory, revision in TOOLS.items():
        actual = subprocess.check_output(['git', '-C', str(directory), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != revision:
            raise RuntimeError('AOSP tool version differs from the reviewed version')
    name = (ROOT / 'artifacts/device-root/LATEST.txt').read_text().strip()
    backup = ROOT / 'artifacts/device-root' / name
    record = json.loads((backup / 'summary.json').read_text())['partitions']['boot']
    original = backup / 'boot.img'
    if digest(original) != record['sha256'] or original.stat().st_size != record['capacity_bytes']:
        raise RuntimeError('Original boot no longer matches the verified backup')
    run(AVB / 'avbtool.py', 'verify_image', '--image', original)
    image = avbtool.ImageHandler(str(original), read_only=True)
    footer, header, descriptors, _ = avbtool.Avb()._parse_image(image)
    if not footer or header.algorithm_type != 0:
        raise RuntimeError('This workflow requires the observed unsigned AVB boot footer')
    hashes = [d for d in descriptors if isinstance(d, avbtool.AvbHashDescriptor)]
    props = [d for d in descriptors if isinstance(d, avbtool.AvbPropertyDescriptor)]
    if len(hashes) != 1 or hashes[0].partition_name != 'boot' or len(descriptors) != len(props) + 1:
        raise RuntimeError('Unexpected original AVB descriptors require review')
    hash_descriptor = hashes[0]
    if hash_descriptor.flags not in {0, 1}:
        raise RuntimeError('Unknown AVB hash flags')
    unpack = DIRECTORY / 'original-boot'
    raw_args = run(MKBOOTIMG / 'unpack_bootimg.py', '--boot_img', original,
                   '--out', unpack, '--format=mkbootimg', '-0')
    if not raw_args.endswith(b'\0'):
        raise RuntimeError('AOSP unpacker did not return a terminated argument list')
    # Empty values, including --board, must be preserved as real arguments.
    args = [item.decode() for item in raw_args.split(b'\0')[:-1]]
    if args[args.index('--header_version') + 1] != '1':
        raise RuntimeError('Unexpected boot header version')
    (unpack / 'mkbootimg-args.json').write_bytes((json.dumps(args, indent=2) + '\n').encode())
    avb_args = ['--partition_size', str(record['capacity_bytes']), '--partition_name', 'boot',
                '--hash_algorithm', hash_descriptor.hash_algorithm,
                '--salt', hash_descriptor.salt.hex(), '--algorithm', 'NONE',
                '--rollback_index', str(header.rollback_index),
                '--rollback_index_location', str(header.rollback_index_location),
                '--flags', str(header.flags)]
    if hash_descriptor.flags & 1:
        avb_args += ['--do_not_use_ab']
    for prop in props:
        avb_args += ['--prop', prop.key + ':' + prop.value.decode()]
    output = DIRECTORY / 'boot-images'
    output.mkdir(exist_ok=True)
    roundtrip_dir = output / 'roundtrip'
    roundtrip_dir.mkdir(exist_ok=True)
    # AVB's verifier resolves the boot descriptor to boot.img in this folder.
    roundtrip = roundtrip_dir / 'boot.img'
    run(MKBOOTIMG / 'mkbootimg.py', *args, '--output', roundtrip)
    if roundtrip.stat().st_size != footer.original_image_size:
        raise RuntimeError('Original payload length changed during round trip')
    run(AVB / 'avbtool.py', 'add_hash_footer', '--image', roundtrip, *avb_args)
    if digest(roundtrip) != record['sha256']:
        raise RuntimeError('Original boot did not survive a byte-identical round trip')
    run(AVB / 'avbtool.py', 'verify_image', '--image', roundtrip)
    comparison_name = 'kernel-dtb-comparison.json' if variant == 'droidspaces' else 'kernel-' + variant + '-dtb-comparison.json'
    comparison = json.loads((DIRECTORY / comparison_name).read_text())
    if not comparison.get('candidate') or not comparison['all_appended_dtbs_match_original']:
        raise RuntimeError('Candidate DTB differs from the original boot')
    audit = json.loads((DIRECTORY / 'config-source-audit.json').read_text())
    if audit['unsatisfied_supported_requirements']:
        raise RuntimeError('Candidate configuration is incomplete')
    extension_audit = None
    if variant.startswith('ext-'):
        extension_audit = json.loads((DIRECTORY / ('kernel-' + variant) / 'audit.json').read_text())
        if not extension_audit.get('build_audit_passed') or not extension_audit.get('kernel_sha256'):
            raise RuntimeError('Extension has not passed its own post-build audit')
        if extension_audit['resolved_config_sha256'] != digest(DIRECTORY / ('kernel-' + variant) / 'resolved.config'):
            raise RuntimeError('Extension configuration changed after audit')
    kernel = DIRECTORY / ('kernel-' + variant) / 'Image.gz-dtb'
    kernel_hash = digest(kernel)
    if kernel_hash != comparison['candidate']['kernel_sha256']:
        raise RuntimeError('Candidate kernel differs from the DTB comparison record')
    if extension_audit and kernel_hash != extension_audit['kernel_sha256']:
        raise RuntimeError('Extension kernel changed after ABI audit')
    args[args.index('--kernel') + 1] = str(kernel)
    suffix = ('-LowRisk2-KSUNext3-Extensions-' + variant[4:] if variant.startswith('ext-') else
              {'droidspaces': '', 'podman': '-Podman1', 'podman2': '-Podman2', 'lowrisk': '-Podman2-LowRisk2', 'ksunext': '-Podman2-LowRisk2-KSUNext3'}[variant])
    candidate_dir = output / ('RMX1931CN-crDroid16-DroidSpaces-v6.6.0' + suffix)
    candidate_dir.mkdir(exist_ok=True)
    candidate = candidate_dir / 'boot.img'
    run(MKBOOTIMG / 'mkbootimg.py', *args, '--output', candidate)
    payload_size = candidate.stat().st_size
    run(AVB / 'avbtool.py', 'add_hash_footer', '--image', candidate, *avb_args)
    verification = run(AVB / 'avbtool.py', 'verify_image', '--image', candidate)
    report_prefix = 'candidate' if variant == 'droidspaces' else variant + '-candidate'
    (output / (report_prefix + '-avb-verification.txt')).write_bytes(verification)
    (output / (report_prefix + '-avb-info.txt')).write_bytes(run(AVB / 'avbtool.py', 'info_image', '--image', candidate))
    candidate_unpack = DIRECTORY / ('candidate-boot' + suffix)
    info = run(MKBOOTIMG / 'unpack_bootimg.py', '--boot_img', candidate, '--out', candidate_unpack)
    (output / (report_prefix + '-header-info.txt')).write_bytes(info)
    extracted = sorted(p.name for p in unpack.iterdir() if p.name in {'kernel', 'ramdisk', 'second', 'dtb', 'recovery_dtbo'})
    for component in extracted:
        expected = kernel_hash if component == 'kernel' else digest(unpack / component)
        if digest(candidate_unpack / component) != expected:
            raise RuntimeError('Candidate component changed unexpectedly: ' + component)
    # All header fields except kernel length and the legacy SHA identifier must
    # remain byte-identical for this v1 image without recovery_dtbo.
    old_header = bytearray(original.read_bytes()[:1648])
    new_header = bytearray(candidate.read_bytes()[:1648])
    for start, end in ((8, 12), (576, 608)):
        old_header[start:end] = b'\0' * (end - start)
        new_header[start:end] = b'\0' * (end - start)
    if old_header != new_header:
        raise RuntimeError('Non-kernel boot header fields changed')
    deployment_record = 'ksunext-boot-result.json' if variant == 'ksunext' else 'candidate-boot-result.json'
    report = {'status': 'Build-time validation; deployment evidence is in ' + deployment_record,
              'original_backup': str(original.relative_to(ROOT)), 'original_boot_sha256': record['sha256'],
              'original_roundtrip_byte_identical': True,
              'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': digest(candidate),
              'partition_bytes': record['capacity_bytes'], 'candidate_bytes': candidate.stat().st_size,
              'payload_bytes': payload_size, 'candidate_kernel_sha256': kernel_hash,
              'ramdisk_sha256': digest(unpack / 'ramdisk'),
              'ramdisk_preserved': True, 'non_kernel_header_fields_preserved': True,
              'dtb_matches_original': True, 'avb_algorithm': 'NONE (same as original ROM boot)',
              'avb_hash_verified': True,
              'tools': {str(k.relative_to(ROOT)): v for k, v in TOOLS.items()},
              'hardware_acceptance': 'pending', 'container_and_docker_acceptance': 'pending'}
    if extension_audit:
        report.update({'status': 'Build-time validation only; extension has not been deployed',
                       'cumulative_stages': extension_audit['cumulative_stages'],
                       'existing_export_crc_preserved': extension_audit['existing_export_crc_preserved'],
                       'external_module_binary_compatibility': 'not established by CRC comparison',
                       'changed_existing_export_crcs': len(extension_audit['export_crc']['changed']),
                       'extension_runtime_acceptance': 'pending'})
    (output / (report_prefix + '-check.json')).write_bytes((json.dumps(report, indent=2) + '\n').encode())
    (candidate.with_suffix('.img.sha256')).write_bytes((report['candidate_sha256'] + '  ' + candidate.name + '\n').encode())
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
