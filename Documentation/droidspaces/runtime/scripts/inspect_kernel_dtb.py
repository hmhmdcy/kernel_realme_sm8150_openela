#!/usr/bin/env python3
"""Compare the original boot kernel's appended DTB with local builds."""
import hashlib
import argparse
import json
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'artifacts/droidspaces'


def inspect(label, path):
    blob = path.read_bytes()
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    image = decoder.decompress(blob) + decoder.flush()
    if not decoder.eof or len(image) < 64 or image[56:60] != b'ARM\x64':
        raise RuntimeError(f'{label}: invalid compressed ARM64 kernel image')
    appended = decoder.unused_data
    if len(appended) < 40:
        raise RuntimeError(f'{label}: appended DTB is missing')
    offset = 0
    dtbs = []
    while offset < len(appended):
        header = struct.unpack_from('>10I', appended, offset)
        magic, size = header[:2]
        if magic != 0xD00DFEED or size < 40 or offset + size > len(appended):
            raise RuntimeError(f'{label}: unexpected trailing data at {offset}')
        data = appended[offset:offset + size]
        dtbs.append({'bytes': size, 'sha256': hashlib.sha256(data).hexdigest(),
                     'version': header[5]})
        offset += size
    (DIRECTORY / (label + '-appended.dtb')).write_bytes(appended)
    return {'kernel_bytes': len(blob), 'image_bytes': len(image),
            'kernel_sha256': hashlib.sha256(blob).hexdigest(),
            'dtb_sha256': hashlib.sha256(appended).hexdigest(), 'dtbs': dtbs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variant', choices=['droidspaces', 'podman', 'podman2', 'lowrisk', 'ksunext',
                        'ext-utilities', 'ext-bbr', 'ext-checkpoint', 'ext-network', 'ext-io'], default='droidspaces')
    variant = parser.parse_args().variant
    paths = {'original': DIRECTORY / 'original-boot/kernel',
             'baseline': DIRECTORY / 'kernel-baseline/Image.gz-dtb',
             'candidate': DIRECTORY / ('kernel-' + variant) / 'Image.gz-dtb'}
    result = {label: inspect(label, path) for label, path in paths.items() if path.exists()}
    if not {'original', 'baseline'} <= result.keys():
        raise RuntimeError('Original kernel and baseline build are required')
    result['all_appended_dtbs_match_original'] = all(
        value['dtb_sha256'] == result['original']['dtb_sha256']
        for value in result.values())
    result['interpretation'] = 'DTB identity only; does not prove hardware operation or kernel binary identity'
    report_name = 'kernel-dtb-comparison.json' if variant == 'droidspaces' else 'kernel-' + variant + '-dtb-comparison.json'
    (DIRECTORY / report_name).write_bytes((json.dumps(result, indent=2) + '\n').encode())
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
