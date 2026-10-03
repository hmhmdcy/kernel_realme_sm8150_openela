#!/usr/bin/env python3
"""Create gzip/xz SquashFS fixtures in WSL, or transfer verified fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/droidspaces/lowrisk-fixtures'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--transfer', action='store_true')
    args = p.parse_args()
    if args.transfer:
        from device_runtime import device, DS, NAME
        adb = device()
        def shell(text):
            return subprocess.check_output(adb + ['shell', 'su -c ' + shlex.quote(text)], timeout=30).decode().strip()
        info = json.loads(shell(shlex.join([DS, '--name=' + NAME, '--format', 'info'])))
        pid = info['pid']
        if info['name'] != NAME or not isinstance(pid, int) or pid <= 1:
            raise RuntimeError('Guest identity mismatch')
        destination = f'/proc/{pid}/root/tmp/rmx1931-lowrisk-fixtures'
        shell(f'test -f /proc/{pid}/root/etc/droidspaces; test ! -L {destination}; mkdir -p {destination}')
        record = json.loads((TARGET / 'manifest.json').read_text())
        for name, expected in record['image_sha256'].items():
            local = TARGET / name
            if sha(local) != expected:
                raise RuntimeError('Fixture changed: ' + name)
            remote = '/data/local/tmp/rmx1931-lowrisk-' + name
            subprocess.run(adb + ['push', str(local), remote], check=True, capture_output=True, timeout=30)
            result = shell(f'test ! -L {destination}/{name}; cp {remote} {destination}/{name}; sha256sum {destination}/{name}')
            if result.split()[0] != expected:
                raise RuntimeError('Fixture transfer mismatch')
        print('SQUASHFS_FIXTURE_TRANSFER_HASHES_PASS')
        return
    TARGET.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rmx1931-lowrisk-fixture-') as temporary:
        source = Path(temporary)
        (source / 'payload').mkdir()
        (source / 'README.txt').write_text('RMX1931 low-risk SquashFS gzip/xz acceptance fixture.\n')
        (source / 'payload/data.bin').write_bytes(bytes(range(256)) * 1601)
        os.setxattr(source / 'payload/data.bin', 'user.rmx1931', b'LOWRISK_XATTR')
        tool = source / 'payload/tool.sh'
        tool.write_text('#!/bin/sh\nprintf "SQUASHFS_TOOL_EXEC_PASS\\n"\n')
        tool.chmod(0o755)
        (source / 'tool-alias').symlink_to('payload/tool.sh')
        os.link(source / 'payload/data.bin', source / 'data-hardlink')
        checksums = {str(path.relative_to(source)): sha(path) for path in (source / 'README.txt', source / 'payload/data.bin', tool)}
        (source / 'SHA256SUMS').write_text(''.join(value + '  ' + name + '\n' for name, value in checksums.items()))
        for compression in ('gzip', 'xz'):
            subprocess.run(['mksquashfs', str(source), str(TARGET / (compression + '.squashfs')),
                            '-noappend', '-comp', compression, '-processors', '1', '-all-root',
                            '-mkfs-time', '0', '-all-time', '0'], check=True, capture_output=True)
        report = {'payload_sha256': checksums, 'image_sha256': {name + '.squashfs': sha(TARGET / (name + '.squashfs')) for name in ('gzip', 'xz')}}
        (TARGET / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
