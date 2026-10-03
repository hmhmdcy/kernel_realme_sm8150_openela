#!/usr/bin/env python3
"""Exercise raw archive integrity, idempotence, failure retry and bounded deletion."""
import hashlib
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BOOT_ID = '12345678-1234-1234-1234-123456789abc'


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='crashlog-test-')
        self.root = Path(self.temp.name)
        self.base = self.root / 'data/adb/rmx1931-crashlog'
        self.pstore = self.root / 'sys/fs/pstore'
        self.pstore.mkdir(parents=True)
        proc = self.root / 'proc'
        (proc / 'sys/kernel/random').mkdir(parents=True)
        (proc / 'sys/kernel/random/boot_id').write_text(BOOT_ID + '\n')
        for name, value in {'uptime': '123.45 10.0\n', 'cmdline': 'fixture\n',
                            'modules': '', 'mounts': f'pstore {self.pstore} pstore rw 0 0\n'}.items():
            (proc / name).write_text(value)
        (proc / 'config.gz').write_bytes(b'\x1f\x8bfixture\x00')
        self.raw = b'panic fixture\x00\xff\x81\n'
        (self.pstore / 'dmesg-ramoops-0').write_bytes(self.raw)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name, value in {'getprop': 'echo RMX1931CN', 'getenforce': 'echo Enforcing',
                            'id': 'echo 0', 'dmesg': 'echo current-kernel-log'}.items():
            path = self.bin / name
            path.write_text('#!/bin/sh\n' + value + '\n')
            path.chmod(0o755)
        source = (ROOT / 'packages/rmx1931-crashlog/collect.sh').read_text()
        source = re.sub(r'(?<![\w/])/(data|proc|sys)\b',
                        lambda match: str(self.root) + match.group(), source)
        self.script = self.root / 'collect.sh'
        self.script.write_text(source)

    def tearDown(self):
        self.temp.cleanup()

    def run_collector(self, mode='boot'):
        return subprocess.run(['sh', str(self.script), mode], capture_output=True,
                              env={**os.environ, 'PATH': str(self.bin) + ':' + os.environ['PATH']}, timeout=10)

    def test_binary_integrity_and_idempotence(self):
        first = self.run_collector()
        self.assertEqual(first.returncode, 0, first.stderr)
        dest = self.base / ('boot-' + BOOT_ID)
        self.assertEqual((dest / 'pstore-dmesg-ramoops-0').read_bytes(), self.raw)
        self.assertEqual((self.pstore / 'dmesg-ramoops-0').read_bytes(), self.raw)
        self.assertIn('uptime_seconds=123.45', (dest / 'metadata.txt').read_text())
        for row in (dest / 'SHA256SUMS').read_text().splitlines():
            digest, name = row.split('  ', 1)
            self.assertEqual(digest, hashlib.sha256((dest / name).read_bytes()).hexdigest())
        self.assertEqual(self.run_collector().returncode, 0)
        self.assertEqual(len(list(self.base.glob('boot-*'))), 1)

    def test_failed_read_is_preserved_and_retryable(self):
        (self.bin / 'dmesg').write_text('#!/bin/sh\nexit 7\n')
        self.assertNotEqual(self.run_collector().returncode, 0)
        self.assertFalse((self.base / ('boot-' + BOOT_ID)).exists())
        self.assertEqual(len(list(self.base.glob('*incomplete-*'))), 1)
        (self.bin / 'dmesg').write_text('#!/bin/sh\necho recovered\n')
        self.assertEqual(self.run_collector().returncode, 0)

    def test_lock_and_symlink_guards(self):
        self.base.mkdir(parents=True)
        lock = self.base / ('.lock-' + BOOT_ID)
        lock.mkdir()
        self.assertEqual(self.run_collector().returncode, 3)
        lock.rmdir()
        (self.base / ('boot-' + BOOT_ID)).symlink_to(self.root)
        self.assertNotEqual(self.run_collector().returncode, 0)

    def test_rotation_preserves_unknown_files_and_source(self):
        self.base.mkdir(parents=True)
        for n in range(12):
            directory = self.base / ('boot-' + f'{n:08x}-1234-1234-1234-123456789abc')
            directory.mkdir()
            (directory / 'complete').write_text('complete\n')
            (directory / 'metadata.txt').write_text('old\n')
            os.utime(directory, (1000 + n, 1000 + n))
        unknown = self.base / 'boot-00000000-1234-1234-1234-123456789abc'
        (unknown / 'unrelated.txt').write_text('preserve\n')
        os.utime(unknown, (1000, 1000))
        self.assertEqual(self.run_collector().returncode, 0)
        self.assertTrue((unknown / 'unrelated.txt').exists())
        self.assertEqual(len(list(self.base.glob('boot-*'))), 11)
        self.assertEqual((self.pstore / 'dmesg-ramoops-0').read_bytes(), self.raw)

    def test_sequence_survives_early_boot_clock_order(self):
        self.base.mkdir(parents=True)
        directories = []
        for n in range(1, 11):
            directory = self.base / ('boot-' + f'{n:08x}-1234-1234-1234-123456789abc')
            directory.mkdir()
            (directory / 'complete').write_text('complete\n')
            (directory / 'order.txt').write_text(str(n) + '\n')
            directories.append(directory)
        dest = self.base / ('boot-' + BOOT_ID)
        # Mimic ls -dt placing this boot last because its early UTC is 1970.
        listing = self.bin / 'ls'
        listing.write_text('#!/bin/sh\ncase "$*" in *snapshot*) exit 0 ;; esac\nprintf "%s\\n" ' + ' '.join(str(p) for p in reversed(directories)) + ' ' + str(dest) + '\n')
        listing.chmod(0o755)
        self.assertEqual(self.run_collector().returncode, 0)
        self.assertTrue((dest / 'complete').exists())
        self.assertEqual((dest / 'order.txt').read_text().strip(), '11')
        self.assertFalse(directories[0].exists())
        self.assertEqual(len(list(self.base.glob('boot-*'))), 10)


if __name__ == '__main__':
    unittest.main()
