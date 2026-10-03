#!/usr/bin/env python3
"""Export the pinned native CRIU build patch and lock through the checked guest."""
import hashlib
import subprocess
from pathlib import Path
from device_runtime import device, guest_info

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    'gcc13-array-bound.patch': ('patches/criu3.19-gcc13-array-bound.patch',
                              '98ca41252f3ed1ca683784a9bd6514a60d3f86b02c55a3ff473631c3b2af32d9'),
    'source-lock.txt': ('artifacts/droidspaces/criu-source-lock.txt', None),
}


def main():
    adb = device()
    pid = guest_info(adb)['pid']
    base = f'/proc/{pid}/root/opt/rmx1931-extensions/criu-3.19/'
    for name, (target, expected) in FILES.items():
        command = f'test -f /proc/{pid}/root/etc/droidspaces && test ! -L {base}{name} && cat {base}{name}'
        result = subprocess.run(adb + ['exec-out', 'su', '-c', command],
                                capture_output=True, timeout=20, check=True)
        if expected and hashlib.sha256(result.stdout).hexdigest() != expected:
            raise RuntimeError('CRIU patch differs from the recorded build')
        if name == 'source-lock.txt':
            assert b'upstream_commit=f8b14286b092853a4485813e1efd564109df9123\n' in result.stdout
            assert b'b7d2186d7001a009102e53f657c35ec7ab531ee2a30fb093404c55d4e3a05893' in result.stdout
        path = ROOT / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(result.stdout)
        print(target, hashlib.sha256(result.stdout).hexdigest())


if __name__ == '__main__':
    main()
