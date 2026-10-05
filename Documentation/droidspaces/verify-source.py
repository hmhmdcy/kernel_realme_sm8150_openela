#!/usr/bin/env python3
"""Verify accepted a16pf source/config and the pinned KernelSU overlay."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

DOC = Path(__file__).resolve().parent
ROOT = DOC.parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--apply-ksu-overlay', action='store_true')
    group.add_argument('--check-ksu-overlay', action='store_true', help='Validate without modifying the submodule')
    args = parser.parse_args()
    lock = json.loads((DOC / 'source-lock.json').read_text())
    git = shutil.which('git')
    require(git is not None, 'git is required')
    ksu = ROOT / 'KernelSU-Next'
    revision = subprocess.check_output([git, '-C', str(ksu), 'rev-parse', 'HEAD']).decode().strip()
    require(revision == lock['kernel_su_gitlink'], 'KernelSU revision differs')
    overlay = lock['kernel_su_overlay']
    target = ROOT / overlay['path']
    patch = DOC / overlay['patch']
    require(sha(patch.read_bytes()) == overlay['patch_sha256'], 'KernelSU patch differs')
    relative = str(Path(overlay['path']).relative_to('KernelSU-Next')).replace('\\', '/')
    original = target.read_bytes().replace(b'\r\n', b'\n')
    if sha(original) == overlay['before_sha256']:
        if args.apply_ksu_overlay:
            subprocess.run([git, '-c', 'core.autocrlf=false', '-C', str(ksu), 'apply', '--check', str(patch)], check=True)
            subprocess.run([git, '-c', 'core.autocrlf=false', '-C', str(ksu), 'apply', str(patch)], check=True)
        elif args.check_ksu_overlay:
            with tempfile.TemporaryDirectory(prefix='a16pf-ksu-') as directory:
                scratch = Path(directory) / relative
                scratch.parent.mkdir(parents=True)
                scratch.write_bytes(original)
                subprocess.run([git, '-c', 'core.autocrlf=false', '-C', directory, 'apply', str(patch)], check=True)
                require(sha(scratch.read_bytes()) == overlay['after_sha256'], 'Applied KernelSU source differs')
        else:
            raise SystemExit('KernelSU overlay is required; run with --apply-ksu-overlay or --check-ksu-overlay')
    else:
        require(sha(original) == overlay['after_sha256'], 'Unexpected local KernelSU edits')
    hashes = lock['cumulative_source_sha256']
    for name, expected in hashes.items():
        if name == overlay['path'] and args.check_ksu_overlay and sha(original) == overlay['before_sha256']:
            continue
        require(sha((ROOT / name).read_bytes().replace(b'\r\n', b'\n')) == expected, 'Source differs: ' + name)
    require(sha((ROOT / lock['config_path']).read_bytes().replace(b'\r\n', b'\n')) == lock['resolved_config_sha256'], 'Resolved config differs')
    print(json.dumps({'passed': True, 'source_files': len(hashes), 'config_matches_accepted_build': True, 'kernel': lock['kernel']}))


if __name__ == '__main__':
    main()
