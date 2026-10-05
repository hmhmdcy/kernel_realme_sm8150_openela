#!/usr/bin/env python3
"""Use saved human authorization and the previously verified pinned transport."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('phase', choices=('reboot-bootloader', 'flash-reboot', 'verify'))
args = parser.parse_args()
auth = json.loads((ROOT / 'artifacts/droidspaces/authorized-native-cpu-repair.json').read_text(encoding='utf-8'))
command = [sys.executable, str(ROOT / 'scripts/deploy_kernel_extensions.py'), args.phase,
    '--stage', 'android16-group-psi-reclaim-fix']
if args.phase != 'verify':
    command += ['--authorization', auth['authorization'], '--allow-abi-change']
if args.phase == 'flash-reboot':
    command += ['--fastboot-serial', '62bc28a1']
raise SystemExit(subprocess.run(command).returncode)
