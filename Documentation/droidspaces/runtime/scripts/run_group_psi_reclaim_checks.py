#!/usr/bin/env python3
"""Run each new-kernel probe once, preserving its own durable evidence."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
STAGE = 'android16-group-psi-reclaim-fix'
LABEL = 'a16pf-20261005'
BASE = '/var/tmp/rmx1931-psi-persist-' + LABEL
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('phase', choices=('pressure', 'pressure-remaining', 'persistence-prepare', 'persistence-after-restart', 'regression'))
args = parser.parse_args()


def invoke(script, *arguments):
    result = subprocess.run([sys.executable, str(SCRIPTS / script), *arguments], capture_output=True)
    stdout = result.stdout.decode(errors='replace')
    stderr = result.stderr.decode(errors='replace')
    print(json.dumps({'script': script, 'arguments': arguments, 'returncode': result.returncode,
        'stdout_tail': stdout[-600:], 'stderr_tail': stderr[-1500:]}), flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)


def fixture(script, prefix, *values, retain=False, timeout='240'):
    argv = ['run-file', '--label', prefix + '-' + LABEL, '--script', str(SCRIPTS / script),
            '--guest-service', '--timeout', timeout]
    for value in values:
        argv += ['--script-arg', value]
    if retain:
        argv.append('--retain-detached-workloads')
    invoke('device_runtime.py', *argv)


if args.phase in ('pressure', 'pressure-remaining'):
    if args.phase == 'pressure':
        invoke('probe_group_psi_host_health.py', '--stage', STAGE, '--label', 'psi-host-before-' + LABEL)
        fixture('probe_group_psi_policy.sh', 'psi-policy-full2', 'full')
    fixture('probe_group_psi_policy.sh', 'psi-policy-some', 'some')
    fixture('probe_group_psi_reclaim_migration.sh', 'psi-reclaim-migration')
    fixture('probe_group_psi_monitor_lifecycle.sh', 'psi-monitor-lifecycle')
elif args.phase == 'persistence-prepare':
    fixture('probe_group_psi_persistence.sh', 'psi-persistence-prepare', 'prepare', BASE, retain=True)
    invoke('record_group_psi_restart.py', '--stage', STAGE, '--label', 'psi-restart-before-' + LABEL, '--base', BASE)
elif args.phase == 'persistence-after-restart':
    invoke('record_group_psi_restart.py', '--stage', STAGE, '--label', 'psi-restart-after-' + LABEL,
        '--base', BASE, '--previous', str(ROOT / 'artifacts/droidspaces/runtime' / ('psi-restart-before-' + LABEL + '.json')))
    fixture('probe_group_psi_persistence.sh', 'psi-persistence-resume', 'resume', BASE, retain=True)
else:
    fixture('probe_container_seccomp_setresuid.sh', 'psi-filter')
    fixture('probe_native_cpu_podman.sh', 'psi-native-cpu')
    fixture('probe_resource_policy_smoke.sh', 'psi-policy-crun', 'crun')
    fixture('probe_resource_policy_smoke.sh', 'psi-policy-runc', 'runc')
    invoke('run_binder_public_api_probe.py', '--stage', STAGE, '--label', 'psi-binder-public-api-' + LABEL)
    invoke('probe_group_psi_host_health.py', '--stage', STAGE, '--label', 'psi-host-final-' + LABEL,
        '--baseline', str(ROOT / 'artifacts/droidspaces/runtime' / ('psi-host-before-' + LABEL + '.json')))
print('GROUP_PSI_RECLAIM_PHASE_PASS ' + args.phase, flush=True)
