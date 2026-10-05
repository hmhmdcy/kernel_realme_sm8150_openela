#!/usr/bin/env python3
"""Explicit full legacy acceptance; select feature probes for daily iteration."""
import argparse
import datetime as dt
import re
import subprocess
import sys
from pathlib import Path
from deploy_kernel_extensions import STAGES, RELEASE_SUFFIX
from device_runtime import device, read_identity

HERE = Path(__file__).resolve().parent
ART = HERE.parent / 'artifacts/droidspaces'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full', action='store_true', help='Explicitly run the cumulative legacy suite and guest preparation')
    parser.add_argument('--stage', choices=STAGES, help='Default: detect the currently running extension stage')
    parser.add_argument('--run-label', default=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    parser.add_argument('--with-wifi', action='store_true', help='Opt in to Wi-Fi toggle/reconnect regression')
    parser.add_argument('--reuse-lifecycle-label', help='Use the already completed lifecycle fixture from this boot')
    args = parser.parse_args()
    if not args.full:
        parser.error('The cumulative suite requires --full. Select affected feature probes using docs/test-policy.md.')
    if args.stage is None:
        kernel = read_identity(device())['kernel']
        prefix_release = '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-'
        matches = [stage for stage in STAGES if prefix_release + RELEASE_SUFFIX.get(stage, stage) == kernel]
        if len(matches) != 1:
            raise RuntimeError('Current kernel is not a recognized extension stage')
        args.stage = matches[0]
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', args.run_label):
        raise RuntimeError('Invalid run label')
    prefix = 'extensions-' + args.stage + '-' + args.run_label + '-'
    if any(ART.glob(prefix + '*')) or any((ART / 'runtime').glob(prefix + '*')):
        raise RuntimeError('Run label already has evidence; use a fresh label or inspect/resume individual probes')

    def run(name, *arguments):
        subprocess.run([sys.executable, str(HERE / name), *arguments], check=True)

    print('Acceptance will prepare this guest; existing Podman workloads must be stopped.', flush=True)
    if args.with_wifi:
        print('Explicit Wi-Fi regression requested: Wi-Fi will be toggled.', flush=True)
    run('start_podman_guest.py')
    if STAGES.index(args.stage) >= STAGES.index('io'):
        run('probe_io_throttling.py', '--label', prefix + 'io')
    run('check_kernel_extension_runtime.py', '--stage', args.stage, '--run-label', args.run_label,
        *(['--reuse-lifecycle-label', args.reuse_lifecycle_label] if args.reuse_lifecycle_label else []))
    if args.with_wifi:
        run('probe_lowrisk_wifi.py', '--label', prefix + 'wifi')
    run('record_extension_acceptance.py', '--stage', args.stage, '--run-label', args.run_label,
        *(['--with-wifi'] if args.with_wifi else []))
    print('PHONE_ACCEPTANCE_PASS ' + str(ART / (prefix + 'acceptance.json')), flush=True)


if __name__ == '__main__':
    main()
