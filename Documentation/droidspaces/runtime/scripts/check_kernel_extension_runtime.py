#!/usr/bin/env python3
"""Run cumulative functionality and existing Podman/diagnostic regressions per boot."""
import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys
from deploy_kernel_extensions import STAGES, candidate
from device_runtime import device, read_identity, read_root

HERE = Path(__file__).resolve().parent
ART = HERE.parent / 'artifacts/droidspaces'


def current_probe(record, identity):
    return (record.get('returncode') == 0 and
            all(record.get(key) == value for key, value in identity.items()) and
            record.get('end_identity') == identity)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=STAGES, required=True)
    parser.add_argument('--retry', action='append', default=[], help='Inspected failed probe; use a fresh label and retain failure evidence')
    parser.add_argument('--run-label', help='Separate fresh acceptance run; resume only evidence from the current boot')
    parser.add_argument('--reuse-lifecycle-label', help='Use a completed lifecycle probe from this exact boot')
    args = parser.parse_args()
    if args.run_label and not re.fullmatch(r'[a-zA-Z0-9_-]+', args.run_label):
        raise RuntimeError('Invalid run label')
    if args.reuse_lifecycle_label and not re.fullmatch(r'[a-zA-Z0-9_-]+', args.reuse_lifecycle_label):
        raise RuntimeError('Invalid lifecycle evidence label')
    _, check, _, release = candidate(args.stage)
    boot = json.loads((ART / f'extensions-{args.stage}-boot-result.json').read_text())
    if boot['kernel'] != release or not boot.get('running_config_matches'):
        raise RuntimeError('Verify deployed boot before running probes')
    adb = device()
    identity = read_identity(adb)
    if identity['kernel'] != release or read_root(adb, 'sha256sum /dev/block/by-name/boot').decode().split()[0] != check['candidate_sha256']:
        raise RuntimeError('Current phone does not match the verified boot')
    prefix = 'extensions-' + args.stage + '-' + (args.run_label + '-' if args.run_label else '')
    evidence = {}
    def probe(action, label, *arguments):
        name = prefix + label
        if label in args.retry:
            index = 1
            while (ART / 'runtime' / (name + '-retry' + str(index) + '.json')).exists():
                index += 1
            name += '-retry' + str(index)
        path = ART / 'runtime' / (name + '.json')
        if label not in args.retry and path.exists():
            alternatives = sorted((ART / 'runtime').glob(name + '-retry*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
            for option in alternatives:
                record = json.loads(option.read_text())
                if current_probe(record, identity):
                    path, name = option, option.stem
                    break
        if path.exists():
            old = json.loads(path.read_text())
            if current_probe(old, identity):
                evidence[label] = {'path': path.relative_to(HERE.parent).as_posix(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                print('Retained verified probe: ' + name, flush=True)
                return
            raise RuntimeError('Inspect failed/stale probe before retrying: ' + name)
        if label == 'checkpoint':
            command = [sys.executable, str(HERE / 'probe_checkpoint_privileged.py'), '--label', name]
        elif label == 'lifecycle':
            command = [sys.executable, str(HERE / 'privileged_guest.py'), '--label', name,
                       '--script', str(HERE / 'probe_container_lifecycle.sh'), '--timeout', '180']
        else:
            command = [sys.executable, str(HERE / 'device_runtime.py'), action,
                       '--label', name, '--guest-service', '--timeout', '60', *arguments]
        result = subprocess.run(command, capture_output=True)
        if result.returncode:
            print(result.stdout.decode(errors='replace')[-7000:], flush=True)
            print(result.stderr.decode(errors='replace')[-2000:], file=sys.stderr)
            raise RuntimeError('Probe failed: ' + name)
        record = json.loads(path.read_text())
        if not current_probe(record, identity):
            raise RuntimeError('Probe ran on the wrong kernel/boot or failed')
        evidence[label] = {'path': path.relative_to(HERE.parent).as_posix(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        print('PROBE_PASS ' + name, flush=True)
    def file(label, script, *arguments):
        probe('run-file', label, '--script', str(HERE / script), *arguments)
    def rootless(label, source_label, argument=''):
        source_name = Path(evidence[source_label]['path']).stem
        command = ('set -e; runuser -u podmantest -- env HOME=/home/podmantest '
                   'USER=podmantest LOGNAME=podmantest XDG_RUNTIME_DIR=/run/user/1000 '
                   'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus '
                   'sh -s -- ' + argument + ' < /tmp/rmx1931-tests/' + source_name + '.sh')
        probe('run', label, '--command', command)
    probe('run', 'identity', '--command', 'set -e; test "$(uname -r)" = ' + release +
          '; test -f /etc/droidspaces; echo EXTENSION_GUEST_IDENTITY_PASS')
    file('erofs', 'probe_extension_erofs.sh')
    file('binfmt', 'probe_kernel_extensions.sh', '--script-arg', 'binfmt')
    for label, minimum in [('bbr', 1), ('checkpoint', 2), ('nft', 3)]:
        if STAGES.index(args.stage) >= minimum:
            file(label, 'probe_kernel_extensions.sh', '--script-arg', label)
    if STAGES.index(args.stage) >= STAGES.index('io'):
        reports = sorted((ART / 'runtime').glob(prefix + 'io*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
        verified = next((path for path in reports if (lambda r: r.get('kernel') == release and
                        r.get('status') == 'passed' and r.get('cleanup_errors') == [] and
                        r.get('boot_id') == identity['boot_id'] and r.get('end_identity') == identity)(json.loads(path.read_text()))), None)
        if not verified:
            raise RuntimeError('Run probe_io_throttling.py with a fresh label and inspect its actual enforcement evidence')
        evidence['io'] = {'path': verified.relative_to(HERE.parent).as_posix(), 'sha256': hashlib.sha256(verified.read_bytes()).hexdigest()}
        print('PROBE_PASS ' + verified.stem, flush=True)
    file('wireguard', 'probe_kernel_extensions.sh', '--script-arg', 'wireguard')
    file('lxc', 'probe_extension_lxc.sh')
    file('rootful-build', 'probe_podman_rootful_build.sh')
    probe('run', 'rootless-build', '--command',
          'set -e; podman-rootless build --no-cache --network=none '
          '-t localhost/rmx1931-probe:1 /tmp/rmx1931-tests/build-rootful; echo ROOTLESS_COPY_RUN_BUILD_PASS')
    file('rootful-functional', 'probe_podman_functional.sh', '--script-arg', 'rootful')
    rootless('rootless-functional', 'rootful-functional', 'rootless')
    for kind in ('memory', 'pids'):
        file('rootful-' + kind, 'probe_podman_' + kind + '_enforcement.sh')
        rootless('rootless-' + kind, 'rootful-' + kind)
    file('sockets', 'probe_lowrisk_socket_diag.sh')
    transfer = subprocess.run([sys.executable, str(HERE / 'prepare_lowrisk_fixtures.py'), '--transfer'], capture_output=True)
    if transfer.returncode:
        raise RuntimeError('SquashFS fixture transfer failed: ' + transfer.stderr.decode(errors='replace'))
    file('squashfs', 'probe_lowrisk_squashfs.sh')
    if STAGES.index(args.stage) >= STAGES.index('harden1'):
        if args.reuse_lifecycle_label:
            path = ART / 'runtime' / (args.reuse_lifecycle_label + '.json')
            record = json.loads(path.read_text())
            digest = hashlib.sha256((HERE / 'probe_container_lifecycle.sh').read_bytes().replace(b'\r\n', b'\n')).hexdigest()
            if (not current_probe(record, identity) or record.get('script_source_sha256') != digest or
                    record.get('cleanup_errors') != [] or
                    'CONTAINER_LIFECYCLE_ACCEPTANCE_PASS' not in record.get('stdout', '')):
                raise RuntimeError('Provided lifecycle evidence is failed, stale, or uses a different fixture')
            evidence['lifecycle'] = {'path': path.relative_to(HERE.parent).as_posix(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        else:
            file('lifecycle', 'probe_container_lifecycle.sh')
    if read_identity(adb) != identity:
        raise RuntimeError('Phone rebooted during the suite; repeat with a fresh run label')
    suite_name = prefix + 'probes.json'
    (ART / suite_name).write_text(json.dumps(
        {'stage': args.stage, **identity, 'run_label': args.run_label,
         'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
         'boot_sha256': check['candidate_sha256'], 'probes': evidence, 'passed': True}, indent=2) + '\n')
    print('CUMULATIVE_EXTENSION_FUNCTIONAL_REGRESSIONS_PASS ' + args.stage, flush=True)


if __name__ == '__main__':
    main()
