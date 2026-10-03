#!/usr/bin/env python3
"""Run cumulative functionality and existing Podman/diagnostic regressions per boot."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from deploy_kernel_extensions import STAGES, candidate

HERE = Path(__file__).resolve().parent
ART = HERE.parent / 'artifacts/droidspaces'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=STAGES, required=True)
    parser.add_argument('--retry', action='append', default=[], help='Inspected failed probe; use a fresh label and retain failure evidence')
    args = parser.parse_args()
    _, _, _, release = candidate(args.stage)
    boot = json.loads((ART / f'extensions-{args.stage}-boot-result.json').read_text())
    if boot['kernel'] != release or not boot.get('running_config_matches'):
        raise RuntimeError('Verify deployed boot before running probes')
    prefix = 'extensions-' + args.stage + '-'
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
                if record['returncode'] == 0 and record.get('kernel') == release:
                    path, name = option, option.stem
                    break
        if path.exists():
            old = json.loads(path.read_text())
            if old['returncode'] == 0 and old.get('kernel') == release:
                evidence[label] = {'path': path.relative_to(HERE.parent).as_posix(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                print('Retained verified probe: ' + name, flush=True)
                return
            raise RuntimeError('Inspect failed/stale probe before retrying: ' + name)
        if label == 'checkpoint':
            command = [sys.executable, str(HERE / 'probe_checkpoint_privileged.py'), '--label', name]
        else:
            command = [sys.executable, str(HERE / 'device_runtime.py'), action,
                       '--label', name, '--guest-service', '--timeout', '60', *arguments]
        result = subprocess.run(command, capture_output=True)
        if result.returncode:
            print(result.stdout.decode(errors='replace')[-7000:], flush=True)
            print(result.stderr.decode(errors='replace')[-2000:], file=sys.stderr)
            raise RuntimeError('Probe failed: ' + name)
        record = json.loads(path.read_text())
        if record.get('kernel') != release:
            raise RuntimeError('Probe ran on the wrong kernel')
        evidence[label] = {'path': path.relative_to(HERE.parent).as_posix(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        print('PROBE_PASS ' + name, flush=True)
    def file(label, script, *arguments):
        probe('run-file', label, '--script', str(HERE / script), *arguments)
    def rootless(label, source_label, argument=''):
        command = ('set -e; runuser -u podmantest -- env HOME=/home/podmantest '
                   'USER=podmantest LOGNAME=podmantest XDG_RUNTIME_DIR=/run/user/1000 '
                   'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus '
                   'sh -s -- ' + argument + ' < /tmp/rmx1931-tests/' + prefix + source_label + '.sh')
        probe('run', label, '--command', command)
    probe('run', 'identity', '--command', 'set -e; test "$(uname -r)" = ' + release +
          '; test -f /etc/droidspaces; echo EXTENSION_GUEST_IDENTITY_PASS')
    file('erofs', 'probe_extension_erofs.sh')
    file('binfmt', 'probe_kernel_extensions.sh', '--script-arg', 'binfmt')
    for label, minimum in [('bbr', 1), ('checkpoint', 2), ('nft', 3)]:
        if STAGES.index(args.stage) >= minimum:
            file(label, 'probe_kernel_extensions.sh', '--script-arg', label)
    if args.stage == 'io':
        reports = sorted((ART / 'runtime').glob(prefix + 'io*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
        verified = next((path for path in reports if (lambda r: r.get('kernel') == release and
                        r.get('status') == 'passed' and r.get('cleanup_errors') == [] and
                        r.get('boot_id') == json.loads((ART / 'runtime' / (prefix + 'identity.json')).read_text())['boot_id'])(json.loads(path.read_text()))), None)
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
    (ART / f'extensions-{args.stage}-probes.json').write_text(json.dumps(
        {'stage': args.stage, 'kernel': release, 'probes': evidence, 'passed': True}, indent=2) + '\n')
    print('CUMULATIVE_EXTENSION_FUNCTIONAL_REGRESSIONS_PASS ' + args.stage, flush=True)


if __name__ == '__main__':
    main()
