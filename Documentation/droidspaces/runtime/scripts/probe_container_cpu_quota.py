#!/usr/bin/env python3
"""Verify the operator quota entry on actual filtered rootful/rootless containers."""
import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from device_runtime import ROOT, device, read_identity, read_root


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--label', required=True)
    p.add_argument('--mode', choices=['both', 'rootful', 'rootless'], default='both')
    args = p.parse_args()
    assert re.fullmatch(r'[a-z0-9-]+', args.label)
    directory = ROOT / 'artifacts/droidspaces/runtime'
    destination = directory / (args.label + '.json')
    assert not destination.exists()
    adb = device()
    identity = read_identity(adb)
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
              'interface': 'Android-root container quota management entry', 'passed': False, 'containers': []}

    def fixture(action, name, mode, phase):
        label = args.label + '-' + mode + '-' + phase
        command = [sys.executable, str(ROOT / 'scripts/device_runtime.py'), 'run-file',
                        '--script', str(ROOT / 'scripts/probe_container_cpu_fixture.sh'),
                        '--script-arg', action, '--script-arg', name, '--script-arg', mode,
                        '--guest-service', '--timeout', '80', '--label', label]
        if action == 'prepare':
            command.append('--retain-detached-workloads')
        subprocess.run(command, check=True,
                       stdout=subprocess.DEVNULL)
        return json.loads((directory / (label + '.json')).read_text())['stdout'].strip()

    def quota(action, name, mode, phase, state=None):
        label = args.label + '-' + mode + '-' + phase
        command = [sys.executable, str(ROOT / 'scripts/set_container_cpu_quota.py'), action,
                   '--container', name, '--label', label]
        if mode == 'rootless':
            command.append('--rootless')
        if action == 'apply':
            command += ['--cpus', '.5']
        else:
            command += ['--state', str(state)]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        return directory / (label + '.json')

    try:
        for mode in (('rootful', 'rootless') if args.mode == 'both' else (args.mode,)):
            name = 'rmx1931-cpu-' + args.label + '-' + mode
            row = {'mode': mode, 'container_name': name}
            report['containers'].append(row)
            prepared = False
            applied = None
            released = False
            try:
                row['container_id'] = fixture('prepare', name, mode, 'prepare').splitlines()[-1]
                prepared = True
                row['baseline'] = json.loads(fixture('measure', name, mode, 'baseline'))
                applied = quota('apply', name, mode, 'apply')
                state = json.loads(applied.read_text())
                row['quota_entry'] = state
                group = state['v1_cpu_group']
                before = dict(line.split() for line in read_root(adb, 'cat ' + group + '/cpu.stat').decode().splitlines())
                row['limited'] = json.loads(fixture('measure', name, mode, 'limited'))
                after = dict(line.split() for line in read_root(adb, 'cat ' + group + '/cpu.stat').decode().splitlines())
                row['throttled_periods'] = int(after['nr_throttled']) - int(before['nr_throttled'])
                row['quota_stats_before'] = before
                row['quota_stats_after'] = after
                row['release_entry'] = json.loads(quota('release', name, mode, 'release', applied).read_text())
                released = True
                row['restored'] = json.loads(fixture('measure', name, mode, 'restored'))
                for phase in ('baseline', 'limited', 'restored'):
                    value = row[phase]
                    value['cpu_ratio'] = value['cpu_seconds'] / value['wall_seconds']
                    assert value['seccomp'] == 2, 'Container filter changed'
                assert row['baseline']['cpu_ratio'] > 1.2 and row['restored']['cpu_ratio'] > 1.2
                assert .3 <= row['limited']['cpu_ratio'] <= .75
                assert row['limited']['cpu_ratio'] < row['baseline']['cpu_ratio'] / 2
                assert row['throttled_periods'] >= 10
                row['passed'] = True
            finally:
                if applied and not released:
                    try:
                        quota('release', name, mode, 'failure-release', applied)
                    except Exception as error:
                        row['release_error'] = str(error)
                if prepared:
                    try:
                        row['cleanup'] = fixture('cleanup', name, mode, 'cleanup')
                    except Exception as error:
                        row['cleanup_error'] = str(error)
        report['passed'] = all(row.get('passed') and not row.get('cleanup_error') for row in report['containers'])
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        report['end_identity'] = read_identity(adb)
        if report['end_identity'] != identity:
            report['passed'] = False
        destination.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2), flush=True)
    assert report['passed']


if __name__ == '__main__':
    main()
