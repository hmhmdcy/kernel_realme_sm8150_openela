#!/usr/bin/env python3
"""Record actual Android app transitions and Power HAL boost observations."""
import datetime as dt
import argparse
import hashlib
import json
import re
import shlex
import subprocess
from device_runtime import ROOT, device, read_identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('--label', default='native-android-scheduler-profiles-h2cp4-20261004')
    args = parser.parse_args()
    label = args.label
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', label)
    path = ROOT / 'artifacts/droidspaces/runtime' / (label + '.json')
    source = ROOT / 'scripts/probe_android_scheduler_profiles.sh'
    content = source.read_bytes().replace(b'\r\n', b'\n')
    digest = hashlib.sha256(content).hexdigest()
    normalized = ROOT / 'tools/droidspaces' / (label + '.sh')
    normalized.write_bytes(content)
    remote = '/data/local/tmp/' + label + '.sh'
    adb = device()
    identity = read_identity(adb)
    assert identity['kernel'].endswith('-ext-h2cp4')
    work = remote[:-3] + '-result'
    if not args.collect:
        assert not path.exists(), 'Collect the existing probe; never replay its launch'
        subprocess.run(adb + ['push', str(normalized), remote], check=True, capture_output=True, timeout=20)
        report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
            'script_source_sha256': digest, 'execution': 'detached Android fixture; durable status and logs',
            'pending': True, 'passed': False, 'complete_stage_3_accepted': False, 'returncode': None}
        path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        payload = ('trap "" HUP; echo $$ > ' + work + '/launcher.pid; /system/bin/sh ' + shlex.quote(remote) + ' > ' + work + '/stdout 2> ' + work + '/stderr; '
                   'status=$?; echo "$status" > ' + work + '/status')
        command = ('set -e; test "$(sha256sum ' + remote + ' | cut -d " " -f 1)" = ' + digest + '; '
                   'test ! -e ' + work + '; mkdir -m 700 ' + work + '; '
                   '/system/bin/setsid /system/bin/sh -c ' + shlex.quote(payload) + ' < /dev/null > /dev/null 2>&1 &')
        launched = subprocess.run(adb + ['shell', 'su -c ' + shlex.quote(command)], capture_output=True, timeout=15)
        report.update(launch_returncode=launched.returncode, launch_stdout=launched.stdout.decode(errors='replace'),
            launch_stderr=launched.stderr.decode(errors='replace'))
        path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print('ANDROID_PROFILE_FIXTURE_LAUNCH_RECORDED; use --collect, never replay')
        raise SystemExit(0 if launched.returncode == 0 else 1)
    previous = json.loads(path.read_text(encoding='utf-8'))
    assert previous['pending'] and previous['script_source_sha256'] == digest
    assert all(previous[key] == value for key, value in identity.items())
    command = ('set -e; test -f ' + work + '/status; cat ' + work + '/status; '
               'cat ' + work + '/stdout; printf "\\nANDROID_PROFILE_STDERR_BOUNDARY\\n"; cat ' + work + '/stderr')
    result = subprocess.run(adb + ['shell', 'su -c ' + shlex.quote(command)], capture_output=True, timeout=15)
    assert result.returncode == 0, 'Fixture pending or USB interrupted; keep pending evidence and collect later'
    raw = result.stdout.decode(errors='replace').replace('\r\n', '\n')
    status, raw = raw.split('\n', 1)
    stdout, stderr = raw.split('\nANDROID_PROFILE_STDERR_BOUNDARY\n', 1)
    status = int(status)
    phases = {}
    current = None
    for line in stdout.splitlines():
        if line.startswith('PHASE|'):
            _, current, pid = line.split('|')
            phases[current] = {'pid': int(pid), 'membership': [], 'threads': []}
        elif current is not None:
            if re.match(r'^\d+:', line): phases[current]['membership'].append(line)
            elif line.startswith('Cpus_allowed_list:'): phases[current]['affinity'] = line.split(':')[1].strip()
            elif line.startswith('SETTINGS_TOP_RESUMED|'): phases[current]['top_resumed'] = line.endswith('|yes')
            elif line.startswith('THREAD|'):
                _, tid, allowed, groups = line.split('|')
                phases[current]['threads'].append({'tid': int(tid), 'affinity': allowed, 'membership': groups.split(';')[:-1]})
    histogram = re.search(r'BOOST_HISTOGRAM_BEGIN\n(.*?)BOOST_HISTOGRAM_END', stdout, re.S)
    boosts = {int(row.split()[1]): int(row.split()[0]) for row in histogram.group(1).splitlines()} if histogram else {}
    end = read_identity(adb)
    checks = {
        'script_completed': status == 0 and 'ANDROID_PROFILE_PROBE_COMPLETED' in stdout,
        'same_boot': end == identity,
        'all_transitions_observed': set(phases) == {'foreground', 'background', 'relaunch'},
        'power_hal_boost_observed': any(value > 0 for value in boosts),
    }
    if checks['all_transitions_observed']:
        checks['settings_pid_preserved'] = len({row['pid'] for row in phases.values()}) == 1
        for tag in ('foreground', 'relaunch'):
            row = phases[tag]
            checks[tag + '_top_resumed'] = row.get('top_resumed', False)
            checks[tag + '_legacy_profiles'] = all(any(line.split(':')[1] == controller and line.split(':')[2] == '/top-app'
                for line in row['membership']) for controller in ('cpuset', 'schedtune'))
            # This ROM's vendor MaxPerformance overrides CPU grouping with
            # schedtune; the legacy CPU root is the observed Android policy.
            checks[tag + '_legacy_cpu_root'] = any(line.split(':')[1] == 'cpu' and line.split(':')[2] == '/'
                for line in row['membership'])
            checks[tag + '_affinity'] = row.get('affinity') == '0-7'
        checks['background_no_longer_top_resumed'] = not phases['background'].get('top_resumed', True)
        checks['background_cpuset_moved'] = any(line.split(':')[1] == 'cpuset' and line.split(':')[2] != '/top-app'
            for line in phases['background']['membership'])
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity, 'end_identity': end,
        'returncode': status, 'script_source_sha256': digest, 'stdout': stdout,
        'stderr': stderr, 'phases': phases, 'boost_histogram': boosts, 'pending': False,
        'execution': previous['execution'], 'launch_record': previous,
        'checks': checks, 'passed': all(checks.values()),
        'scope': 'Real Settings foreground/background/relaunch profiles and Power HAL boost; no performance gain claim',
        'complete_stage_3_accepted': False}
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'passed': report['passed'], 'checks': checks, 'boost_histogram': boosts}, ensure_ascii=False))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__': main()
