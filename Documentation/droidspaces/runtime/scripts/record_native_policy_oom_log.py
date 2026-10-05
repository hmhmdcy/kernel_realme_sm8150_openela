#!/usr/bin/env python3
"""Bind kernel group-OOM messages to the exact native policy containers."""
import argparse
import datetime as dt
import hashlib
import json
import shlex
from pathlib import Path
from device_runtime import ROOT, device, read_identity, read_root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-suffix', choices=('h2cp4',), required=True)
    args = parser.parse_args()
    suffix = args.kernel_suffix
    directory = ROOT / 'artifacts/droidspaces/runtime'
    source = directory / ('native-policy-admission-' + suffix + '-20261004.json')
    path = directory / ('native-policy-oom-log-bound-' + suffix + '-20261004.json')
    assert not path.exists()
    admission = json.loads(source.read_text(encoding='utf-8'))
    assert admission['returncode'] == 0 and 'RESOURCE_POLICY_ADMISSION_PASS_KERNEL_OOM_LOG_REQUIRED' in admission['stdout']
    state = json.JSONDecoder().raw_decode(admission['stdout'].lstrip())[0]
    assert state['admission_passed']
    domains = ['/libpod-' + row['admission']['oom_container_id'] + '.scope/container' for row in state['modes']]
    assert len(domains) == 2 and len(set(domains)) == 2
    adb = device()
    identity = read_identity(adb)
    assert identity['kernel'].endswith('-ext-' + suffix) and admission['end_identity'] == identity
    command = 'uname -r; cat /proc/sys/kernel/random/boot_id; dmesg | grep -F ' + ' '.join('-e ' + shlex.quote(domain) for domain in domains)
    output = read_root(adb, command).decode(errors='replace')
    assert output.splitlines()[:2] == [identity['kernel'], identity['boot_id']]
    matches = {domain: {
        'limit_oom': any(domain in line and 'killed as a result of limit of' in line for line in output.splitlines()),
        'group_oom': any(domain in line and 'are going to be killed due to memory.oom.group set' in line for line in output.splitlines())}
        for domain in domains}
    end = read_identity(adb)
    passed = end == identity and all(all(row.values()) for row in matches.values())
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity, 'end_identity': end,
        'action': 'shell', 'command': command, 'returncode': 0 if passed else 1, 'passed': passed,
        'stdout': output, 'stderr': '', 'exact_container_oom_domains_verified': passed, 'domains': matches,
        'admission_path': source.name, 'admission_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': passed, 'domains': matches}))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__': main()
