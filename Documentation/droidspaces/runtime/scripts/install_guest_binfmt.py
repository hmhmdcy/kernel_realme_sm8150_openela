#!/usr/bin/env python3
"""Install the isolated foreground binfmt helper in the current guest."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
from device_runtime import ROOT, device, guest_info, read_identity, read_root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--upgrade-from', type=Path)
    args = parser.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.label)
    report_path = ROOT / 'artifacts/droidspaces/runtime' / (args.label + '.json')
    assert not report_path.exists()
    source = ROOT / 'scripts/rmx1931_binfmt.py'
    content = source.read_bytes().replace(b'\r\n', b'\n')
    compile(content, str(source), 'exec')
    digest = hashlib.sha256(content).hexdigest()
    adb = device()
    identity = read_identity(adb)
    assert identity['kernel'].endswith('-ext-h3bm2')
    assert read_root(adb, 'getenforce').strip() == b'Enforcing'
    pid = guest_info(adb)['pid']
    root = '/proc/' + str(pid) + '/root'
    target = root + '/usr/local/bin/rmx1931-binfmt'
    assert read_root(adb, 'test -f ' + root + '/etc/droidspaces && echo VERIFIED').strip() == b'VERIFIED'

    def remote_digest():
        for attempt in range(2):
            words = read_root(adb, 'if test -e ' + target + '; then sha256sum ' + target + '; else echo absent; fi').decode().split()
            if words and (words[0] == 'absent' or re.fullmatch('[a-f0-9]{64}', words[0])):
                return words[0]
            if attempt == 0:
                subprocess.run(adb + ['wait-for-device'], capture_output=True, check=True, timeout=25)
        raise RuntimeError('Existing helper digest read was truncated; do not replay installation')

    previous = remote_digest()
    allowed = {'absent', digest}
    if args.upgrade_from:
        prior_path = args.upgrade_from.resolve()
        assert prior_path.parent == report_path.parent.resolve()
        prior = json.loads(prior_path.read_text(encoding='utf-8'))
        assert prior['action'] == 'install-guest-binfmt' and prior['completed']
        assert prior['guest_target'] == '/usr/local/bin/rmx1931-binfmt'
        allowed.add(prior['source_sha256'])
    assert previous in allowed, 'Existing helper source is not reviewed'
    if previous != digest:
        local = ROOT / 'tools/droidspaces' / (args.label + '.py')
        local.write_bytes(content)
        staging = '/data/local/tmp/' + args.label + '.py'
        subprocess.run(adb + ['push', str(local), staging], capture_output=True, check=True, timeout=30)
        command = ('set -e; test ! -L ' + target + '; test -d ' + root + '/usr/local/bin; '
                   'cp ' + staging + ' ' + target + '; chown 0:0 ' + target + '; chmod 755 ' + target)
        result = subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=25)
        assert result.returncode == 0, result.stderr
    observed = remote_digest()
    assert observed == digest
    end = read_identity(adb)
    assert end == identity
    report = {'action': 'install-guest-binfmt', 'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              **identity, 'end_identity': end, 'guest_pid': pid, 'completed': True,
              'source_sha256': digest, 'guest_target': '/usr/local/bin/rmx1931-binfmt',
              'existing_identical_source_reused': previous == digest,
              'foreground_only': True, 'global_registry_modified': False, 'guest_filters_changed': False,
              'runtime_acceptance': 'pending actual helper build/run proof'}
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
