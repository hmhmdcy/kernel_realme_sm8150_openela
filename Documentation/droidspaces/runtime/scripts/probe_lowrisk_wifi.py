#!/usr/bin/env python3
"""Toggle Wi-Fi, check reassociation and probe the actual wlan gateway."""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
from device_runtime import device, read_root

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', default='lowrisk-wifi')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', args.label):
        raise RuntimeError('Invalid evidence label')
    adb = device()
    def shell(text):
        if not text.startswith('svc wifi '):
            return read_root(adb, text, timeout=12).decode(errors='replace').strip()
        result = subprocess.run(adb + ['shell', 'su -c ' + shlex.quote(text)], capture_output=True, timeout=12)
        if result.returncode:
            raise RuntimeError('Wi-Fi command failed (exit ' + str(result.returncode) + '): ' + result.stderr.decode(errors='replace'))
        return result.stdout.decode(errors='replace').strip()
    def state():
        # Avoid preserving SSIDs and device identifiers in the shared report.
        status = shell('cmd wifi status')
        return {'enabled': status.startswith('Wifi is enabled'),
                'associated': 'Supplicant state: COMPLETED' in status,
                'validated': 'VALIDATED' in status}
    report = {'observed_at': dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
              'kernel': shell('uname -r'), 'before': state()}
    if not report['before']['enabled'] or not report['before']['associated']:
        raise RuntimeError('A connected Wi-Fi baseline is required')
    try:
        shell('svc wifi disable')
        for _ in range(8):
            report['disabled'] = state()
            if not report['disabled']['enabled']:
                break
            time.sleep(1)
        if report['disabled']['enabled']:
            raise RuntimeError('Wi-Fi did not disable')
    finally:
        shell('svc wifi enable')
    for _ in range(20):
        report['after'] = state()
        if report['after']['associated'] and report['after']['validated']:
            break
        time.sleep(1)
    if not report['after']['associated'] or not report['after']['validated']:
        raise RuntimeError('Wi-Fi did not reconnect/validate')
    route = shell('ip -4 route show table all dev wlan0')
    gateway = re.search(r'default via ([0-9.]+)', route)
    if not gateway:
        raise RuntimeError('wlan0 gateway is unavailable')
    report['gateway_probe'] = shell('ping -I wlan0 -c 3 -W 2 ' + gateway[1])
    report['passed'] = True
    destination = ROOT / ('artifacts/droidspaces/' + args.label + '.json')
    destination.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
