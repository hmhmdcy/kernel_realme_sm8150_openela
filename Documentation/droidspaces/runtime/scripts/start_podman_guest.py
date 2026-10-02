#!/usr/bin/env python3
"""Start and prepare the already provisioned RMX1931 Ubuntu Podman guest.

Requires an accepted podman2, lowrisk2 or KSU v3 kernel, authorized ADB/Shell root, the checked
DroidSpaces binary and the existing isolated guest image. Never flashes.
"""
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ksunext_case = ''
ksunext_result = HERE.parent / 'artifacts/droidspaces/ksunext-boot-result.json'
if ksunext_result.exists():
    checked = json.loads(ksunext_result.read_text())
    if checked['kernel'] != '4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2-lr2-ksu3' or not re.fullmatch(r'[a-f0-9]{64}', checked['boot_sha256']):
        raise RuntimeError('Unexpected KSU candidate acceptance record')
    ksunext_case = checked['kernel'] + ') expected=' + checked['boot_sha256'] + ' ;; '
label = 'podman-profile-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def runtime(action, *args, suffix, accepted=(0,)):
    r = subprocess.run([sys.executable, str(HERE / 'device_runtime.py'), action,
                        '--label', label + '-' + suffix, '--timeout', '50', *args])
    if r.returncode not in accepted:
        raise RuntimeError('Guest setup phase failed: ' + suffix)
    return r.returncode


runtime('shell', '--command', 'set -e; case "$(uname -r)" in '
        '4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2) '
        'expected=71591c95ec72f1a5582cd0fc3f3e7ce96d74fc469e9dace231f10ed0765118b9 ;; '
        '4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2-lowrisk2) '
        'expected=a54700cab0088215c5b9975301023736ffc0c0d02579ceaa89d7ec7cf7bd8bfd ;; '
        + ksunext_case + '*) exit 1 ;; esac; '
        'test "$(sha256sum /dev/block/by-name/boot | cut -d " " -f 1)" = "$expected"; '
        'test "$(getprop sys.boot_completed)" = 1; test "$(getenforce)" = Enforcing; '
        'test "$(sha256sum /data/local/tmp/rmx1931-droidspaces-check | cut -d " " -f 1)" = '
        '26dbd935d24b8ba8b55a9cb65b2edc43ebbaf298317f243939e67a92a8a8558e', suffix='kernel')
state = runtime('info', suffix='state', accepted=(0, 255))
if state == 255:
    runtime('start', '--auto-cgroup', suffix='start')
subprocess.run([sys.executable, str(HERE / 'delegate_guest_cgroup_v2.py'),
                '--label', label + '-controllers'], check=True)
subprocess.run([sys.executable, str(HERE / 'prepare_guest_sandbox.py'),
                '--label', label + '-sysfs'], check=True)
runtime('run-file', '--script', str(HERE / 'configure_podman_user_session.sh'), suffix='session')
runtime('run-file', '--script', str(HERE / 'install_guest_podman_oom_wrapper.sh'), suffix='oom-launchers')
runtime('run', '--command', 'set -e; podman info --format=json >/dev/null; '
        'podman-rootless info --format=json >/dev/null; echo PODMAN_GUEST_PROFILE_READY', suffix='ready')
print('Guest ready. In Ubuntu: podman ... or podman-rootless ...')
