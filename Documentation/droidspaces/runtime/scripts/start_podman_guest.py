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
from device_runtime import device, guest_info, read_root

HERE = Path(__file__).resolve().parent
ksunext_case = ''
ksunext_result = HERE.parent / 'artifacts/droidspaces/ksunext-boot-result.json'
if ksunext_result.exists():
    checked = json.loads(ksunext_result.read_text())
    if checked['kernel'] != '4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2-lr2-ksu3' or not re.fullmatch(r'[a-f0-9]{64}', checked['boot_sha256']):
        raise RuntimeError('Unexpected KSU candidate acceptance record')
    ksunext_case = checked['kernel'] + ') expected=' + checked['boot_sha256'] + ' ;; '
# A boot-only verification record permits guest startup for the functional tests.
# It does not count as complete runtime acceptance or permit the next deployment.
for stage in ('utilities', 'bbr', 'checkpoint', 'network', 'io', 'resources', 'dualio', 'harden1', 'harden2-cpuset', 'harden2-cpuset-fix', 'harden2-cpuset-decay', 'harden2-cpuset-stats', 'harden3-binfmt', 'harden3-binfmt-fix', 'harden4-seccomp-notify', 'harden5-binder-freeze', 'harden5-binder-freeze-fix', 'android16-group-psi', 'android16-group-psi-reclaim-fix'):
    result = HERE.parent / f'artifacts/droidspaces/extensions-{stage}-boot-result.json'
    if not result.exists():
        continue
    checked = json.loads(result.read_text())
    packaging = json.loads((HERE.parent / f'artifacts/droidspaces/boot-images/ext-{stage}-candidate-check.json').read_text())
    suffix={'harden2-cpuset':'h2cp','harden2-cpuset-fix':'h2cp2','harden2-cpuset-decay':'h2cp3','harden2-cpuset-stats':'h2cp4','harden3-binfmt':'h3bm','harden3-binfmt-fix':'h3bm2','harden4-seccomp-notify':'h4sn','harden5-binder-freeze':'h5bf','harden5-binder-freeze-fix':'h5bf2','android16-group-psi':'a16ps','android16-group-psi-reclaim-fix':'a16pf'}.get(stage,stage)
    expected_release = '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-' + suffix
    if (checked['kernel'] != expected_release or not checked.get('running_config_matches') or
            checked['boot_sha256'] != packaging['candidate_sha256'] or
            not re.fullmatch(r'[a-f0-9]{64}', checked['boot_sha256'])):
        raise RuntimeError('Unexpected extension boot verification record')
    ksunext_case += checked['kernel'] + ') expected=' + checked['boot_sha256'] + ' ;; '
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
    started = runtime('start', '--auto-cgroup', suffix='start', accepted=(0, 255))
    if started == 255:
        # Entry streams may close after the background guest was started.
        # Observe the resulting state; never replay a partly executed start.
        runtime('info', suffix='start-observed')
# DroidSpaces returns before systemd finishes boot. Its initial tmpfiles setup
# can remove a prematurely launched transient probe's result directory.
runtime('run', '--command', 'set -e; for attempt in $(seq 1 35); do '
        'state=$(systemctl is-system-running 2>/dev/null || true); '
        'if test "$state" = running; then echo GUEST_SYSTEMD_BOOT_READY; exit 0; fi; '
        'sleep 1; done; systemctl --failed --no-legend; exit 1', suffix='boot-ready')
runtime('run', '--command', 'set -e; rootful=$(podman ps -q); rootless=$(podman-rootless ps -q); '
        'test -z "$rootful"; test -z "$rootless"; echo NO_ACTIVE_PODMAN_WORKLOADS',
        '--guest-service', suffix='workloads')
subprocess.run([sys.executable, str(HERE / 'delegate_guest_cgroup_v2.py'),
                '--label', label + '-controllers'], check=True)
subprocess.run([sys.executable, str(HERE / 'prepare_guest_sandbox.py'),
                '--label', label + '-sysfs'], check=True)
runtime('run-file', '--script', str(HERE / 'configure_podman_user_session.sh'), '--guest-service', suffix='session')
runtime('run-file', '--script', str(HERE / 'install_guest_podman_oom_wrapper.sh'), '--guest-service', suffix='oom-launchers')
adb = device()
current_kernel = read_root(adb, 'uname -r').decode().strip()
if current_kernel.endswith(('ext-resources', 'ext-dualio', 'ext-harden1')):
    runtime('run-file', '--script', str(HERE / 'install_guest_cpu_runtime.sh'), '--guest-service', suffix='cpu-runtime')
    runtime('run-file', '--script', str(HERE / 'prepare_guest_cpu_mounts.sh'), '--guest-service', suffix='cpu-leaf-propagation')
if current_kernel.endswith(('ext-resources', 'ext-dualio', 'ext-harden1', 'ext-h2cp', 'ext-h2cp2', 'ext-h2cp3', 'ext-h2cp4', 'ext-h3bm', 'ext-h3bm2', 'ext-h4sn', 'ext-h5bf', 'ext-h5bf2', 'ext-a16ps', 'ext-a16pf')):
    installed_policy = '/proc/' + str(guest_info(adb)['pid']) + '/root/etc/rmx1931/resource-policies.json'
    if read_root(adb, 'if test -f ' + installed_policy + '; then echo installed; fi').strip() == b'installed':
        subprocess.run([sys.executable, str(HERE / 'install_guest_resource_policy.py'),
                        '--ensure', '--label', label + '-persistent-policy'], check=True)
if current_kernel.endswith(('ext-checkpoint', 'ext-network', 'ext-io', 'ext-resources', 'ext-dualio', 'ext-harden1', 'ext-h2cp', 'ext-h2cp2', 'ext-h2cp3', 'ext-h2cp4', 'ext-h3bm', 'ext-h3bm2', 'ext-h4sn', 'ext-h5bf', 'ext-h5bf2', 'ext-a16ps', 'ext-a16pf')):
    guest_pid = guest_info(adb)['pid']
    for namespace in ('pid', 'ipc', 'mnt'):
        if read_root(adb, 'readlink /proc/1/ns/' + namespace) == read_root(adb, 'readlink /proc/' + str(guest_pid) + '/ns/' + namespace):
            raise RuntimeError('Checkpoint sysctls require distinct guest namespaces')
    # The script exposes only namespace-local PID/IPC checkpoint ID controls.
    runtime('run-file', '--script', str(HERE / 'prepare_guest_checkpoint.sh'), '--guest-service', suffix='checkpoint-sysctl')
runtime('run', '--command', 'set -e; podman info --format=json >/dev/null; '
        'podman-rootless info --format=json >/dev/null; echo PODMAN_GUEST_PROFILE_READY', '--guest-service', suffix='ready')
print('Guest ready. In Ubuntu: podman ... or podman-rootless ...')
