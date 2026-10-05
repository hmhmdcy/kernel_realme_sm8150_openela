#!/usr/bin/env python3
"""Install or ensure the Android-root policy server in the current guest.

The full V1 CPU hierarchy is mounted only in the server's private mount
namespace. The normal filtered guest and unrelated Android groups are retained.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root

LEGACY_WRAPPERS = {'f44643b25d86b62b749e1d63a421ccc6c21318f6ca21a4d5df23424b875235f9',
                   'bd0c90e98c93b83fc420c010166a7476b43da017d4ac0d008b6d795b14e305d9'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--ensure', action='store_true', help='Require installed code; restart only a verified absent server')
    parser.add_argument('--upgrade-from', type=Path, help='Allow exactly the source digests recorded by a previous local installer attempt')
    args = parser.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.label)
    path = ROOT / 'artifacts/droidspaces/runtime' / (args.label + '.json')
    assert not path.exists(), 'Use a fresh evidence label'
    adb = device()
    identity = read_identity(adb)
    assert identity['kernel'].endswith(('-ext-harden1', '-ext-h2cp', '-ext-h2cp2', '-ext-h2cp3', '-ext-h2cp4', '-ext-h3bm', '-ext-h3bm2', '-ext-h4sn', '-ext-h5bf', '-ext-h5bf2', '-ext-a16ps', '-ext-a16pf')), 'Unsupported lifecycle/native CPU candidate'
    assert read_root(adb, 'getenforce').strip() == b'Enforcing'
    init = guest_info(adb)['pid']
    root = '/proc/' + str(init) + '/root'
    for ns in ('pid', 'mnt', 'ipc'):
        assert read_root(adb, 'readlink /proc/1/ns/' + ns) != read_root(adb, 'readlink /proc/' + str(init) + '/ns/' + ns)
    sources = {name: (ROOT / 'scripts' / name).read_bytes().replace(b'\r\n', b'\n')
               for name in ('rmx1931_resource_policy.py', 'oci_resource_entry.py', 'rmx1931_pressure.py')}
    hashes = {name: hashlib.sha256(content).hexdigest() for name, content in sources.items()}
    previous = {}
    if args.upgrade_from:
        upgrade = args.upgrade_from.resolve()
        assert upgrade.parent == path.parent.resolve()
        prior = json.loads(upgrade.read_text(encoding='utf-8'))
        assert prior['action'] == 'install-resource-policy'
        assert prior['kernel'].endswith(('-ext-harden1', '-ext-h2cp', '-ext-h2cp2', '-ext-h2cp3', '-ext-h2cp4', '-ext-h3bm', '-ext-h3bm2', '-ext-h4sn', '-ext-h5bf', '-ext-h5bf2', '-ext-a16ps', '-ext-a16pf'))
        previous = prior['source_sha256']
    report = {'action': 'install-resource-policy', 'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              **identity, 'guest_pid': init, 'source_sha256': hashes, 'completed': False,
              'guest_filters_changed': False, 'full_cpu_mount_private': True, 'phases': []}

    def mutate(command, timeout=30):
        result = subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, text=True, timeout=timeout)
        report['phases'].append({'command': command, 'returncode': result.returncode,
                                 'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode:
            raise RuntimeError('Inspect partial policy installation before retry: ' + result.stderr)
        return result.stdout.strip()

    def guest(command):
        return mutate(shlex.join([DS, '--name=' + NAME, 'run', '/bin/sh', '-c', command]))

    def digest(remote):
        output = read_root(adb, 'if test -f ' + remote + '; then sha256sum ' + remote + '; else echo absent; fi').decode().strip()
        return output.split()[0]

    try:
        assert read_root(adb, 'test -f ' + root + '/etc/droidspaces && echo isolated').strip() == b'isolated'
        mutate('set -e; for d in ' + root + '/usr/local/libexec ' + root + '/etc/rmx1931 ' + root +
               '/var/lib/rmx1931-policy ' + root + '/var/lib/rmx1931-policy/containers ' + root +
               '/run/rmx1931-policy; do test ! -L "$d"; mkdir -p "$d"; chown 0:0 "$d"; chmod 755 "$d"; done; '
               'test ! -L ' + root + '/run/rmx1931-policy/cpu; mkdir -p ' + root + '/run/rmx1931-policy/cpu; '
               'chown 0:0 ' + root + '/run/rmx1931-policy/cpu; chmod 700 ' + root + '/run/rmx1931-policy/cpu')
        targets = [('rmx1931_resource_policy.py', '/usr/local/libexec/rmx1931_resource_policy.py'),
                   ('rmx1931_pressure.py', '/usr/local/bin/rmx1931-pressure'),
                   ('oci_resource_entry.py', '/usr/local/libexec/rmx1931-oci-crun'),
                   ('oci_resource_entry.py', '/usr/local/libexec/rmx1931-oci-runc')]
        for name, target in targets:
            remote = root + target
            observed = digest(remote)
            if args.ensure:
                assert observed == hashes[name], 'Installed policy source changed: ' + target
                continue
            allowed = {hashes[name], previous.get(name), 'absent'}
            if name == 'oci_resource_entry.py':
                allowed |= LEGACY_WRAPPERS
            assert observed in allowed, 'Unreviewed existing runtime source: ' + target
            if observed == hashes[name]:
                continue
            local = ROOT / 'tools/droidspaces' / (args.label + '-' + name)
            local.write_bytes(sources[name])
            staging = '/data/local/tmp/' + args.label + '-' + name
            subprocess.run(adb + ['push', str(local), staging], capture_output=True, check=True, timeout=30)
            mutate('set -e; test ! -L ' + remote + '; cp ' + staging + ' ' + remote +
                   '; chown 0:0 ' + remote + '; chmod 755 ' + remote)
            assert digest(remote) == hashes[name]
        policy = root + '/etc/rmx1931/resource-policies.json'
        if digest(policy) == 'absent':
            assert not args.ensure
            mutate('set -e; test ! -L ' + policy + '; printf ' + shlex.quote('{"version":1,"profiles":{}}\n') +
                   ' > ' + policy + '; chown 0:0 ' + policy + '; chmod 644 ' + policy)
        guest('set -e; /usr/bin/python3 /usr/local/libexec/rmx1931_resource_policy.py validate; '
              'test ! -L /usr/local/bin/rmx1931-policy; '
              'if test ! -e /usr/local/bin/rmx1931-policy; then '
              'printf \'#!/bin/sh\nexec /usr/bin/python3 /usr/local/libexec/rmx1931_resource_policy.py "$@"\n\' '
              '> /usr/local/bin/rmx1931-policy; chmod 755 /usr/local/bin/rmx1931-policy; fi')
        socket = root + '/run/rmx1931-policy/control.sock'
        present = read_root(adb, 'if test -S ' + socket + '; then echo socket; fi').strip() == b'socket'
        if present:
            health = json.loads(guest('/usr/bin/python3 /usr/local/libexec/rmx1931_resource_policy.py ping'))
            assert health['boot_id'] == identity['boot_id']
            assert health['pid_namespace'] == read_root(adb, 'readlink /proc/' + str(init) + '/ns/pid').decode().strip()
            if not args.ensure and previous:
                # Stop only the ping-verified, current guest server before a
                # reviewed source upgrade; no broad process-name termination.
                guest('kill -TERM ' + str(health['pid']))
                for _ in range(30):
                    if read_root(adb, 'if test -S ' + socket + '; then echo socket; fi').strip() != b'socket':
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError('Previous policy server has not stopped')
                present = False
        if not present:
            group = '/sys/fs/cgroup/droidspaces/' + NAME + '/resource-policy-server'
            mutate('set -e; test ! -L ' + group + '; mkdir -p ' + group + '; '
                   'test -z "$(cat ' + group + '/cgroup.procs)"; '
                   'printf "134217728\\n" > ' + group + '/memory.max; printf "64\\n" > ' + group + '/pids.max')
            # Mount namespace is privatized before exposing the full CPU tree.
            inner = ('set -e; printf "0\\n" > /proc/self/oom_score_adj; '
                     'test -f /etc/droidspaces; '
                     'test "$(sed -n "s/^Seccomp:[[:space:]]*//p" /proc/self/status)" = 0; '
                     'if ! grep -qw cpu /sys/fs/cgroup/cgroup.controllers; then '
                     'mount -t cgroup -o cpu cpu /run/rmx1931-policy/cpu; fi; '
                     'exec /usr/bin/python3 /usr/local/libexec/rmx1931_resource_policy.py serve '
                     '--cpu-root /run/rmx1931-policy/cpu --detach')
            entry = shlex.join([root + '/usr/bin/busybox', 'nsenter', '-t', str(init), '-m', '-p', '-n', '-i', '-u',
                                '-r' + root, '--', '/usr/bin/env', '-i', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                'LANG=C.UTF-8', '/usr/bin/unshare', '--mount', '--propagation', 'private',
                                '/bin/sh', '-c', inner])
            log = root + '/run/rmx1931-policy/server.log'
            child = 'set -e; echo $$ > ' + group + '/cgroup.procs; exec ' + entry
            mutate('/system/bin/sh -c ' + shlex.quote(child) + ' > ' + log +
                   ' 2>&1 < /dev/null')
            for _ in range(50):
                if read_root(adb, 'if test -S ' + socket + '; then echo socket; fi').strip() == b'socket':
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('Server did not become ready: ' + read_root(adb, 'cat ' + log).decode())
        health = json.loads(guest('/usr/bin/python3 /usr/local/libexec/rmx1931_resource_policy.py ping'))
        assert health['boot_id'] == identity['boot_id']
        assert health['pid_namespace'] == read_root(adb, 'readlink /proc/' + str(init) + '/ns/pid').decode().strip()
        # The full tree must not be mounted in the ordinary guest namespace.
        guest('set -e; test ! -e /run/rmx1931-policy/cpu/cpu.cfs_quota_us; '
              'test "$(sed -n "s/^Seccomp:[[:space:]]*//p" /proc/1/status)" = 2; '
              'echo POLICY_SERVER_PRIVATE_CPU_AND_FILTERS_PASS')
        report['server'] = health
        report['cpu_backend'] = health.get('cpu_backend', 'v1')
        report['legacy_cpu_mount_used'] = report['cpu_backend'] == 'v1'
        report['completed'] = True
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        report['end_identity'] = read_identity(adb)
        if report['end_identity'] != identity:
            report['completed'] = False
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2, ensure_ascii=False), flush=True)
    assert report['completed']


if __name__ == '__main__':
    main()
