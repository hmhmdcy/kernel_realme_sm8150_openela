#!/usr/bin/env python3
"""Run a reviewed fixture via Android root inside the existing isolated guest.

The regular guest and its workloads keep their filters. Only this operator and
its descendants enter a fresh guest-owned cgroup through an unfiltered entry.
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
from device_runtime import device, guest_info, read_identity, read_root, ROOT, NAME

DURABLE_LAUNCHER = r'''import os, subprocess, sys, traceback
from pathlib import Path
work = Path(sys.argv[1])
reader, writer = os.pipe()
pid = os.fork()
if pid:
    os.close(writer)
    ready = os.read(reader, 1)
    os.close(reader)
    if ready != b'1':
        raise SystemExit(125)
    print('OWNED_DURABLE_FIXTURE_LAUNCHED', flush=True)
    raise SystemExit(0)
os.close(reader)
try:
    os.setsid()
    for descriptor, path, flags in [(0, '/dev/null', os.O_RDONLY),
            (1, str(work / 'stdout'), os.O_WRONLY | os.O_CREAT | os.O_TRUNC),
            (2, str(work / 'stderr'), os.O_WRONLY | os.O_CREAT | os.O_TRUNC)]:
        fd = os.open(path, flags, 0o600)
        os.dup2(fd, descriptor)
        if fd != descriptor:
            os.close(fd)
    (work / 'launcher.pid').write_text(str(os.getpid()) + '\n')
    os.write(writer, b'1')
    os.close(writer)
    result = subprocess.run(['/bin/sh', str(work / 'probe.sh'), *sys.argv[2:]])
    temporary = work / 'status.tmp'
    temporary.write_text(str(result.returncode) + '\n')
    temporary.replace(work / 'status')
except BaseException:
    traceback.print_exc()
    (work / 'status').write_text('125\n')
finally:
    os._exit(0)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script', type=Path, required=True)
    parser.add_argument('--script-arg', action='append', default=[])
    parser.add_argument('--label', required=True)
    parser.add_argument('--timeout', type=int, default=90)
    parser.add_argument('--durable', action='store_true', help='Detach the owned launcher from ADB and collect its explicit status; never replay on a stream closure')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', args.label):
        raise RuntimeError('Invalid label')
    source = args.script.resolve()
    if source.suffix != '.sh' or not source.is_relative_to(ROOT / 'scripts'):
        raise RuntimeError('Only reviewed workspace shell scripts may run')
    report_path = ROOT / 'artifacts/droidspaces/runtime' / (args.label + '.json')
    if report_path.exists():
        raise RuntimeError('Do not overwrite privileged fixture evidence')
    adb = device()
    identity = read_identity(adb)
    pid = guest_info(adb)['pid']
    guest_root = '/proc/' + str(pid) + '/root'
    namespaces = {}
    for name in ('pid', 'ipc', 'mnt', 'net', 'uts'):
        host = read_root(adb, 'readlink /proc/1/ns/' + name).decode().strip()
        guest = read_root(adb, 'readlink /proc/' + str(pid) + '/ns/' + name).decode().strip()
        if host == guest:
            raise RuntimeError('Distinct guest namespace required: ' + name)
        namespaces[name] = {'host': host, 'guest': guest}
    if read_root(adb, 'getenforce').strip() != b'Enforcing':
        raise RuntimeError('Android SELinux must remain Enforcing')
    content = source.read_bytes().replace(b'\r\n', b'\n')
    digest = hashlib.sha256(content).hexdigest()
    local = ROOT / 'tools/droidspaces' / (args.label + '.sh')
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(content)
    staging = '/data/local/tmp/rmx1931-' + args.label + '.sh'
    subprocess.run(adb + ['push', str(local), staging], capture_output=True, check=True, timeout=30)
    launcher_staging = None
    if args.durable:
        launcher_local = ROOT / 'tools/droidspaces' / (args.label + '-launcher.py')
        launcher_local.write_bytes(DURABLE_LAUNCHER.encode())
        launcher_staging = '/data/local/tmp/rmx1931-' + args.label + '-launcher.py'
        subprocess.run(adb + ['push', str(launcher_local), launcher_staging], capture_output=True, check=True, timeout=30)
    work = '/tmp/rmx1931-tests/privileged-' + args.label
    host_work = guest_root + work
    group = '/sys/fs/cgroup/droidspaces/' + NAME + '/privileged-' + args.label

    def mutate(command, timeout=30):
        return subprocess.run(adb + ['exec-out', 'su', '-c', command], capture_output=True, timeout=timeout)

    setup = ('set -e; test -f ' + guest_root + '/etc/droidspaces; test ! -L ' + guest_root + '/tmp/rmx1931-tests; '
             'mkdir -p ' + guest_root + '/tmp/rmx1931-tests; test ! -e ' + host_work + '; test ! -L ' + host_work + '; '
             'mkdir -m 700 ' + host_work + '; cp ' + staging + ' ' + host_work + '/probe.sh; '
             'test ! -e ' + group + '; mkdir ' + group)
    created = mutate(setup)
    if created.returncode:
        raise RuntimeError('Inspect partial setup before retry: ' + created.stderr.decode(errors='replace'))
    if read_root(adb, 'sha256sum ' + host_work + '/probe.sh').decode().split()[0] != digest:
        raise RuntimeError('Fixture transfer digest changed')
    if args.durable:
        copied = mutate('cp ' + launcher_staging + ' ' + host_work + '/launcher.py; chmod 600 ' + host_work + '/launcher.py')
        if copied.returncode or read_root(adb, 'sha256sum ' + host_work + '/launcher.py').decode().split()[0] != hashlib.sha256(DURABLE_LAUNCHER.encode()).hexdigest():
            raise RuntimeError('Durable launcher transfer changed')
    fixture_entry = (['/usr/bin/python3', work + '/launcher.py', work, *args.script_arg] if args.durable else
                     ['/bin/sh', work + '/probe.sh', *args.script_arg])
    inner = ('set -e; exec 3<&-; test -f /etc/droidspaces; '
             'test "$(sed -n "s/^Seccomp:[[:space:]]*//p" /proc/self/status)" = 0; '
             'printf "0\\n" > /proc/self/oom_score_adj; ulimit -l 65536; cd /root; '
             'exec ' + shlex.join(['/usr/bin/nsenter', '--cgroup=/proc/1/ns/cgroup', '--', *fixture_entry]))
    command = shlex.join([guest_root + '/usr/bin/busybox', 'nsenter', '-t', str(pid),
                         '-m', '-p', '-n', '-i', '-u', '-r' + guest_root, '--', '/usr/bin/env', '-i',
                         'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                         'USER=root', 'LOGNAME=root', 'LANG=C.UTF-8', '/bin/sh', '-c', inner])
    launch = ('echo $$ > ' + group + '/cgroup.procs; ' + command +
              '; code=$?; printf "%s\\n" "$code" > ' + host_work + '/status')
    timed_out = False
    entry_returncode = None
    launcher_pid = None
    launcher_starttime = None
    pending = report_path.with_name(args.label + '-privileged-launch.json')
    if pending.exists():
        raise RuntimeError('Inspect the existing privileged launch; do not replay')
    pending.write_text(json.dumps({'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
        **identity, 'guest_pid': pid, 'script_source_sha256': digest, 'namespaces': namespaces,
        'operator_cgroup': group, 'work': work, 'durable_launcher': args.durable,
        'phase': 'prepared; next operation launches once'}, indent=2) + '\n', encoding='utf-8')
    if args.durable:
        try:
            # Foreground handshake proves the child detached before the ADB
            # entry returns; Android su can terminate shell background jobs.
            entry = mutate('echo $$ > ' + group + '/cgroup.procs; ' + command, timeout=20)
            entry_returncode = entry.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            status = read_root(adb, 'if test -f ' + host_work + '/status; then cat ' + host_work + '/status; fi').strip()
            if status.isdigit():
                break
            value = read_root(adb, 'if test -f ' + host_work + '/launcher.pid; then cat ' + host_work + '/launcher.pid; fi').strip()
            if value.isdigit():
                launcher_pid = int(value)
                pid_path = guest_root + '/proc/' + str(launcher_pid)
                stat = read_root(adb, 'if test -f ' + pid_path + '/stat; then cat ' + pid_path + '/stat; fi').decode().strip()
                if not stat:
                    # A status write can race with the last process observation.
                    status = read_root(adb, 'if test -f ' + host_work + '/status; then cat ' + host_work + '/status; fi').strip()
                    break
                fields = stat.rsplit(')', 1)[-1].split()
                if len(fields) < 20:
                    # A stream can close with exit 0 and a partial stat. A
                    # finished status remains authoritative; never replay.
                    status = read_root(adb, 'if test -f ' + host_work + '/status; then cat ' + host_work + '/status; fi').strip()
                    if status.isdigit():
                        break
                    time.sleep(1)
                    continue
                starttime = fields[19]
                if launcher_starttime is not None and launcher_starttime != starttime:
                    raise RuntimeError('Owned launcher PID was reused; do not replay')
                launcher_starttime = starttime
            time.sleep(1)
    else:
        try:
            entry = mutate('(' + launch + ') > ' + host_work + '/stdout 2> ' + host_work + '/stderr < /dev/null',
                           timeout=args.timeout)
            entry_returncode = entry.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
    status = read_root(adb, 'if test -f ' + host_work + '/status; then cat ' + host_work + '/status; fi').strip()
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), **identity,
              'guest_pid': pid, 'action': 'privileged-guest-fixture', 'command': command,
              'script_source_sha256': digest, 'namespaces': namespaces, 'operator_cgroup': group,
              'returncode': int(status) if status.isdigit() else 124,
              'durable_launcher': args.durable, 'launcher_pid': launcher_pid,
              'launcher_pid_view': 'guest' if args.durable else None,
              'durable_launcher_sha256': hashlib.sha256(DURABLE_LAUNCHER.encode()).hexdigest() if args.durable else None,
              'launcher_starttime': launcher_starttime, 'entry_returncode': entry_returncode,
              'entry_timed_out': timed_out, 'guest_filters_changed': False,
              'stdout': read_root(adb, 'cat ' + host_work + '/stdout').decode(errors='replace'),
              'stderr': read_root(adb, 'cat ' + host_work + '/stderr').decode(errors='replace'),
              'cleanup_errors': []}
    if status.isdigit():
        if args.durable:
            for attempt in range(20):
                if not read_root(adb, 'cat ' + group + '/cgroup.procs').strip():
                    break
                time.sleep(.1)
        cleaned = mutate('test -z "$(cat ' + group + '/cgroup.procs)" && rmdir ' + group)
        if cleaned.returncode:
            report['cleanup_errors'].append(cleaned.stderr.decode(errors='replace'))
            report['returncode'] = 125
    else:
        report['stderr'] += '\nTask still unverified; inspect existing operator cgroup/status before retrying.\n'
    report['end_identity'] = read_identity(adb)
    if report['end_identity'] != identity:
        report['returncode'] = 125
        report['stderr'] += '\nPhone rebooted during the fixture.\n'
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2), flush=True)
    raise SystemExit(report['returncode'])


if __name__ == '__main__':
    main()
