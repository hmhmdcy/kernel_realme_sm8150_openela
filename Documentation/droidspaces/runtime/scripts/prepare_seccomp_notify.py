#!/usr/bin/env python3
"""Adapt fixed Linux 5.10 stable user notification to the accepted 4.14 tree."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
from audit_lowrisk_kernel import config, symbols

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
REF = ROOT / 'references/seccomp-notify-upstream'
BASE = ART / 'kernel-ext-harden3-binfmt-fix'
DEST = ART / 'kernel-ext-harden4-seccomp-notify'
STAGE = 'harden4-seccomp-notify'
RELEASE = '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h4sn'
COMMIT = '587461ddf5d522bfcb50ebd55078c0dac37be496'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def section(text, start, end):
    assert text.count(start) == 1 and text.count(end) >= 1, (start, end)
    begin = text.index(start)
    return text[begin:text.index(end, begin + len(start))]


def replace(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new)


def derive(old, upstream):
    text = old
    extra = '''#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/lockdep.h>
#include <linux/poll.h>
#include <linux/completion.h>
#include <linux/semaphore.h>
#include <linux/random.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/netprio_cgroup.h>
#include <net/cls_cgroup.h>
'''
    extra = ''.join(line + '\n' for line in extra.splitlines() if line not in text)
    text = replace(text, '#include <linux/uaccess.h>\n', '#include <linux/uaccess.h>\n' + extra)
    start = '/**\n * struct seccomp_filter'
    end = '/* Limit any path through the tree'
    notification_types = section(upstream, '/*\n * When SECCOMP_IOCTL_NOTIF_ID_VALID', end)
    text = replace(text, section(text, start, end), notification_types)
    lifetime = section(upstream, 'static inline void seccomp_filter_free', '/**\n * seccomp_filter_release')
    anchor = '/**\n * seccomp_sync_threads'
    text = replace(text, anchor, lifetime + anchor)
    # Keep 4.14 get/put signatures used by fork, free_task and KernelSU. Only
    # the listener/ptrace reference helper increments refs without users.
    getters = section(upstream, 'static void __get_seccomp_filter', 'static void seccomp_init_siginfo')
    getters += '''/* Preserve the 4.14 task-release API (caller owns detachment). */
void put_seccomp_filter(struct task_struct *tsk)
{
\t__seccomp_filter_release(tsk->seccomp.filter);
}

'''
    text = replace(text, section(text, 'static void __get_seccomp_filter', 'static void seccomp_init_siginfo'), getters)
    text = replace(text, '\trefcount_set(&sfilter->usage, 1);',
                   '\tmutex_init(&sfilter->notify_lock);\n\trefcount_set(&sfilter->refs, 1);\n'
                   '\trefcount_set(&sfilter->users, 1);\n\tinit_waitqueue_head(&sfilter->wqh);')
    attach_start = 'static long seccomp_attach_filter'
    attach_end = 'static void __get_seccomp_filter'
    attach = section(text, attach_start, attach_end)
    attach = replace(attach, '\t\tif (ret)\n\t\t\treturn ret;',
                     '\t\tif (ret)\n\t\t\treturn flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH ? -ESRCH : ret;')
    text = replace(text, section(text, attach_start, attach_end), attach)
    # Match 4.14 SCM_RIGHTS checks/counting, with the target executing the
    # operation. Existing replace_fd handles references and RLIMIT_NOFILE.
    fd_helpers = '''/* 4.14 equivalent of check_zeroed_user: 1 zero, 0 nonzero, -EFAULT. */
static int seccomp_check_zeroed_user(const void __user *user, unsigned int size)
{
\tunsigned int offset = 0;
\tunsigned char bytes[64];
\twhile (offset < size) {
\t\tunsigned int count = min_t(unsigned int, sizeof(bytes), size - offset);
\t\tif (copy_from_user(bytes, (const char __user *)user + offset, count))
\t\t\treturn -EFAULT;
\t\tif (memchr_inv(bytes, 0, count))
\t\t\treturn 0;
\t\toffset += count;
\t}
\treturn 1;
}

static int seccomp_receive_fd(int fd, struct file *file, unsigned int flags)
{
\tint ret, error;
#ifdef CONFIG_NET
\tstruct socket *sock;
\tint socket_error;
#endif
\terror = security_file_receive(file);
\tif (error)
\t\treturn error;
\tif (fd < 0) {
\t\tret = get_unused_fd_flags(flags);
\t\tif (ret < 0)
\t\t\treturn ret;
\t\tfd_install(ret, get_file(file));
\t} else {
\t\tret = replace_fd(fd, file, flags);
\t\tif (ret < 0)
\t\t\treturn ret;
\t}
#ifdef CONFIG_NET
\tsock = sock_from_file(file, &socket_error);
\tif (sock) {
\t\tsock_update_netprioidx(&sock->sk->sk_cgrp_data);
\t\tsock_update_classid(&sock->sk->sk_cgrp_data);
\t}
#endif
\treturn ret;
}

/* Extensible addfd ABI: reject nonzero future bytes, as copy_struct does. */
static int seccomp_copy_addfd(struct seccomp_notif_addfd *arg,
\t\t\t     const void __user *user, unsigned int size)
{
\tunsigned int copied = min_t(unsigned int, size, sizeof(*arg));
\tunsigned int offset = sizeof(*arg);
\tunsigned char tail[64];
\tmemset(arg, 0, sizeof(*arg));
\tif (copy_from_user(arg, user, copied))
\t\treturn -EFAULT;
\twhile (offset < size) {
\t\tunsigned int bytes = min_t(unsigned int, sizeof(tail), size - offset);
\t\tif (copy_from_user(tail, (const char __user *)user + offset, bytes))
\t\t\treturn -EFAULT;
\t\tif (memchr_inv(tail, 0, bytes))
\t\t\treturn -E2BIG;
\t\toffset += bytes;
\t}
\treturn 0;
}

'''
    core = section(upstream, 'static u64 seccomp_next_notify_id', 'static int __seccomp_filter')
    core = core.replace('receive_fd(addfd->file, addfd->flags)', 'seccomp_receive_fd(-1, addfd->file, addfd->flags)')
    core = core.replace('receive_fd_replace(addfd->fd, addfd->file, addfd->flags)',
                        'seccomp_receive_fd(addfd->fd, addfd->file, addfd->flags)')
    assert 'receive_fd_replace' not in core and 'ret = receive_fd(' not in core
    core = core.replace('current_pt_regs()', 'task_pt_regs(current)')
    text = replace(text, '#ifdef CONFIG_SECCOMP_FILTER\nstatic int __seccomp_filter',
                   '#ifdef CONFIG_SECCOMP_FILTER\n' + fd_helpers + core + 'static int __seccomp_filter')
    # Keep seccomp_data on the syscall stack for the full notification lifetime.
    filter_start = 'static int __seccomp_filter(int this_syscall'
    index = text.index(filter_start)
    first_end = text.index('\n#else\nstatic int __seccomp_filter', index)
    block = text[index:first_end]
    block = replace(block, '\tint data;', '\tint data;\n\tstruct seccomp_data sd_local;')
    block = replace(block, '\tfilter_ret = seccomp_run_filters(sd, &match);',
                    '\tif (!sd) {\n\t\tpopulate_seccomp_data(&sd_local);\n\t\tsd = &sd_local;\n\t}\n\n'
                    '\tfilter_ret = seccomp_run_filters(sd, &match);')
    block = replace(block, '\tcase SECCOMP_RET_LOG:',
                    '\tcase SECCOMP_RET_USER_NOTIF:\n\t\tif (seccomp_do_user_notification(this_syscall, match, sd))\n'
                    '\t\t\tgoto skip;\n\t\treturn 0;\n\n\tcase SECCOMP_RET_LOG:')
    text = text[:index] + block + text[first_end:]
    # Listener methods and NEW_LISTENER/TSYNC_ESRCH error cleanup are copied
    # together from stable, retaining reference and locking dependencies.
    methods = section(upstream, 'static void seccomp_notify_free', '\n#else\nstatic inline long seccomp_set_mode_filter')
    methods = methods.replace('__poll_t', 'unsigned int')
    methods = replace(methods, 'check_zeroed_user(buf, sizeof(unotif))',
                      'seccomp_check_zeroed_user(buf, sizeof(unotif))')
    methods = replace(methods, 'copy_struct_from_user(&addfd, sizeof(addfd), uaddfd, size)',
                      'seccomp_copy_addfd(&addfd, uaddfd, size)')
    old_methods = section(text, 'static long seccomp_set_mode_filter', '\n#else\nstatic inline long seccomp_set_mode_filter')
    text = replace(text, old_methods, methods)
    text = replace(text, section(text, 'static long seccomp_get_action_avail', '\nSYSCALL_DEFINE3(seccomp'),
                   section(upstream, 'static long seccomp_get_action_avail', '\nSYSCALL_DEFINE3(seccomp'))
    # Preserve the existing 4.14 sys_seccomp prototype/export declaration.
    # GET_NOTIF_SIZES writes through this argument; const is historical ABI
    # annotation only, as with existing output-pointer syscalls.
    text = replace(text, 'return do_seccomp(op, flags, uargs);',
                   'return do_seccomp(op, flags, (void __user *)uargs);')
    text = replace(text, '#define SECCOMP_LOG_ALLOW\t\t(1 << 6)',
                   '#define SECCOMP_LOG_ALLOW\t\t(1 << 6)\n#define SECCOMP_LOG_USER_NOTIF\t\t(1 << 7)')
    text = replace(text, '\t\t\t\t    SECCOMP_LOG_ERRNO |',
                   '\t\t\t\t    SECCOMP_LOG_ERRNO |\n\t\t\t\t    SECCOMP_LOG_USER_NOTIF |')
    log_start = 'static inline void seccomp_log'
    log_end = '/*\n * Secure computing mode 1'
    logging = section(text, log_start, log_end)
    logging = replace(logging, '\tcase SECCOMP_RET_LOG:',
                      '\tcase SECCOMP_RET_USER_NOTIF:\n\t\tlog = requested && seccomp_actions_logged & SECCOMP_LOG_USER_NOTIF;\n'
                      '\t\tbreak;\n\tcase SECCOMP_RET_LOG:')
    text = replace(text, section(text, log_start, log_end), logging)
    names_start = 'static const char seccomp_actions_avail[]'
    names_end = 'static bool seccomp_names_from_actions_logged'
    text = replace(text, section(text, names_start, names_end), section(upstream, names_start, names_end))
    text = replace(text, '#define SECCOMP_RET_TRACE_NAME',
                   '#define SECCOMP_RET_USER_NOTIF_NAME\t"user_notif"\n#define SECCOMP_RET_TRACE_NAME')
    for flag in ('IN', 'RDNORM', 'OUT', 'WRNORM', 'ERR', 'HUP'):
        text = text.replace('EPOLL' + flag, 'POLL' + flag)
    assert '->usage' not in text and 'filter_count' not in text
    assert 'copy_struct_from_user(' not in text and 'current_pt_regs()' not in text
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--after-build', action='store_true')
    args = parser.parse_args()
    prior = read(BASE / 'audit.json')
    accepted = ART / 'binfmt-stage4-acceptance.json'
    baseline = ART / 'runtime/seccomp-notify-baseline-h3bm2-20261004.json'
    assert read(accepted)['complete_stage_4_accepted'] and prior['build_audit_passed']
    missing = read(baseline)
    assert missing['returncode'] == 0 and 'SECCOMP_NOTIFY_BASELINE_MISSING' in missing['stdout']
    assert missing['end_identity'] == {k: missing[k] for k in ('kernel', 'boot_id')}
    assert missing['kernel'] == read(accepted)['kernel'] and missing['boot_id'] == read(accepted)['boot_id']
    assert hashlib.sha256((ROOT / 'scripts/probe_seccomp_notification_baseline.sh').read_bytes().replace(b'\r\n', b'\n')).hexdigest() == missing['script_source_sha256']
    upstream = read(REF / 'linux-5.10.y-source-lock.json')
    assert upstream['commit'] == COMMIT
    for record in upstream['files'].values():
        assert sha(REF / record['filename']) == record['sha256']
    before = Path(prior['source']['source'])
    assert all(sha(before / n) == h for n, h in prior['cumulative_source_sha256'].items())
    names = ['kernel/seccomp.c', 'include/uapi/linux/seccomp.h', 'include/linux/seccomp.h']
    old = {n: (before / n).read_text() for n in names}
    assert all(sha(before / n) == sha(REF / ('h3bm2-' + n.replace('/', '-'))) for n in names)
    new = {
        names[0]: derive(old[names[0]], (REF / 'linux-5.10.y-kernel-seccomp.c').read_text()),
        names[1]: (REF / 'linux-5.10.y-include-uapi-linux-seccomp.h').read_text(),
        names[2]: replace(old[names[2]], 'SECCOMP_FILTER_FLAG_SPEC_ALLOW)',
                          'SECCOMP_FILTER_FLAG_SPEC_ALLOW | \\\n\t\t\t\t  SECCOMP_FILTER_FLAG_NEW_LISTENER | \\\n\t\t\t\t  SECCOMP_FILTER_FLAG_TSYNC_ESRCH)')
    }
    new[names[2]] = replace(new[names[2]], '#include <uapi/linux/seccomp.h>',
        '#include <uapi/linux/seccomp.h>\n\n#define SECCOMP_NOTIFY_ADDFD_SIZE_VER0 24\n'
        '#define SECCOMP_NOTIFY_ADDFD_SIZE_LATEST SECCOMP_NOTIFY_ADDFD_SIZE_VER0')
    patch = ''.join(''.join(difflib.unified_diff(old[n].splitlines(True), new[n].splitlines(True),
                                               fromfile='a/' + n, tofile='b/' + n)) for n in names)
    patch_path = ROOT / 'patches/rmx1931-seccomp-user-notification.patch'
    if args.prepare:
        assert args.source and args.source.is_dir() and args.source.resolve() != before.resolve()
        for n in names:
            current = (args.source / n).read_text()
            assert current in (old[n], new[n]), n
            if current == old[n]:
                (args.source / n).write_text(new[n])
        if patch_path.exists():
            assert patch_path.read_text(encoding='utf-8') == patch
        else:
            patch_path.write_text(patch, encoding='utf-8')
        DEST.mkdir(parents=True, exist_ok=True)
        record = {'stage': STAGE, 'source': str(args.source.resolve()), 'base_source': str(before),
                  'predecessor_audit_sha256': sha(BASE / 'audit.json'), 'stage4_acceptance_sha256': sha(accepted),
                  'baseline_sha256': sha(baseline), 'upstream_commit': COMMIT,
                  'upstream_source_lock_sha256': sha(REF / 'linux-5.10.y-source-lock.json'),
                  'adaptation': 'Linux 5.10 stable listener/core/ID validation/lifetime/addfd; retain 4.14 get/put task API, architecture entry/audit and task layout; local extensible argument copy and existing SCM fd checks/socket cgroup updates',
                  'patch_sha256': sha(patch_path),
                  'modified_sources': {n: {'before_sha256': sha(before / n), 'after_sha256': sha(args.source / n)} for n in names}}
        failures = sorted((DEST / 'failed-attempts').glob('compile-*/failure.json'))
        if failures:
            record['unbuilt_failures_sha256'] = {p.parent.name: sha(p) for p in failures}
        path = DEST / 'source.json'
        if path.exists():
            assert read(path) == record
        else:
            path.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
        print('SECCOMP_NOTIFY_SOURCE_READY')
        return
    record = read(DEST / 'source.json')
    assert record['patch_sha256'] == sha(patch_path) and record['baseline_sha256'] == sha(baseline)
    source = Path(record['source'])
    hashes = {**prior['cumulative_source_sha256'], **{n: v['after_sha256'] for n, v in record['modified_sources'].items()}}
    assert all(sha(source / n) == h for n, h in hashes.items())
    assert config(BASE / 'resolved.config') == config(DEST / 'resolved.config')
    result = {'stage': STAGE, 'source': record, 'cumulative_stages': prior['cumulative_stages'] + [STAGE],
              'cumulative_source_sha256': hashes, 'verified_source_files': len(hashes), 'config_changes': {},
              'walt_source_sha256': sha(source / 'kernel/sched/walt.c'),
              'generic_cgroup_core_sha256': sha(source / 'kernel/cgroup/cgroup.c'),
              'generic_cgroup_core_unchanged_from_harden1': True, 'build_audit_passed': False,
              'runtime_acceptance': 'pending', 'android_v1_cpu_cpuset_retained': True}
    assert result['walt_source_sha256'] == prior['walt_source_sha256']
    assert result['generic_cgroup_core_sha256'] == prior['generic_cgroup_core_sha256']
    if args.after_build:
        assert (DEST / 'kernel.release').read_text().strip() == RELEASE
        previous = symbols(BASE / 'Module.symvers')
        current = symbols(DEST / 'Module.symvers')
        missing_symbols = sorted(previous.keys() - current.keys())
        assert not missing_symbols
        changed = sorted(n for n in previous.keys() & current.keys() if previous[n] != current[n])
        linked = {l.split()[-1] for l in (DEST / 'System.map').read_text().splitlines() if l.split()}
        # Clang may inline the private notification core. Require its syscall
        # entry and actual listener vtable/methods rather than a static name.
        required = ['__seccomp_filter', 'seccomp_notify_ops', 'seccomp_notify_ioctl', 'seccomp_notify_poll', 'seccomp_notify_release', 'put_seccomp_filter', 'get_seccomp_filter']
        assert set(prior['linked_symbols'] + required) <= linked
        result.update(build_audit_passed=True, export_crc={'missing': missing_symbols, 'changed': changed},
                      existing_export_crc_preserved=not changed, linked_symbols=prior['linked_symbols'] + required)
        result.update({k: sha(DEST / f) for k, f in [('kernel_sha256', 'Image.gz-dtb'), ('resolved_config_sha256', 'resolved.config'),
                                                  ('module_symvers_sha256', 'Module.symvers'), ('system_map_sha256', 'System.map')]})
    (DEST / 'audit.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'build_audit_passed': result['build_audit_passed'], 'verified_source_files': len(hashes),
                      'kernel_sha256': result.get('kernel_sha256')}))


if __name__ == '__main__':
    main()
