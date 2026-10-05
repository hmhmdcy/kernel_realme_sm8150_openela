#!/usr/bin/env python3
"""Backport the fixed Android 16 Binder freeze notification state machine."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
from audit_lowrisk_kernel import config, symbols

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
REF = ROOT / 'references/android16-binder-upstream'
BASE = ART / 'kernel-ext-harden4-seccomp-notify'
DEST = ART / 'kernel-ext-harden5-binder-freeze'
STAGE = 'harden5-binder-freeze'
RELEASE = '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h5bf'
COMMIT = '5fd39602326ec050bf53ae07528e1fe1ecefb531'
NAMES = ['drivers/android/binder.c', 'include/uapi/linux/android/binder.h']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def section(text, start, end):
    assert text.count(start) == 1, start
    begin = text.index(start)
    return text[begin:text.index(end, begin + len(start))]


def replace(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new)


def derive(old, upstream, internal):
    text = old
    text = replace(text, '\tBINDER_STAT_COUNT\n', '\tBINDER_STAT_FREEZE,\n\tBINDER_STAT_COUNT\n')
    text = replace(text, 'br[_IOC_NR(BR_ONEWAY_SPAM_SUSPECT) + 1]', 'br[_IOC_NR(BR_CLEAR_FREEZE_NOTIFICATION_DONE) + 1]')
    text = replace(text, 'bc[_IOC_NR(BC_REPLY_SG) + 1]', 'bc[_IOC_NR(BC_FREEZE_NOTIFICATION_DONE) + 1]')
    text = replace(text, '\t\tBINDER_WORK_CLEAR_DEATH_NOTIFICATION,\n',
                   '\t\tBINDER_WORK_CLEAR_DEATH_NOTIFICATION,\n\t\tBINDER_WORK_FROZEN_BINDER,\n\t\tBINDER_WORK_CLEAR_FREEZE_NOTIFICATION,\n')
    types = section(internal, 'struct binder_ref_freeze {', '/**\n * struct binder_ref_data')
    text = replace(text, '/**\n * struct binder_ref_data', types + '/**\n * struct binder_ref_data')
    text = replace(text, '\tstruct binder_node *node;\n\tstruct binder_ref_death *death;\n};',
                   '\tstruct binder_node *node;\n\tstruct binder_ref_death *death;\n\tstruct binder_ref_freeze *freeze;\n};')
    text = replace(text, '\tstruct list_head delivered_death;\n', '\tstruct list_head delivered_death;\n\tstruct list_head delivered_freeze;\n')
    text = replace(text, '\tbinder_stats_deleted(BINDER_STAT_REF);\n',
                   '\tif (ref->freeze) {\n\t\tbinder_dequeue_work(ref->proc, &ref->freeze->work);\n'
                   '\t\tbinder_stats_deleted(BINDER_STAT_FREEZE);\n\t}\n\tbinder_stats_deleted(BINDER_STAT_REF);\n')
    text = replace(text, '\tkfree(ref->death);\n', '\tkfree(ref->death);\n\tkfree(ref->freeze);\n')
    handlers = section(upstream, 'static int\nbinder_request_freeze_notification', '/**\n * binder_free_buf')
    text = replace(text, 'static int binder_thread_write(', handlers + 'static int binder_thread_write(')
    write_start = 'static int binder_thread_write('
    write_end = 'static void binder_stat_br('
    write = section(text, write_start, write_end)
    commands = section(upstream, '\t\tcase BC_REQUEST_FREEZE_NOTIFICATION:', '\t\tdefault:')
    write_default = '\t\tdefault:\n\t\t\tpr_err("%d:%d unknown command %d\\n",'
    write = replace(write, write_default, commands + write_default)
    text = replace(text, section(text, write_start, write_end), write)
    read_start = 'static int binder_thread_read('
    read_end = 'static void binder_release_work('
    reading = section(text, read_start, read_end)
    callbacks = section(upstream, '\t\tcase BINDER_WORK_FROZEN_BINDER: {', '\t\tdefault:')
    # The old switch ends after its death work, without a default arm.
    reading = replace(reading, '\t\t} break;\n\t\t}\n\n\t\tif (!t)',
                      '\t\t} break;\n' + callbacks + '\t\t}\n\n\t\tif (!t)')
    text = replace(text, section(text, read_start, read_end), reading)
    release_start = 'static void binder_release_work('
    release_end = 'static struct binder_thread *binder_get_thread_ilocked('
    releasing = section(text, release_start, release_end)
    clear_work = section(upstream, '\t\tcase BINDER_WORK_CLEAR_FREEZE_NOTIFICATION: {\n\t\t\tstruct binder_ref_freeze *freeze;', '\t\tdefault:')
    releasing = replace(releasing, '\t\tdefault:', clear_work + '\t\tdefault:')
    text = replace(text, section(text, release_start, release_end), releasing)
    text = replace(text, '\tBUG_ON(!list_empty(&proc->delivered_death));',
                   '\tBUG_ON(!list_empty(&proc->delivered_death));\n\tBUG_ON(!list_empty(&proc->delivered_freeze));')
    old_freeze = section(text, 'static int binder_ioctl_freeze(', 'static int binder_ioctl_get_freezer_info(')
    new_freeze = section(upstream, 'static void binder_add_freeze_work(', 'static int binder_ioctl_get_freezer_info(')
    text = replace(text, old_freeze, new_freeze)
    text = replace(text, '\tINIT_LIST_HEAD(&proc->delivered_death);',
                   '\tINIT_LIST_HEAD(&proc->delivered_death);\n\tINIT_LIST_HEAD(&proc->delivered_freeze);')
    text = replace(text, '\tbinder_release_work(proc, &proc->delivered_death);',
                   '\tbinder_release_work(proc, &proc->delivered_death);\n\tbinder_release_work(proc, &proc->delivered_freeze);')
    text = replace(text, '\t"BR_ONEWAY_SPAM_SUSPECT",\n',
                   '\t"BR_ONEWAY_SPAM_SUSPECT",\n\t"BR_RESERVED_20",\n\t"BR_FROZEN_BINDER",\n\t"BR_CLEAR_FREEZE_NOTIFICATION_DONE",\n')
    text = replace(text, '\t"BC_REPLY_SG",\n',
                   '\t"BC_REPLY_SG",\n\t"BC_REQUEST_FREEZE_NOTIFICATION",\n\t"BC_CLEAR_FREEZE_NOTIFICATION",\n\t"BC_FREEZE_NOTIFICATION_DONE",\n')
    text = replace(text, '\t"transaction_complete"\n', '\t"transaction_complete",\n\t"freeze"\n')
    death_debug = '\tlist_for_each_entry(w, &proc->delivered_death, entry) {\n\t\tseq_puts(m, "  has delivered dead binder\\n");\n\t\tbreak;\n\t}\n'
    text = replace(text, death_debug, death_debug +
                   '\tlist_for_each_entry(w, &proc->delivered_freeze, entry) {\n\t\tseq_puts(m, "  has delivered freeze binder\\n");\n\t\tbreak;\n\t}\n')
    # Keep old transaction/allocator APIs, Binderfs layout and freeze PID ABI.
    assert 'trace_android_vh' not in text and 'ANDROID_OEM_DATA' not in text
    return text


def derive_uapi(old, upstream):
    frozen = section(upstream, 'struct binder_frozen_state_info {', '/* struct binder_extened_error')
    old = replace(old, '#define BINDER_WRITE_READ', frozen + '#define BINDER_WRITE_READ')
    returns = section(upstream, '\tBR_FROZEN_BINDER =', '};\n\nenum binder_driver_command_protocol')
    old = replace(old, '};\n\nenum binder_driver_command_protocol', returns + '};\n\nenum binder_driver_command_protocol')
    commands = section(upstream, '\tBC_REQUEST_FREEZE_NOTIFICATION =', '};\n\n#endif')
    closing = '};\n\n#endif /* _UAPI_LINUX_BINDER_H */'
    old = replace(old, closing, commands + closing)
    assert 'BINDER_GET_EXTENDED_ERROR' not in old and 'BR_TRANSACTION_PENDING_FROZEN' not in old
    return old


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--after-build', action='store_true')
    parser.add_argument('--preview', action='store_true')
    args = parser.parse_args()
    upstream_lock = read(REF / 'android16-fixed-source-lock.json')
    assert upstream_lock['common_commit'] == COMMIT
    for name, digest in upstream_lock['files'].items(): assert sha(REF / name) == digest
    baseline_path = ART / 'runtime/binder-freeze-baseline3-h4sn-20261005.json'
    baseline = read(baseline_path)
    accepted_path = ART / 'seccomp-notify-stage5-acceptance.json'
    accepted = read(accepted_path)
    assert accepted['complete_stage_5_accepted'] and baseline['returncode'] == 0
    assert baseline['end_identity'] == {k: accepted[k] for k in ('kernel', 'boot_id')}
    # Historical baseline used an unsanitized packed UAPI. Its EINVAL cannot
    # prove the callback command was missing; retain only transport/cleanup proof.
    assert 'protocol_and_real_cross_process_transaction' in baseline['stdout'] and baseline['fixture_mount_directory_removed']
    assert baseline['ordinary_guest_seccomp'] == '2'
    snapshot = REF / 'h4sn-binder-source-lock.json'
    old_lock = read(snapshot)
    for name, record in old_lock.items(): assert sha(REF / ('h4sn-' + name.replace('/', '-'))) == record['sha256']
    old = {n: (REF / ('h4sn-' + n.replace('/', '-'))).read_text() for n in NAMES}
    assert all('BC_REQUEST_FREEZE_NOTIFICATION' not in text for text in old.values()), 'Confirm absence from fixed driver/UAPI sources'
    upstream = (REF / 'android16-6.12-drivers-android-binder.c').read_text()
    internal = (REF / 'android16-6.12-drivers-android-binder_internal.h').read_text()
    header = (REF / 'android16-6.12-include-uapi-linux-android-binder.h').read_text()
    new = {NAMES[0]: derive(old[NAMES[0]], upstream, internal), NAMES[1]: derive_uapi(old[NAMES[1]], header)}
    patch = ''.join(''.join(difflib.unified_diff(old[n].splitlines(True),new[n].splitlines(True),fromfile='a/'+n,tofile='b/'+n)) for n in NAMES)
    patch_path = ROOT / 'patches/rmx1931-binder-freeze-notification.patch'
    if patch_path.exists(): assert patch_path.read_text(encoding='utf-8') == patch
    else: patch_path.write_text(patch, encoding='utf-8')
    if args.preview:
        print(json.dumps({'preview_generated': True, 'modified_files': NAMES, 'patch_sha256': sha(patch_path)}))
        return
    prior = read(BASE / 'audit.json'); assert prior['build_audit_passed']
    before = Path(prior['source']['source'])
    assert all(sha(before/n)==digest for n,digest in prior['cumulative_source_sha256'].items())
    assert all(sha(before/n)==old_lock[n]['sha256'] for n in NAMES)
    if args.prepare:
        assert args.source and args.source.is_dir() and args.source.resolve() != before.resolve()
        for n in NAMES:
            current = (args.source/n).read_text(); assert current in (old[n],new[n]), n
            if current == old[n]: (args.source/n).write_text(new[n])
        DEST.mkdir(parents=True,exist_ok=True)
        record = {'stage': STAGE, 'source': str(args.source.resolve()), 'base_source': str(before),
                  'predecessor_audit_sha256':sha(BASE/'audit.json'),'stage5_acceptance_sha256':sha(accepted_path),
                  'baseline_sha256':sha(baseline_path),'upstream_commit':COMMIT,
                  'upstream_source_lock_sha256':sha(REF/'android16-fixed-source-lock.json'),
                  'patch_sha256':sha(patch_path),'modified_sources':{n:{'before_sha256':sha(before/n),'after_sha256':sha(args.source/n)} for n in NAMES},
                  'adaptation':'Fixed Android 16 notification handlers, coalescing/ack state, freeze work traversal and cleanup; retain 4.14 transaction/allocator interfaces, Binderfs and existing freeze PID ABI; add only callback UAPI, reserve return index 20 without claiming pending-frozen transaction support'}
        path=DEST/'source.json'
        if path.exists(): assert read(path)==record
        else: path.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
        print('BINDER_FREEZE_SOURCE_READY'); return
    record=read(DEST/'source.json');source=Path(record['source'])
    assert record['patch_sha256']==sha(patch_path) and record['baseline_sha256']==sha(baseline_path)
    hashes={**prior['cumulative_source_sha256'],**{n:v['after_sha256'] for n,v in record['modified_sources'].items()}}
    assert all(sha(source/n)==digest for n,digest in hashes.items())
    assert config(BASE/'resolved.config')==config(DEST/'resolved.config')
    result={'stage':STAGE,'source':record,'cumulative_stages':prior['cumulative_stages']+[STAGE],
            'cumulative_source_sha256':hashes,'verified_source_files':len(hashes),'config_changes':{},
            'walt_source_sha256':sha(source/'kernel/sched/walt.c'),
            'generic_cgroup_core_sha256':sha(source/'kernel/cgroup/cgroup.c'),
            'generic_cgroup_core_unchanged_from_harden1':True,'build_audit_passed':False,
            'runtime_acceptance':'pending','android_v1_cpu_cpuset_retained':True}
    assert result['walt_source_sha256']==prior['walt_source_sha256']
    assert result['generic_cgroup_core_sha256']==prior['generic_cgroup_core_sha256']
    if args.after_build:
        assert (DEST/'kernel.release').read_text().strip()==RELEASE
        previous=symbols(BASE/'Module.symvers');current=symbols(DEST/'Module.symvers')
        missing=sorted(previous.keys()-current.keys());assert not missing
        changed=sorted(n for n in previous.keys()&current.keys() if previous[n]!=current[n])
        linked={line.split()[-1] for line in (DEST/'System.map').read_text().splitlines() if line.split()}
        # Notification helpers may inline; their externally dispatched entry
        # functions and actual runtime tests prove the state machine instead.
        required=['binder_ioctl','binder_release_work']
        assert set(prior['linked_symbols']+required)<=linked
        result.update(build_audit_passed=True,export_crc={'missing':missing,'changed':changed},
                      existing_export_crc_preserved=not changed,linked_symbols=prior['linked_symbols']+required)
        result.update({key:sha(DEST/name) for key,name in [('kernel_sha256','Image.gz-dtb'),('resolved_config_sha256','resolved.config'),('module_symvers_sha256','Module.symvers'),('system_map_sha256','System.map')]})
    (DEST/'audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'build_audit_passed':result['build_audit_passed'],'verified_source_files':len(hashes),'kernel_sha256':result.get('kernel_sha256')}))


if __name__=='__main__': main()
