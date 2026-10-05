#!/usr/bin/env python3
"""Repair the real Android 16 Binder capability-discovery failure on h5bf."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
from audit_lowrisk_kernel import config, symbols

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
REF = ROOT / 'references/android16-binder-upstream'
BASE = ART / 'kernel-ext-harden5-binder-freeze'
DEST = ART / 'kernel-ext-harden5-binder-freeze-fix'
STAGE = 'harden5-binder-freeze-fix'
RELEASE = '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h5bf2'
FILE = 'drivers/android/binderfs.c'

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path): return json.loads(path.read_text(encoding='utf-8'))
def replace(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--after-build', action='store_true')
    args = parser.parse_args()
    boot = read(ART / 'extensions-harden5-binder-freeze-boot-result.json')
    failure_path = ART / 'runtime/binder-public-api3-h5bf-20261005.json'
    failure = read(failure_path)
    assert boot['running_config_matches'] and failure['returncode'] == 1
    assert failure['end_identity'] == {k: boot[k] for k in ('kernel', 'boot_id')}
    assert 'new kernel must support public callback' in failure['listener_stderr']
    assert not failure['cleanup_errors'] and all(failure['owned_pids_removed'].values())
    raw_path = ART / 'runtime/binder-freeze-callbacks2-h5bf-20261005.json'
    raw = read(raw_path)
    assert raw['returncode'] == 0 and 'BINDER_FREEZE_CALLBACKS_PASS cases=14' in raw['stdout']
    assert raw['end_identity'] == failure['end_identity'] and raw['fixture_mount_directory_removed']
    lock_path = REF / 'framework-probe/source-lock.json'
    upstream = read(lock_path)
    for framework in upstream['frameworks']:
        for name, entry in framework['files'].items(): assert sha(REF / 'framework-probe' / name) == entry['sha256']
    assert sha(REF / 'framework-probe/android16-binderfs.c') == upstream['binderfs']['sha256']
    native = (REF / 'framework-probe/ProcessState.cpp').read_text()
    ipc = (REF / 'framework-probe/IPCThreadState.cpp').read_text()
    assert '#define DRIVER_FEATURES_PATH "/dev/binderfs/features/"' in native
    assert 'readDriverFeatureFile(DRIVER_FEATURES_PATH "freeze_notification")' in native
    assert 'ProcessState::DriverFeature::FREEZE_NOTIFICATION' in ipc
    prior = read(BASE / 'audit.json'); assert prior['build_audit_passed']
    before = Path(prior['source']['source'])
    assert all(sha(before / name) == digest for name, digest in prior['cumulative_source_sha256'].items())
    old = (before / FILE).read_text()
    assert sha(before / FILE) == read(REF / 'h4sn-binder-source-lock.json')[FILE]['sha256']
    upstream_text = (REF / 'framework-probe/android16-binderfs.c').read_text()
    begin = upstream_text.index('static int binder_features_show(')
    end = upstream_text.index('static int init_binder_features(', begin)
    show = upstream_text[begin:end]
    # DEFINE_SHOW_ATTRIBUTE is available in this tree, retaining standard seq_file ops.
    feature = ('static bool binder_freeze_notification = true;\n\n' + show +
        'static int init_binder_features(struct super_block *sb)\n{\n'
        '\tstruct dentry *dentry, *dir;\n\n'
        '\tdir = binderfs_create_dir(sb->s_root, "features");\n'
        '\tif (IS_ERR(dir))\n\t\treturn PTR_ERR(dir);\n\n'
        '\tdentry = binderfs_create_file(dir, "freeze_notification",\n'
        '\t\t\t\t      &binder_features_fops,\n'
        '\t\t\t\t      &binder_freeze_notification);\n'
        '\tif (IS_ERR(dentry))\n\t\treturn PTR_ERR(dentry);\n\n\treturn 0;\n}\n\n')
    new = replace(old, 'static int init_binder_logs(struct super_block *sb)', feature + 'static int init_binder_logs(struct super_block *sb)')
    new = replace(new, '\tif (info->mount_opts.stats_mode == STATS_GLOBAL)\n\t\treturn init_binder_logs(sb);',
        '\tret = init_binder_features(sb);\n\tif (ret)\n\t\treturn ret;\n\n\tif (info->mount_opts.stats_mode == STATS_GLOBAL)\n\t\treturn init_binder_logs(sb);')
    patch = ''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile='a/' + FILE, tofile='b/' + FILE))
    patch_path = ROOT / 'patches/rmx1931-binder-freeze-feature-discovery.patch'
    if patch_path.exists(): assert patch_path.read_text(encoding='utf-8') == patch
    else: patch_path.write_text(patch, encoding='utf-8')
    if args.prepare:
        assert args.source and args.source.is_dir() and args.source.resolve() != before.resolve()
        assert (args.source / FILE).read_text() in (old, new)
        if (args.source / FILE).read_text() == old: (args.source / FILE).write_text(new)
        DEST.mkdir(parents=True, exist_ok=True)
        record = {'stage': STAGE, 'source': str(args.source.resolve()), 'base_source': str(before),
            'predecessor_audit_sha256': sha(BASE / 'audit.json'), 'public_api_failure_sha256': sha(failure_path),
            'native_callback_pass_sha256': sha(raw_path), 'framework_source_lock_sha256': sha(lock_path),
            'patch_sha256': sha(patch_path), 'modified_sources': {FILE: {'before_sha256': sha(before / FILE), 'after_sha256': sha(args.source / FILE)}},
            'adaptation': 'Backport standard read-only Binderfs feature discovery for implemented freeze notifications only. Every Binderfs mount gets features/freeze_notification=1. No declaration of unimplemented extended-error or transaction-report interfaces.'}
        path = DEST / 'source.json'
        if path.exists(): assert read(path) == record
        else: path.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
        print('BINDER_FREEZE_FEATURE_SOURCE_READY'); return
    record = read(DEST / 'source.json'); source = Path(record['source'])
    assert record['patch_sha256'] == sha(patch_path) and record['public_api_failure_sha256'] == sha(failure_path)
    hashes = {**prior['cumulative_source_sha256'], FILE: record['modified_sources'][FILE]['after_sha256']}
    assert all(sha(source / name) == digest for name, digest in hashes.items())
    assert config(BASE / 'resolved.config') == config(DEST / 'resolved.config')
    result = {'stage': STAGE, 'source': record, 'cumulative_stages': prior['cumulative_stages'] + [STAGE],
        'cumulative_source_sha256': hashes, 'verified_source_files': len(hashes), 'config_changes': {},
        'walt_source_sha256': sha(source / 'kernel/sched/walt.c'), 'generic_cgroup_core_sha256': sha(source / 'kernel/cgroup/cgroup.c'),
        'generic_cgroup_core_unchanged_from_harden1': True, 'build_audit_passed': False,
        'runtime_acceptance': 'pending', 'android_v1_cpu_cpuset_retained': True}
    assert result['walt_source_sha256'] == prior['walt_source_sha256'] and result['generic_cgroup_core_sha256'] == prior['generic_cgroup_core_sha256']
    if args.after_build:
        assert (DEST / 'kernel.release').read_text().strip() == RELEASE
        previous = symbols(BASE / 'Module.symvers'); current = symbols(DEST / 'Module.symvers')
        missing = sorted(previous.keys() - current.keys()); assert not missing
        changed = sorted(name for name in previous.keys() & current.keys() if previous[name] != current[name])
        linked = {line.split()[-1] for line in (DEST / 'System.map').read_text().splitlines() if line.split()}
        assert set(prior['linked_symbols']) <= linked and 'binder_features_show' in linked
        result.update(build_audit_passed=True, export_crc={'missing': missing, 'changed': changed},
            existing_export_crc_preserved=not changed, linked_symbols=prior['linked_symbols'] + ['binder_features_show'])
        result.update({key: sha(DEST / name) for key, name in [('kernel_sha256', 'Image.gz-dtb'), ('resolved_config_sha256', 'resolved.config'), ('module_symvers_sha256', 'Module.symvers'), ('system_map_sha256', 'System.map')]})
    (DEST / 'audit.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'build_audit_passed': result['build_audit_passed'], 'verified_source_files': len(hashes), 'kernel_sha256': result.get('kernel_sha256')}))

if __name__ == '__main__': main()
