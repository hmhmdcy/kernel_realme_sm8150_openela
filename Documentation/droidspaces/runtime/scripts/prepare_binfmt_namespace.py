#!/usr/bin/env python3
"""Backport upstream binfmt user namespaces onto the accepted h2cp4 tree."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
from audit_lowrisk_kernel import config, symbols

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
BASE = ART / 'kernel-ext-harden2-cpuset-stats'
DEST = ART / 'kernel-ext-harden3-binfmt'
RELEASE = '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h3bm'
REFERENCES = {
    '1c5976ef0f7ad76319df748ccb99a4c7ba2ba464': '1fe864f6d1652d81f6a36b54e616fda53dee6846a9b2a5174dae458653be506c',
    '21ca59b365c091d583f36ac753eaa8baf947be6f': 'a7cf2b1f6a64a9e8b4c72fe2e8e17c1d7f818fd461f5558a8d52a170d64e6828',
    '79055d82772b9584f259b747fe40ff56a076678d': '6f50375dfd5c2255fa9ed88fb35ecacf22bd19868f757775a363ee6c208e0785',
}
BASELINE = ART / 'runtime/binfmt-namespace-baseline-h2cp4-20261004.json'
ACCEPTANCE = ART / 'native-cpu-cpuset-stage3-h2cp4-acceptance.json'

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p): return json.loads(p.read_text(encoding='utf-8'))
def save(p, d): p.write_text(json.dumps(d, indent=2) + '\n', encoding='utf-8')
def replace(t, old, new):
    assert t.count(old) == 1, repr(old)
    return t.replace(old, new)

def changes_from(base):
    changes = {}
    name = 'fs/binfmt_misc.c'
    old = (base / name).read_text()
    t = replace(old, '#include <linux/uaccess.h>', '#include <linux/uaccess.h>\n#include <linux/user_namespace.h>\n#include <linux/cred.h>')
    t = replace(t, 'static LIST_HEAD(entries);\nstatic int enabled = 1;\n\n', '')
    t = replace(t, 'static DEFINE_RWLOCK(entries_lock);\n', '')
    t = replace(t, 'static Node *search_binfmt_handler(struct linux_binprm *bprm)',
        'static Node *search_binfmt_handler(struct binfmt_misc *misc,\n\t\t\t\t   struct linux_binprm *bprm)')
    t = replace(t, 'list_for_each_entry(e, &entries, list)', 'list_for_each_entry(e, &misc->entries, list)')
    t = replace(t, 'static Node *get_binfmt_handler(struct linux_binprm *bprm)',
        'static Node *get_binfmt_handler(struct binfmt_misc *misc,\n\t\t\t\tstruct linux_binprm *bprm)')
    t = replace(t, 'e = search_binfmt_handler(bprm);', 'e = search_binfmt_handler(misc, bprm);')
    # All existing lock sites acquire a registry explicitly below.
    t = t.replace('&entries_lock', '&misc->entries_lock')
    loader = '''/*
 * A namespace without its own instance inherits the nearest ancestor's
 * handlers. The caller's credentials pin its namespace and all ancestors;
 * the instance lives until free_user_ns(), independently of a superblock.
 */
static struct binfmt_misc *load_binfmt_misc(void)
{
\tconst struct user_namespace *user_ns = current_user_ns();
\tstruct binfmt_misc *misc;

\twhile (user_ns) {
\t\t/* Pairs with the first mount's smp_store_release(). */
\t\tmisc = smp_load_acquire(&user_ns->binfmt_misc);
\t\tif (misc)
\t\t\treturn misc;
\t\tuser_ns = user_ns->parent;
\t}
\treturn &init_binfmt_misc;
}

'''
    t = replace(t, '/*\n * the loader itself\n */', loader + '/*\n * the loader itself\n */')
    t = replace(t, '\tretval = -ENOEXEC;\n\tif (!enabled)', '\tstruct binfmt_misc *misc = load_binfmt_misc();\n\n\tretval = -ENOEXEC;\n\tif (!READ_ONCE(misc->enabled))')
    t = replace(t, 'fmt = get_binfmt_handler(bprm);', 'fmt = get_binfmt_handler(misc, bprm);')
    t = replace(t, 'e = kmalloc(memsize, GFP_KERNEL);', 'e = kmalloc(memsize, GFP_KERNEL_ACCOUNT);')
    t = replace(t, 'char *masked = kmalloc(e->size, GFP_KERNEL);', 'char *masked = kmalloc(e->size, GFP_KERNEL_ACCOUNT);')
    helper = '''/* The superblock pins s_user_ns; publication completed before mounting. */
static struct binfmt_misc *i_binfmt_misc(struct inode *inode)
{
\treturn inode->i_sb->s_user_ns->binfmt_misc;
}

'''
    t = replace(t, '/**\n * bm_evict_inode', helper + '/**\n * bm_evict_inode')
    t = replace(t, '\tif (e) {\n\t\twrite_lock(&misc->entries_lock);',
        '\tif (e) {\n\t\tstruct binfmt_misc *misc = i_binfmt_misc(inode);\n\n\t\twrite_lock(&misc->entries_lock);')
    t = replace(t, 'static void remove_binfmt_handler(Node *e)', 'static void remove_binfmt_handler(struct binfmt_misc *misc, Node *e)')
    assert t.count('\t\t\tremove_binfmt_handler(e);') == 2
    t = t.replace('\t\t\tremove_binfmt_handler(e);', '\t\t\tremove_binfmt_handler(i_binfmt_misc(inode), e);')
    t = replace(t, '\tstruct dentry *root = sb->s_root, *dentry;', '\tstruct dentry *root = sb->s_root, *dentry;\n\tstruct binfmt_misc *misc = sb->s_user_ns->binfmt_misc;')
    t = replace(t, '\tif (e->flags & MISC_FMT_OPEN_FILE) {\n\t\tf = open_exec(e->interpreter);', '''\tif (e->flags & MISC_FMT_OPEN_FILE) {
\t\tconst struct cred *old_cred;

\t\t/* Use the credentials that opened register, including delegated FDs. */
\t\told_cred = override_creds(file->f_cred);
\t\tf = open_exec(e->interpreter);
\t\trevert_creds(old_cred);''')
    t = replace(t, 'list_add(&e->list, &entries);', 'list_add(&e->list, &misc->entries);')
    t = replace(t, '\tchar *s = enabled ? "enabled\\n" : "disabled\\n";',
        '\tstruct binfmt_misc *misc = i_binfmt_misc(file_inode(file));\n\tchar *s = READ_ONCE(misc->enabled) ? "enabled\\n" : "disabled\\n";')
    anchor = 'static ssize_t bm_status_write(struct file *file, const char __user *buffer,\n\t\tsize_t count, loff_t *ppos)\n{'
    t = replace(t, anchor, anchor + '\n\tstruct binfmt_misc *misc = i_binfmt_misc(file_inode(file));')
    t = replace(t, '\t\tenabled = 0;', '\t\tWRITE_ONCE(misc->enabled, false);')
    t = replace(t, '\t\tenabled = 1;', '\t\tWRITE_ONCE(misc->enabled, true);')
    t = replace(t, 'list_for_each_entry_safe(e, next, &entries, list)\n\t\t\tremove_binfmt_handler(i_binfmt_misc(inode), e);',
        'list_for_each_entry_safe(e, next, &misc->entries, list)\n\t\t\tremove_binfmt_handler(misc, e);')
    anchor = 'static int bm_fill_super(struct super_block *sb, void *data, int silent)\n{\n\tint err;'
    t = replace(t, anchor, anchor + '\n\tstruct user_namespace *user_ns = sb->s_user_ns;\n\tstruct binfmt_misc *misc;')
    t = replace(t, '\terr = simple_fill_super(sb, BINFMTFS_MAGIC, bm_files);', '''\tif (WARN_ON(user_ns != current_user_ns()))
\t\treturn -EINVAL;

\t/* Prevent F handlers and stacked filesystems from pinning this instance. */
\tsb->s_iflags |= SB_I_NOEXEC | SB_I_NODEV;
\tsb->s_stack_depth = FILESYSTEM_MAX_STACK_DEPTH;

\t/* mount_ns() serializes first/remount initialization using s_umount. */
\tmisc = user_ns->binfmt_misc;
\tif (!misc) {
\t\tmisc = kzalloc(sizeof(*misc), GFP_KERNEL_ACCOUNT);
\t\tif (!misc)
\t\t\treturn -ENOMEM;
\t\tINIT_LIST_HEAD(&misc->entries);
\t\trwlock_init(&misc->entries_lock);
\t\tsmp_store_release(&user_ns->binfmt_misc, misc);
\t}
\t/* Inode eviction empties handlers on last unmount; remount re-enables. */
\tWRITE_ONCE(misc->enabled, true);

\terr = simple_fill_super(sb, BINFMTFS_MAGIC, bm_files);''')
    t = replace(t, '\treturn mount_single(fs_type, flags, data, bm_fill_super);', '''\tstruct user_namespace *user_ns = current_user_ns();

\t/* Keyed by userns; alloc_super() owns the namespace reference in 4.14. */
\treturn mount_ns(fs_type, flags, data, user_ns, user_ns, bm_fill_super);''')
    t = replace(t, '\t.mount\t\t= bm_mount,', '\t.mount\t\t= bm_mount,\n\t.fs_flags\t= FS_USERNS_MOUNT,')
    assert '&entries,' not in t and 'simple_pin_fs' not in t and 'mount_single(' not in t
    changes[name] = old, t
    name = 'include/linux/binfmts.h'; old = (base / name).read_text()
    t = replace(old, 'extern void __register_binfmt(struct linux_binfmt *fmt, int insert);', '''#if IS_ENABLED(CONFIG_BINFMT_MISC)
struct binfmt_misc {
\tstruct list_head entries;
\trwlock_t entries_lock;
\tbool enabled;
} __randomize_layout;

extern struct binfmt_misc init_binfmt_misc;
#endif

extern void __register_binfmt(struct linux_binfmt *fmt, int insert);''')
    changes[name] = old, t
    name = 'include/linux/user_namespace.h'; old = (base / name).read_text()
    t = replace(old, 'struct user_namespace {', '#if IS_ENABLED(CONFIG_BINFMT_MISC)\nstruct binfmt_misc;\n#endif\n\nstruct user_namespace {')
    t = replace(t, '\tint ucount_max[UCOUNT_COUNTS];', '\tint ucount_max[UCOUNT_COUNTS];\n#if IS_ENABLED(CONFIG_BINFMT_MISC)\n\tstruct binfmt_misc *binfmt_misc;\n#endif')
    changes[name] = old, t
    name = 'kernel/user.c'; old = (base / name).read_text()
    t = replace(old, '#include <linux/proc_ns.h>', '''#include <linux/proc_ns.h>
#include <linux/binfmts.h>

#if IS_ENABLED(CONFIG_BINFMT_MISC)
struct binfmt_misc init_binfmt_misc = {
\t.entries = LIST_HEAD_INIT(init_binfmt_misc.entries),
\t.enabled = true,
\t.entries_lock = __RW_LOCK_UNLOCKED(init_binfmt_misc.entries_lock),
};
EXPORT_SYMBOL_GPL(init_binfmt_misc);
#endif''')
    t = replace(t, '\t.flags = USERNS_INIT_FLAGS,', '\t.flags = USERNS_INIT_FLAGS,\n#if IS_ENABLED(CONFIG_BINFMT_MISC)\n\t.binfmt_misc = &init_binfmt_misc,\n#endif')
    changes[name] = old, t
    name = 'kernel/user_namespace.c'; old = (base / name).read_text()
    t = replace(old, '\t\tretire_userns_sysctls(ns);', '#if IS_ENABLED(CONFIG_BINFMT_MISC)\n\t\tkfree(ns->binfmt_misc);\n#endif\n\t\tretire_userns_sysctls(ns);')
    changes[name] = old, t
    return changes

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepare', action='store_true'); p.add_argument('--source', type=Path)
    p.add_argument('--after-build', action='store_true'); args = p.parse_args()
    prior = read(BASE / 'audit.json'); accepted = read(ACCEPTANCE); baseline = read(BASELINE)
    assert prior['build_audit_passed'] and accepted['passed'] and accepted['complete_stage_3_accepted']
    assert accepted['kernel'] == baseline['kernel'] and baseline['kernel'].endswith('-ext-h2cp4')
    assert baseline['end_identity'] == {'kernel': baseline['kernel'], 'boot_id': baseline['boot_id']}
    assert 'BINFMT_NAMESPACE_BASELINE_MISSING' in baseline['stdout']
    for commit, digest in REFERENCES.items():
        assert sha(ROOT / 'references/binfmt-ns-upstream' / (commit + '.patch')) == digest
    before = Path(prior['source']['source'])
    assert all(sha(before / n) == h for n, h in prior['cumulative_source_sha256'].items())
    changes = changes_from(before)
    patch = ''.join(''.join(difflib.unified_diff(a.splitlines(True), b.splitlines(True), fromfile='a/'+n, tofile='b/'+n)) for n, (a,b) in changes.items())
    patch_path = ROOT / 'patches/rmx1931-binfmt-user-namespace.patch'
    if args.prepare:
        assert args.source is not None and args.source.is_dir() and args.source.resolve() != before.resolve()
        for n, (a,b) in changes.items():
            actual = (args.source / n).read_text(); assert actual in (a,b)
            if actual == a: (args.source / n).write_text(b)
        if patch_path.exists(): assert patch_path.read_text(encoding='utf-8') == patch
        else: patch_path.write_text(patch, encoding='utf-8')
        DEST.mkdir(parents=True, exist_ok=True)
        record = {'stage': 'harden3-binfmt', 'source': str(args.source.resolve()), 'base_source': str(before),
            'predecessor_audit_sha256': sha(BASE / 'audit.json'), 'predecessor_acceptance_sha256': sha(ACCEPTANCE),
            'baseline_path': BASELINE.relative_to(ART).as_posix(), 'baseline_sha256': sha(BASELINE),
            'upstream_references': {c: {'sha256':h, 'url':'https://github.com/torvalds/linux/commit/'+c} for c,h in REFERENCES.items()},
            'cleanup_dependency_already_present': True,
            'adaptation': '4.14 mount_ns keyed by userns replaces fs_context/get_tree_keyed; s_user_ns reference is already owned by alloc_super; existing Node refcounts/last-unmount cleanup retained; F credentials and self-pin defenses included',
            'patch_sha256': sha(patch_path),
            'modified_sources': {n: {'before_sha256':sha(before/n), 'after_sha256':sha(args.source/n)} for n in changes}}
        dest = DEST / 'source.json'
        if dest.exists(): assert read(dest) == record
        else: save(dest, record)
        print('BINFMT_NAMESPACE_SOURCE_READY'); return
    record = read(DEST / 'source.json'); source = Path(record['source'])
    assert record['predecessor_audit_sha256'] == sha(BASE/'audit.json')
    assert record['predecessor_acceptance_sha256'] == sha(ACCEPTANCE) and record['baseline_sha256'] == sha(BASELINE)
    assert record['patch_sha256'] == sha(patch_path)
    hashes = {**prior['cumulative_source_sha256'], **{n:r['after_sha256'] for n,r in record['modified_sources'].items()}}
    assert all(sha(source/n) == h for n,h in hashes.items())
    assert config(BASE/'resolved.config') == config(DEST/'resolved.config')
    assert sha(source/'kernel/sched/walt.c') == prior['walt_source_sha256']
    assert sha(source/'kernel/cgroup/cgroup.c') == prior['generic_cgroup_core_sha256']
    result = {'stage':'harden3-binfmt', 'source':record, 'cumulative_stages':prior['cumulative_stages']+['harden3-binfmt'],
        'cumulative_source_sha256':hashes, 'verified_source_files':len(hashes), 'config_changes':{},
        'walt_source_sha256':prior['walt_source_sha256'], 'generic_cgroup_core_sha256':prior['generic_cgroup_core_sha256'],
        'generic_cgroup_core_unchanged_from_harden1':True, 'build_audit_passed':False,
        'runtime_acceptance':'pending', 'android_v1_cpu_cpuset_retained':True}
    if args.after_build:
        assert (DEST/'kernel.release').read_text().strip() == RELEASE
        previous = symbols(BASE/'Module.symvers'); current = symbols(DEST/'Module.symvers')
        missing = sorted(previous.keys()-current.keys()); assert not missing
        changed = sorted(n for n in previous.keys()&current.keys() if previous[n] != current[n])
        linked = {l.split()[-1] for l in (DEST/'System.map').read_text().splitlines() if l.split()}
        assert set(prior['linked_symbols']) | {'init_binfmt_misc'} <= linked
        result.update(build_audit_passed=True, export_crc={'missing':missing, 'changed':changed},
            existing_export_crc_preserved=not changed, linked_symbols=sorted(set(prior['linked_symbols'])|{'init_binfmt_misc'}))
        result.update({k:sha(DEST/f) for k,f in [('kernel_sha256','Image.gz-dtb'),('resolved_config_sha256','resolved.config'),('module_symvers_sha256','Module.symvers'),('system_map_sha256','System.map')]})
    save(DEST/'audit.json', result)
    print(json.dumps({'build_audit_passed':result['build_audit_passed'], 'verified_source_files':len(hashes), 'kernel_sha256':result.get('kernel_sha256')}))

if __name__ == '__main__': main()
