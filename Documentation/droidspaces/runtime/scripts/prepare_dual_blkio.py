#!/usr/bin/env python3
"""Prepare an optional, opt-in V2 blkcg beside the ROM's legacy V1 blkio.

Personal device fork: not an upstream ABI. The original static queue root and
legacy controller remain the Android path. Only an explicitly selected V2
subtree uses the independent controller. Every replacement is fail-closed.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def transform(name, text):
    def replace(old, new, count=1):
        nonlocal text
        assert text.count(old) == count, (name, old, text.count(old))
        text = text.replace(old, new)

    if name == 'init/Kconfig':
        replace('config BLK_CGROUP\n', '''config RMX1931_DUAL_BLKIO
	bool "RMX1931 opt-in V2 IO beside Android V1 blkio"
	depends on BLK_CGROUP && BLK_DEV_THROTTLING
	depends on !BLK_DEV_THROTTLING_LOW
	default n
	help
	  Personal RMX1931 fork. Preserve Android legacy blkio and its queue
	  root, while exposing an independent V2 io controller. IO remains
	  on legacy blkio unless io.v2_delegate is explicitly set on a V2
	  ancestor. This one-way selection lasts until that group is removed.
	  io.low across the two controllers is unsupported.

config BLK_CGROUP
''')
    elif name == 'include/linux/cgroup_subsys.h':
        replace('SUBSYS(io)\n#endif', '''SUBSYS(io)
#if IS_ENABLED(CONFIG_RMX1931_DUAL_BLKIO)
/* Device-local legacy copy; not a proposed upstream subsystem. */
SUBSYS(blkio)
#endif
#endif''')
    elif name == 'include/linux/blk-cgroup.h':
        replace('\tspinlock_t\t\t\tlock;\n', '''	spinlock_t			lock;
#ifdef CONFIG_RMX1931_DUAL_BLKIO
	/* Set before policy allocation: css.cgroup is not initialized yet. */
	bool				v2_controller;
	bool				v2_delegate;
#endif
''')
        replace('static inline struct blkcg *task_blkcg(struct task_struct *tsk)\n{\n\treturn css_to_blkcg(task_css(tsk, io_cgrp_id));\n}', '''static inline bool blkcg_on_dfl(struct blkcg *blkcg)
{
#ifdef CONFIG_RMX1931_DUAL_BLKIO
	return blkcg->v2_controller;
#else
	return cgroup_subsys_on_dfl(io_cgrp_subsys);
#endif
}

/* The caller holds RCU or a css reference, protecting the ancestor chain. */
static inline bool blkcg_v2_selected(struct cgroup_subsys_state *css)
{
#ifdef CONFIG_RMX1931_DUAL_BLKIO
	for (; css; css = css->parent)
		if (READ_ONCE(css_to_blkcg(css)->v2_delegate))
			return true;
	return false;
#else
	return true;
#endif
}

static inline struct blkcg *task_blkcg(struct task_struct *tsk)
{
	struct cgroup_subsys_state *css = task_css(tsk, io_cgrp_id);
#ifdef CONFIG_RMX1931_DUAL_BLKIO
	if (!blkcg_v2_selected(css))
		css = task_css(tsk, blkio_cgrp_id);
#endif
	return css_to_blkcg(css);
}''')
        replace('\treturn task_get_css(task, io_cgrp_id);', '''	struct cgroup_subsys_state *css = task_get_css(task, io_cgrp_id);
#ifdef CONFIG_RMX1931_DUAL_BLKIO
	if (!blkcg_v2_selected(css)) {
		css_put(css);
		css = task_get_css(task, blkio_cgrp_id);
	}
#endif
	return css;''')
        replace('/**\n * blkcg_parent -', '''/* Keep Android buffered writeback on its original legacy root. */
static inline struct cgroup_subsys_state *blkcg_get_writeback_css(struct cgroup *cgrp)
{
	struct cgroup_subsys_state *css = cgroup_get_e_css(cgrp, &io_cgrp_subsys);
#ifdef CONFIG_RMX1931_DUAL_BLKIO
	if (!blkcg_v2_selected(css)) {
		css_put(css);
		css = blkcg_root_css;
		css_get(css);
	}
#endif
	return css;
}

/* css IDs are per subsystem; partition the congestion key space. */
static inline int blkcg_congested_id(struct blkcg *blkcg)
{
	unsigned int id = blkcg->css.id;
#ifdef CONFIG_RMX1931_DUAL_BLKIO
	if (blkcg->v2_controller)
		id |= 1U << 31;
#endif
	return (int)id;
}

/**
 * blkcg_parent -''')
    elif name == 'block/blk-cgroup.c':
        replace('\t\t\t\t\t       blkcg->css.id,', '\t\t\t\t\t       blkcg_congested_id(blkcg),')
        replace('static struct cftype blkcg_files[] = {', '''#ifdef CONFIG_RMX1931_DUAL_BLKIO
static u64 blkcg_v2_delegate_read(struct cgroup_subsys_state *css,
				struct cftype *cft)
{
	return READ_ONCE(css_to_blkcg(css)->v2_delegate);
}

static int blkcg_v2_delegate_write(struct cgroup_subsys_state *css,
				 struct cftype *cft, u64 value)
{
	/* Never let a delegated child disable an ancestor's IO enforcement. */
	if (value != 1)
		return -EINVAL;
	WRITE_ONCE(css_to_blkcg(css)->v2_delegate, true);
	return 0;
}
#endif

static struct cftype blkcg_files[] = {
#ifdef CONFIG_RMX1931_DUAL_BLKIO
	{
		.name = "v2_delegate",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = blkcg_v2_delegate_read,
		.write_u64 = blkcg_v2_delegate_write,
	},
#endif''')
        replace('blkcg_css_alloc(struct cgroup_subsys_state *parent_css)', 'blkcg_css_alloc_common(struct cgroup_subsys_state *parent_css, bool legacy)')
        replace('\tif (!parent_css) {\n\t\tblkcg = &blkcg_root;', '\tif (!parent_css && legacy) {\n\t\tblkcg = &blkcg_root;')
        replace('\tfor (i = 0; i < BLKCG_MAX_POLS ; i++) {', '''#ifdef CONFIG_RMX1931_DUAL_BLKIO
	blkcg->v2_controller = !legacy;
#endif
	for (i = 0; i < BLKCG_MAX_POLS ; i++) {''')
        replace('/**\n * blkcg_init_queue -', '''static struct cgroup_subsys_state *blkcg_css_alloc(struct cgroup_subsys_state *parent_css)
{
	return blkcg_css_alloc_common(parent_css, true);
}

#ifdef CONFIG_RMX1931_DUAL_BLKIO
struct blkcg *blkcg_v2_root;
EXPORT_SYMBOL_GPL(blkcg_v2_root);

static struct cgroup_subsys_state *blkcg_v2_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cgroup_subsys_state *css = blkcg_css_alloc_common(parent_css, false);
	if (!parent_css && !IS_ERR(css))
		blkcg_v2_root = css_to_blkcg(css);
	return css;
}
#endif

/**
 * blkcg_init_queue -''')
        replace('struct cgroup_subsys io_cgrp_subsys = {\n\t.css_alloc = blkcg_css_alloc,', '''#ifdef CONFIG_RMX1931_DUAL_BLKIO
struct cgroup_subsys blkio_cgrp_subsys = {
	.css_alloc = blkcg_css_alloc,
	.css_offline = blkcg_css_offline,
	.css_free = blkcg_css_free,
	.can_attach = blkcg_can_attach,
	.bind = blkcg_bind,
	.legacy_cftypes = blkcg_legacy_files,
	.legacy_name = "blkio",
};
EXPORT_SYMBOL_GPL(blkio_cgrp_subsys);
#endif

struct cgroup_subsys io_cgrp_subsys = {
#ifdef CONFIG_RMX1931_DUAL_BLKIO
	.css_alloc = blkcg_v2_css_alloc,
#else
	.css_alloc = blkcg_css_alloc,
#endif''')
        replace('\t.legacy_cftypes = blkcg_legacy_files,\n\t.legacy_name = "blkio",\n#ifdef CONFIG_MEMCG', '''#ifdef CONFIG_RMX1931_DUAL_BLKIO
	.legacy_name = "rmx_io",
#else
	.legacy_cftypes = blkcg_legacy_files,
	.legacy_name = "blkio",
#endif
#ifdef CONFIG_MEMCG''')
        replace('cgroup_add_legacy_cftypes(&io_cgrp_subsys,', '''cgroup_add_legacy_cftypes(
#ifdef CONFIG_RMX1931_DUAL_BLKIO
						  &blkio_cgrp_subsys,
#else
						  &io_cgrp_subsys,
#endif''')
        replace('\t\t\tif (blkcg->cpd[pol->plid])\n\t\t\t\tpol->cpd_bind_fn', '''			if (blkcg->cpd[pol->plid]
#ifdef CONFIG_RMX1931_DUAL_BLKIO
			    && blkcg->css.ss == root_css->ss
#endif
			   )
				pol->cpd_bind_fn''')
    elif name == 'block/blk-throttle.c':
        replace('cgroup_subsys_on_dfl(io_cgrp_subsys)', 'blkcg_on_dfl(blkg->blkcg)', 4)
        # Global postorder walks must include both independent roots. Per-group
        # stat/config walks deliberately continue to use their own css tree.
        replace('static void blk_throtl_update_limit_valid(struct throtl_data *td)', '''#ifdef CONFIG_RMX1931_DUAL_BLKIO
extern struct blkcg *blkcg_v2_root;

static struct cgroup_subsys_state *throtl_next_queue_css(struct cgroup_subsys_state *pos)
{
	struct cgroup_subsys_state *root = &blkcg_root.css;
	struct cgroup_subsys_state *next;
	if (pos && css_to_blkcg(pos)->v2_controller)
		root = &blkcg_v2_root->css;
	next = css_next_descendant_post(pos, root);
	if (!next && root == &blkcg_root.css && blkcg_v2_root)
		next = css_next_descendant_post(NULL, &blkcg_v2_root->css);
	return next;
}

#define throtl_for_each_queue_post(blkg, pos_css, q) \\
	for ((pos_css) = throtl_next_queue_css(NULL); (pos_css); \\
	     (pos_css) = throtl_next_queue_css(pos_css)) \\
		if (((blkg) = __blkg_lookup(css_to_blkcg(pos_css), (q), false)))
#else
#define throtl_for_each_queue_post(blkg, pos_css, q) \\
	blkg_for_each_descendant_post(blkg, pos_css, (q)->root_blkg)
#endif

static void blk_throtl_update_limit_valid(struct throtl_data *td)''')
        replace('blkg_for_each_descendant_post(blkg, pos_css, td->queue->root_blkg)', 'throtl_for_each_queue_post(blkg, pos_css, td->queue)', 4)
    elif name == 'block/cfq-iosched.c':
        replace('cgroup_subsys_on_dfl(io_cgrp_subsys) ?', 'blkcg_on_dfl(cpd_to_blkcg(cpd)) ?')
        replace('bool on_dfl = cgroup_subsys_on_dfl(io_cgrp_subsys);', 'bool on_dfl = blkcg_on_dfl(blkcg);')
    elif name == 'block/bfq-cgroup.c':
        replace('cgroup_subsys_on_dfl(io_cgrp_subsys)', 'blkcg_on_dfl(cpd_to_blkcg(cpd))')
    elif name == 'block/bio.c':
        replace('#include <linux/cgroup.h>', '#include <linux/cgroup.h>\n#include <linux/blk-cgroup.h>')
        replace('bio->bi_css = task_get_css(current, io_cgrp_id);', 'bio->bi_css = task_get_blkcg_css(current);')
    elif name == 'mm/backing-dev.c':
        replace('cgroup_get_e_css(memcg_css->cgroup, &io_cgrp_subsys)', 'blkcg_get_writeback_css(memcg_css->cgroup)')
        replace('cgroup_get_e_css(memcg_css->cgroup,\n\t\t\t\t\t\t     &io_cgrp_subsys)', 'blkcg_get_writeback_css(memcg_css->cgroup)')
        replace('wb_init(wb, bdi, blkcg_css->id, gfp)', 'wb_init(wb, bdi, blkcg_congested_id(blkcg), gfp)')
        replace('\tif (!memcg_css->parent)\n\t\treturn &bdi->wb;', '''#ifdef CONFIG_RMX1931_DUAL_BLKIO
	/* Preserve Android's pre-existing single root writeback path. */
	{
		struct cgroup_subsys_state *css = blkcg_get_writeback_css(memcg_css->cgroup);
		bool selected = css != blkcg_root_css;
		css_put(css);
		if (!selected)
			return &bdi->wb;
	}
#endif
	if (!memcg_css->parent)
		return &bdi->wb;''')
    elif name == 'include/linux/backing-dev.h':
        replace('\tmemcg_css = task_css(current, memory_cgrp_id);', '''#ifdef CONFIG_RMX1931_DUAL_BLKIO
	if (!blkcg_v2_selected(task_css(current, io_cgrp_id)))
		return &bdi->wb;
#endif
	memcg_css = task_css(current, memory_cgrp_id);''')
    else:
        raise ValueError(name)
    return text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    assert args.base.resolve() != args.source.resolve()
    names = ['init/Kconfig', 'include/linux/cgroup_subsys.h', 'include/linux/blk-cgroup.h',
             'block/blk-cgroup.c', 'block/blk-throttle.c', 'block/cfq-iosched.c',
             'block/bfq-cgroup.c', 'block/bio.c', 'mm/backing-dev.c', 'include/linux/backing-dev.h']
    record = {'source': str(args.source), 'base_source': str(args.base), 'modified_sources': {},
              'scope': 'Personal opt-in V2 blkcg, retaining Android V1 root and policy semantics'}
    patch = []
    prepared = {}
    for name in names:
        before = (args.base / name).read_bytes()
        after = transform(name, before.decode()).encode()
        prepared[name] = (before, after)
        record['modified_sources'][name] = {'before_sha256': sha(before), 'after_sha256': sha(after)}
        patch.extend(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                         fromfile='a/' + name, tofile='b/' + name))
    if not args.source.exists():
        shutil.copytree(args.base, args.source, symlinks=True)
    destination = ROOT / 'artifacts/droidspaces/kernel-ext-dualio'
    previous = {}
    if (destination / 'source.json').exists():
        manifest = json.loads((destination / 'source.json').read_text())
        assert manifest['source'] == str(args.source) and manifest['base_source'] == str(args.base)
        previous = manifest['modified_sources']
    for name, (before, after) in prepared.items():
        target = args.source / name
        actual = target.read_bytes()
        old = previous.get(name, {})
        known_previous = old.get('before_sha256') == sha(before) and old.get('after_sha256') == sha(actual)
        assert actual in (before, after) or known_previous, ('Unreviewed source change', name)
        target.write_bytes(after)
    destination.mkdir(parents=True, exist_ok=True)
    patch_path = ROOT / 'patches/rmx1931-opt-in-dual-blkio.patch'
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_text(''.join(patch), encoding='utf-8', newline='\n')
    record['patch_sha256'] = sha(patch_path.read_bytes())
    (destination / 'source.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
