/* SPDX-License-Identifier: GPL-2.0 */
/* Included by cpuset.c. Basic V2 interface follows Linux 4ec22e9c5a90. */
static struct cgroup_subsys_state *
rmx_cpuset_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cgroup_subsys_state *css;

	if (!parent_css)
		return &top_cpuset_v2.css;
	css = cpuset_css_alloc(parent_css);
	if (!IS_ERR(css))
		clear_bit(CS_SCHED_LOAD_BALANCE, &css_cs(css)->flags);
	return css;
}

static void rmx_cpuset_css_reset(struct cgroup_subsys_state *css)
{
	struct cpuset *cs = css_cs(css);
	cpumask_t new_cpus;
	nodemask_t new_mems;

	if (!css->parent)
		return;
	cpus_read_lock();
	mutex_lock(&cpuset_mutex);
	spin_lock_irq(&callback_lock);
	cpumask_clear(cs->cpus_requested);
	cpumask_clear(cs->cpus_allowed);
	nodes_clear(cs->mems_allowed);
	spin_unlock_irq(&callback_lock);
	update_cpumasks_hier(cs, &new_cpus);
	update_nodemasks_hier(cs, &new_mems);
	mutex_unlock(&cpuset_mutex);
	cpus_read_unlock();
}

static struct cftype rmx_cpuset_files[] = {
	{
		.name = "cpus",
		.seq_show = cpuset_common_seq_show,
		.write = cpuset_write_resmask,
		.max_write_len = (100U + 6 * NR_CPUS),
		.private = FILE_CPULIST,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "mems",
		.seq_show = cpuset_common_seq_show,
		.write = cpuset_write_resmask,
		.max_write_len = (100U + 6 * MAX_NUMNODES),
		.private = FILE_MEMLIST,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "cpus.effective",
		.seq_show = cpuset_common_seq_show,
		.private = FILE_EFFECTIVE_CPULIST,
	},
	{
		.name = "mems.effective",
		.seq_show = cpuset_common_seq_show,
		.private = FILE_EFFECTIVE_MEMLIST,
	},
	{ }
};

struct cgroup_subsys cpuset_cgrp_subsys = {
	.css_alloc = rmx_cpuset_css_alloc,
	.css_online = cpuset_css_online,
	.css_offline = cpuset_css_offline,
	.css_free = cpuset_css_free,
	.css_reset = rmx_cpuset_css_reset,
	.can_attach = cpuset_can_attach,
	.cancel_attach = cpuset_cancel_attach,
	.attach = cpuset_attach,
	.post_attach = cpuset_post_attach,
	.bind = cpuset_bind,
	.dfl_cftypes = rmx_cpuset_files,
	.legacy_name = "rmx_cpuset",
	.early_init = true,
	.threaded = true,
};
