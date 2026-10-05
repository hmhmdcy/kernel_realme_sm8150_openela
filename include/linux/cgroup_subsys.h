/* SPDX-License-Identifier: GPL-2.0 */
/*
 * List of cgroup subsystems.
 *
 * DO NOT ADD ANY SUBSYSTEM WITHOUT EXPLICIT ACKS FROM CGROUP MAINTAINERS.
 */

/*
 * This file *must* be included with SUBSYS() defined.
 */

#if IS_ENABLED(CONFIG_CPUSETS)
SUBSYS(cpuset)
#if IS_ENABLED(CONFIG_RMX1931_DUAL_CPUSET)
/* Device-local compatibility tree, keeping the ROM mount name. */
SUBSYS(cpuset_legacy)
#endif
#endif

#if IS_ENABLED(CONFIG_CGROUP_SCHED)
SUBSYS(cpu)
#if IS_ENABLED(CONFIG_RMX1931_DUAL_CPU)
/* Personal legacy copy, retaining the Android mount name "cpu". */
SUBSYS(cpu_legacy)
#endif
#endif

#if IS_ENABLED(CONFIG_CGROUP_CPUACCT)
SUBSYS(cpuacct)
#endif

#if IS_ENABLED(CONFIG_SCHED_TUNE)
SUBSYS(schedtune)
#endif

#if IS_ENABLED(CONFIG_BLK_CGROUP)
SUBSYS(io)
#if IS_ENABLED(CONFIG_RMX1931_DUAL_BLKIO)
/* Device-local legacy copy; not a proposed upstream subsystem. */
SUBSYS(blkio)
#endif
#endif

#if IS_ENABLED(CONFIG_MEMCG)
SUBSYS(memory)
#endif

#if IS_ENABLED(CONFIG_CGROUP_DEVICE)
SUBSYS(devices)
#endif

#if IS_ENABLED(CONFIG_CGROUP_FREEZER)
SUBSYS(freezer)
#endif

#if IS_ENABLED(CONFIG_CGROUP_NET_CLASSID)
SUBSYS(net_cls)
#endif

#if IS_ENABLED(CONFIG_CGROUP_PERF)
SUBSYS(perf_event)
#endif

#if IS_ENABLED(CONFIG_CGROUP_NET_PRIO)
SUBSYS(net_prio)
#endif

#if IS_ENABLED(CONFIG_CGROUP_HUGETLB)
SUBSYS(hugetlb)
#endif

#if IS_ENABLED(CONFIG_CGROUP_PIDS)
SUBSYS(pids)
#endif

#if IS_ENABLED(CONFIG_CGROUP_RDMA)
SUBSYS(rdma)
#endif

/*
 * The following subsystems are not supported on the default hierarchy.
 */
#if IS_ENABLED(CONFIG_CGROUP_DEBUG)
SUBSYS(debug)
#endif

/*
 * DO NOT ADD ANY SUBSYSTEM WITHOUT EXPLICIT ACKS FROM CGROUP MAINTAINERS.
 */
