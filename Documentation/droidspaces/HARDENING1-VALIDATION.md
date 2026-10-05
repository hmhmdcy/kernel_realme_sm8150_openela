# 第一阶段：容器 OOM 与清理功能验收

2026-10-04 已部署并验收 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-harden1`。当前 boot SHA-256 为 `774963cfead434af43434a055974f4030e2a7bae446f3074314cc2da1f17c4d5`，boot ID 为 `53691308-0284-4dd0-b313-2ac387166080`。原 ROM 的 ramdisk、DTB 和非内核 header 字段保留，实际配置与构建配置一致，KernelSU 33304/UAPI4、SELinux Enforcing、普通 guest seccomp=2。报告见[第一阶段验收](hardening1-acceptance.json)。

| 功能 | 当前启动的实测结果 |
| --- | --- |
| memory.oom.group | 默认关闭；开启后杀死同组任务和线程；oom_score_adj=-1000 进程保留；父组覆盖后代，叶子 OOM 不越过发生 OOM 的内存域；邻组存活 |
| cgroup.kill | 仅接受 1；递归清理后代，邻组不受影响；冻结组可清理；threaded cgroup 返回 EOPNOTSUPP；12 轮有 pids.max=32 的并发 fork 清理通过 |
| 实际 Podman | rootful/rootless 各执行分组关闭与开启对照；关闭时 OOM 子进程被杀而父进程正常退出，开启时整组退出 137；四个 payload 均 seccomp=2 |
| 累计回归 | 20 项功能证据、官方 27 项能力检查通过；包含已有存储、构建、端口、DNS、内存/PID 限额、LXC、WireGuard 和 checkpoint 用例 |
| 既有 CPU 管理入口 | rootful/rootless 与 exec 从约 4 核降至 0.5 核，出现 throttling；解除后恢复，叶子与挂载清理 |
| 原生 V2 IO | guest/rootful/rootless 的 16 MiB 读写在 2 MiB/s 下约 8 秒；解除后恢复；父组限额、兄弟隔离、缓冲写回通过 |
| 最终状态 | 临时测试 cgroup、测试容器、CPU 叶子挂载清理；全局 cgroup 根没有 cgroup.kill；当前 dmesg 未发现 BUG/Oops/panic 或模块版本错误 |

新增源补丁回移了上游 cgroup.kill、fork 竞争修复、memory.oom.group、OOM 迁移域边界及 css_reset 修复。为 4.14 的旧 fork、信号和 memcg 引用 API 做适配，保留已有 OOM 选中任务引用修复。没有新增配置开关或自动为 Android 进程启用整组 OOM。源文件和上游摘要记录在构建材料及 source lock 中。

第一次九个内核用例已通过，但 Podman 从独立无过滤操作入口启动，未满足普通 guest 过滤验收条件，故该报告保留为失败。修正为通过已过滤的 guest systemd 启动实际容器后，13 项全部通过；没有更改普通 guest 的过滤策略。

此阶段相对 dualio 改变 8,220 个已有导出 CRC，无导出缺失，外部 .ko 必须重编。测试手机没有加载或发现外部内核模块。既有 CPU 限额仍是 V1 独立管理入口，尚未提供原生 V2 CPU/cpuset 和跨重启持久策略。

本记录验收第一阶段。[补强计划](CONTAINER-HARDENING-PLAN.md)中的第 1–5 阶段现已分别完成验收；第 6 阶段完整 Android 16 桌面与应用容器于 2026-10-05 按用户要求暂停。宿主与现有 Linux 容器使用的 Android 16 Binder/LMKD/eBPF 补强继续进行。KVM/AVF 的当前 EL1 限制和类似案例见[平台可行性](VIRTUALIZATION-FEASIBILITY.md)。本轮没有再次触发 panic；Wi-Fi、传感器等常规专项未执行，遵循[测试范围](TEST-POLICY.md)。源码和文档为本地未提交迭代。
