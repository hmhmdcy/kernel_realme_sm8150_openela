# 分组 PSI 与容器内存策略

完整 Android 16 桌面按用户要求保持暂停。本项用于宿主 Android 和现有 Linux 容器，与完整桌面交付分开记录。

当前状态：a16pf 已通过[同 boot 联合验收](runtime/candidates/a16pf/evidence/group-psi-acceptance.json)，为最新已验证版本。下文保留 a16ps 的失败及 a16pf 构建/修复过程；后续测试按[精简范围](TEST-POLICY.md)执行。

基线 h5bf2 已包含分组 PSI 的任务统计、cgroup 文件和触发器实现，但内置 `CONFIG_CMDLINE` 与 ROM boot header 各包含一个 `cgroup_disable=pressure`。实机因此缺少容器自己的 `memory.pressure`，而 LMKD 已使用两个全局 `/proc/pressure/memory` 文件。见同 boot 基线（本地证据：`runtime/candidates/a16ps/evidence/runtime/cgroup-psi-baseline-h5bf2-20261005.json`）。

候选 `android16-group-psi` / `a16ps` 保留 h5bf2 全部源码。唯一有效配置变更是将 `CONFIG_CMDLINE="cgroup_disable=pressure"` 换成标准 `psi=1`；打包时只移除原 boot header 中最后那个禁用参数。保留 ramdisk、DTB 与其余 header 字段，单独审核这项启动参数变化，不声称整个非内核 header 完全未变。未增加自定义强制启用接口，不把已有 PSI 当作新回移功能。

首次本地尝试使用空 `CONFIG_CMDLINE`，导致 Kconfig 隐藏启动参数选择及 `CONFIG_INITRAMFS_FORCE`；严格配置审计在内核编译前拒绝。已保留本地失败记录（本地证据：`runtime/candidates/a16ps/evidence/kernel-ext-android16-group-psi/attempts/empty-cmdline-config/result.json`），改用现有标准 `psi=1` 后仅一项配置变化。该失败未操作手机。

guest 策略新增可选 `--memory-high-mib`，必须至少 16 MiB 且小于 `--memory-mib` 硬限额。原格式继续可用；未填写时沿用原行为。该阈值由 OCI 在首条应用指令前写入本容器 `memory.high`，超过阈值触发本组回收，不自动杀死宿主应用。仍保留 `memory.max`、`memory.oom.group` 和原有过滤。

`rmx1931-pressure` 是前台通知工具。它固定完整容器 ID、进程启动时间和已打开的 cgroup 目录，等待该容器的真实内存压力通知；进程退出、移组或同名替换时拒绝跟随。工具关闭即撤销自己的触发器，不改变限额或 LMKD，也不自动停止容器。

在已安装工具的 Ubuntu guest 中：

```sh
rmx1931-policy set my-memory-policy --mode rootful --cpus .5 \
  --memory-mib 64 --memory-high-mib 32 --pids 32 \
  --read-bps 2097152 --write-bps 2097152 --oom-group
podman run -d --name my-container --network=none \
  --annotation io.rmx1931.resource-policy=my-memory-policy IMAGE COMMAND
rmx1931-pressure --mode rootful --name my-container \
  --threshold-us 50000 --window-us 1000000 --timeout 60
```

rootless 使用 UID 1000 的策略与 `podman-rootless`，通知工具参数改为 `--mode rootless`。观察必须在可信 guest root 操作入口运行。达到通知次数返回 0；截止时间内未达到返回 3。通知说明发生内存停顿，不能据此宣称性能、续航或抗 OOM 效果已经改善。

验收状态：候选完整构建与审计通过，59 个累计修改文件摘要一致、现有导出符号 CRC 未变化。空间清理后已完成打包、刷入与独立启动核验（本地证据：`runtime/candidates/a16ps/evidence/extensions-android16-group-psi-boot-result.json`），当前仍未通过完整运行验收。策略的 9 项离线边界测试通过；这不代替分组 PSI 实机通过。实测以 rootful/rootless、crun/runc 的真实限额内存负载检查首条指令、压力统计/通知、父组传播、空闲邻组、参数错误/重复触发器、关闭与组清理、停止启动及重建。负载前后记录同 boot 的宿主关键服务和 LMKD 全局 PSI 文件，保持 SELinux Enforcing，并复验受影响的容器能力。

首轮夹具失败于通知工具只识别 scope 根目录，而 crun 的真实应用进程位于 `libpod-完整ID.scope/container`。工具现接受该标准子目录及 scope 根目录，仍要求完整 ID、固定进程启动时间和目录 FD；不同 ID、路径穿越及其他子目录继续拒绝。两项离线身份边界测试通过，修正版已安装。保留首轮失败（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-policy-a16ps-20261005.json`）、实际 cgroup 诊断（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-monitor-diagnostic-a16ps-20261005.json`）及工具安装记录（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-monitor-child-fix-a16ps-20261005.json`）。

第二轮已收到真实压力通知，子组 `some` 增长 4,350,957 微秒，但测试错误要求父组总值必须大于等于子组而失败。实际 `psi.c` 的 `collect_percpu_times()` 根据各组自己的非空闲 CPU 时间加权归一化；`iterate_groups()` 传播任务状态，但这种统计不保证父子数值的大小关系。已保留失败结果（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-policy2-a16ps-20261005.json`）、原通知日志（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-retained-diagnostic-a16ps-20261005.json`）及实际源码与失败夹具快照（本地证据：`runtime/candidates/a16ps/evidence/runtime/source-versions/group-psi-parent-diagnostic/source.json`）。后续判据改为子组和父组各自增长并独立收到触发器通知，邻组保持无压力；不以修改内核累计算法来满足错误判据。两次失败后宿主健康核验（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-host-after-failures-a16ps-20261005.json`）通过：同一 boot 的四个关键服务未重启，LMKD 保留全局压力监视，未发现 PSI underflow、leak、inconsistent 或内核致命诊断。

依据：[Linux PSI 接口与 per-cgroup 通知](https://docs.kernel.org/accounting/psi.html)；实际可用参数与格式以本机现有 4.14 源码和真实验收为准，不推断所有新版 PSI 接口可用。

后续同 boot 验收已取得以下通过结果：四种容器的 some 压力与父组通知（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-policy3-a16ps-20261005.json`）、通知工具超时/进程移组/同名替换（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-monitor-lifecycle-a16ps-20261005.json`）、真实 guest 重启前（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-restart-before-a16ps-20261005.json`）与重启后身份（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-restart-after-a16ps-20261005.json`）、策略恢复/首条指令/exec/工具订阅及清理（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-persistence-collected2-a16ps-20261005.json`）。guest PID 从 4636 变为 15784，PID namespace 变化，四个完整容器 ID、策略文件摘要及工具摘要保持一致。恢复夹具最初立即读取日志导致空结果；随后又错误假定日志目录能证明保留方式。修正为按 JSON `StartedAt` 等待本次启动输出后，从已经观察到的原进程继续收集，未重放该容器启动。原始首次收集失败（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-persistence-resume-a16ps-20261005.json`）、目录假设失败（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-persistence-collected-a16ps-20261005.json`）、源版本和诊断均保留。

受影响回归已通过：过滤保留（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-filter-a16ps-20261005.json`）、实际 CPU/cpuset 与权重负载（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-native-cpu-a16ps-20261005.json`）、crun 旧格式策略（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-policy-crun-a16ps-20261005.json`）、runc 旧格式策略（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-policy-runc-a16ps-20261005.json`）及Android 16 Binder 公开回调（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-binder-public-api-a16ps-20261005.json`）。这些通过仍不能替代尚未通过的 full 通知测试。

`full` 订阅在首次实测（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-policy-full-a16ps-20261005.json`）没有收到通知，按 deadline 返回 3。计数诊断（本地证据：`runtime/candidates/a16ps/evidence/runtime/psi-policy-full-diagnostic-a16ps-20261005.json`）确认 8.18 秒内存回收负载中，子组 full 计数实际增长 654,858 微秒，父组增长 656,567 微秒，但 full-only 订阅仍无通知。硬限额和过滤保留，OOM kill 为 0，夹具已清理。当前不能把 a16ps 标记为完整运行验收通过，最新已验证版本仍为 h5bf2。

失败候选仍用 `NR_RUNNING == 0` 判断 memory full；正在回收内存的任务留在运行队列上，旧 tick 采样会增加 full 计数，但不等同于 full 状态已进入并驱动独立触发器。已找到直接相关的固定上游修复 [cb0e52b：区分 runnable reclaimer 与正常 productive task](https://github.com/torvalds/linux/commit/cb0e52b7748737b2cf6481fdd9b920ce7e1ebbdf)，保存原补丁、当前源码及摘要（本地证据：`runtime/candidates/a16ps/source-versions/group-psi-upstream/source-lock.json`），准备三文件适配（本地证据：`runtime/candidates/a16pf/evidence/kernel-ext-android16-group-psi-reclaim-fix/preparation.json`）。适配保留本机 `PF_MEMSTALL`，在 enqueue/dequeue 中维护 runnable memstall，并同步补齐本机手工重建状态的 `cgroup_move_task`；不引入本机没有的 `TSK_ONCPU` 或修改 WALT。准备阶段只导出并验证补丁，未声称实机修复。后续构建、部署与验收状态单独记录如下。

后续修复候选 `android16-group-psi-reclaim-fix` / `a16pf` 已在独立 WSL 源码和输出目录完成内核与模块构建。累计源码核验为 62 文件，其中继承 h5bf2 的 59 文件保持一致，仅增加上述 3 文件修改；有效配置沿用 a16ps，与 h5bf2 的差异仍只有标准 `psi=1`。WALT 和通用 cgroup 核心摘要不变。原 DTB、ramdisk 和 PSI 参数以外的非内核 header 字段核验通过，打包记录（本地证据：`runtime/candidates/a16pf/evidence/boot-images/ext-android16-group-psi-reclaim-fix-candidate-check.json`）与实际启动核验（本地证据：`runtime/candidates/a16pf/evidence/extensions-android16-group-psi-reclaim-fix-boot-result.json`）均已生成，当前 boot 为 `b5d511b9-fe8d-44d0-94a9-957babb14d53`。完整运行验收仍待完成，h5bf2 仍为最新完整验收版本。

这次修复确实改变 ABI：12,219 个导出符号均保留，3,916 个 CRC 改变，包括 `module_layout`。初次严格审计拒绝的原始记录（本地证据：`runtime/candidates/a16pf/evidence/kernel-ext-android16-group-psi-reclaim-fix/abi-change/build-audit-before-review.json`）保留。类型诊断（本地证据：`runtime/candidates/a16pf/evidence/kernel-ext-android16-group-psi-reclaim-fix/abi-change/type-analysis.json`）使用两个实际构建上下文，重现 unchanged `core.c` 的 23 个导出 CRC 并与实际 `Module.symvers` 一致；其可达类型定义中唯一变化是 `NR_PSI_TASK_COUNTS` 从 3 到 4，解释类型递归传播。依据会话已有的明确 ABI 变更授权完成限定审计（本地证据：`runtime/candidates/a16pf/evidence/kernel-ext-android16-group-psi-reclaim-fix/abi-change/review.json`），没有伪造旧 CRC，也不声称旧模块兼容。配置驱动均内建，构建记录 `MODPOST 0 modules`；部署前实际核验（本地证据：`runtime/candidates/a16pf/evidence/extensions-android16-group-psi-reclaim-fix-preflight.json`）确认手机没有加载或可用的外部 `.ko`。该条件仍是部署与验收的必要门槛。

上述构建/部署段落记录当时的未验收状态。后续 a16pf 已完成同 boot 联合验收，见[不可变验收结果](runtime/candidates/a16pf/evidence/group-psi-acceptance.json)。四种 some/full 独立通知、父组传播/邻组无压力、首条指令/exec/停止启动/重建、监视身份/超时/移组/替换拒绝、回收任务移组、真实 guest 重启持久化及过滤/CPU/旧策略/Binder/宿主回归全部通过。guest PID 从 4700 变为 20820，namespace 改变，容器 ID 与策略摘要保持；夹具清理完成。最新已验收版本更新为 a16pf，h5bf2 保留为回退版本。

首轮 a16pf full 已收到实际通知，随后因按 StartedAt 过滤重建日志得到空输出而失败；保留原报告（本地证据：`runtime/candidates/a16pf/evidence/runtime/psi-policy-full-a16pf-20261005.json`），改为按实际 PID starttime 识别首条输出后复测通过（本地证据：`runtime/candidates/a16pf/evidence/runtime/psi-policy-full2-a16pf-20261005.json`）。此为夹具修正，未重刷内核。两次 guest 配置遇 ADB 中断均从已观察到的原 PID 继续缺失配置，未重放启动。

本轮完整矩阵作为首次交付证据保留。后续复验遵循[精简测试范围](TEST-POLICY.md)，不为汇总重复已通过同 boot 用例，不把全矩阵变成每次工具修正的要求。eBPF 的当前 ROM 实际需求仍待核查，完整桌面继续暂停。

原始日志与完整历史封存保留本地；上面的本地证据路径用于定位，GitHub 发布精选验收摘要。
