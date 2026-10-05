# 当前 Android 16 的 cgroup V2 迁移评估

2026-10-04，只读核对 RMX1931 当前运行的 Android 16（API 36）及 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-harden1`。完整迁移到单一 V2 可作为长期目标；当前依赖跨越内核、ROM 初始化、任务配置和 Power HAL，难度高，不能通过改挂载路径或一个配置项完成。最初依赖评估未修改手机配置；后续原生 CPU/cpuset 过渡候选已刷入，完整功能验收仍在进行。

## 实机依赖

| 项目 | 当前实际状态 | 迁移影响 |
| --- | --- | --- |
| 控制器布局 | V1 挂载 `/dev/cpuctl`、`/dev/cpuset`、`/dev/stune`、`/dev/blkio`；V2 对外启用 `io memory pids` | Android 16 版本号不能证明宿主已经采用全 V2 |
| 系统配置 | `/system/etc/cgroups.json` 声明 V1 CPU、cpuset、blkio；task profiles 使用这些控制器 | 需同步改控制器声明、任务动作、文件名和权限 |
| 厂商任务配置 | `/vendor/etc/task_profiles.json` 将多种性能 profile 覆盖为 schedtune 分组，使用 `schedtune.boost`、`schedtune.prefer_idle` | 仅改 system 配置会被 vendor 覆盖；需一起迁移 |
| 厂商启动脚本 | `init.target.rc` 直接写 cpuset 的核集合及 schedtune boost、prefer_idle、colocate；多份服务 rc 使用 V1 `writepid` | 需逐条替换初始化和服务归组操作，确认原调度意图；发现的写入不能都视作当前内核有效接口 |
| 实际 Power HAL | `android.hardware.power-service.lineage-libperfmgr` 正在运行；`powerhint.json` 的 TASchedtuneBoost 写 `/dev/stune/top-app/schedtune.boost`，值含 30、10、0 | 必须保留或重新实现这些性能提示；删除 stune 后不能让提示静默失效 |
| CPU 接口 | `top-app` 只有 CFS quota/period、shares、stat 等接口，没有 `cpu.uclamp.*` | stock profile 中出现 UClamp 属性不代表内核已实现；需选择并验证 WALT 性能策略迁移方案 |
| V2 线程基础 | 实际非根组存在 `cgroup.type`、`cgroup.threads`，system_server 所在组类型为 domain | 基础线程机制已存在；仍需验证 CPU/cpuset 控制器与 Android 逐线程归组的完整配合。根目录没有 cgroup.type 不能用于判定线程机制缺失 |
| 独立归组轴 | SurfaceFlinger 在 V1 schedtune foreground、cpuset system-background，V2 在 `/system/uid_1000/pid_694` | 多棵 V1 树的归属无法直接照搬成一棵 V2 树；需设计进程内存域、线程性能分组和容器子树 |
| 内核 cpuset | 基线 cpuset 只注册 legacy_cftypes；V1 挂载参数有 cpuset_v2_mode | cpuset_v2_mode 不等于存在原生 V2 cpuset 控制器，仍需补齐接口与层级行为 |

实机报告及 SHA-256 见评估证据（本地证据：`cgroup-v2-migration-assessment.json`）。报告中的 fingerprint 保留 Android 11 字符串，而 SDK 为 36；该字符串不能单独用于判断运行系统或厂商实现的新旧。

## 完整迁移的工作量

1. **内核控制器：中等到较高。** 补齐单一 CPU 控制器的 V2 quota、weight、统计及 cpuset 请求/有效核集合、父子约束、继承、热插拔行为。已有 V2 memory/pids/io 降低了工作量；不必重写整个调度器，也不必为了 V2 更换 WALT。
2. **统一层级及 Android 用户态：较高。** 保留当前 UID/PID 内存与冻结管理，重新设计 top-app/foreground/background 等线程调度位置。核对 libprocessgroup 实际 V2 线程写入行为，修改 system/vendor task profiles、init 及 SELinux 权限。不同 V1 控制器原本可以分别移动线程，V2 的统一归属与 threaded/domain 规则需要明确处理。
3. **schedtune / Power HAL：较高，是当前最明显的依赖。** 上游 V2 没有同名 schedtune 控制器。可评估 uclamp 与必要的 WALT 策略支持；boost 百分比、prefer_idle、colocate 与 uclamp 的语义不同，不能按相同数值或名称机械转换。保留 V1 stune 只能算阶段性混合布局，不能称为全 V2。
4. **其他 V1 使用者：继续盘点。** 将 blkio 策略迁至 V2 io；旧 devices 控制要使用 V2 cgroup BPF 的等效机制，net_prio 若有实际使用则需要替代策略。当前没有挂载这些旧控制器，不代表全部消费者已经排除。厂商闭源库、其他配置目录和运行时调用尚未完成完整审计。
5. **实际验收：较高。** 覆盖启动、应用前后台切换、Power HAL 提示、CPU 核集合/性能行为、LMKD/冻结、rootful/rootless 容器策略及 guest 生命周期。只检查文件存在或能启动不足以验收。测试限于受影响功能，沿用[测试范围](TEST-POLICY.md)，不恢复 Wi-Fi、传感器等默认整机专项。

这些是基于当前证据的工程评估，尚未完成全 V2 ROM 原型和运行验证，不给出确定工期或性能提升幅度。

## 独立 CPU 任务组与第二套控制器

容器自己的 CPU cgroup 仍有用途：为该容器设置限额、权重、核心范围并统计消耗。统一 V2 后可以在同一棵树下划分 Android 与容器子树，无须为容器另造一套 CPU 控制器。

目前候选中的 dual CPU 是迁移兼容方案：保留 Android 的 V1 路径，并给容器提供 V2 CPU 接口。这增加了 CSS 状态、归组选择和维护/验收范围。候选按任务选择实际 CFS task_group，不能描述成每个任务同时受到两套 CPU quota；运行开销尚未测量。宿主全部迁移并验收后，第二套兼容控制器应移除。

阶段 2 的原验收使用 V1 `/dev/cpuctl`。策略服务现已补充原生 V2 后端：guest 提供 CPU 控制器时使用 OCI CPU quota/period，否则继续使用 V1。升级后的服务已在 harden1 上完成 crun/runc 的 rootful/rootless 回归及真实 CPU 压测；0.5 CPU 策略分别测得约 0.501/0.506 核，无策略的四线程对照约 3.97 核。原生 V2 后端已在 h2cp 完成 rootful/rootless 创建、exec、停止/再启动、重新创建、策略服务退出及恢复、整组 OOM、邻组隔离和真实 guest 停止/重启后的完整生命周期回归。重启后 0.5 CPU 分别测得约 0.507/0.508 核，8 MiB 直接 IO 受 2 MiB/s 限制约耗时 4 秒，pids 限制返回 EAGAIN；策略摘要和容器 ID 保持一致，测试容器及策略已清理。见[原生策略验收](native-policy-h2cp-acceptance.json)。该结果只验收 h2cp 的持久化策略，不代表阶段 3 或后续修复镜像已经通过。

当前建议把单一 V2 作为最终架构，把双控制器作为保留现有 ROM 的可退出过渡方案。全 V2 属于 ROM 与内核协同迁移；当前工作区没有发现完整 Android framework / Power HAL 构建工程。先完成消费者清单及层级、性能策略方案，再决定全 V2 原型的实施范围，不能直接在日用 ROM 禁用所有 V1。

## 当前候选状态与依据

最新已验收镜像为 `ext-h2cp4`，boot ID 为 `33e13536-7ccc-4e64-a66e-0b4413a56b60`，阶段 3 联合结果已通过。以下按候选版本保留历史构建、失败诊断和修复证据；早期失败不代表 h2cp4 的当前结论。

原生 V2 CPU 与 cpuset 累计候选 `ext-h2cp` 已通过完整内核构建和 45 个源码文件、配置及符号审计，镜像 SHA-256 为 `1c4311c1d9687d022c2c95739d263eb677c471b0ad95b1657d81d99415964e37`；相对 harden1 有 3916 个导出 CRC 变化，无导出符号缺失。DTB 与原 boot 相同。已刷入并通过 boot 验证，阶段 3 的完整功能验收尚未完成。此前 CPU 单独候选及失败的过长 release 名称构建记录保留，历史 harden1 和阶段 2 验收保持原结论。

部署更新：boot 已完成原镜像逐字节重建、ramdisk/header 保留与 AVB 校验，SHA-256 为 `1e1643c193ae5037416cb7525148050202e612bf7f561fefd58ae0558e4393d9`。首次 fastboot 发送阶段以 Windows USB 错误 995 失败，记录已封存。用户返回 Android 后确认原 harden1 boot 未改变，重新预检并按已有部署/ABI 授权进入 bootloader；使用已确认序列号直接 flash，发送和写入均返回 OKAY，重启后 release/config/boot SHA、SELinux Enforcing 及 KSU 通过。该次 boot ID 为 `c9b7751f-d8f9-417f-a0a1-ed4f58ae5d83`。部署工具已支持 `--fastboot-serial`，核对预检序列号摘要后直接写入，不再额外枚举/getvar。见部署记录（本地证据：`extensions-harden2-cpuset-deployment.json`）、boot 验证（本地证据：`extensions-harden2-cpuset-boot-result.json`）及保留的传输失败记录（本地证据：`native-cpuset-deployment-transport-failure-20261004.json`）。

部署后验收工具已补齐：原生 Podman CPU 负载（本地证据：`runtime/candidates/h2cp/scripts/probe_native_cpu_podman.sh`）覆盖 rootful/rootless、crun/runc 的 quota、核心绑定、fork/exec、cpu.stat 节流及同核权重竞争；cpuset 层级测试（本地证据：`runtime/candidates/h2cp/scripts/probe_native_cpuset_hierarchy.sh`）覆盖空请求继承、请求/有效集合、父组收窄/扩展、affinity 限制和进程/线程继承。h2cp 的 cpuset 层级及 CPU 7 真实离线/上线测试已通过，有效核集合与工作线程 affinity 同步收窄和恢复，全部 CPU 恢复在线。热插拔首次测试因核集合文本格式比较失败，保留失败记录，改为集合比较后的成功不覆盖原记录。

rootful Podman 的 quota、fork/exec 和绑定已通过。rootless 最初缺少用户服务的 cpuset 委派，修正受管 drop-in 并真实重启 guest 后，crun/runc 与 live exec 的 0.5 CPU 分别测得约 0.503/0.504/0.502 核，线程限定在 CPU 6、7，普通过滤仍为 Seccomp 2。CPU 权重仍有实测故障：同步起跑、预热和逐线程 affinity 核对后的 rootful 比值为 12.532，rootless 为 18.392，均超出原定验收范围。直接自建 cgroup 的等权、4:1、交换权重与嵌套案例通过，不能代替 Podman 场景的失败。

调度诊断显示 Podman 父组的 task_group 总负载贡献残留，权重分配因此偏离。已依据上游 [02da26ad](https://android.googlesource.com/kernel/common/+/02da26ad5ed6ea8680e5d01f20661439611ed776) 制作 `ext-h2cp2` 修复候选，在 `update_blocked_averages()` 的父组更新中加入 `UPDATE_TG`。累计 46 个源码文件构建审计通过，配置、WALT 源码和通用 cgroup 核心不变；内核 SHA-256 为 `f36fa1a9ef6094dcb5ed559122175c07fecd4398278789611750802d60ccf8bf`，boot SHA-256 为 `96a11ef6bf97f7388442fd8a1314802ea0d3368409e4ed53bc61d51a97ec345a`，DTB/ramdisk/header/AVB 校验通过。修复效果必须由新镜像实机负载验证。

修复候选首次按已确认序列号直接刷入，在发送阶段因 Windows USB 错误 433 失败，未出现 boot 写入记录，原失败记录已封存。Windows 恢复正确的 bootloader 接口后，直接使用已确认序列号刷入，未追加 fastboot 枚举或 getvar；发送与写入均返回 OKAY。重启后已确认 `ext-h2cp2`、实际 boot SHA、构建配置、SELinux Enforcing 和 KSU，boot ID 为 `5a19baf4-ecaa-4fbf-95ef-bbf0d239f5f1`，Podman guest 与原生策略服务启动成功。见修复候选部署记录（本地证据：`extensions-harden2-cpuset-fix-deployment.json`）与boot 验证（本地证据：`extensions-harden2-cpuset-fix-boot-result.json`）。h2cp2 的 Podman 权重仍失败：rootful/rootless 高低 CPU 时间比分别为 10.984、11.669；普通 Seccomp=2 的 quota/fork/exec/绑核通过。cgroup/systemd 与 cpuset 层级边界重复通过；真实 V1/V2 CPU 选择、cpuset 交集/冲突回退及负向 OCI 策略准入通过，见[单项共存验收](native-coexist-h2cp2-acceptance.json)。父限额约束较高的子配额请求、两个实际 pthread 的独立 cpuset/配额及跨资源域拒绝也已通过，见层级与线程结果（本地证据：`runtime/native-cpu-hierarchy-threads-h2cp2-20261004.json`）。共存测试使用隔离的无过滤操作进程，普通 guest 的 Seccomp=2 保持；其他 CPU 负载使用普通过滤入口。阶段 3 保持未验收，全部证据见评估证据（本地证据：`cgroup-v2-migration-assessment.json`）。

睡眠任务加组顺序的实机对照已复现偏差：限定 CPU 7 的双层组中，任务先在 CPU 0 运行后睡眠迁入，10:39 的权重产生约 9.070 的 CPU 时间比；在 CPU 7 启动或合法启动组中完成迁移后才设权重则约 3.91。见旧镜像诊断（本地证据：`runtime/native-cpu-sleeping-load-order-h2cp2-20261004.json`）。这与上游 [0258bdfaff5b](https://github.com/torvalds/linux/commit/0258bdfaff5bd13c4d2383150b7097aecd6b6d82) 描述的睡眠任务绑核后未加入衰减列表、残留 task_group 负载及 crun/runc 不公平一致。已在独立目录适配此补丁、构建并直接刷入 `ext-h2cp3`；旧版列表函数返回 void，适配使用相同的分支连接完成条件，不修改 WALT 源码或通用 cgroup 委派语义。累计 46 个源文件审计通过，内核 SHA-256 为 `df07211fb9a8c013f9068d94b2c35abc08252891bb947a53107d805751cf0540`，boot SHA-256 为 `74b8fce419d69b9598f73ebdcda8b0ccccc1f7cf5fb69d8ae3eb97568493a327`，boot ID 为 `5fdc9b13-420f-458b-9560-a30ea2a33d71`。发送和写入均 OKAY，实际 boot、配置、Enforcing 与 KSU 核对通过，见部署（本地证据：`extensions-harden2-cpuset-decay-deployment.json`）与启动验证（本地证据：`extensions-harden2-cpuset-decay-boot-result.json`）。

h2cp3 使用同一份测试源及原门槛通过实际 Podman CPU 参数验收：rootful/rootless 权重竞争比分别为 3.876、3.905，crun/runc 的 0.5 核配额、fork/exec、运行中 exec 与 cpuset 均通过，负载 Seccomp=2 且资源清理完成，见[单项 Podman 验收](native-podman-h2cp3-acceptance.json)。同源睡眠迁移诊断的失败用例恢复到 3.913，全部五种顺序为 3.906–3.915，见新镜像诊断（本地证据：`runtime/native-cpu-sleeping-load-order-h2cp3-20261004.json`）。真实父子配额/线程域、cpuset 层级、cgroup/systemd 边界、V1/V2 共存及 CPU 热插拔均重复通过，CPU 在线状态恢复为 0–7。完整阶段 3 仍未验收：Android 调度与新 boot 的策略完整生命周期待完成，原生 cpu.stat 的分解统计也须修复。

统计专项已在普通 Seccomp=2 的真实用户态/系统调用混合负载结束、测试组完全无进程后确认缺陷：总 runtime 为 4,053,248 微秒，user/system 合计为 4,140,200 微秒。总 runtime 与实际任务运行时间、父子合计以及计数单调性通过，唯一失败项是逐组分解统计一致性，见静止统计验收（本地证据：`runtime/native-cpu-stat-settled-semantics-h2cp3-20261004.json`）。按 [Linux v4.19 rstat](https://github.com/torvalds/linux/blob/v4.19/kernel/cgroup/rstat.c#L370) 的方式，已独立构建并刷入 `ext-h2cp4`：序列化读取快照，保留每组 prev_cputime 并调用现有 cputime_adjust 校准 user/system；记账写入和调度限制不变。原始统计与校准统计的父子 user/system 分解独立归一化，所以测试精确核对父子总 runtime、逐组 user+system 与 usage，并按归一化容差核对父子分解合计。h2cp4 已通过相同源的静止统计和新增并发读取验收，逐组 user+system 与 usage 的最大差异为 1 微秒；父子总 runtime、单调性和实际任务时间核对通过。8 个并发读取者全部保持单调且分解一致，见静止统计（本地证据：`runtime/native-cpu-stat-settled-semantics-h2cp4-20261004.json`）与并发读取（本地证据：`runtime/native-cpu-stat-concurrent-h2cp4-20261004.json`）。

h2cp4 首轮构建因旧 4.14 公共头文件缺少 cputime_adjust 声明失败；失败构建记录（本地证据：`native-cpu-stat-build-attempt1-20261004.json`）及源码快照已封存。第二轮因补充的外部声明与旧 static 定义冲突而失败，见第二轮失败记录（本地证据：`native-cpu-stat-build-attempt2-20261004.json`）。两次准确源码与日志均已封存；第三轮按上游提供全局 cputime_adjust 定义及 native-accounting 分支，并使用现有 prev_cputime_init，累计 48 个源文件构建审计通过。配置、WALT 与通用 cgroup 核心保持一致。内核 SHA-256 为 `bd074e7097a7ec89c121f2bb12512d75dc27880898c62df7a9a84a014d31d6cc`，boot SHA-256 为 `32db3ca25d5d927f3eb95826683bfccced7a489fe0ef5fc56447b36e4a8dd939`。固定序列号直接刷入时发送和写入均 OKAY，boot ID 为 `33e13536-7ccc-4e64-a66e-0b4413a56b60`；实际配置、镜像哈希、Enforcing 与 KSU 验证通过，见部署（本地证据：`extensions-harden2-cpuset-stats-deployment.json`）和启动验证（本地证据：`extensions-harden2-cpuset-stats-boot-result.json`）。h2cp3 的专属 V1 CPU 权重回归也已通过：128:512 的实际 CPU 时间比为 3.995，交换后为 0.250，宿主既有组配置不变，见V1 调度回归（本地证据：`runtime/native-legacy-cpu-weight-regression-h2cp3-20261004.json`）。这证明保留的 legacy CFS 权重行为，不替代实际 Android 应用前后台与 Power HAL 联动验收；用户解锁后，h2cp4 的实际显示设置应用前台/后台/重新打开归组通过，前台 affinity 为 0–7，后台收窄至 2–3，Power HAL top-app boost 的 0→30 已观察到，见[Android 调度单项验收](native-android-scheduling-h2cp4-acceptance.json)。通用设置 Intent 首轮恢复到权限控制器的 SafetyCenter 页面，因此采样错了后台 Settings；该失败记录与原源码保留，成功使用明确的显示设置 Intent。ROM 的 vendor MaxPerformance 以 schedtune 覆盖 CPU profile，所以本次实际 CPU legacy 根组是预期策略；不把它误判为 CPU/top-app 缺失。

该候选保留 Android V1 CPU/cpuset，并有明确的过渡规则：任务显式位于非根 V1 CPU 组时选择 V1 CFS task_group，否则选择所属的非根 V2 CPU 组；CPU quota 不叠加。原生策略服务拒绝仍在非根 V1 CPU 组的调用者，避免声明 V2 限额却由另一控制器调度。cpuset 在可行时取 V1/V2 有效核集合交集；两者不相交时以 V2 有效集合为准。原生 cpuset 子组不改变 Android 的 legacy scheduler domain 配置。上述选择、迁组、线程、父子约束和热插拔行为必须完成实际验收，不能仅依据构建成功认定兼容。

## 旧 Android R 仓库的同类故障

2026-10-04 重新核对用户指出的仓库，确认有可追溯的 cgroup/systemd 故障链：[c53770aa](https://github.com/hmhmdcy/realmeX2pro-X3-AndroidR-kernel-source/commit/c53770aa93eab472feb287945dd4c09d691e5eec) 放宽内部进程限制，并在挂载及创建子组时自动开启/继承控制器；后续 [d8f652ab](https://github.com/hmhmdcy/realmeX2pro-X3-AndroidR-kernel-source/commit/d8f652abdce3c62839e7f9341304b55a6025c2b2) 为 systemd 257 的 `ssh.service` 等 `Result: resources` 故障恢复两个 EBUSY 检查，并限制自动开启的挂载命名空间。旧说明文档仍有早期自动继承表述，应以固定提交的实际代码为依据。

这是改变通用 V2 委派语义的失败案例，不能据此推断 Android 16 全 V2 迁移已经解决，也不能直接等同于双 CPU/cpuset 控制器的任务选择问题。当前累计候选的 `kernel/cgroup/cgroup.c` 与已验收 harden1 完全相同，SHA-256 为 `76de4a0c40ce94896efb65769af95187fdeb91966570aae516dcdcd000a774d6`；构建审计现在强制核对这个对应关系。保留标准 domain 的内部进程检查及根/线程子树例外；V2 子组不自动继承 subtree_control，挂载不自动开启控制器。启动时继续通过正常接口明确委派。

已在当前 harden1 的 guest 中完成隔离回归：有进程的普通 domain 开启 memory 返回 EBUSY，向已委派 memory 的内部节点迁入进程返回 EBUSY；新子组不自动委派；线程域开启 memory 返回 EOPNOTSUPP；guest 新挂载不改变控制器配置；实际瞬态 systemd 服务启动成功。自建进程、cgroup 和挂载目录已清理，根委派状态仍为 `io memory pids`。当前 `ssh.service` 为 masked/inactive，所以这次结果不证明 SSH 启动成功，也没有为测试修改 SSH 配置。

证据：systemd/cgroup 回归（本地证据：`runtime/native-cgroup-systemd-harden1-20261004.json`）、策略 CPU 压测（本地证据：`runtime/native-policy-harden1-cpu-pressure-20261004.json`）。h2cp 已重复通过相同边界测试，根委派保留为 `cpuset cpu io memory pids`；见候选 cgroup/systemd 回归（本地证据：`runtime/native-cgroup-systemd-h2cp-20261004.json`）。完整 CPU/cpuset 及 guest 重启仍属阶段 3 验收要求。

官方依据：

- [AOSP cgroup 抽象与 task profiles](https://source.android.com/docs/core/perf/cgroups)：Android 支持 V1/V2，控制器布局由配置决定；vendor 可以覆盖 profile，Android 12 起建议服务使用 task_profiles。
- [Linux V2 层级、线程及设备控制](https://www.kernel.org/doc/html/v4.19/admin-guide/cgroup-v2.html)：标准单一控制器不能同时绑定 V1/V2，线程子树与进程资源域有约束，V2 设备控制基于 cgroup BPF。
- [Linux utilization clamping](https://www.kernel.org/doc/html/latest/scheduler/sched-util-clamp.html)：uclamp 控制利用率边界及性能请求，与 CPU quota 和 schedtune boost 不是同一接口。

h2cp4 已重复通过相同源 Podman 原生参数测试，rootful/rootless 竞争权重比为 3.896/3.888，见[Podman 单项验收](native-podman-h2cp4-acceptance.json)。同 boot 的父子限额/线程域、cpuset 层级、V1/V2 共存和 cgroup/systemd 边界均通过；CPU 7 离线/恢复的有效集合与 affinity 通过并恢复全部 0–7 在线。旧 CPU 权重 1:4 与交换后的实测比值为 4.000/0.249。静止及并发统计已封存为[统计单项验收](native-statistics-h2cp4-acceptance.json)。阶段 3 现已完成同 boot 联合验收，见[阶段 3 联合结果](native-cpu-cpuset-stage3-h2cp4-acceptance.json)。新 boot 的策略完整生命周期经过真实 guest 停止/重启、策略摘要及容器 ID 一致性、CPU/IO/pids 约束、整组 OOM、邻组隔离和服务失联回归；13 份策略证据已封存为[原生策略验收](native-policy-h2cp4-acceptance.json)。普通 guest 保留 Seccomp=2，Android 保持 Enforcing，CPU 全部恢复在线，测试容器、镜像及策略清理通过。完整 Android 宿主全 V2 迁移尚未验收。后续阶段 4/5 已分别完成 binfmt_misc 与 seccomp 用户态通知验收；阶段 6 完整 Android 16 桌面与应用容器于 2026-10-05 按用户要求暂停，宿主和现有 Linux 容器的内核补强继续，最新范围见[补强计划](CONTAINER-HARDENING-PLAN.md)。

原始日志与完整历史封存保留本地；上面的本地证据路径用于定位，GitHub 发布精选验收摘要。
