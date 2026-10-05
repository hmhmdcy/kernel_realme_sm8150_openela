# 容器与 Android 16 功能补强

目标：按建议顺序实现功能，并以实际运行结果证明可用。基线为已验收的 ext-dualio，现有源码、设备数据与历史失败证据保留。仅核对状态或检查配置不算完成功能验收。

| 顺序 | 计划行为 | 通过依据 | 当前状态 |
| --- | --- | --- | --- |
| 1 | V2 memory.oom.group 与 cgroup.kill | 多进程整组 OOM、受保护进程例外、父子层级边界；清理并发 fork 和冻结组；邻组/Android 进程保持正常 | 已验收，见[第一阶段结果](HARDENING1-VALIDATION.md) |
| 2 | CPU/IO/memory/pids 策略持久化 | rootful/rootless 创建、exec、停止/再启动、重新创建及 guest 重启后恢复策略；失败可诊断且不误改其他容器 | 已验收，见[第二阶段结果](RESOURCE-POLICY-VALIDATION.md) |
| 3 | 原生 V2 CPU/cpuset | Podman 原生参数、权重、限额、核心绑定实际有效，覆盖 fork/exec/层级；Android WALT 与既有资源策略可用；保留正常 domain/线程域及 systemd 委派语义 | h2cp4 已完成同 boot 联合验收：原生参数、统计一致性/并发读取、线程域与层级、共存与热插拔、V1 权重、实际 Android 前后台/Power HAL 和资源策略完整生命周期通过，见[阶段 3 结果](native-cpu-cpuset-stage3-h2cp4-acceptance.json) |
| 4 | binfmt_misc 命名空间隔离 | 两套注册互不影响，amd64 真实容器运行和构建，撤销与清理正常；ARM64 原生执行正常 | h3bm2 已完成同 boot 联合验收：隔离/栈保护、普通 guest 的 rootful/rootless amd64/ARM64 构建与运行、crun/runc、UID 1000、撤销清理及受影响资源策略回归通过；前台入口已安装，见[阶段 4 结果](BINFMT-NAMESPACE-VALIDATION.md) |
| 5 | Seccomp 用户态通知 | 实际运行时/代理接收和处理请求，拒绝未授权调用，超时/退出/目标变化可处理；普通 guest 过滤保留 | h4sn 同 boot 联合验收通过：25 项上游测试、真实 rootful/rootless crun 代理及目标绑定、普通过滤与受影响资源策略/跨架构回归完成，前台示例代理已安装，见[阶段 5 记录](SECCOMP-NOTIFY-VALIDATION.md) |
| 6 | 独立 Binderfs 的完整 Android 16 桌面与应用容器 | 若恢复实施，仍需验证独立 Binder 设备、系统服务、桌面显示与输入、实际应用安装和运行、与宿主隔离、生命周期与清理 | 2026-10-05 按用户要求暂停；已做 Binder 接口与 ARM64 镜像调研，尚未部署或验收完整桌面 |

2026-10-05 用户要求“这个完整桌面先暂停一下吧”。第 6 阶段暂停实施，待用户明确恢复后继续；已有调研与前 5 阶段验收保留。当前必交付范围不包含完整 Android 桌面与应用容器，该项暂停不阻塞其他内核补强交付。宿主 Android 与现有 Linux 容器直接使用的 Binder、内存压力及资源管理工作继续进行。

完整 Android 容器的主要用途是运行另一套独立应用数据与桌面环境，或测试 Android 系统服务和应用兼容性。本机宿主已运行 Android 16，日常收益取决于是否需要这套独立环境。桌面可用还需要 system/vendor、图形显示、输入和生命周期配合，内核接口通过不代表完整桌面通过。共享内核容器也不提供独立客体内核的虚拟机隔离。

Android 16 补强同时覆盖 Binder 冻结状态通知及公开回调、LMKD/分组 PSI 与容器内存策略联动、当前 ROM 的 eBPF 加载与具体接口需求。已有 PSI、基础 PIDFD、Binderfs、基础 Binder 冻结接口属于基线，不重复计作新增成果。

分组 PSI 启用候选保留累计源码，精确替换内置禁用参数并移除 boot header 同项禁用标记；guest 新增可选 `memory.high` 策略与前台容器压力通知。构建与实机状态独立记录于[分组 PSI 验收](GROUP-PSI-VALIDATION.md)，未通过前不计为交付完成。

Binder 冻结回调已在 h5bf2 完成同 boot 联合验收：原生 15 项、实际 Android 16 公开回调、能力发现文件、过滤保留与受影响容器资源策略回归全部通过，见[Binder 补强记录](BINDER-FREEZE-VALIDATION.md)。h5bf 的公开 API 能力探测失败已通过标准 Binderfs 只读声明修复；旧基线 EINVAL 的接口缺失推断因夹具 ABI 问题已撤回，原始证据保留。这项宿主接口已完成，已暂停的完整桌面状态保持不变。

2026-10-05 的后续只读核查确认：当前源码已包含分组 PSI 的任务统计、cgroup 文件与触发器实现；实机启动参数两次携带 `cgroup_disable=pressure`，因此只显示全局压力文件，容器的独立压力文件缺失。LMKD 已打开两个 `/proc/pressure/memory` 文件。下一项需要解决分组 PSI 的启用条件，验收独立压力统计/通知、层级归属与资源策略联动，不能把已有源码记为新回移成果。ROM 的 `bpf.progs_loaded=1` 且存在 netd、timeInState 等程序和映射；`ro.bpf.kver_override=5.4.186` 是用户态选择版本，不等同于实际 4.14 内核版本或所有新接口已通过，后续按实际程序需求核对。

根据用户提出的全 V2 与独立 CPU 任务组问题，已只读核对当前 ROM 的 V1 控制器、厂商 task profiles、Power HAL 及启动脚本。单一 V2 是可评估的最终架构；双控制器属于保留现有 ROM 的过渡方案，不能作为永久架构要求。容器独立资源分组仍需保留。完整迁移涉及 ROM 与内核协同，不能仅改内核开关；当前未禁用宿主 V1，未将候选构建记作实机通过。

用户指出的旧 Android R 仓库确实记录过自动开启/继承 cgroup 控制器导致 systemd 服务 `Result: resources` 的故障。当前候选保持通用 cgroup 核心与 harden1 一致；基线已完成 domain 内部进程限制、线程域控制器边界、挂载不自动委派和实际 systemd 服务启动回归。新候选已重复通过这些边界测试，继续验收新增 CPU/cpuset 负载及生命周期，详见[对应源码与实机证据](ANDROID16-CGROUP-V2-MIGRATION.md#旧-android-r-仓库的同类故障)。

MGLRU 为后续实验方向。按用户提出的骁龙 855 EL2 限制，已完成[虚拟化平台检索与本机核查](VIRTUALIZATION-FEASIBILITY.md)：本机 CPU 从 EL1 启动，KVM / pKVM / AVF 移至平台研究项，不作为近期交付。已暂停的完整 Android 16 桌面方案采用共享内核容器，跨架构执行采用 QEMU 用户态模拟；不得把配置启用、模拟或源码存在当作硬件虚拟化已通过。

每批记录上游提交/来源及摘要、实际修改、构建配置、镜像身份、模块 ABI、部署和当前 boot 的功能证据。保持 SELinux Enforcing、KSU 与原有容器能力。当前范围内的内核补强完成前本目标保持进行中；已暂停的完整桌面单独保留状态。历史验收记录保留当时范围，最新以本计划及当前范围记录（本地证据：`runtime/candidates/a16ps/evidence/container-hardening-current-scope.json`）为准。

2026-10-05 后续 a16pf 已完成[分组 PSI 联合验收](runtime/candidates/a16pf/evidence/group-psi-acceptance.json)，替代此前候选未通过状态。按用户复盘要求，后续执行[专项与短回归政策](TEST-POLICY.md)，合并兼容补丁、一批目标一次刷入，工具/夹具修正复用当前内核，已有同 boot 合适证据直接引用。全套测试和长压测仅按影响扩大，详细日志留文件、终端输出摘要。下一步只核查当前 ROM 真实使用的 eBPF 接口与负载；遇具体缺失再迭代，不按理论新接口清单扩展。

后续上述 eBPF 核查已完成，见[当前 ROM 实机验收](ANDROID16-BPF-VALIDATION.md)：34 程序/54 映射及 13 类 netd 有效挂载、短 CPU/timeInState 与 IPv4/IPv6 回环 UID 网络记账均通过，无需新增 BPF 内核代码或再刷入。现有阶段 1–5、Binder 补强、分组 PSI 与本项实际需求的功能范围已取得证据；完整桌面仍暂停，MGLRU 和完整 ROM V2 迁移仍是研究方向。最终交付前按原范围核对证据和源码归档，不把历史全套报告扩大为当前必做矩阵。

原始日志与完整历史封存保留本地；上面的本地证据路径用于定位，GitHub 发布精选验收摘要。
