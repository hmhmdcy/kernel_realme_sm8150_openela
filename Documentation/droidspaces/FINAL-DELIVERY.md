# 当前约定范围的交付结果

2026-10-05 完成[逐项交付审计](FINAL-DELIVERY-ACCEPTANCE.json)，15 项要求均有证据，当前约定范围无必需工作剩余。完整 Android 16 桌面与应用容器按用户要求继续暂停；MGLRU、完整 ROM V2 迁移及 EL2/KVM/AVF 保留研究状态，不声称已经实现。

最新已验收内核为 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf`，boot ID `b5d511b9-fe8d-44d0-94a9-957babb14d53`，boot SHA-256 `dfe18875661164e7cb64eba7942b856e80ffe20abb537aec815da4bf43995cdd`。实际运行配置、KSU 33304/UAPI4、SELinux Enforcing、LMKD 监视与普通 guest 过滤通过核对，关键 Android 服务保持正常。

| 功能 | 证据范围 |
| --- | --- |
| 原有 CRIU、设备 BPF、IO、挂载传播和 WireGuard 等 | 历史实际验收保留，作为继承基线 |
| memory.oom.group / cgroup.kill、资源策略持久化 | 阶段 1–2 历史完整验收；新策略的首条指令、exec、重建与 guest 重启在当前 boot 通过 |
| 原生 V2 CPU/cpuset 与 Android V1 共存 | 阶段 3 完整验收；当前实际 quota/affinity/权重回归通过 |
| binfmt 隔离、跨架构容器与 seccomp 用户通知 | 阶段 4–5 历史完整验收，累计源码保持；普通 guest 过滤当前复验通过 |
| Android 16 Binder 公开冻结回调 | h5bf2 原生/公开 API 联合验收；当前公开 API 回归通过 |
| 分组 PSI、回收 full 通知、memory.high 与监视工具 | 当前 boot 完整负载、层级、目标绑定、移组及 guest 重启验收通过 |
| 当前 ROM eBPF | 34 程序/54 映射、13 类实际 netd 挂载；短 CPU/timeInState 和 IPv4/IPv6 回环 UID 记账通过 |

历史通过不冒充当前全套实测。当前测试按[精简政策](TEST-POLICY.md)选择，源码和配置核对证明继承关系，本次改动与受影响回归使用当前 boot 的证据。测试容器、策略和探针临时目录已清理，guest 保持运行。

PSI 修复有 3,916 个导出 CRC 变化，无导出符号缺失；已按既有授权完成限定 ABI 审查，手机实际无外部 `.ko`。旧外部模块须针对新 ABI 重编译并验证，不能宣称二进制兼容。没有性能、续航或所有硬件认证的额外承诺。

最新源码/输出、工具链、a16pf boot、已验证 h5bf2 回退和原机 boot 保留；此前清理约 4.16 GiB Windows 文件和 85.39 GiB WSL 旧构建。标准 VHD 压缩受原格式限制，fstrim 已成功；后续[最新 WSL 保留核验](FINAL-WSL-RETENTION.json)确认 62 个源码和 4 个输出摘要仍匹配。

累计 62 个实际编译源文件已同步到发布树；KernelSU 单文件修改由固定 gitlink 上的构建补丁复现。源码/配置锁、精选验收摘要与精简测试政策随源码发布。原始日志、完整历史封存和镜像保留本地。

当前工作区默认探针打印短摘要，完整日志留 JSON；需要详情才加 `--verbose`。旧累计全套仅显式 `python scripts/accept_phone.py --full` 运行，已修正 a16pf 等短 release 名称的识别；它不替代新功能专项。工具快照用于审查，不是独立 rootfs 安装器。
