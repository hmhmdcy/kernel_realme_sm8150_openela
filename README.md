# Realme X2 Pro 容器内核 / Android 16

最新已验收内核为 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf`，适用本项目 RMX1931CN / crDroid 16 环境。

已实现并实测 Podman rootful/rootless、原生 cgroup V2 CPU/cpuset/IO、整组 OOM/清理、持久化资源策略、隔离 binfmt、seccomp 用户通知、Android 16 Binder 冻结回调、分组 PSI 和当前 ROM eBPF 记账。Android V1 CPU/cpuset 与 Qualcomm WALT 保留。

构建步骤、验收边界及源码锁见 [项目说明](Documentation/droidspaces/README.md)。完整 Android 16 桌面容器暂停；KVM/AVF 为平台研究，未实现。旧外部内核模块需重编译；boot 和原始设备日志保留本地。

原 Linux 内核说明保留在 [README](README)。
