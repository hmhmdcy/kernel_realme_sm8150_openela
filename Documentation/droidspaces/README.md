# RMX1931CN / Android 16 容器内核

2026-10-05 最新已验收版本：`4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf`，运行于 RMX1931CN / crDroid 16 / Android 16。当前约定的内核与 Linux 容器功能已完成验收，见[交付结果](FINAL-DELIVERY.md)。完整 Android 16 桌面与应用容器按用户要求暂停；完整 ROM cgroup V2 迁移、MGLRU 和 KVM/AVF 仍为研究范围。

| 功能 | 验收状态 |
| --- | --- |
| Podman rootful/rootless、原生 V2 IO | 实际容器、限流、记账、层级和缓冲写回通过 |
| memory.oom.group / cgroup.kill、持久化资源策略 | OOM 边界、启动前生效、exec、重建和 guest 重启通过 |
| 原生 V2 CPU/cpuset | quota、权重、affinity 与生命周期通过；Android V1 CPU/cpuset/WALT 保留 |
| binfmt namespace / amd64 容器 | namespace 隔离和实际跨架构容器通过 |
| seccomp 用户通知 | 上游 25 项与真实 OCI 代理通过；普通 guest 保持过滤 |
| Android 16 Binder | 公开冻结回调及实际应用 API 通过 |
| 分组 PSI / memory.high | some/full 通知、回收、移组、监视目标和持久化通过 |
| 当前 ROM eBPF | 实际加载/挂载、CPU UID 与 IPv4/IPv6 UID 记账通过 |

历史完整验收作为继承基线；a16pf 实测新增 PSI、当前 ROM BPF 和受影响回归。没有将历史记录表述为当前 boot 全套测试。KernelSU Next 固定 cd739c7（33304/UAPI4），Android SELinux Enforcing，普通 guest seccomp=2。容器继续使用已准备的 Ubuntu guest，需要 Android root 启动 DroidSpaces。

## 在 Linux 构建

```sh
git submodule update --init KernelSU-Next
python3 Documentation/droidspaces/verify-source.py --check-ksu-overlay
CLANG_DIR=/path/to/clang-r547379 bash Documentation/droidspaces/build-ksunext.sh
```

使用 Linux 文件系统、Python 3、AOSP Clang 20 r547379 和 ARM32 GNU binutils。`OUT_DIR`、`JOBS` 可配置。构建入口核对固定 KSU revision，应用已验收的容器 seccomp 补丁，并校验全部 62 个累计源文件和完整 defconfig；补丁只覆盖固定子模块中的一个文件，gitlink 保持上游 cd739c7。生成配置必须与已验收 resolved config 一致。工具链或构建环境差异可能改变二进制摘要。

[当前源码锁](source-lock.json)绑定源码、配置、Image 和 boot 摘要；[a16pf 验收锁](source-lock-group-psi-a16pf.json)保留原验收绑定。PSI 修复相对 h5bf2 改变 3,916 个导出 CRC，无导出符号缺失。旧外部 `.ko` 必须重编译并验证；已验收手机没有外部模块。这里不宣称性能、续航或全部硬件认证。

boot 打包须保留当前 ROM 的 ramdisk、DTB 和其他 header 字段，仅移除最终的 `cgroup_disable=pressure` 参数以启用 PSI。GitHub 发布源码、构建入口、运行工具和精选验收摘要；boot、原 ramdisk、原始设备日志和完整历史封存继续保留本地。

使用方法见[运行说明](RUNTIME.md)、[资源操作](RUNTIME-RESOURCES.md)和[刷入/回滚](FLASHING.md)。脚本依赖原工作区的候选记录和已经安装的 guest，不是独立 rootfs 安装器。日常按[精简测试政策](TEST-POLICY.md)进行新功能专项与受影响短回归；累计全套仅显式 `accept_phone.py --full`，Wi-Fi/传感器不属于默认要求。
