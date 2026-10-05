# binfmt_misc 隔离与跨架构容器验收

阶段 4 已在 h3bm2 完成[同 boot 联合验收](runtime/candidates/h3bm/evidence/binfmt-stage4-acceptance.json)，绑定 13 份功能与安装证据。当前运行内核为 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h3bm2`，boot ID 为 `7b6e7c93-825c-4bf7-9d4c-584c1553c14c`。h2cp4 保留为阶段 3 的已验收回退版本；h3bm 的失败结果和各次诊断源码完整保留。

## 实际缺口与实现

h2cp4 的基线实测（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-namespace-baseline-h2cp4-20261004.json`）证明：UID 映射后的用户命名空间具备自己的 CAP_SYS_ADMIN，tmpfs 挂载正常，binfmt_misc 挂载返回 EPERM。全局注册表摘要前后相同。

采用 Linux 上游 [用户命名空间隔离](https://github.com/torvalds/linux/commit/21ca59b365c091d583f36ac753eaa8baf947be6f)，其[最后卸载清理依赖](https://github.com/torvalds/linux/commit/1c5976ef0f7ad76319df748ccb99a4c7ba2ba464)的 Node 引用计数和 inode 清理已在当前源码中。适配 Linux 4.14 的 `mount_ns`、`sget_userns`，由超级块持有用户命名空间引用；注册表按用户命名空间共享，未创建独立实例的子命名空间使用最近祖先的处理器。

同时纳入 [F 标志自引用修复](https://github.com/torvalds/linux/commit/79055d82772b9584f259b747fe40ff56a076678d)：设置 SB_I_NOEXEC、SB_I_NODEV 和文件系统堆叠深度。F 标志打开解释器时使用打开 register 文件的凭据。h3bm 累计核对 53 个源文件，配置、WALT 和通用 cgroup 核心保持一致；构建与实际 boot/config 摘要分别保存于源码审计（本地证据：`runtime/candidates/h3bm/evidence/kernel-ext-harden3-binfmt/audit.json`）和启动核对（本地证据：`runtime/candidates/h3bm/evidence/extensions-harden3-binfmt-boot-result.json`）。

## 已完成的隔离实测

h3bm 注册隔离实测（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-isolation-h3bm-20261004.json`）通过：

- 从普通 UID 1000 创建的两套用户命名空间使用同名处理器，分别执行 alpha 和 beta 的原生解释器；禁用 alpha 不影响 beta。
- 未挂载自己的实例的子命名空间正确继承；同一用户命名空间内的第二次挂载共享注册表。
- 并发执行与删除/重新注册正常；最后一次卸载清空注册表，再挂载恢复 enabled 状态。
- F 标志持有的原生 ELF 解释器在原路径删除后仍可执行；自身文件作为 F 解释器返回 EACCES。
- 全局注册表摘要前后相同，普通 guest 保持 Seccomp=2，测试挂载、进程和目录清理完成。

旧 overlayfs 不支持用户命名空间挂载，普通 UID 的堆叠尝试返回 EPERM，不能将该拒绝计作 s_stack_depth 保护的实机覆盖。补充的堆叠保护实测（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-stack-guard-h3bm-20261004.json`）在具备初始用户命名空间权限的私有挂载上下文中通过：普通 lower 的 overlay 挂载成功，来自独立用户命名空间的 binfmt lower 返回 EINVAL；全局注册和普通 guest 过滤保持不变，全部挂载清理。

## 跨架构构建中的实际兼容故障

测试使用固定 Clang 生成的 amd64 与 ARM64 静态 ELF，以 `FROM scratch`、COPY、实际 RUN 生成 `/built`，再用容器读取标记。QEMU 为设备现有的用户态模拟器；不会把该路径描述为 KVM/AVF。临时 VFS 存储和用户命名空间注册避免修改全局注册、现有容器镜像和存储配置。

首次与显式过滤配置的 RUN 均进入 amd64 程序，但检测到 Seccomp=0 而失败。诊断版增加失败阶段输出；随后实际 OCI 配置审计（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-crossarch-builder-oci-audit-h3bm-20261004.json`）显示配置确实含有过滤规则，runc 对照也复现相同失效。历史失败源码、ELF 和原始结果按次保存，未覆盖。

原生 setresuid 复现（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-seccomp-setresuid-baseline-h3bm-20261004.json`）确认问题：guest PID 命名空间与新用户命名空间中，过滤安装后 getppid 返回 EPERM；setresuid(0,0,0) 后 Seccomp 从 2 变为 0，原本禁止的调用恢复成功。KernelSU 旧内核 setuid 钩子对授权 UID 调用 disable_seccomp，未限定宿主命名空间。

h3bm2 将该 Android UID 授权处理限制在初始用户及 PID 命名空间，避免容器 UID 与 Android UID 交叉影响。显式宿主 su/root-profile 路径保持原实现。原生拒绝保留（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-seccomp-setresuid-h3bm2-20261004.json`）证明 setresuid 后仍为 Seccomp=2、getppid 仍返回 EPERM；注册隔离（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-isolation-h3bm2-20261004.json`）、堆叠保护（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-stack-guard-h3bm2-20261004.json`）和普通 guest 挂载（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-filtered-mount-h3bm2-20261004.json`）均已通过。

## 完成的跨架构交付

普通过滤 guest 的构建与运行（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-crossarch-podman-filtered-h3bm2-20261004.json`）和已安装入口验收（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-crossarch-helper-extents-h3bm2-20261004.json`）均通过：rootful/rootless 两种模式、amd64/ARM64 两种架构均实际执行 OCI RUN 生成镜像标记，再由 crun、UID 1000 和 runc 读取标记，程序直接报告 UID/GID 与 Seccomp=2。撤销本地解释器后 amd64 执行返回 exec format error；全局注册摘要保持一致，镜像、容器、挂载和暂停命名空间完成清理。

可复用入口为 guest 内的 `/usr/local/bin/rmx1931-binfmt`，见[使用说明](BINFMT-USAGE.md)。入口为每次前台调用创建独立用户及挂载命名空间。crun 1.14.1 对全范围身份映射的命名空间判断会误判为初始命名空间；采用受限映射后保持正常资源配置与运行时原有的用户命名空间处理。旧内核 `map_id_range_down` 要求每条映射落在父映射的一条区间内，因此入口按 Podman 的 UID 0 和 subordinate IDs 分段提交。

原生 CPU/cpuset（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-native-cpu-regression-h3bm2-20261004.json`）、策略 CPU 压力（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-policy-cpu-regression-h3bm2-20261004.json`）、crun/runc 的首次载荷准入以及策略生命周期（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-policy-lifecycle-prepare-h3bm2-20261004.json`）与清理（本地证据：`runtime/candidates/h3bm/evidence/runtime/binfmt-policy-lifecycle-cleanup-h3bm2-20261004.json`）完成受影响回归。覆盖创建、exec、停止再启动、重建、CPU/IO/pids 实际限额、分组 OOM 与邻组正常。当前配置匹配构建，KSU 33304/UAPI 4、SELinux Enforcing、CPU 0—7 在线，未发现致命内核日志。原始启动核对记录保持不可变，由单独的 runtime-result 与联合验收声明功能通过。

## 使用边界与后续

当前入口支持前台构建与运行，映射 UID/GID 0—65535，使用 VFS 存储。分离运行需要持续持有命名空间的服务，尚未交付；旧 overlayfs 用户命名空间挂载没有在本阶段扩展。QEMU 是用户态模拟。现有阶段 1—4 结果保留；阶段 5 用户态通知已在 h4sn 完成[联合验收](SECCOMP-NOTIFY-VALIDATION.md)。阶段 6 完整 Android 16 桌面与应用容器于 2026-10-05 按用户要求暂停，尚未部署或验收，最新范围见[补强计划](CONTAINER-HARDENING-PLAN.md)。验收范围遵循[测试范围](TEST-POLICY.md)，不安排 Wi-Fi、传感器专项和新的 panic。

原始日志与完整历史封存保留本地；上面的本地证据路径用于定位，GitHub 发布精选验收摘要。
