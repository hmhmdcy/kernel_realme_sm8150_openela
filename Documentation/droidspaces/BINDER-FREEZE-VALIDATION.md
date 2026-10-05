# Android 16 Binder 冻结状态通知

2026-10-05 当前状态：`h5bf2` 已完成同 boot 联合验收，见[不可变验收记录](runtime/candidates/h5bf/evidence/binder-freeze-acceptance.json)。原生 15 项、宿主 Android 16 公开回调、容器过滤、原生 CPU/cpuset、crun/runc 资源策略及宿主健康共 7 份功能证据通过。完整 Android 16 桌面与应用容器按用户要求保持暂停，本项属于宿主 Android 的内核接口补强。

实际运行内核为 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h5bf2`，boot ID 为 `db5703c3-a205-47fb-9bda-c6f077eb0ee6`，boot SHA-256 为 `7355ff5724ffb6b77baa551d9bf3d50118ab505fed49acc0537ad1211fb82f00`。构建审计覆盖累计 59 个文件，配置与 WALT/通用 cgroup 核心保持原实现，已有导出符号 CRC 无缺失或变化。boot 配置、实际镜像、DTB、ramdisk、KSU 与 Enforcing 已核对；boot 核对（本地证据：`runtime/candidates/h5bf/evidence/extensions-harden5-binder-freeze-fix-boot-result.json`）保持独立，功能验收另存，未将启动成功等同于功能完成。

## 已确认的缺口

固定的 h4sn 驱动和 UAPI 快照没有冻结状态订阅、确认和取消指令。旧内核上自建 Binderfs 的两个进程已完成真实同步请求及回复，并正常卸载，见原始基线结果（本地证据：`runtime/candidates/h5bf/evidence/runtime/binder-freeze-baseline3-h4sn-20261005.json`）。但后续发现原始夹具直接包含未处理的内核 UAPI，`__packed` 未展开，handle/cookie 结构实际为 16 字节而标准 ABI 要求 12 字节。因此原始 EINVAL 结果不能作为正确回调指令缺失的实机证明；这里撤回此前的该项推断，原始报告和源码保留。缺口依据为固定驱动/UAPI 源码对照。

首次传输在 root 专用目录前失败，测试没有启动；对应目录检查和源码已保留。第二次测试完成通信与接口检查，但收尾因 Binder 延迟释放持有文件引用而返回 EBUSY，仍记为失败。第三次使用有界等待后完成正常卸载，没有覆盖失败结果。见传输失败（本地证据：`runtime/candidates/h5bf/evidence/runtime/binder-freeze-baseline-transfer-attempt1-h4sn-20261005.json`）、第二次测试（本地证据：`runtime/candidates/h5bf/evidence/runtime/binder-freeze-baseline2-h4sn-20261005.json`）及夹具源码（本地证据：`runtime/candidates/h5bf/source-versions/runtime-probes/binder-freeze/binder_freeze_test.c`）。

新内核第一次原生测试也因相同夹具 ABI 问题失败，驱动记录了错误长度的未知命令。修正打包属性并增加编译期布局断言后，第二次原生测试通过，未因此重编或重刷 h5bf。见失败报告（本地证据：`runtime/candidates/h5bf/evidence/runtime/binder-freeze-callbacks-h5bf-20261005.json`）、对应日志（本地证据：`runtime/candidates/h5bf/evidence/runtime/binder-freeze-callbacks-failure-dmesg-h5bf-20261005.json`）和14 项通过报告（本地证据：`runtime/candidates/h5bf/evidence/runtime/binder-freeze-callbacks2-h5bf-20261005.json`）。

## 实现与来源

固定上游为 AOSP `android16-6.12-2026-03_r70`，提交 [5fd39602](https://android.googlesource.com/kernel/common/+/5fd39602326ec050bf53ae07528e1fe1ecefb531)。来源锁（本地证据：`runtime/candidates/h5bf/source-versions/android16-binder-upstream/android16-fixed-source-lock.json`）记录 Binder 驱动、内部类型和公开 UAPI 的实际摘要；旧驱动快照（本地证据：`runtime/candidates/h5bf/source-versions/android16-binder-upstream/h4sn-binder-source-lock.json`）保留 h4sn 对照。

通知补丁（本地证据：`runtime/candidates/h5bf/patches/rmx1931-binder-freeze-notification.patch`）修改 `drivers/android/binder.c` 和 `include/uapi/linux/android/binder.h`，补充订阅、初始状态、冻结/解冻通知、确认后重发、取消订阅及引用/进程退出清理。保留 4.14 事务与分配器接口及既有冻结 ioctl 的 PID 语义；配置、WALT 与通用 cgroup 核心保持原实现。没有把 6.12 驱动整体替换进旧内核。

首次公开 API 功能失败由 ROM 用户态能力探测引起。固定 Android 16 `IPCThreadState.cpp` 在订阅前调用 `ProcessState::isDriverFeatureEnabled(FREEZE_NOTIFICATION)`，后者读取 `/dev/binderfs/features/freeze_notification` 并缓存结果；旧 Binderfs 没有该目录，因而返回不支持。见固定框架来源锁（本地证据：`runtime/candidates/h5bf/source-versions/android16-binder-upstream/framework-probe/source-lock.json`）及实机公开 API 失败（本地证据：`runtime/candidates/h5bf/evidence/runtime/binder-public-api3-h5bf-20261005.json`）。两个测试进程均已清理，普通 guest 保持 Seccomp=2，Android 保持 Enforcing。更早的控制器编译失败和 ART 参数启动失败也按独立编号保留，没有覆盖或重放原进程。

能力发现修复（本地证据：`runtime/candidates/h5bf/patches/rmx1931-binder-freeze-feature-discovery.patch`）只补充 `drivers/android/binderfs.c`：每次挂载创建标准的只读 `features/freeze_notification`，值为 1，并传播创建失败。只声明已经实现的冻结通知，不声明尚未实现的扩展错误或事务报告功能。h5bf 的原生状态机保持相同源码。

实际构建的三个修改文件已按审计摘要导出供审阅：Binder 驱动（本地证据：`runtime/candidates/h5bf/evidence/kernel-ext-harden5-binder-freeze-fix/modified-sources/drivers/android/binder.c`）、UAPI（本地证据：`runtime/candidates/h5bf/evidence/kernel-ext-harden5-binder-freeze-fix/modified-sources/include/uapi/linux/android/binder.h`）、Binderfs（本地证据：`runtime/candidates/h5bf/evidence/kernel-ext-harden5-binder-freeze-fix/modified-sources/drivers/android/binderfs.c`）。公共源码目录是稀疏工作树，未因此覆盖其中其他未提交改动；已验收的镜像来自独立构建源及累计摘要审计。

此次只增加冻结回调 UAPI 及其能力发现接口。扩展错误 ioctl、冻结时异步事务返回提示等其他新接口没有因此完成；统计表中的返回编号 20 保留空位。当前基础冻结 ioctl 使用宿主 PID，原生夹具据此运行在宿主 PID 视图中，自建 mount/IPC 命名空间和 Binderfs，未打开宿主 Android Binder 设备。公开 API 夹具只控制两个自建短期 app_process 进程；使用宿主 Binder 的冻结 ioctl 时检查 PID、启动时间、命令名和 UID，未冻结系统服务。不能把本项记为容器内 PID 语义迁移或完整 Android 容器验收。

## 已完成的功能验收

- h5bf 的完整配置、实际 boot 镜像、KSU、SELinux 与模块 ABI 核对通过；首次 fastboot 下载拒绝已归档，安卓实际核对旧 boot 未改写后再恢复部署，没有将失败传输记为写入成功。
- h5bf 原生 14 项通过：初始状态、冻结/解冻、同步请求拒绝与恢复、错误句柄/重复订阅/错误 cookie、未确认时状态合并和重发、发送前/发送后取消、多观察者、32 次已排队或未确认通知的关闭，以及目标退出和原有死亡回调。正常卸载通过。
- h5bf2 构建与实际部署通过；私有 Binderfs 的标准能力文件值为 1，模式 0444，写入被拒绝，未声明扩展错误与事务报告，原生共 15 项通过，见当前原生结果（本地证据：`runtime/candidates/h5bf/evidence/runtime/binder-freeze-callbacks-h5bf2-20261005.json`）。
- 宿主 Android 16 的公开 `IBinder.addFrozenStateChangeCallback` 和 `removeFrozenStateChangeCallback` 通过：实际远端同步请求/回复可用，收到初始未冻结、冻结、解冻三次通知，解冻后请求恢复；移除后再次冻结/解冻保持静默，原有死亡通知到达。见公开 API 结果（本地证据：`runtime/candidates/h5bf/evidence/runtime/binder-public-api-h5bf2-20261005.json`）。
- 同 boot 的容器过滤保留、真实 rootful/rootless 原生 CPU/cpuset 参数及 crun/runc 的 memory/IO/pids/CPU/OOM 分组资源策略通过；binfmt 与 seccomp 示例入口摘要未变。7 份证据由联合记录逐项绑定源码摘要。
- 测试进程与服务已退出/移除，私有 Binderfs 正常卸载；宿主关键服务运行正常，内核日志无本项检查范围内的致命错误。普通 shell 无需 su 即可读取能力文件，见宿主健康结果（本地证据：`runtime/candidates/h5bf/evidence/runtime/binder-host-health-h5bf2-20261005.json`）。按[测试范围](TEST-POLICY.md)执行，没有增加 Wi-Fi、传感器等整机专项或新的 panic。

本项已完成；当前范围内的 LMKD/分组 PSI 与实际 ROM eBPF 接口核查继续进行。完整 Android 16 桌面和应用容器仍暂停，不能将本项验收作为恢复或完成桌面的依据。

Android 官方说明该公开回调从 API 36 提供，事件可能合并，调用者应按最新冻结状态处理；内核不支持时可以抛出 UnsupportedOperationException。用途是让调用方知道远端服务暂时不能处理请求，从而调整发送行为，不代表自动提升性能或减少耗电。见[公开接口文档](https://developer.android.com/reference/android/os/IBinder#addFrozenStateChangeCallback(java.util.concurrent.Executor,%20android.os.IBinder.FrozenStateChangeCallback))。

原始日志与完整历史封存保留本地；上面的本地证据路径用于定位，GitHub 发布精选验收摘要。
