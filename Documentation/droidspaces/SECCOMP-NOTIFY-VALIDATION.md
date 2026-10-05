# Seccomp 用户态通知：h4sn 候选

阶段 5 已完成 h4sn 同 boot 联合验收。25 项上游测试零失败、零跳过；普通 guest 的真实 crun rootful/rootless 通知代理、目标绑定以及受影响容器/资源策略回归通过。见[阶段 5 联合结果](runtime/candidates/h4sn/evidence/seccomp-notify-stage5-acceptance.json)。实际启动、配置、KernelSU 33304/UAPI 4、SELinux Enforcing、清理和内核错误日志均已核对。

在已验收的 h3bm2 上，普通 guest 的 `Seccomp=2` 保持不变，`GET_ACTION_AVAIL(USER_NOTIF)` 返回 EOPNOTSUPP，`GET_NOTIF_SIZES` 和 `NEW_LISTENER` 返回 EINVAL。见实际缺失基线（本地证据：`runtime/candidates/h4sn/evidence/runtime/seccomp-notify-baseline-h3bm2-20261004.json`）。

实现固定于 Linux 5.10.271 的 [587461dd](https://github.com/gregkh/linux/commit/587461ddf5d522bfcb50ebd55078c0dac37be496)，包括 listener、通知 ID 校验、生命周期、CONTINUE、ADDFD/SETFD 和 TSYNC_ESRCH。4.14 适配保留原有 get/put task 接口、任务结构、架构入口、审计和既有导出 ABI；文件描述符注入在目标进程执行，并保留安全钩子、RLIMIT_NOFILE 和 socket cgroup 更新。没有宣称支持 ADDFD_SEND 或 WAIT_KILLABLE_RECV。

累计核对 56 个源码文件，Android V1 CPU/cpuset、WALT、通用 cgroup 核心和配置保持已有实现，现有导出 CRC 改变数为 0。DTB、ramdisk、非 kernel 启动头和 AVB 校验通过。见构建审核（本地证据：`runtime/candidates/h4sn/evidence/kernel-ext-harden4-seccomp-notify/audit.json`）、封装审核（本地证据：`runtime/candidates/h4sn/evidence/boot-images/ext-harden4-seccomp-notify-candidate-check.json`）和实机启动（本地证据：`runtime/candidates/h4sn/evidence/extensions-harden4-seccomp-notify-boot-result.json`）。两个尚未刷入的编译失败版本及一次内联符号检查失败已保存于候选的 failed-attempts，后续修复没有修改 h3bm2 的验收证据。

实际通过的验收：

- 固定上游的 25 个测试覆盖旧过滤/ERRNO/TSYNC 回归以及通知接收、信号、listener 关闭、PID namespace、错误缓冲区、CONTINUE、无任务 HUP、ADDFD 扩展结构和 FD 限额。测试主体保留原文，两个 CLONE_FILES 测试仅通过严格的 helper 适配使用 4.14 clone ABI；跳过不能计作通过。测试在单独的作用域内运行，普通 guest 继续过滤。
- 普通 guest 的真实 crun rootful/rootless OCI 容器通过通知代理处理请求，覆盖返回值代理、拒绝、CONTINUE、ADDFD/CLOEXEC、错误 token/错误 FD 拒绝、listener 关闭和超时。代理绑定容器 ID、bundle、PID/starttime、namespace 和通知 ID。
- 普通过滤保留、跨架构构建、原生 CPU/cpuset 和资源策略回归通过，并验证测试容器、代理 socket、私有运行时状态及临时挂载清理。

其中，已安装代理对继承过滤器的子进程请求返回 EPERM，原目标进程仍取得预期的代理结果；rootful/rootless 均实测通过。跨架构探针曾因两个顺序释放的 namespace 复用同一 inode 而误报，改用新探针同时持有两份 namespace FD 后通过，旧探针和失败原始结果保留。

代理已安装到 guest 的 `/usr/local/bin/rmx1931-seccomp-notify`，源码 SHA256 为 `873edd945f700c3abb915547a8a5d974cdfbad39e257650f73a832b027410637`，与真实 crun 测试一致。见安装结果（本地证据：`runtime/candidates/h4sn/evidence/runtime/seccomp-notify-broker-install-h4sn-20261004.json`）。可运行 `rmx1931-seccomp-notify --help` 查看入口；按测试夹具准备同 UID 控制的 OCI bundle，再设置 `linux.seccomp.listenerPath` 和与代理 `--token` 相同的 `listenerMetadata`。socket 必须位于该 UID 拥有的 0700 目录中，代理创建 0600 socket；CLI 还需要 `--bundle`、`--container-id` 和有界 `--timeout`。

代理是前台、单进程、ARM64 示例，只处理四个不含指针的示例 syscall：getppid 返回固定 777，getuid 拒绝，getpid CONTINUE，getgid 返回带有代理自建数据的注入 FD。只有显式通知 profile 才触发这些示例行为，普通容器继续使用原过滤规则。未知目标请求拒绝；CONTINUE 不用于检查目标可变内存或路径权限。通用业务代理或持久服务需另行定义策略及生命周期。

2026-10-05 按用户要求暂停阶段 6 的完整 Android 16 桌面和实际应用容器，已有 Binder 接口与镜像调研保留；宿主与现有 Linux 容器的内核补强继续。阶段 5 的验收独立成立，完整 Android 容器仍未部署或验收。最新范围见[补强计划](CONTAINER-HARDENING-PLAN.md)。

原始日志与完整历史封存保留本地；上面的本地证据路径用于定位，GitHub 发布精选验收摘要。
