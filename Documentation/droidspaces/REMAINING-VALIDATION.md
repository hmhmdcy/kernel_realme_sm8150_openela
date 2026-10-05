# 历史 dualio 内核与容器功能验收（2026-10-04）

最新 harden1 迭代和当前启动结果见[第一阶段验收](HARDENING1-VALIDATION.md)。下面保留 dualio 当时的实测结果。

后续默认复验按 [测试范围](TEST-POLICY.md)，Wi-Fi、传感器等硬件专项不再列为要求或待办。下表保留本轮实际结果。

此前明确列出的九项未完成验证现已完成，发现的问题已修复并复测。已连接真机并按授权刷入 dualio；明确授权的一次真实 panic 也已完成。最终报告为 remaining-acceptance-20261004.json（本地证据：`../artifacts/droidspaces/remaining-acceptance-20261004.json`），操作说明为 [container-operations.md](RUNTIME-RESOURCES.md)。

当前 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-dualio`，boot SHA-256 `fe5edbce96623c20c51f5cf83d08d302298004e71540ae8b7771df6c8d866bac`。最终功能证据全部绑定真实 panic 恢复后的同一次 boot；panic 记录同时核对崩溃前镜像与恢复后身份。运行配置与构建一致，KSU 33304/UAPI4、SELinux Enforcing、普通 guest seccomp=2，Android 默认 cubic 保留。

| 项目 | 实际结果 | 当前证据（相对 artifacts/droidspaces） |
| --- | --- | --- |
| 整容器 checkpoint/restore | 父子进程、两份内存、计数器、UNIX socket、overlay、卷、memory/pids 限额在停止后恢复 | runtime/checkpoint-management-postpanic20261004.json |
| sandboxed CRIU 的可用操作入口 | 普通入口创建容器，独立 Android root 管理入口 checkpoint/restore；普通 guest 和现有容器过滤保持 | 同上及其普通 fixture、两份 operator 报告 |
| LXC 设备 BPF | /dev/null 允许，/dev/zero 与同设备号别名确实 EPERM；有效 BPF 查询和清理通过 | runtime/lxc-bpf-postpanic20261004.json |
| CPU quota | rootful/rootless 实际容器及 exec 均从约 4 核降至 0.5 核，出现 throttling，release 后恢复 | runtime/container-cpu-postpanic20261004.json |
| guest V2 io.max | guest/rootful/rootless 16 MiB 读写在 2 MiB/s 时约 8 秒，解除后恢复；rootless 自写自己的限额；父组、兄弟隔离、缓冲写回及 Android V1 回归通过 | runtime/native-io-postpanic20261004.json、runtime/io-hierarchy-writeback-postpanic20261004.json、runtime/extensions-dualio-postpanic20261004-io.json |
| panic 留存 | 真实 sysrq panic 与唯一标记；recovery 原件、live pstore、自动归档三份 522632 字节、同 SHA-256 | crashlog/controlled-panic-dualio20261004/panic.json |
| BBR 与电流对照 | cubic/BBR 各三轮外部 Wi-Fi 吞吐、RTT、发送 CPU 和实际电流积分；input_suspend 已恢复 | runtime/bbr-cubic-battery-postpanic20261004-retry2.json |
| bind mount 传播 | rootful/rootless rslave、rprivate、只读及 rootful 显式特权 rshared 双向传播；清理通过 | runtime/bind-propagation-postpanic20261004.json |
| 外部 WireGuard | WSL 实际 peer，MTU 1420 边界，双向约 226/239 Mbps，错误 key 拒绝，正确 key 重连零丢包 | runtime/externalwg-postpanic20261004-retry3.json |

累计 19 项功能与官方 27 项能力、Wi-Fi 关闭/重连零丢包通过，当前启动 dmesg 未见 BUG/Oops/panic。测试容器、CPU 叶子/挂载、临时 WireGuard/NAT 已清理；保留诊断目录、镜像缓存与原始失败证据。最终检查还按完整 ID 清理了早期失败的 Created 状态 CPU 测试容器。

本轮修复包含 WALT/CFS bandwidth 的配置约束、受控 OCI 入口保证后续 exec 继承 CPU 组、rootless 传播源与 IO 委派、双 IO 控制器的块层/写回选择、LXC memlock 入口，以及 OEM kmsg 标记前缀丢弃问题。网络首轮存在未到达 guest 的失败，已保留；物理接口绑定/可达性确认与真实握手等待后通过，不能把失败原因确定归于代理。Android 默认拥塞算法未改变。

CPU 限额使用独立 V1 操作入口，原生 V2 cpu.max 仍不提供；先 release 再停止/删除容器。完整恢复需要 rootful runc/CRIU 与独立 Android root 入口。dualio 是默认关闭的个人设备补丁，不支持 io.low，外部模块 ABI 改变。BBR 的吞吐与净电池积分仅代表所记录 Wi-Fi 工况。完整相机/传感器/IMS 硬件认证、跨设备迁移和任意设备/TCP 恢复不属于本次验收。

源码/config/helpers/操作文档已同步到本地 KSU 工作树：32 个累计锁定源文件与实际编译树相同，dualio 相对 resources 的完整差异仅有记录中的 10 个文件。公开形态报告仅含脱敏摘要；原 boot、ramdisk、原始设备日志和私钥保留本地。本轮未 commit/push/发布，既有修改保留。

原始日志与完整历史封存保留本地；上面的本地证据路径用于定位，GitHub 发布精选验收摘要。
