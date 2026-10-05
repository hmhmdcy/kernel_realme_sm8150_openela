> 以下为阶段 2 的历史验收；最新原生 V2 CPU/cpuset、Binder、PSI 和 BPF 已完成，当前状态见 [FINAL-DELIVERY](FINAL-DELIVERY.md)。

# 第二阶段资源策略验收

2026-10-04，CPU/IO/memory/pids 策略持久化已实现并验收。手机仍运行 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-harden1`，本阶段未修改或刷写内核。当前 boot ID 为 `53691308-0284-4dd0-b313-2ac387166080`。结果汇总及来源哈希见[验收记录](resource-policy-acceptance.json)，使用方式见[策略管理](RESOURCE-POLICY.md)。

| 验收行为 | 实际结果 |
| --- | --- |
| rootful/rootless 从应用第一条指令起受限 | 均读取到 memory 64 MiB、pids 32、IO 读写各 2 MiB/s、memory.oom.group=1；普通过滤保持 Seccomp=2 |
| CPU/IO/pids 实际压力 | CPU 约 0.50–0.51 核；8 MiB 直接读写各约 4 秒；fork 在 30 个测试子进程后返回 EAGAIN，pids.events 增加 |
| 同一容器停止/启动 | 容器 ID 不变，CPU、IO 与进程压力重新通过 |
| 同名容器重新创建 | 容器 ID 改变，保留策略注解后，资源限额和压力重新通过 |
| 实际内存压力与整组 OOM | 有界分配器触发该容器的 memory 限额，应用整组退出 137；内核日志中的 OOM 域和终止组均匹配精确容器 ID；邻近容器存活 |
| 未选择策略的邻近容器 | 仍为 memory 96 MiB、pids 48、无 IO 限速；约 3.97 核，8 MiB IO 远小于 2 秒 |
| 策略准入和管理权限 | 未知策略、跨用户策略均拒绝；非管理员修改拒绝；已有容器引用的策略不能修改/删除 |
| 管理服务中断 | 已运行容器保留限额；新创建、启动和 exec 明确拒绝；未选择策略的邻近容器仍可 exec |
| 管理服务恢复 | 原容器重新启动后，CPU、IO、pids 压力再次通过 |
| Ubuntu guest 真正停止/重启 | PID 命名空间从 `pid:[4026535305]` 变为 `pid:[4026535309]`；策略文件哈希和原容器 ID 不变；启动入口恢复服务，资源压力再次通过 |
| runc 兼容性 | rootful/rootless 实际启动后，从应用第一条指令读取到四类资源配置及 Seccomp=2；完整压力/生命周期使用 crun |
| 旧手工 CPU 接口回归 | rootful/rootless 均约 4 核→0.5 核→4 核；exec 继承、实际节流、解除和清理通过 |
| 清理和宿主状态 | 无验收容器、验收策略、运行记录、遗留 CPU 组或 CPU 绑定；SELinux Enforcing，普通 guest Seccomp=2，当前内核无 fatal 日志 |

策略注册表位于 guest 磁盘，运行记录与容器 ID、用户和当前 guest 绑定。OCI 入口在 crun/runc 创建/执行应用前取得服务确认并应用资源；没有使用启动后轮询补限额。CPU 使用现有 V1 CFS，不能把本阶段记作原生 V2 CPU/cpuset 已完成。IO 针对 guest rootfs 文件系统的 loop 设备；设备号在每次启动时重新识别，本次 guest 重启恰好复用了 `7:312`，不能据此把它写死为下次设备号。

Podman 的 HostConfig 可能显示被策略覆盖前的请求值；验收读取实际 cgroup、应用首条指令输出并执行压力。整组 OOM 后运行时删除 cgroup，持有的 memory.events 文件可返回 ENODEV；因此该项使用精确容器 ID 的内核 OOM/整组终止日志及实际退出结果证明，未把消失的事件文件或 Podman 的 OOMKilled 字段误记为事件计数通过。

初次跨步骤验收使用临时 systemd 服务，服务退出会清理 rootful conmon，留下陈旧 Podman 状态。相关失败记录保留，并通过明确的 `--retain-detached-workloads` 测试选项修正；第二轮完整验收及 guest 重启全部通过。该选项仅用于需要保留受限容器进行后续步骤的测试，普通探针的默认清理行为不变。

日常 Wi-Fi、传感器及整机硬件专项未执行，也未记作通过。阶段 3–6 和 Android 16 的 Binder 状态通知、LMKD/PSI 联动及 eBPF 接口补强仍未完成；总目标保持进行中。
