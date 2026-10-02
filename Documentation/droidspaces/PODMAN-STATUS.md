# RMX1931CN Podman 真机验收

本文保留历史 Podman2 验收。当前 KSU v3 / LowRisk2 结果见 [KSUNEXT-STATUS.md](KSUNEXT-STATUS.md)，旧源码锁定见 [source-lock-podman2.json](source-lock-podman2.json)。

2026-10-02，国行 RMX1931CN，crDroid 16 / Android 16。当前内核 `4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2` 已只刷入 boot 并完成分区摘要回读，SELinux **Enforcing**。

Ubuntu 24.04.5 运行于独立 6 GiB ext4 镜像，使用未经修改的官方 DroidSpaces v6.6.0、NAT、allow-sandboxing；systemd 为 guest PID 1，状态 running，无失败服务。Ubuntu 软件源签名和日期验证保持开启。

Podman 4.9.3（Ubuntu 包 4.9.3+ds1-1ubuntu0.2）、crun 1.14.1、fuse-overlayfs 1.13、slirp4netns 1.2.1，cgroup v2 / systemd。rootless 用户为 podmantest（UID/GID 1000，subuid/subgid 100000:65536）。

| 验收项 | rootful | rootless |
| --- | --- | --- |
| 官方 quay.io/podman/hello；info JSON | 通过 | 通过，连续 JSON 回归通过 |
| FROM scratch，COPY + RUN 本地构建 | 原生 overlay 通过 | FUSE overlay 通过 |
| 文件读写和 UID/GID | 通过 | 通过；实际 fuse.fuse-overlayfs 挂载已核对 |
| 容器 DNS | 通过 | 通过 |
| 命名卷持久性及 UID/GID | 通过 | 通过 |
| 本地端口映射 HTTP | 18081 通过 | 18082 通过 |
| exec、正常停止、重新启动 | 通过 | 通过 |
| memory.max / pids.max 配置 | 64 MiB / 64，回读一致 | 64 MiB / 64，回读一致 |
| 32 MiB 内存限制实际执行 | 分配子进程被杀 137；本容器 oom_kill=1 | 同样通过 |
| pids 限制实际执行 | 不限时 20 个短进程通过，限制 8 时 fork 被拒绝 | 同样通过 |
| guest 完整停止、重新启动后运行 | 通过 | 通过，后代 OOM 分数为 0 |

外网验证：guest 对 quay.io 的 HTTPS 使用正常 CA 验证并收到预期 401；rootless 容器下载 Ubuntu 软件源元数据的 IPv4 TCP 测试通过。DNS 返回 AAAA 不等同于 IPv6 NAT 已验收。一次 wlan0 ICMP 探测丢包，未计作通过。

停止后 guest PID、私有 cgroup、rootfs 挂载已消失，镜像保留；Android Wi-Fi enabled、Enforcing。DroidSpaces 空桥和共享控制器 accounting 可继续存在。最终已通过发布的脚本重新启动 guest，测试容器和测试卷已清理，保留已准备的镜像供使用。

用户在两次修复内核重启后实际确认 Wi-Fi 开关/重连、触摸和屏下指纹正常，并反馈未发现硬件问题。相机各镜头、IMS、NFC、快充、长时间待机等没有分别认证。

## 必需的运行配置

见 [启动指南](RUNTIME.md)。内核补丁与 guest 配置共同构成已验收环境：

- cgroup v2 委派 memory/pids。只把本 guest 的两个已核对 DroidSpaces monitor 移到自己的 host-monitor 子组；不移动 Android 进程、不修改 Android 资源限额。
- 在 guest 独立 network namespace 中，把 pristine sysfs seed 改为 RW，供 crun 先挂载再 remount RO；Android /sys flags 不变，内核挂载可见性检查保留。
- 委派后只对 guest systemd 执行 daemon-reexec，建立用户 DBus 和 memory/pids accounting。
- 把 Ubuntu PID 1 和 Podman 入口的继承 OOM 分数从 -1000 调为 0。DroidSpaces host monitor 仍受保护。未改变内核 oom_score_adj 权限。
- 从 root guest shell 运行 rootless 时使用 `podman-rootless`。直接从受保护的 DroidSpaces worker 降权可能无权修正 OOM 分数，不能用该路径替代启动器。

## 修复依据与边界

FUSE userns/UID/GID 映射参照 Linux 4.18，保留非初始 userns 的 POSIX ACL 边界；BPF_CGROUP_DEVICE query 参照 Linux 4.19。proc cmdline 修复采用上游完整的 [3d712546](https://github.com/torvalds/linux/commit/3d712546d8ba9f25cdf080d79f90482aa4231ed4) 和 [d26d0cd9](https://github.com/torvalds/linux/commit/d26d0cd97c88eb1a5704b42e41ab443406807810)，修复末尾 NUL 丢失，保留 setproctitle、长度边界和任务访问检查。实测解决 rootless libc 崩溃、镜像名尾部错字与构建 COPY 子进程参数读取失败。

原 Wi-Fi 开关故障在后续切换/重连中恢复，但根因未确立；没有把容器补丁描述为已证明的 Wi-Fi 修复。保留 WALT，CPU quota 不可用；完整 nftables/IPv6 NAT 未逐项验收。Docker daemon 尚未验收。本次交付是现有 ROM 的内核和 Podman 适配。

固定源码、改动文件/脚本摘要、通过标记见 [source-lock.json](source-lock.json)。原始设备日志、boot/recovery 备份和专有 ramdisk 仅保存在本机。
