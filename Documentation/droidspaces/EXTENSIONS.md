> Historical ext-io acceptance. Its unavailable/unverified boundaries describe that earlier image. Current a16pf scope is in [FINAL-DELIVERY](FINAL-DELIVERY.md); historical dualio evidence and operations are in [REMAINING-VALIDATION](REMAINING-VALIDATION.md) and [RUNTIME-RESOURCES](RUNTIME-RESOURCES.md).

# 旧项目扩展：实现顺序与验收边界

2026-10-03。以已验收的 `7c423d6` / KSU v3 / podman2-lowrisk2 为输入，按风险累计实现。按用户“请直接刷入，然后检验，不要分批了”的指示，已直接刷入包含全部扩展的最终 `io` 镜像。当前运行 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-io`；boot 回读与运行配置一致，19 项功能回归、官方 27 项能力检查及 Wi-Fi 重连通过，SELinux Enforcing，未观察到 BUG/Oops/panic。

| 顺序 | 功能 | 实现与当前状态 |
| --- | --- | --- |
| 0 | 崩溃日志归档 | 现有 pstore/ramoops + KernelSU 开机归档模块 1.1 已安装并核对源码摘要。自动开机归档、快照、原字节导出和普通重启 pmsg 留存通过；实际 panic 留存未验证 |
| 已有 | socket 诊断、SquashFS | 保留此前真机验收和 xattr，不重复移植 |
| 1 utilities | EROFS、binfmt_misc/QEMU | EROFS LZ4 镜像实际挂载、1 MiB 内容摘要/xattr/链接/只读/卸载通过；x86_64 ELF 自动 QEMU 分派及撤销注册通过 |
| 2 bbr | 可选 BBR/FQ | 独立 netns 的 socket 实际使用 BBR，FQ 队列及 1 MiB 传输通过；Android 默认仍为 cubic。性能和耗电未认证 |
| 3 checkpoint | CRIU 内核接口 | 原生 arm64 CRIU 3.19 检查、单个 sleep 进程保存/终止/恢复通过。需要明确的特权 namespace 入口；普通 sandboxed guest 入口不能完成 dump，整容器恢复未认证 |
| 4 network | 当前 4.14 nftables、IPv6 NAT | inet/ip/ip6/arp/bridge/netdev 六类 family、双栈转发和 NAT 后源地址/counter、socket transparent/no-socket 实测通过；保留原有 Podman 网络后端 |
| 5 io | 块层限流 | BLK_DEV_THROTTLING 启用、实验性 .low 关闭。实际 ext4 loop 的 V1 测试进程 16 MiB 读限流通过：约 0.14 → 8.16 秒，2 MiB/s，实际记账非零，清理通过。1,033 个旧导出 CRC 改变；guest V2 没有 io.max |
| 已有 | WireGuard | 已实测两个独立 netns 的真实双端握手和隧道三包，0% 丢包；未认证外网 VPN/性能 |
| 用户态 | LXC | 已安装签名包；最小 native container 的 PID 1、hostname、proc、持久文件断言和停止状态通过。设备 BPF 探测被拒绝，设备隔离未认证 |

构建顺序为 utilities → bbr → checkpoint → network → io，后者累计包含前者。utilities/bbr 曾独立验收，checkpoint 独立镜像未完成验收、network 独立镜像未刷入；本次统一在最终 io 镜像验收全部功能。CPU quota/完整 Android cgroup V2 迁移需要调度、vendor 和 ROM 另外适配，按评审保留当前 WALT 与 CPU quota 不支持的边界。

## 崩溃日志

模块源在 `packages/rmx1931-crashlog/`。已读取实际 DT 和 ramoops 参数：`0xb7e00000`、4 MiB 保留区，record/console 各 256 KiB，pmsg 2 MiB，`dump_oops=1`。pstore 已挂载，console/pmsg 可读。

panic/oops 仍由 ramoops 回调写保留 RAM。模块仅在正常用户空间复制原始 pstore、配置、模块列表，记录 UTC 与 `/proc/uptime` 并生成 SHA256SUMS。不删除 pstore，不修改 SELinux，不在 panic 回调中执行 VFS/fsync。post-fs-data 后台收集，service 再采集运行快照；开机归档幂等。完成的开机归档保留十份、快照两份，失败记录保留诊断。真实早期开机 UTC 曾为 1970；1.1 用持久序号轮转，避免误将新归档排在旧归档之前，保留原始 UTC 以供诊断。

`python scripts/crashlog.py export` 导出到 Git 忽略的 `artifacts/droidspaces/crashlog/private/`；`package` 生成模块 ZIP，`collect` 立即归档，`disable` 禁用后续采集并保留日志。1.1 更新前核对原 1.0 四个文件的摘要，并保存完整旧模块目录；更新后四个摘要和实际快照通过。最终导出 110 个文件、当前一条 pmsg 记录，所有归档 SHA256SUMS 匹配、读取错误为空。包为 `artifacts/droidspaces/crashlog/rmx1931-crashlog-1.1.zip`，SHA-256 `80018a7a51991273522ababbf1b767eab7f3f630f979d4db8b6adbd525006ae7`。

跨普通重启：重启前 `mark` 写入唯一 `/dev/kmsg` 与 `/dev/pmsg0` 标记，重启后 `export`、`verify-marker` 要求 boot ID 改变，且标记存在于 pstore 原字节。utilities 镜像的普通重启已在 `pmsg-ramoops-0` 找到标记，见 `artifacts/droidspaces/crashlog/retention-utilities-pmsg-normal.json`。此前 console 标记未找到的失败报告保留；当前未触发 panic。普通重启通过不能替代 panic/看门狗/断电路径的验收。RAM 是否存活取决于复位路径，见 [ramoops 官方说明](https://docs.kernel.org/admin-guide/ramoops.html)。

本次最终 io 刷入经过 bootloader，标记没有保留，负结果为 `artifacts/droidspaces/crashlog/retention-io-bootloader.json`；当前 pmsg 文件可读不等于该标记留存成功。正常重启与 bootloader 路径的结论分别记录。

## 配置与源码

`configs/kernel-extensions.json` 定义顺序、允许配置变化和实际链接符号；各批配置累计叠加，输出独立的 kernel-ext-*。前四批原有 12,166 个导出符号 CRC 均无变化；I/O 批改变 1,033 个，旧外部模块必须重新构建。2026-10-03 实读 `/proc/modules` 为空，常见 vendor/odm/system/DLKM 和 KSU 模块目录未发现 `.ko`；这仅说明当前手机的外部模块状态。每批要求 MODVERSIONS、DEBUG_LIST、WALT、cubic、默认队列、pstore 和旧 Wi-Fi ABI 红线配置保持原值。CRC 一致不能代替结构布局与驱动兼容性检查；受影响功能按 [测试范围](TEST-POLICY.md) 复验，报告的 `existing_export_crc_preserved` 仅表示摘要比较结果。

网络配置第一次编译暴露原有 nft_socket 的头文件依赖缺失和不存在的 ctx->family。源码还把无 socket 写成值 0，并缓存 lookup 引用到 skb。本次在 src-ext-network 独立副本修正包含关系、4.14 的 ctx->afi->family、无匹配的 NFT_BREAK、netns 检查和查找引用释放，保留原 transparent key 范围。补丁为 `patches/nft-socket-4.14-compat.patch`，前后摘要在 `artifacts/droidspaces/extensions-network-source.json`。当前树 xt_socket.c 同样只释放 lookup 返回的引用；[Linux v4.19](https://raw.githubusercontent.com/torvalds/linux/v4.19/net/netfilter/nft_socket.c)可核对 namespace/no-socket 行为。高风险候选需要实际规则回归。

签名 apt 源没有原生 arm64 CRIU 包，本次固定 [CRIU 3.19 提交](https://github.com/checkpoint-restore/criu/commit/f8b14286b092853a4485813e1efd564109df9123)，归档摘要为 `5cbbeda7313b8f8299f7bfbc63ce4289a0f715e1e2ca57d1e887ff2e0fecd9bd`。原生构建脚本使用签名开发依赖；GCC 13 不能推导已经检查过的动态计数，循环改为等值常量数组界限，保留 Werror/FORTIFY。上游唯一绝对 protobuf symlink 由发行版依赖文件替代，tar 安全过滤保持开启。单进程恢复不等于整容器恢复。

已构建的原生 CRIU 可执行文件 SHA-256 为 `b7d2186d7001a009102e53f657c35ec7ab531ee2a30fb093404c55d4e3a05893`，本地补丁见 `patches/criu3.19-gcc13-array-bound.patch`，构建摘要见 `artifacts/droidspaces/criu-source-lock.txt`。保留用户态与内核功能验收的区别。

实际 CRIU 失败记录保留：DroidSpaces 的只读 `/proc/sys` 阻止 ns_last_pid 和三个 IPC next_id 文件；`prepare_guest_checkpoint.sh` 只在 guest 的 PID/IPC/mount namespace 开放这四个命名空间文件，其他 proc/sys 仍只读。随后普通 guest 入口的 seccomp=2 阻止 PTRACE_O_SUSPEND_SECCOMP。`probe_checkpoint_privileged.py` 从已授权 Android root，经静态 BusyBox nsenter 进入独立的 guest PID/IPC/mount/net/UTS namespace，以 seccomp=0 的专用测试进程执行单进程恢复；现有 guest PID 1 和工作负载的 seccomp 保持启用。此结果不表示普通 `criu dump` 或 Podman checkpoint 已自动可用。

## guest 边界

4.14 binfmt_misc 是全局注册表。现有 QEMU 包有多个自动注册定义，binfmt-support 服务已启用，因此新内核会有开机注册风险。`prepare_extension_guest.sh` 在旧内核尚无 binfmt_misc 时关闭两个自动注册服务，显式 QEMU 可继续使用。注册测试只创建唯一名字的 x86_64 ELF handler，最后撤销自己的条目，不启用 C 凭据标志。guest 的新挂载点不是私有注册表。参见 [binfmt_misc](https://docs.kernel.org/admin-guide/binfmt-misc.html)。

nft/BBR/WireGuard 只在新 netns 探测，不安装 Android 默认规则，不切换当前 Podman 网络后端。IPv6 NAT 要求接收端实际看到 NAT 后源地址且 counter 非零。LXC 包自动启用的启动服务已关闭，默认不启动它的网桥/daemon。

Android 的 blkio 目前属于 V1，guest V2 只有 memory/pids。`probe_io_throttling.py` 在 host 新建的 V1 测试组中运行自己的静态 BusyBox 读进程，对 guest `/var/tmp` 下已核对为 ext4 loop rootfs 的 16 MiB O_DIRECT 文件比较限流前后耗时与实际记账，随后撤销限额、删除空组。两次失败探测保留：DroidSpaces run 会改变测试进程 cgroup，guest `/tmp` 是 tmpfs；修正为直接读实际 loop 文件后通过。实际路径为 `/dev/block/loop39`（7:312），最终报告为 `artifacts/droidspaces/runtime/extensions-io-io-retry2.json`。不迁移 Android 进程、不限制整块 UFS；不将此测试声称为 io.max/Podman I/O 限制。控制器归属见 [cgroup V2](https://docs.kernel.org/admin-guide/cgroup-v2.html)。

## 构建和验收

WSL 中执行 `bash scripts/build_kernel_extensions.sh utilities`，最后的参数可改为 bbr/checkpoint/network/io。默认四个任务；本次资源核对后可用 `RMX1931_BUILD_JOBS=8`。保存 olddefconfig、完整配置、构建日志、Image.gz-dtb、Module.symvers、System.map 和 audit.json。

打包：`python scripts/inspect_kernel_dtb.py --variant ext-utilities` 后执行 `python scripts/prepare_boot_candidate.py --variant ext-utilities`；其它批次使用对应 ext-*。打包要求本批 post-build audit，并再次检查 config/kernel 摘要、DTB、原 boot 往返、ramdisk/header、AVB hash。

真机探测入口：`device_runtime.py run-file --script scripts/probe_kernel_extensions.sh --script-arg binfmt|bbr|nft|checkpoint|wireguard`，EROFS/LXC 用专用脚本；推荐 --guest-service 保存明确退出码。返回 77 是不可用，不计通过。I/O 用 `probe_io_throttling.py`。

最终验收见 `artifacts/droidspaces/extensions-io-acceptance.json`，关联 19 项实际探测的路径及摘要、Wi-Fi、官方 27 项能力、运行配置、KSU 模块与 dmesg。rootful/rootless 构建、overlay/卷/UID/GID、DNS/端口、启停、实际 memory OOM 与 pids 限额通过；socket 诊断、gzip/xz SquashFS、WireGuard 与 LXC 回归通过。Wi-Fi 实际重连、链路 validated、网关三包零丢包。相机/显示/全部传感器未逐项认证。

最终 I/O preflight 核对当前 boot、已验证回滚镜像、型号、电量 100%、日志模块源码、外部模块为空，见 `artifacts/droidspaces/extensions-io-preflight.json`。`deploy_kernel_extensions.py --combined --allow-abi-change` 按用户的新指示跳过逐批功能前置条件，仍要求运行的是已核对摘要/配置的先前镜像、外部模块为空，以及候选/回滚/fastboot 产品和解锁状态匹配。部署记录保存原文授权；未放宽模块 CRC 校验。原 KSU v3 回滚 boot 摘要为 `9588a95055bf35ced553297541a4e703b038451dcdfa775281b1f8c9f7a0bc58`。

五个候选均为 96 MiB 的 boot-only 镜像，包验收报告分别为 `artifacts/droidspaces/boot-images/ext-<stage>-candidate-check.json`：

| 批次 | boot SHA-256 | 已有导出 CRC 变化 |
| --- | --- | ---: |
| utilities | fdccd7221b4d22509ae59a1e7b54603195d7c264f670b11d326c07f3ac7451c8 | 0 |
| bbr | db92608cc827cf9686ced65b8fbcfbaa5bee507a75611c5f0b1c2be175609b0d | 0 |
| checkpoint | 2a056c093583ef0827de968909677824f3052985fa6b396a5255f779079a1fa2 | 0 |
| network | c69541f200e3b963a0ed3ef08fcc88adf6722de092d6178b2d2ce8d4185b81bf | 0 |
| io | 47d9ee609d4c28a0c9cae423bb25f72d4490d5efb1c3b8f91942098ad9a45ee5 | 1033 |

源码锁为 `kernel-extensions.sources.lock.json`，状态摘要为 `artifacts/droidspaces/extensions-readiness.json`。五项归档行为测试（含早期开机时钟倒退）和六项部署拒绝路径测试通过；新代码的 Python/heredoc 与 shell 语法检查通过。构建保留基线已有的四项 section mismatch 警告。
