# a16pf 内核与容器操作

适用本机 RMX1931CN / crDroid 16 / Android 16，以及已经准备的 Ubuntu 24.04.5 guest。当前内核为 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf`，boot SHA-256 为 `dfe18875661164e7cb64eba7942b856e80ffe20abb537aec815da4bf43995cdd`。第一阶段[验收结果](HARDENING1-VALIDATION.md)包含新 OOM/清理能力及既有 CPU/IO 回归。脚本依赖原工作区的 ADB、构建与候选验收材料；复制脚本不能代替 rootfs 安装。标签必须唯一，旧失败记录不会覆盖。

## 启动与普通容器

在 Windows 工作区执行：

```powershell
python scripts/start_podman_guest.py
```

看到 `PODMAN_GUEST_PROFILE_READY` 后，在手机 root 终端进入：

```sh
su -c '/data/local/tmp/rmx1931-droidspaces-check --name=rmx1931-podman enter'
podman run --rm quay.io/podman/hello
podman-rootless run --rm quay.io/podman/hello
```

两套存储独立。rootless 使用 UID 1000 的 podmantest 用户会话；DroidSpaces 本身需要 Android root。启动脚本确认没有活动 Podman 容器后才重配用户服务和迁移 rootless pause。手机或 guest 重启后需重新运行它。普通 guest 保持 seccomp=2，Android SELinux 保持 Enforcing。

## 整组 OOM 与清理

`memory.oom.group` 默认是 0。需要内存不足时将多进程容器作为一个整体终止，可给 rootful/rootless 的创建命令加入 `--memory=256m --memory-swap=256m --cgroup-conf=memory.oom.group=1`。oom_score_adj=-1000 的任务仍是 OOM 保护例外；DroidSpaces 管理进程的保护保留，普通 Podman caller 已通过既有 wrapper 归一化为 0。

专用容器叶子提供写入 1 的 `cgroup.kill`，用于递归清理任务，包括冻结组。普通管理继续使用 `podman stop` / `podman rm`，以更新运行时状态；直接写 cgroup.kill 只适用于经过完整容器 ID 和 payload 路径核对的故障清理。不要向 delegated guest 根组写入，也不要把 OOM 例外误当成 cgroup.kill 的保护。该文件不在全局 hierarchy 根提供。

## 持久化资源策略

第二阶段已提供 rootful/rootless 的 CPU/IO/memory/pids 策略。使用 root 管理的磁盘注册表和 `io.rmx1931.resource-policy` 注解选择策略，停止启动无需重新指定；重建时保留注解。已验收启动前生效、实际压力、服务中断拒绝启动、guest 重启后恢复与邻组隔离，见[使用方法](RESOURCE-POLICY.md)和[结果](RESOURCE-POLICY-VALIDATION.md)。`start_podman_guest.py` 会核对并恢复已安装服务，普通 guest 过滤保持不变。当前 CPU 策略检测并使用原生 V2，旧 V1 后端只作兼容回退。

## 原生 V2 CPU/cpuset

当前 guest 已委派原生 V2 CPU/cpuset，与 Android V1 CPU/cpuset/schedtune 和 WALT 共存。普通 Podman 的 `--cpus`、OCI cpuset 以及资源策略在 payload 启动前生效，覆盖 fork/exec；quota、权重、affinity、层级与重建已实际验收，见[阶段 3 汇总](native-cpu-cpuset-stage3-h2cp4-acceptance.json)。

```sh
podman run --rm --cpus 0.5 quay.io/podman/hello
podman-rootless run --rm --cpus 0.5 quay.io/podman/hello
```

旧 `set_container_cpu_quota.py` V1 手工入口保留作旧镜像兼容；当前内核使用原生 OCI/V2 接口，无需建立额外的 V1 CPU 叶子。持久策略用[资源策略](RESOURCE-POLICY.md)管理。

## 原生 V2 IO

个人补丁 `CONFIG_RMX1931_DUAL_BLKIO` 默认关闭；此镜像明确启用。新 IO 控制器仅为写入 `io.v2_delegate=1` 的 V2 子树选择新路径。启动脚本对本 DroidSpaces 子树做一次选择并委派 `io memory pids`，同时保留 Android V1 blkio 及原有 root/background 权重。选择不能在子组撤销，移除子树才结束。`io.low` 不受支持，外部 `.ko` 必须按新 ABI 重编。

已验收的是实际 V2 `io.max` / `io.stat`：guest 进程、rootful/rootless 容器的读写限流，父组继承、兄弟组隔离，以及缓冲写回。不要把 loop 号写死，也不要限额 Android 根组。下面在 guest root 中取得一个运行中容器的 payload 路径：

```sh
name=my-container
pid=$(podman inspect --format '{{.State.Pid}}' "$name")
id=$(podman inspect --format '{{.Id}}' "$name")
relative=$(awk -F: '$1 == "0" {print $3}' "/proc/$pid/cgroup")
case "$relative" in *"/libpod-$id.scope/container") ;; *) exit 1 ;; esac
group=/sys/fs/cgroup$relative
device=$(findmnt -n -o MAJ:MIN /)
test -f "$group/io.max"
printf '%s rbps=2097152 wbps=2097152\n' "$device" > "$group/io.max"
cat "$group/io.max" "$group/io.stat"
# 解除本叶子的读写限额：
printf '%s rbps=max wbps=max\n' "$device" > "$group/io.max"
```

rootless 取 PID/ID 时改用 `podman-rootless inspect`。UID 1000 可直接写自己的已委派 IO 叶子，已通过实际验收；普通用户不能写其他用户的组。示例限制的是根文件系统所在的实际 loop 设备；其他卷应核对实际设备。`io.stat` 记录块层活动，不能假定所有场景都与应用逻辑字节完全相等。本轮没有验收所有 Podman `--device-*-bps` 参数转换。

## 完整容器恢复入口

普通 guest 的 CRIU dump 仍受既有过滤限制。恢复管理命令从 Android root 进入现有 guest 的隔离命名空间，为操作进程建立独立组，现有 guest 与容器过滤保持开启。仅支持经过验证的 rootful runc/CRIU 路径；创建时使用 `podman --runtime=runc ...`。当前 crun 缺少 CRIU 支持。

在 Windows 对已有容器执行：

```powershell
python scripts/privileged_guest.py --script scripts/control_podman_checkpoint.sh --script-arg checkpoint --script-arg my-container --label my-checkpoint
python scripts/privileged_guest.py --script scripts/control_podman_checkpoint.sh --script-arg restore --script-arg my-container --label my-restore
```

checkpoint 成功后容器停止，restore 在原容器上恢复。接口拒绝不匹配的运行状态和 paused 容器。完整验收涵盖父子进程、两份内存、UNIX socket、计数器、overlay、命名卷和 memory/pids 配额。使用 `--keep` 保留诊断；归档可能包含应用敏感状态，应按原数据权限保管。本轮未验收跨设备迁移、rootless checkpoint、任意 TCP 连接和任意宿主设备恢复。

## LXC、挂载与网络

设备 BPF 配置通过实际 allow/deny、同 major/minor 的设备别名和有效 BPF 程序查询验收。guest 已安装 root 专用 `lxc-start-bpf`；它只为该启动操作提高 memlock 到 64 MiB，避免共享 UID 的 BPF 锁页预算不足。普通 LXC 不需要此入口时可继续使用 `lxc-start`。

需要传播时只共享专用 bind 源。rootful/rootless 的 rslave、rprivate、只读挂载，以及显式 SYS_ADMIN / unconfined 测试容器的 rshared 双向传播已验收。普通容器不会因此自动获得 mount 能力。新增共享源后，空闲 rootless pause 需要 `podman-rootless system migrate` 才能继承源；先确认没有运行中的 rootless 工作负载。根 `/` 保持 private。

Android TCP 默认 cubic。BBR/FQ 可按 socket 选择；外部 Wi-Fi 对照与电池电流积分仅代表该负载和供电工况，不据此默认改成 BBR。WireGuard 外部测试使用独立 WSL peer，并验证 MTU、双向传输、错误 key 和重连；临时 DNAT 只匹配电脑来源与专用端口，测试后删除。

## 日志与复验

crashlog 1.1 开机归档 pstore。OEM 会丢弃带 printk 级别前缀的某些用户 kmsg 写入，标记入口现使用无前缀消息并核对实时 dmesg。2026-10-04 明确授权的真实 panic 已验证 recovery、live pstore 与自动归档三份完全相同；OEM 在 panic 后进入 recovery，保存日志后正常重启 Android。不要把历史 pstore 中的这次故意 panic 当作当前启动的新故障。

普通累积复验（需先停止工作负载）：

```powershell
python scripts/accept_phone.py --full
```

它自动识别当前扩展阶段，运行实际 IO、累积功能和官方 27 项能力；harden1 为 20 项累积功能证据。默认不切换 Wi-Fi、不要求 Wi-Fi 证据。Wi-Fi、传感器等硬件专项已移出默认验收；仅在相关改动、故障或明确需求时按需测试，见 [测试范围](TEST-POLICY.md)。需要 Wi-Fi 重连专项时显式加 `--with-wifi`。此前 dualio 扩展专项证据见 `docs/remaining-validation.md` 和 `artifacts/droidspaces/remaining-acceptance-20261004.json`；当前持久策略另见[第二阶段结果](RESOURCE-POLICY-VALIDATION.md)。真实 panic 不包含在普通复验命令内。
