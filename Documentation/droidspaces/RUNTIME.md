# 启动已准备的 Ubuntu Podman guest

本机现有 guest 已安装所需包与两个启动器。每次手机或 guest 重启后，在 Windows 工作区执行：

```powershell
python scripts/start_podman_guest.py
```

看到 `PODMAN_GUEST_PROFILE_READY` 后，从有 root 的 Android 终端进入：

```sh
su -c '/data/local/tmp/rmx1931-droidspaces-check --name=rmx1931-podman enter'
podman run --rm quay.io/podman/hello
podman-rootless run --rm quay.io/podman/hello
```

`podman` 以 guest root 运行；`podman-rootless` 自动降到 podmantest 并设置用户 DBus。两套镜像/容器存储独立。正常的 podmantest systemd 用户会话也能直接使用 podman。这里的 rootless 容器仍运行在需要 Android root 启动的 DroidSpaces guest 内。

Windows 也可直接调用：

```powershell
python scripts/device_runtime.py run --label podman-hello --command 'podman-rootless run --rm quay.io/podman/hello' --timeout 40
python scripts/device_runtime.py stop --label ubuntu-stop --timeout 40
```

停止会保留 rootfs 镜像、安装包和 Podman 数据。共享 cgroup memory/pids accounting 不会自动关闭；未设置 Android 资源限额。下次用 start_podman_guest.py 启动。不要使用 force-cgroupv1；此版本 schedtune 不支持所需 v1 嵌套。

## 在源码 fork 中使用这些脚本

`Documentation/droidspaces/runtime` 本身可以作为 Windows 工作区，或把其 scripts 文件夹复制到自己的工作区。工作区结构必须为：

```text
runtime/
  scripts/                         # 本仓库发布的 helpers
  tools/platform-tools/adb.exe      # 官方 Android platform-tools
  artifacts/droidspaces/runtime/    # 自动创建的本地验收记录
```

切换到 runtime 目录执行 Python 命令。Python 3.9+，电脑只连接一台已授权调试的 RMX1931/RMX1931CN，KSU Shell root 已授权。脚本严格检查已验收的 podman2、lowrisk2 或 `podman2-lr2-ksu3` 内核与对应 boot SHA、Android 完整开机、SELinux Enforcing 与官方 DroidSpaces 二进制 SHA。KSU v3 支持已在此工作区更新；从旧发布分支复制的脚本需同步新版，并带上本地 `artifacts/droidspaces/ksunext-boot-result.json` 验收记录。自行重新构建产生不同内核身份时，应先核对新构建并评审身份检查。

脚本准备的是已创建的 guest，不能代替全新 rootfs 安装：需要官方 DroidSpaces v6.6.0 二进制放在 `/data/local/tmp/rmx1931-droidspaces-check`；Ubuntu24.04.5 ext4 镜像在 `/data/local/Droidspaces/Containers/rmx1931-podman/rootfs.img`，有官方 `/etc/droidspaces` 标记，systemd PID 1。

guest 包需包含 podman、crun、fuse-overlayfs、slirp4netns、uidmap、dbus-user-session、libpam-systemd、netavark、aardvark-dns；构建测试还用官方 Ubuntu busybox-static。podmantest UID/GID 必须是 1000，subuid/subgid 范围为 100000:65536，并具备 Android aid_inet（3003）网络组。guest SSH/ssh.socket 和自动校时服务在本次环境中禁用。重新安装或替换 guest 时需重新核对这些前提；device_runtime.py 的 prepare 路径依赖原工作区的下载与提取材料，未打包为独立安装器。

脚本只配置本 guest 的 NAT/allow-sandboxing、cgroup 委派、sysfs seed、用户服务与 Podman OOM 入口；不会刷分区。run-file 仅接受该工作区 scripts 中的 shell 文件，并核对传输摘要。现有运行 guest 上再次执行准备会重启用户服务并迁移 rootless pause；先停止自己的工作负载再执行。

当前累计扩展镜像 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-io` 也已验收。启动脚本要求本地 `extensions-io-boot-result.json` 与对应 `boot-images/ext-io-candidate-check.json`，并回读 boot SHA；运行配置由部署验收核对。为 CRIU 仅开放隔离 guest 的 ns_last_pid 和三个 IPC next_id 文件，其他 proc/sys 仍只读，guest seccomp 保留。普通 guest 的 `criu dump` 仍受 seccomp 限制；特权单进程验收入口是 `python scripts/probe_checkpoint_privileged.py --label <新的测试名字>`，它不是通用容器迁移工具。新增功能、外部模块 CRC 变化与 io.max 边界见 [扩展验收](EXTENSIONS.md)。

验收 probe 会创建并清理专用测试容器/卷，镜像名 `localhost/rmx1931-probe:1` 由构建测试准备。不要在有同名生产工作负载的环境中直接运行 probe。
