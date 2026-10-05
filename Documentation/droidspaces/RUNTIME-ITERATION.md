> 本文件记录 2026-10-03 当时的脚本行为与实测结果。自 2026-10-04 起，默认复验按 [测试范围](TEST-POLICY.md)，不再切换 Wi-Fi，未认证硬件不列为待办。

# 2026-10-03 晚间运行迭代与真机验收

已连接 RMX1931CN / crDroid 16 / Android 16，核对 root、完整开机、SELinux Enforcing、boot 回读摘要和实际运行配置。当前内核为 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-io`，boot SHA-256 为 `47d9ee609d4c28a0c9cae423bb25f72d4490d5efb1c3b8f91942098ad9a45ee5`。本轮迭代运行与验收脚本，继续使用已有内核镜像。

完整报告：extensions-io-final20261003-acceptance.json（本地证据：`runtime-acceptance-20261003.json`）。19 项实际功能测试、27 项官方能力检查通过，Wi-Fi 关闭/重连后网关三包全部收到。dmesg 未观察到 BUG/Oops/panic/导出符号错误，KSU 的 DroidSpaces 和日志模块启用。

| 范围 | 本轮结果 |
| --- | --- |
| rootful / rootless Podman | 本地 COPY/RUN 构建、overlay/FUSE、文件与 UID/GID、卷持久性、DNS、端口、exec、启停通过 |
| memory / pids | 两种权限下 32 MiB 限额实际触发子进程退出 137 和 oom_kill；pids 限额实际拒绝 fork |
| EROFS / SquashFS | EROFS 内容摘要、xattr、硬/软链接、只读、卸载；gzip/xz SquashFS 回归通过 |
| binfmt / QEMU | x86_64 ELF 自动分派通过，专用注册项已撤销 |
| BBR / nft / WireGuard | 独立 netns 的 BBR/FQ、1 MiB 传输、六类 nft family、双栈 NAT 后实际源地址与 counter、WireGuard 双端握手与三包零丢包通过；Android cubic 保持 |
| CRIU / LXC | 明确特权入口的单进程保存/终止/恢复、最小 native LXC 运行及停止通过 |
| I/O | 实际 ext4 loop 的专用 V1 测试组：16 MiB 读取约 0.156 → 8.141 秒，2 MiB/s；实际设备记账非零，测试文件与组清理通过 |
| guest 生命周期 | 完整停止后 PID/cgroup/挂载消失、rootfs 保留；重新启动恢复配置通过。再次从停止状态验证 systemd 等待逻辑，最终 rootful/rootless 容器及 OOM 继承回归通过 |
| 日志归档 | 本轮只读导出 110 个文件，保留归档的 SHA256SUMS 全部匹配，读取错误为空；原始 pstore 仅在本机 private 目录 |

## 实际发现与修复

1. 应用启动的 guest 使用 `--config=.../container.config start`，旧启动器只识别 `--name/--rootfs-img` 方式而拒绝委派。已支持固定配置方式，并加强官方 monitor 可执行文件摘要、配置权限和真实父子关系核对；应用与命令行两条路径都完成真机配置。
2. 运行中的 guest 临时测试目录消失后，直接 `run --guest-service` 无法创建结果目录。已在拒绝 symlink 的前提下准备父目录，缺目录后的实际服务执行通过。
3. 新启动 guest 的 systemd 初始化会清理过早创建的临时服务结果。已在配置前等待 systemd running；第二次从停止状态启动完整通过。
4. CRIU 初次失败是当前应用重启的 guest 未恢复四个私有 PID/IPC sysctl 挂载。失败报告保留为 `extensions-io-live20261003-checkpoint.json`；恢复规定的启动配置后新标签重试和最终整套复验通过。guest seccomp 保留。
5. 旧整套测试可能复用同版本内核在其他开机的成功记录。已要求实际当前 boot ID 和探测结束身份一致，提供独立 run label，并在最终验收回读 boot/config。
6. Wi-Fi 旧探测只依赖 ping 退出码。当时的专项检查要求三包全部收到、明确零丢包，并保留失败报告。
7. 测试名称冲突以前可能触发清理 trap 删除已有对象。容器/卷冲突现在在安装清理 trap 前拒绝，专用卷在失败路径也清理；离线负测试验证未发出删除命令。

新增入口为 `python scripts/accept_phone.py`。它使用已准备的 guest 和本地构建材料；当时会恢复用户会话配置并切换 Wi-Fi，活动 Podman 容器需先停止。每轮使用新标签，失败后的单项重试保留原记录。7 个离线回归测试及 Python/shell/heredoc 语法检查通过。

首次缺目录失败、初次 CRIU 失败和 guest 启动竞态的超时记录均保留。历史 build/source lock 与早先验收报告没有被改写。当前完整验收和最后一次 guest 重启的证据分别记录，最终 guest 保持运行。

## 边界与交付

CPU quota 和 guest V2 io.max 仍不可用；普通 sandboxed CRIU dump、整容器恢复、LXC 设备 BPF 隔离、panic 留存、BBR 性能/耗电及全部相机/传感器硬件认证仍未完成。rootless Podman 会提示根挂载不是 shared；本轮已测试的构建、卷、FUSE 与容器运行均通过，任意主机 bind mount 传播未认证。

修改同步至本地 `worktrees/rmx1931-ksunext3/Documentation/droidspaces/runtime/scripts`，供继续开发和审阅；远端已发布提交仍为 `933a65a`。本轮没有提交或推送 GitHub。脚本及证据摘要见 本轮清单（本地证据：`runtime-iteration-20261003.json`）。

原始日志与完整历史封存保留本地；上面的本地证据路径用于定位，GitHub 发布精选验收摘要。
