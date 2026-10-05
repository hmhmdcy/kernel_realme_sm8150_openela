# 容器资源策略持久化

第二阶段已完成实际验收，见[验收结果](RESOURCE-POLICY-VALIDATION.md)。当前 a16pf 已具备原生 V2 CPU/cpuset；策略自动检测并使用 V2 CPU，V1 后端仅作旧镜像回退。IO、memory、pids 使用 V2。后面的旧阶段记录需结合[当前操作](RUNTIME-RESOURCES.md)阅读。

策略由 guest root 管理，保存在 `/etc/rmx1931/resource-policies.json`。Podman 创建命令中的 `io.rmx1931.resource-policy` 注解选择策略。该注解保存在容器配置中，停止/再启动无需重新设置；重新创建容器时保留同一个注解，便能复用策略。rootful 与 rootless 的策略分别绑定 UID 0 和 UID 1000。

在 Ubuntu guest 中创建策略和容器：

```sh
rmx1931-policy set small-rootful --mode rootful --cpus .5 \
  --memory-mib 64 --pids 32 --read-bps 2097152 --write-bps 2097152 --oom-group
podman run -d --name my-container --network=none \
  --annotation io.rmx1931.resource-policy=small-rootful IMAGE COMMAND

rmx1931-policy set small-rootless --mode rootless --cpus .5 \
  --memory-mib 64 --pids 32 --read-bps 2097152 --write-bps 2097152 --oom-group
podman-rootless run -d --name my-user-container --network=none \
  --annotation io.rmx1931.resource-policy=small-rootless IMAGE COMMAND

rmx1931-policy validate
rmx1931-policy status
runuser -u podmantest -- rmx1931-policy status
```

必须先通过工作区的 `scripts/install_guest_resource_policy.py --label UNIQUE` 安装管理服务；后续使用 `scripts/start_podman_guest.py` 启动或恢复 guest 时，它会核对已安装源码并恢复服务。直接使用其他 DroidSpaces 启动入口后，需要显式运行安装器的 `--ensure` 模式。管理服务未就绪时，带策略的容器拒绝创建、启动和 exec，输出 `RMX1931_RESOURCE_POLICY_ERROR`；已运行的容器保留内核中的限额。普通未选择策略的容器继续使用自身配置。

OCI 入口在真实 crun/runc 执行前请求服务。服务核验 Unix socket 的真实调用者 UID/PID、guest PID 命名空间、容器 ID、Podman storage 路径和配置所有者；不会接受客户端指定的目标 PID。IO、memory、pids 被写入该容器的 OCI resources，CPU 限额在运行时 fork 应用前设置。完整 CPU 层级只挂载在管理服务的私有 mount 命名空间，普通 guest 路径不暴露该层级。guest root 属于可信管理者；这不构成对拥有 guest root 或 rootless cgroup 管理权限的恶意操作者的不可绕过安全边界。

CPU period 为 100000 微秒，`.5` 对应 quota 50000 微秒。memory 为物理内存上限，OCI memory+swap 总上限为两倍 memory；`--oom-group` 控制 V2 整组 OOM。IO 限速针对 guest rootfs 的 loop 设备，包括位于该文件系统的容器存储和卷；服务每次 guest 启动重新识别设备号，不对其他文件系统自动宣称相同限速。

策略覆盖创建命令中这四类资源的原始值。`podman inspect` 的 HostConfig 仍可能显示 Podman 原始请求，应结合 `rmx1931-policy status` 和实际 cgroup 文件判断限额。运行时资源应用失败会拒绝启动，不把配置存在视作实际生效。已有容器引用策略时，拒绝修改或删除该策略；需要新限额时创建新的策略并重新创建容器。删除容器后可执行 `rmx1931-policy remove PROFILE`，空 CPU 组和对应运行记录自动清理。

源码依据：[OCI Linux resources](https://github.com/opencontainers/runtime-spec/blob/v1.1.0/config-linux.md)、[Podman 4.9.3 的 annotation 参数](https://docs.podman.io/en/v4.9.3/markdown/podman-run.1.html)。已验收 rootful/rootless 的首条应用指令、压力执行、停止启动、重建、管理服务中断、guest 重启和清理。完整压力和生命周期使用默认 crun；runc 另通过两种模式的实际启动前资源检查。
