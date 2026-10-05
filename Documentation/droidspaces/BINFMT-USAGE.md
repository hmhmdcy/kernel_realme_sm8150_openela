# guest 内的跨架构构建与运行

`rmx1931-binfmt` 已安装到当前 h3bm2 guest，并从保持 Seccomp=2 的普通 guest 服务完成 rootful/rootless、amd64/ARM64 的真实构建与运行验收，见[验收记录](BINFMT-NAMESPACE-VALIDATION.md)。需要 guest 中已有的 `/usr/bin/qemu-x86_64-static`。

入口在独立用户命名空间注册解释器，仅在前台命令运行期间持有注册。不同调用互不共享注册表；退出时撤销、卸载并删除自己的临时挂载目录。支持 UID/GID 0—65535。当前旧 overlayfs 在用户命名空间内不支持挂载，Podman 使用 VFS 和专用存储路径。

rootful 示例，工作目录须为构建上下文；`my-amd64` 与容器名由调用者选择：

```sh
rmx1931-binfmt -- podman --storage-driver=vfs \
  --root=/var/lib/rmx1931-crossarch/rootful --runroot=/run/rmx1931-crossarch/rootful \
  --cgroup-manager=cgroupfs --runtime=/usr/bin/crun build \
  --platform=linux/amd64 --isolation=oci \
  --security-opt=seccomp=/usr/share/containers/seccomp.json \
  -t localhost/my-amd64:1 .

rmx1931-binfmt -- podman --storage-driver=vfs \
  --root=/var/lib/rmx1931-crossarch/rootful --runroot=/run/rmx1931-crossarch/rootful \
  --cgroup-manager=cgroupfs --runtime=/usr/bin/crun run \
  --rm --pull=never localhost/my-amd64:1
```

rootless 使用已有 `podman-rootless` 入口先进入其用户命名空间，再创建本次调用独立的 binfmt 命名空间；在普通 UID 可访问的构建目录运行：

```sh
podman-rootless --storage-driver=vfs \
  --root=/home/podmantest/.local/share/rmx1931-crossarch \
  --runroot=/run/user/1000/rmx1931-crossarch unshare \
  rmx1931-binfmt -- podman --storage-driver=vfs \
  --root=/home/podmantest/.local/share/rmx1931-crossarch \
  --runroot=/run/user/1000/rmx1931-crossarch --cgroup-manager=systemd \
  --runtime=/usr/bin/crun build --platform=linux/amd64 --isolation=oci \
  --security-opt=seccomp=/usr/share/containers/seccomp.json \
  -t localhost/my-amd64:1 .
```

将内层 `build` 替换为 `run --rm --pull=never localhost/my-amd64:1` 即可运行。测试已覆盖 crun/runc、容器 UID 0 与 UID 1000；示例中的镜像与持久存储由调用者管理，入口只清理自身注册及挂载。

当前入口拒绝直接使用 `-d`/`--detach`。命令必须在前台完成；通过 shell 间接启动后台进程同样超出当前生命周期范围。持续运行服务需要持有用户命名空间和注册表的独立服务。该功能使用 QEMU 用户态模拟，不提供 KVM/AVF。
