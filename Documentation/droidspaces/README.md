# RMX1931CN DroidSpaces / Podman kernel

Validated on Chinese Realme X2 Pro RMX1931CN, crDroid 16 / Android 16 with Ubuntu24.04.5 and DroidSpaces v6.6.0. **Rootful and rootless Podman 4.9.3 passed build, overlay writes, volumes, DNS, ports, lifecycle, memory/pids enforcement and guest restart tests.** The [runtime profile](RUNTIME.md) is required after each guest restart.

Base: [cyborgdc2000/kernel_realme_sm8150](https://github.com/cyborgdc2000/kernel_realme_sm8150), lineage-23.0-ksunext, commit `1a5720a5213b093c4cd54a7d8db5c5eeed2ca344`. Changes enable the missing namespace/IPC/cgroup/netfilter options, provide Android noprefix cgroup aliases with rollback/cleanup, backport FUSE userns mappings and BPF device query, and complete the upstream proc cmdline fix. Original hardware config, WALT, KernelSU-Next gitlink and SELinux remain enabled.

Live tested kernel: `4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2`. Boot SHA-256: `71591c95ec72f1a5582cd0fc3f3e7ce96d74fc469e9dace231f10ed0765118b9`. DTB, ramdisk and non-kernel boot header fields were preserved; flash and readback succeeded. User confirmed Wi-Fi reconnect/toggle, touch and fingerprint, and reported no new hardware fault. These observations do not individually certify every hardware feature. The original installed kernel had unknown uncommitted changes, so this is not a bit-for-bit reconstruction.

## Build on Linux

Use AOSP clang-r547379 (20.0.0), LLVM tools and arm32 GNU binutils. Initialize KernelSU-Next with complete history (2580 commits at `54b26fd32c90ec15fba5c87a4107a34918a66ed2`, KSU_VERSION=12780); do not shallow-clone that submodule.

```sh
git submodule update --init KernelSU-Next
export PATH=/path/to/clang-r547379/bin:$PATH
export LD_LIBRARY_PATH=/path/to/clang-r547379/lib64
make O=out ARCH=arm64 LLVM=1 LLVM_IAS=1 CC=clang LD=ld.lld \
  CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-gnu- \
  CROSS_COMPILE_ARM32=arm-linux-gnueabi- CROSS_COMPILE_COMPAT=arm-linux-gnueabi- \
  LOCALVERSION=-droidspaces-v6.6.0-podman2 rmx1931_droidspaces_defconfig
make O=out ARCH=arm64 LLVM=1 LLVM_IAS=1 CC=clang LD=ld.lld \
  CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-gnu- \
  CROSS_COMPILE_ARM32=arm-linux-gnueabi- CROSS_COMPILE_COMPAT=arm-linux-gnueabi- \
  LOCALVERSION=-droidspaces-v6.6.0-podman2 -j4 Image.gz-dtb modules
```

The full defconfig matches the tested resolved config. CONFIG_LOCALVERSION_AUTO can add a Git suffix in a checkout; the tested kernel was built from a source archive. Build timestamp/user/host and tree metadata also affect binary hashes, so a rebuild is not promised to match the tested binary. Four inherited section mismatch warnings were present in the tested build.

Kernel source and helpers are published; private backups, proprietary ramdisk and boot images are not. Use this exact device/ROM baseline and verified original backups when packaging a boot image. CPU quota is unavailable with WALT; complete nftables and IPv6 NAT coverage, Docker daemon and other ROM/device baselines are unverified.

See [Podman acceptance](PODMAN-STATUS.md), [startup guide](RUNTIME.md), [source/config hashes](source-lock.json), and [official DroidSpaces](https://github.com/ravindu644/Droidspaces-OSS/tree/v6.6.0).
