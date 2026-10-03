# RMX1931CN kernel extensions / DroidSpaces / Podman

Current tested kernel: `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-io`, on RMX1931CN / crDroid 16 / Android 16. Boot readback/config matched; 19 functional probes and 27 official capability checks passed. Wi-Fi reconnect, rootful/rootless Podman builds, storage, networking, lifecycle and actual memory/pids limits passed. SELinux Enforcing; no BUG/Oops/panic observed.

Added EROFS LZ4/xattrs/ACL, automatic QEMU binfmt dispatch, optional BBR/FQ with Android cubic unchanged, checkpoint interfaces, nftables families/IPv6 NAT and block throttling. KernelSU Next stays pinned at cd739c7 (33304/UAPI4). Crashlog module 1.1 archives raw pstore after normal boot without disabling SELinux; sequence-based rotation handles early 1970 clocks.

See [implementation and acceptance](EXTENSIONS.md), [sanitized evidence](extensions-acceptance.json), [source lock](source-lock.json), [runtime setup](RUNTIME.md), and [boot image location / flashing instructions](FLASHING.md). Images and original ramdisk are retained locally; GitHub contains source/config/module and sanitized evidence.

## Build the final kernel on Linux

```sh
git clone --branch codex/rmx1931-ksunext3 https://github.com/hmhmdcy/kernel_realme_sm8150_openela.git
cd kernel_realme_sm8150_openela
git submodule update --init KernelSU-Next
CLANG_DIR=/path/to/clang-r547379 bash Documentation/droidspaces/build-ksunext.sh
```

Use a Linux filesystem, full KSU history (3015 commits), AOSP Clang 20 r547379 and ARM32 GNU binutils. Output defaults to out-extensions; JOBS and OUT_DIR are configurable. The full rmx1931_droidspaces_defconfig matches the accepted resolved config. Binary reproduction is not guaranteed across toolchain/build environments. Repacking requires the original boot from the intended ROM, preserving its ramdisk/DTB/header.

Source audit checked all 73,108 base archive files/symlinks and all 22 locked modified files against the compiled tree. Two new source changes fix this baseline's nft_socket backport; config changes are cumulative. 1,033 existing export CRCs change versus KSU3: rebuild old external .ko modules. The tested phone had no loaded/available external modules. Four inherited section mismatch warnings remain.

CRIU acceptance covers a single process via explicit privileged entry; the normal sandboxed guest entry cannot dump it. Guest seccomp stays enabled. I/O acceptance covers v1 test subprocess throttling on the actual ext4 loop; guest v2 io.max and CPU quota remain unavailable with this Android/WALT setup. Panic/watchdog retention, full-container restore, LXC device BPF filtering, BBR performance/battery and individual hardware certification are outside acceptance.

Runtime helpers require the existing provisioned guest and original local artifacts; they are not a new rootfs installer. The portable kernel build above is separate from workspace-specific candidate/boot packaging scripts. Historical KSU3 details are in [KSUNEXT-STATUS](KSUNEXT-STATUS.md) and [its lock](source-lock-ksunext3.json); the historical builder uses rmx1931_ksunext3_defconfig.
