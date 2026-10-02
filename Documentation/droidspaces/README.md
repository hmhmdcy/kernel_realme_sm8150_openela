# RMX1931CN DroidSpaces / Podman / KernelSU Next

Validated on Chinese Realme X2 Pro RMX1931CN, crDroid 16 / Android 16, DroidSpaces v6.6.0 and Ubuntu24.04.5. Running kernel: `4.14.356-openela-rc1-perf-droidspaces-v6.6.0-podman2-lr2-ksu3`. KernelSU Next legacy revision `cd739c78802333455391df973db17d9f28328b83`, kernel version 33304 / UAPI 4, official manager and ksud v3.4.0. Manager status is **Working / BUILT-IN (LEGACY) / Manual**. SELinux remains Enforcing; the existing Shell root grant and DroidSpaces daemon module are preserved.

Rootful/rootless Podman 4.9.3 passed no-cache builds, overlay/FUSE writes, ownership, volumes, DNS, ports, lifecycle and actual memory/pids enforcement. All 27 official DroidSpaces capability checks passed. UNIX/netlink/packet socket diagnostics and gzip/xz SquashFS also passed. Use the [runtime profile](RUNTIME.md) after each guest restart.

Base: Cyborg lineage-23.0-ksunext `1a5720a5213b093c4cd54a7d8db5c5eeed2ca344`, with previously published Podman fixes. This update migrates manual KSU hooks, includes upstream legacy seccomp/SELinux compatibility backports, updates the KSU gitlink and publishes the complete tested defconfig. All 73108 base archive files/symlinks were compared to the compiled source: exactly 20 locked kernel source files differ; one tar-normalized symlink has an equivalent target. The original ten Podman source changes remain byte-identical.

## Build on Linux

Clone this branch on a Linux filesystem. KSU needs complete history: 3015 commits reachable from the pinned legacy revision. The helper verifies this and sets upstream-supported version overrides. The fixed kernel release prevents an added Git suffix from exceeding the 64-character utsname limit.

```sh
git clone --branch codex/rmx1931-ksunext3 https://github.com/hmhmdcy/kernel_realme_sm8150_openela.git
cd kernel_realme_sm8150_openela
git submodule update --init KernelSU-Next
CLANG_DIR=/path/to/clang-r547379 bash Documentation/droidspaces/build-ksunext.sh
```

Use AOSP Clang r547379 / 20.0.0, LLVM tools and arm32 GNU binutils in PATH. Output defaults to out-ksunext; set OUT_DIR and JOBS as needed. The full rmx1931_droidspaces_defconfig is byte-identical to the tested resolved config. A rebuild is not promised to reproduce binary hashes; Git/build metadata and compiler inputs also matter.

The Windows publication worktree uses sparse checkout for relevant source, config, documentation and the complete KSU submodule. It supports editing/publication. Use the Linux clone above for a full build.

## Verified artifacts and limits

Boot SHA-256: `9588a95055bf35ced553297541a4e703b038451dcdfa775281b1f8c9f7a0bc58`. Image.gz-dtb SHA-256: `8330300492f9b550d5a8588fa0f8e715e6f8e38f9ade7f54dc26f553c9bda5c9`. DTB, ramdisk and non-kernel boot header fields were preserved; boot-only flash and readback succeeded. The original installed kernel had unknown uncommitted changes; this is not a bit-for-bit reconstruction of that original binary.

The exported set remains 12166 symbols, but the seccomp compatibility backport changes 8183 CRCs. Rebuild external .ko modules. No external modules are loaded on the tested phone; drivers are built in. Four inherited section mismatch warnings remain. Physical hardware and long-term stability were not individually re-certified during this update. CPU quota with WALT, Docker daemon, complete nftables, IPv6 NAT and other device/ROM baselines remain outside acceptance.

DroidSpaces is a daemon-only module (mount=false) and works without a mount metamodule. No additional metamodule was installed. Modules needing system mounts require their own dependency validation.

See [current KSU acceptance](KSUNEXT-STATUS.md), [source/config/helper hashes](source-lock.json), [historical Podman2 acceptance](PODMAN-STATUS.md) and [historical source lock](source-lock-podman2.json). Source, configuration and sanitized evidence are published. Boot images, proprietary ramdisk, root backups and raw device logs remain private.
