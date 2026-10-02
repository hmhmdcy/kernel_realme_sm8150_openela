# KernelSU Next v3 update acceptance - 2026-10-03

The updated kernel was compiled, flashed to boot only, booted on RMX1931CN and verified. [Official manager/ksud v3.4.0](https://github.com/KernelSU-Next/KernelSU-Next/releases/tag/v3.4.0) is paired with legacy commit [cd739c7](https://github.com/KernelSU-Next/KernelSU-Next/commit/cd739c78802333455391df973db17d9f28328b83), required for this Linux 4.14 non-GKI manual integration. Kernel version changed from 12780 to 33304 / UAPI 4. The local version tag is v3.4.0-legacy-cd739c7.

| Check | Result |
|---|---|
| Boot/config | Readback SHA matches flashed image; live config matches resolved config byte-for-byte |
| Manager/ksud | Official APK digest, certificate and Android installer signature checks pass; manager Working / Manual; ksud 3.4.0 |
| Root/SELinux | Original Shell grant preserved; root uid 0 / u:r:ksu:s0; SELinux Enforcing |
| PTY | /dev/pts allocation and root command pass |
| DroidSpaces | v6.6.0 daemon module enabled; Ubuntu running; official capabilities 27/27 |
| Podman rootful/rootless | No-cache build, overlay/FUSE ownership, volumes, DNS, ports, exec/stop/start pass |
| Actual memory | Both modes: bounded 32 MiB memcg test kills child with exit 137 and oom_kill=1 |
| Actual pids | Both modes: control forks succeed; limited forks fail with resource temporarily unavailable |
| Socket diagnostics | Real UNIX/netlink/packet sockets appear in diagnostic dumps and ss |
| SquashFS | gzip/xz mount, hashes, hard/symbolic links, execution, xattr, EROFS, unmount and loop cleanup pass |
| Runtime startup | Complete profile outputs PODMAN_GUEST_PROFILE_READY |

| Artifact | SHA-256 |
|---|---|
| boot.img | `9588a95055bf35ced553297541a4e703b038451dcdfa775281b1f8c9f7a0bc58` |
| Image.gz-dtb | `8330300492f9b550d5a8588fa0f8e715e6f8e38f9ade7f54dc26f553c9bda5c9` |
| Resolved/running config | `6b3880005d9313c776ed33b854ef3cd3cfba1dddbbd16b66e339fb3ce4c61f52` |
| Official manager APK | `50339a93c0f812b8a72c1a387a1b441891e3df0f20b2d9daf80fd798d04b3de8` |

[source-lock.json](source-lock.json) pins source, helper and private evidence hashes. Previous boot, old KSU/ksud state and v1.0.9 APK are backed up locally. Rollback must restore the old kernel and matching userspace as a set; rollback was not executed during acceptance.

The seccomp backport changes external module CRCs, so old .ko files need recompilation. Four existing section mismatch warnings remain. No extra mount metamodule was installed; DroidSpaces does not require one. Physical hardware and long-term power/stability were not individually re-certified. CPU quota, Docker daemon, full nftables and IPv6 NAT remain outside acceptance.
