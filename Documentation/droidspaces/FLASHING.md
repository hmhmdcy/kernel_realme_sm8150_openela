# a16pf boot 与回滚

2026-10-05 已在 RMX1931CN / crDroid 16 / Android 16 刷入并验收 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-a16pf`。当前源码与完整配置见[源码锁](source-lock.json)，功能范围见[交付结果](FINAL-DELIVERY.md)。

本地镜像：`artifacts/droidspaces/boot-images/RMX1931CN-crDroid16-DroidSpaces-v6.6.0-LowRisk2-KSUNext3-Extensions-android16-group-psi-reclaim-fix/boot.img`，大小 100,663,296 字节，SHA-256 `dfe18875661164e7cb64eba7942b856e80ffe20abb537aec815da4bf43995cdd`。Image SHA-256 `ecc93ef7e4aaf8256d95ff0471be78be9c3ab17a6d6cd419eb9748729ec955c9`。

GitHub 不包含 boot 或原 ROM ramdisk。重新构建时保留适用 ROM 的 ramdisk/DTB/header，仅去掉最终 `cgroup_disable=pressure` 参数，以 `psi=1` 启用分组 PSI。换 ROM 须重新打包并验收。PSI 修复相对 h5bf2 改变 3,916 个导出 CRC；旧外部 `.ko` 须重编译并验证。

## 已准备镜像的刷入

适用已解锁 bootloader 的目标手机。刷入前完成摘要、容量、打包与回滚核对；固定目标序列号。遇到传输失败先确认原刷写状态，不盲目重复写入或枚举设备。

```powershell
$boot = 'artifacts/droidspaces/boot-images/RMX1931CN-crDroid16-DroidSpaces-v6.6.0-LowRisk2-KSUNext3-Extensions-android16-group-psi-reclaim-fix/boot.img'
$expected = 'dfe18875661164e7cb64eba7942b856e80ffe20abb537aec815da4bf43995cdd'
if ((Get-FileHash -LiteralPath $boot -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'boot 摘要不匹配' }
if (-not $env:RMX1931_ADB_SERIAL) { throw '先设置目标手机 RMX1931_ADB_SERIAL' }
# 手机已在 fastboot 且目标身份与解锁状态已核对时执行：
& ./tools/platform-tools/fastboot.exe -s $env:RMX1931_ADB_SERIAL flash boot $boot
if ($LASTEXITCODE -ne 0) { throw '写入失败，保留输出并先检查状态' }
& ./tools/platform-tools/fastboot.exe -s $env:RMX1931_ADB_SERIAL reboot
```

开机后一次核对 release、实际配置、镜像身份与 SELinux Enforcing，再执行受影响功能验收。仅刷 boot 不安装 Ubuntu/Podman 用户态。日常按[测试政策](TEST-POLICY.md)选择专项与短回归，不默认运行累计全套或真实 panic。

已验收 h5bf2 回退镜像与原机 boot 保留本地；使用 `fastboot flash boot` 前按各自候选记录核对摘要。完整保留核验见[WSL 记录](FINAL-WSL-RETENTION.json)。
