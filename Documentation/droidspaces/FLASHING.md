# 最终 boot 镜像与自行刷入

本文件对应 2026-10-03 已实际刷入并验收的累计 io 镜像，包含所有五组扩展。

镜像位置：

```text
<本地工作区>\artifacts\droidspaces\boot-images\RMX1931CN-crDroid16-DroidSpaces-v6.6.0-LowRisk2-KSUNext3-Extensions-io\boot.img
```

大小 100,663,296 字节（96 MiB）；同目录 `boot.img.sha256` 为校验文件。SHA-256：

```text
47d9ee609d4c28a0c9cae423bb25f72d4490d5efb1c3b8f91942098ad9a45ee5
```

适用当前 RMX1931CN / crDroid 16 / Android 16 环境，bootloader 已解锁。镜像保留此 ROM 的 ramdisk/DTB/header，换 ROM 时需要根据新 ROM 的原 boot 重新打包。1,033 个旧外部模块 CRC 改变，旧 `.ko` 需重编；本次手机没有加载或发现外部 `.ko`。

在本工作区打开 PowerShell，依次执行下面的命令。它们只写 boot，刷入前核对唯一设备、产品 `msmnile` 和解锁状态；不刷 recovery/vbmeta，不执行数据擦除。

```powershell
$boot = Join-Path (Get-Location) 'artifacts\droidspaces\boot-images\RMX1931CN-crDroid16-DroidSpaces-v6.6.0-LowRisk2-KSUNext3-Extensions-io\boot.img'
$expected = '47d9ee609d4c28a0c9cae423bb25f72d4490d5efb1c3b8f91942098ad9a45ee5'
if ((Get-FileHash -LiteralPath $boot -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'boot 镜像摘要不匹配' }
& .\tools\platform-tools\adb.exe devices
& .\tools\platform-tools\adb.exe reboot bootloader
& .\tools\platform-tools\fastboot.exe devices
& .\tools\platform-tools\fastboot.exe getvar product
& .\tools\platform-tools\fastboot.exe getvar unlocked
# 上述列表只有目标手机、产品为 msmnile、unlocked 为 yes/true 后再执行：
& .\tools\platform-tools\fastboot.exe flash boot $boot
if ($LASTEXITCODE -ne 0) { throw 'boot 写入失败，先检查输出' }
& .\tools\platform-tools\fastboot.exe reboot
```

开机后核对：

```powershell
& .\tools\platform-tools\adb.exe shell uname -r
# 预期：4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-io
& .\tools\platform-tools\adb.exe shell getenforce
# 预期：Enforcing
python scripts/start_podman_guest.py
```

仅刷 boot 不会安装 Ubuntu/Podman/CRIU/QEMU 用户态，也不会安装日志模块；本次现有 guest 和 KernelSU 模块已经配置。日志模块安装包为 `artifacts\droidspaces\crashlog\rmx1931-crashlog-1.1.zip`，通过 KernelSU 管理器安装。已有模块时无需重复安装。日志保存在手机 `/data/adb/rmx1931-crashlog`，导出用 `python scripts/crashlog.py export`。

原已验收 KSU v3 回滚镜像保留在：

```text
artifacts\droidspaces\boot-images\RMX1931CN-crDroid16-DroidSpaces-v6.6.0-Podman2-LowRisk2-KSUNext3\boot.img
```

其 SHA-256 为 `9588a95055bf35ced553297541a4e703b038451dcdfa775281b1f8c9f7a0bc58`。回滚时仍用 `fastboot flash boot`，参数换成核对过摘要的回滚路径。原 boot、ramdisk、原始设备日志只保留本地；GitHub 提交包含源码、配置、模块源码、构建/运行 helpers 与脱敏验收。
