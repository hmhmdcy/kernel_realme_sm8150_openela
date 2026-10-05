# RMX1931 的 KVM / AVF 可行性

2026-10-04，按用户要求检索骁龙 855 / SM8150 类似案例，并在当前手机上只读核查。结论：当前启动链没有向本内核提供 KVM 所需的 EL2 入口。KVM / AVF 移至平台研究项，不作为近期容器补强的可交付功能。

需要区分 AVF 的不同后端：pKVM 是 AOSP 参考实现，而 Qualcomm 也提供通过 Gunyah 接入 AVF 的路径，其 Linux 驱动在 EL1 与 EL2 hypervisor 通信。因此“Linux 从 EL1 启动”直接约束本内核自行安装 KVM/pKVM，不能单独证明所有 AVF 后端均不可能。本次没有找到本机固件、驱动和系统组件支持 Gunyah AVF 的可核验案例，也不能仅凭 hyp 分区名称把本机固件认定为具备现代 Gunyah API。

本机证据：只读检查（本地证据：`virtualization-platform-evidence.json`），内核 `4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-harden1`，日志为 `CPU: All CPU(s) started at EL1`，没有 `/dev/kvm`，分区名包含 `hyp`、`abl`、`xbl`。实际运行配置与构建配置一致；构建配置未启用 KVM。没有 KVM 节点本身不能证明硬件不支持；EL1 启动才是本次观察到的关键平台限制。仅发现 hyp 分区也不能单独证明其中固件的运行状态或可替换性。

AVF 后端只读检查（本地证据：`virtualization-avf-evidence.json`）显示 `/dev/kvm` 和 `/dev/gunyah` 均不存在，两个 ro.boot.hypervisor 的 VM 能力属性为空，`com.android.virt` APEX 存在。即当前 ROM 带有用户态组件，但没有据此发现可工作的虚拟化内核入口；APEX 存在不等于 VM 能够启动。这不是所有固件接口的穷尽证明。

| 一手资料 / 案例 | 观察和适用范围 |
| --- | --- |
| [2019 年 SM8150 / SC7180 的 Linux 上游讨论](https://lkml.rescloud.iu.edu/hypermail/linux/kernel/1910.2/03162.html)及[开发者后续澄清](https://lkml.iu.edu/1910.2/03428.html) | Qualcomm 开发者澄清“不支持 KVM”针对未从 EL2 启动的 downstream Android；SC7180 不属于该 Android 情形。Marc Zyngier 指出 EL2 入口和异构核心的 32 位客体差异。不能把原帖理解为所有高通芯片没有虚拟化硬件，也没有证明零售 SM8150 手机成功运行 KVM。 |
| [2024 年 SA8155P-ADP 的 U-Boot 移植](https://lists.u-boot-project.org/pipermail/u-boot/2024-February/547068.html)及[Xen 平台补丁](https://lists.xenproject.org/archives/html/xen-devel/2024-03/msg01789.html) | SA8155P 是 SM8150 的汽车变体。该开发板加载链支持测试密钥，作者为移植 Xen 将 U-Boot 放到 hypervisor 阶段，以 EL2 启动。这是最接近芯片系列的具体案例，但依赖专用开发板加载链，不能推断 RMX1931 允许相同操作；资料不能作为本机 KVM 验收。 |
| [qhypstub 项目](https://github.com/msm8916-mainline/qhypstub) | 明确列出已工作的 Snapdragon 410 / MSM8916 和 615 / MSM8939，通过替换 hyp 固件允许 EL2 / KVM。没有列出 SM8150。直接替换固件要求设备允许自定义固件，旧设备的运行时替换另依赖特定 TZ 缺陷；这些条件都不能从 Android bootloader 已解锁推导出来。 |
| [Qualcomm Secure-Launch 研究](https://github.com/TravMurav/Qcom-Secure-Launch)及[SLBounce 实现](https://github.com/TravMurav/slbounce) | Windows-on-ARM 平台可借其固件提供的 Secure Launch 机制接管 EL2，另有特定开发板的 Gunyah 交接接口。SLBounce FAQ 明确表示 Android 设备不能使用其方案：QHEE 检查的 Secure Launch devcfg 标志仅在出厂 Windows 设备上设置。因此不能直接移植为 RMX1931 的 EL2 切换方案。 |
| [2026 年 Qualcomm 提交的早期 EL2 切换补丁](https://lists.u-boot-project.org/pipermail/u-boot/2026-May/618646.html) | 使用 TrustZone SMC 退出 Gunyah 并切到 EL2，说明固件接口是必要环节。这是补丁提案，资料没有证明接口可用于 SM8150 或本机。 |
| [2024 年 Qualcomm 的 Gunyah / AVF 接入介绍](https://www.qualcomm.com/developer/blog/2024/01/gunyah-hypervisor-software-supporting-protected-vms-android-virtualization-framework)及[EL1 Linux 驱动介绍](https://www.qualcomm.com/developer/blog/2024/08/learn-about-gunyah--qualcomm-s-open-source--lightweight-hypervis) | AVF 可通过厂商 hypervisor 而非 pKVM 实现；依赖 Gunyah 固件、资源管理器、Linux 驱动、crosvm 和 pVM 引导组件。资料没有证明零售 SM8150 / RMX1931 已具备这套接口。 |
| [开发者在 Lenovo Y700 四代 / Snapdragon 8 Elite 上运行 Gunyah VM 的记录](https://github.com/polygraphene/gunyah-on-sd-guide) | 作者给出设备、Android 15 环境和 crosvm 日志，通过 `/dev/gunyah` 启动 Debian 12 ARM64 客体并进入维护 shell；还说明需要调整客体服务和 fstab。属于新一代芯片上的实际启动案例，使用 Gunyah，不能记作 SM8150 的 KVM 成功，也不能据此保证完整桌面、图形加速或 RMX1931 固件兼容。 |
| [Snapdragon 855 Windows BSP 项目](https://github.com/WOA-Project/windows_silicon_qcom_hana) | 维护者列出 Hyper-V 与其 IOMMU 映射未工作。属于不同操作系统的间接案例，不能当作 Linux KVM 的失败实验。 |
| [Galaxy Tab S6 / SM8150 的独立开发记录](https://0xd.to/blog/hypervisor-said-no) | 作者报告 EL2 hypervisor 对 SMMU 操作的限制；这是 Samsung 设备上的报告，不能把 Samsung 的具体策略直接归于本机。 |

[Linux ARM hypervisor ABI 文档](https://www.kernel.org/doc/html/v6.1/virt/kvm/arm/hyp-abi.html)要求内核由 HYP/EL2 进入，才能安装自身 hypervisor；[AOSP AVF 架构](https://source.android.com/docs/core/virtualization/architecture)的 pKVM 启动还要求相应 bootloader、hypervisor 和系统组件。开启 CONFIG_KVM、升级 Android 版本或拿到 Android root 都不会自行改变固件提供的异常级。

本次检索没有找到可核验的 RMX1931/Realme X2 Pro 在保留日常 Android 启动链下成功运行 KVM/AVF 的案例。这里记录的是检索结果与当前启动的限制，不能据此宣称所有 SM8150 硬件永久无法虚拟化。

上述例外共同依赖固件加载或交接权限。Android root、Android bootloader 解锁、自定义 boot.img 与能够替换已签名的 hyp / TrustZone 是不同条件。后续若重新评估，应先核验 RMX1931 固件是否提供受支持的 EL2 交接或 VM 管理接口，再考虑驱动和内核配置；现有资料没有满足这个前提。

2026-10-05 按用户要求暂停完整 Android 16 桌面与应用容器，保留 namespaces、cgroups、独立 Binderfs 的方案与前期调研；该方案不依赖 EL2。当前继续补强宿主与现有 Linux 容器的内核能力。跨架构执行使用 QEMU 用户态模拟和隔离的 binfmt_misc；如以后需要独立客体内核，可另评估 QEMU TCG 的性能。TCG 不能记作 KVM 硬件加速。固件 EL2 切换研究需先找到本平台可核验入口，当前工作不修改 hyp / TrustZone / bootloader 分区。

原始日志与完整历史封存保留本地；上面的本地证据路径用于定位，GitHub 发布精选验收摘要。
