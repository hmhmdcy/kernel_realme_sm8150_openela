# Android 16 当前 ROM 的 eBPF 验收

当前 a16pf 已完成[联合验收](runtime/candidates/a16pf/evidence/android16-bpf-acceptance.json)，boot ID 与 PSI 联合验收一致。本项核查宿主 ROM 实际使用的接口，不恢复完整 Android 16 桌面；已有内核实现满足本轮需求，没有新增 BPF 内核代码或再次刷入。

只读 native 探针按实际构建树的 UAPI 编译，只使用 OBJ_GET、OBJ_GET_INFO_BY_FD、PROG_QUERY 和 MAP_LOOKUP_ELEM。34 个固定程序与 54 个映射信息全部读取成功；netd 的 ingress/egress、socket-create、IPv4/IPv6 bind/connect、UDP sendmsg/recvmsg、get/setsockopt 共 13 类有效挂载均匹配当前加载的程序 ID，见库存与挂载（本地证据：`runtime/candidates/a16pf/evidence/runtime/android16-bpf-readonly-a16pf-20261005-inventory.json`）。仅有这些元数据不算功能验收。

独立负载在自身进程降为 UID 2000 后执行 2 秒 CPU 工作，再做 IPv4/IPv6 各 64 次、每包 1024 字节的本机 UDP 往返。实际 bind/connect/sendmsg/recvmsg/get/setsockopt 成功且数据逐包一致。已有 timeInState UID 映射增长 2,305,329,499 纳秒，netd UID 映射收发各增长 256 包、271,872 字节，见负载及前后记账（本地证据：`runtime/candidates/a16pf/evidence/runtime/android16-bpf-workload-a16pf-20261005-result.json`）。UID 2000 总量可包含其他活动，不将总增量当作精确的独占进程 CPU 时间。

timeInState 的 UID/bucket、每 CPU 频率时间数组及 netd StatsValue 按固定 AOSP 参考（本地证据：`runtime/candidates/a16pf/references/android16-bpf-aosp/source-lock.json`）及时间结构参考（本地证据：`runtime/candidates/a16pf/references/android16-bpf-aosp/layout-header-reference.json`）解读，并核对实际映射类型/尺寸。参考代码不宣称与当前 ROM 编译源逐字相同；实际功能结论来自本机调用和计数。[AOSP timeInState](https://android.googlesource.com/platform/system/bpfprogs/+/cdb14b57cc698975b796224c507b4d15698b4788/timeInState.c)与[netd](https://android.googlesource.com/platform/packages/modules/Connectivity/+/627eb3c63e7c7cb3cb9f8ea319e4bb1676079c3a/bpf/progs/netd.c)为来源。

负载后宿主健康（本地证据：`runtime/candidates/a16pf/evidence/runtime/bpf-host-final-a16pf-20261005.json`）通过：同 boot、关键服务未重启、LMKD 全局监视、KSU 与普通 guest 过滤保持，SELinux Enforcing，无观察到的致命内核日志。两套 host/guest 专用临时目录已核对二进制摘要并清理（本地证据：`runtime/candidates/a16pf/evidence/runtime/android16-bpf-workload-a16pf-20261005-cleanup.json`）。首次编译准备遇目录属主导致 push 失败，修正后续编译，未重启或重复刷入。

范围限于当前实际加载的接口、CPU UID 记账、回环通信与网络 UID 记账；不宣称所有 netd 策略重写配置、外网吞吐、续航、GPU/热点硬件都已认证。`ro.bpf.kver_override=5.4.186` 仍为用户态覆盖值，不改变实际 4.14 内核版本。后续仅具体消费者出现缺失或错误时修复；按[测试政策](TEST-POLICY.md)执行。

原始日志与完整历史封存保留本地；上面的本地证据路径用于定位，GitHub 发布精选验收摘要。
