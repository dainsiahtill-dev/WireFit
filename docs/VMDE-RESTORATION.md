# vmde 还原进度

目标是经由 Wirefit 逐步恢复用户指定 vmde 的启动及业务行为，所有结论绑定实际输入和证据。当前仍未恢复成可独立运行的程序，也未建立完整算法或原始源码的还原。

最新进展：生成 [兼容入口候选并实际进入应用主函数](../artifacts/research/vmde/startup-compat/README.md)。19 项生成工具测试、两个原始 SEH helper 合成 CPU 帧检查通过；公共 CLI 的实测已到 Qt 包装函数、主函数和 Qt 应用对象构造。随后仍发生访问异常，主函数另有 `42474f → D2ED39 → AA35DE` 的剩余保护转移；候选尚不可正常使用，不能称为完全脱壳或真正 OEP 恢复。

此前本轮恢复 [三个标签状态操作](../tools/label-state/README.md)，32 项定向测试及 26 次原始机器码 CPU 仿真全部通过；仍是合成状态的局部验证。[分割阶段证据](../artifacts/research/vmde/segmentation-results/README.md) 保留自然标签与对象别名的未完成项。正常图像输入/矢量输出和完整业务行为仍是整体目标。

原文件 `E:\Vector Magic 2021\vmde.exe` 的 SHA256 为 `9a0fa724e4a2f189da4cafdd700842d5b6c7aa6c571269500e5eb56cc3fa9a5d`。已有分析转储 SHA256 为 `50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992`。原文件及历史失败均保留。

| 阶段 | 当前证据与缺口 |
| --- | --- |
| 文件清点、壳识别、工作副本 | 已完成；目标为 Themida/Winlicense，非本轮 VMP 样本 |
| 分析转储 | 已生成；入口 `0x4b12bc` 为依赖调用栈的 SEH helper，直接启动发生访问异常 |
| 静态业务结构 | 75 个 Qt revision-1 类候选、526 条方法签名；部分元方法、分派表和直接调用已关联 |
| 原目标运行证据 | 被动运行完成：Qt 主窗口及正常激活窗口出现，43 个末态模块、16 份初末片段；带断点对照出现扰动 |
| 完整主模块内存 | 已实际采集 14,561,280 字节；223 个连续范围逐一复核，未知字节 0；另有 512 字节私有目标片段 |
| 私有执行区域追踪 | 新一轮从四个实时 caller 派生目标，完整采集两个 4KiB 页；系统模块间接指针/依赖仍未闭合 |
| 完整启动、TLS、导入运行状态 | 未恢复；须确认真实 CRT 转移和 DLL 实际加载状态 |
| 业务算法及输入输出回归 | 未完成；没有把名称、调用关系或反编译成功写成算法恢复 |
| 局部可执行还原 | 节点编号及返回计数已与 904 组原生调用记录匹配；40 字节记录写入器已通过 31/31 CPU 仿真逐字节比较；整图矢量输出未验证 |

静态结构证据在 [architecture.md](../artifacts/research/vmde/static-startup/architecture.md)。MainModel 的 `vectorizeImageWithMruSettings(int)` 分派到调用 `0x42b560`，`advUpdateSegmentation()` 对应调用 `0x427ff0`，`advUpdateContours()` 对应 `0x425260`。工作线程的表项和包装函数关联到分割 `0x46df50`、轮廓平滑 `0x46e0e0`、贝塞尔拟合 `0x46e200` 等候选。这些是方法记录、表项和调用字节的关联；尚未证明调用方实际执行顺序或被调函数的全部语义。

首轮产品作业 `job_b90dc62b6e4c4605b7aed3028ce94de1`、结果 `binary_trace_83e36ccd2e1241958ef4851d011a95fb` 位于 `cases/vmde-runtime-20261020`，[收据](../artifacts/native/trace-vmde-startup-20261020.json) 保留当时协议。源文件未变，目标与 session、Windows Job 清理均获确认。该历史收据产生于采集器进一步加固之前；没有事后补写源码身份或覆盖原记录。

初末内存比对发现 CRT 前段 576 字节和应用入口 1,344 字节均未变化，与受保护原文件相同，和转储中的解码字节不同；TLS 模板、回调区和旧 IAT 观测区在两个采样时点均为零。保护跳板附近 64 字节中有 62 字节发生变化，末态与分析转储吻合。这并不证明该跳板已执行。3 次原生异常后仍有 API 事件，不应直接当作致命退出。完整比较及文件哈希见 [运行证据分析](../artifacts/research/vmde/runtime-startup-analysis/)。

正控试验使用已实际观测到的 API 返回地址与 CRT 候选地址，检查断点可靠性；不能仅凭零命中断言启动路径没有执行。修复入口或重建 PE 前，仍须取得实际转移、栈、初始化状态和依赖基址证据。

后续对照已完成，补充了关键限制：60 秒正控运行命中两个 API 返回地址，但采集结束时内部超时；移除 API 挂钩后仍超时。保持相同窗口并移除硬件断点后，作业 `job_238a83286a6740eead4a871ea966288f` 成功，结果 `binary_trace_9b79c47b1da8468b9b187766bcea27f4` 保存 15 条事件和 16 份初末快照，四项清理确认均为 true。窗口采样在目标 PID、工作路径和生命周期匹配下观测到 `QWidget: Vector Magic Desktop Edition` 与 `Activate the Software`；[原始窗口收据](../artifacts/research/vmde/window-observation/passive-control-20261020.json) 和 [被动运行收据](../artifacts/native/trace-vmde-passive-control-20261020.json) 均保留。

这推翻了把先前断点运行直接当作原程序启动阶段的做法：当前支持硬件断点配置相关扰动，具体机制仍未知。被动末态有 MSVCR71 `0x7c340000`、QtCore4 `0x67000000`、QtGui4 `0x65000000`、QtNetwork4 `0x64000000`，CRT、应用代码和旧 IAT 范围均已改变；TLS 图像模板仍为零。进入界面不等于矢量化输入输出回归已通过，正常激活界面也未被工具操作。

另一路真实 Ghidra 探针已产生四份范围校验通过的候选 C：`0x46df50`、`0x46e0e0`、`0x46e200`、`0x42b560`；`0x42ce10` 的反编译扩展到范围外，明确拒绝。四份代码仍有未知 ABI、对象字段和被调函数，不能称为完整算法。脚本关闭增量分析，有限 listing 与限时反编译分别记录，详见 [业务函数证据](../artifacts/research/vmde/business-functions/README.md)。

沿实际调用链再分析五个候选，进入了 `0x499eb0` 的二维整数网格与邻域扫描，以及 `0x46b9a0` 的 x87 参数映射；其余包含包装和状态更新。五份结果的 listing、p-code PC 与来源字节均通过范围核验。当前适合继续追踪的节点是扫描内调用 `0x4999d0`（调用点 `0x49a0bc`）。未知对象布局、偏移表和被调语义仍保留，见 [算法候选记录](../artifacts/research/vmde/algorithm-candidates/README.md)。

进一步的一轮五函数分析已沿该调用点完成。累计 14 份候选 C 通过 PC 范围核验，另有先前一份越界结果被拒绝；范围通过并不保证 ABI 或变量恢复正确。新一轮取得三组四项二维偏移表的实际 store、整数网格与记录字段候选、局部方向 eligibility，并提供能被现有 Wirefit 模型验证器和 evaluator 接受的 BV32 表达式。初始化 store 未被当作每次调用时仍成立的不变量；完整循环及外部链表/分配 callee 仍未知，详见 [网格调用链](../artifacts/research/vmde/grid-kernel-analysis/README.md)。

其中无外部 CALL 的 `0x498a50` 已实现为独立 [Python 候选](../artifacts/research/vmde/kernel-replay/candidate.py)，恢复标签图到节点编号的规则。固定原始机器码 637 字节在有界 x86 CPU 仿真中给出期望输出，冻结候选独立计算输出，**896/896 匹配、203/203 已列指令起点被执行**。每个样本重新构造分离的对象、源/目标数组和栈，检查读写范围、返回、寄存器及 canary；覆盖极值标签与行 padding。该结果只支持明确的合成契约，指令覆盖不是全路径证明，仿真也不是原 PE 的原生 Oracle；没有把它升级成完整函数/整程序等价或图像矢量化已恢复，见 [局部机器码回放](../artifacts/research/vmde/kernel-replay/README.md)。

完整主模块采集发生于第二次带 PE 头采样的被动运行，父结果 `binary_trace_02728295103844969703fbce3ae1afa1`。镜像是 [flat-RVA 内存数据](../artifacts/research/vmde/module-image/vmde-main-v2-20261020.bin)，SHA256 `4933d735ecbb9cb6b070b814518ae982066a5b98dd8394a6bafa1591a153cb20`；[采集收据](../artifacts/research/vmde/module-image/vmde-main-v2-20261020.json) 记录同一进程 HANDLE 的路径、精确创建 FILETIME、源文件身份、全部范围的真实字节摘要与非原子观察性质。采样时程序已出现 Qt 主窗口，原程序 PE 头的入口 RVA 被改为 0；此值不能当作可用 OEP。最初采集器错误要求入口字段不变，拒绝了这类运行时变化；失败摘要及当时工具原字节均保留，没有伪造缺失的完整 stdout 收据。

同进程的 `0x4b10c8` 当前 CALL 指令经重新读取确认后，另采集其私有目标 `0x06180000` 的 512 字节。片段可见内部跳转、计时指令及截断边界，尚不能从现有字节证明完整 API 实现。Qt 命令行包装代码还有其他清单外目标，完整主模块不包含这些依赖；真实入口、完整保护状态及依赖闭合均未建立。逐范围哈希审计、导入槽差异归因和私有片段完整指令见 [完整内存只读报告](../artifacts/research/vmde/full-memory-analysis/README.md)。

案例通过新不可变结果 `binary_trace_evidence_f47cc89a4d494d41ae14e78fa0d61c48` 收纳镜像、窗口及私有片段，原 run/job 未覆盖。可交付包位于 [vmde-restoration-20261020](../exports/vmde-restoration-20261020/report.md)，含 55 个 manifest 文件；复制到独立目录后再次核验 55/55 文件身份匹配。验证器不执行 PE，`runnable_verified=false`。附加工具在 writer lease 内检查终态，避免自动恢复历史 job 的竞态。

后续私有区域采集已实际完成：作业 `job_fe540b1642684bf18aabbdd89931d63d` / 父结果 `binary_trace_287648cdab9c4d9c8cf73843ef779ca7` 在新 case 中运行，4 个实时 caller 分别指向 `0x62d0356`、`0x6290012`（两处）和 `0x6290018`。本轮主图 SHA256 为 `e5bfd679469174d240d598b3e778f9f326d2dcd43867d55ce48bae501668648a`，仍为 14,561,280 字节全部实读；两个 committed/private/readable/executable 页共 8,192 字节全部实读。两个 allocation 的元数据扫描看到 free 边界，系统模块内实际间接指针仍未采集，不能称程序依赖已闭合。新的主图中 `0x498a50` 的 637 字节也与已回放机器码 SHA 一致，这不是原进程执行该函数的证据。原始源、工作副本和采集源码均未变，4 项清理确认全真；独立 22 项工件审计通过，详见 [私有依赖记录](../artifacts/research/vmde/private-closure/README.md)。

新增 `private-regions.py` 支持受限 VQE/RPM、同 HANDLE 调用字节复核、全局预算及部分证据保存。当轮完整产品回归 **433/433，0 跳过**，类型检查与构建通过；[原始回归 JSON](../artifacts/vmde-private-reviewed-vitest.json) 保留。正常图像输入/矢量导出、真实入口与启动环境、完整算法、可独立运行的新程序仍未完成。

本轮 [交付包](../exports/vmde-private-closure-20261020/FOLLOWUP.md) 保留产品 52 文件闭包，另以独立 manifest 包含私有原始数据、审计、两页分析和网格候选，合计核验 94 个登记文件。复制到独立目录后再次核验 94/94，导出的 Python 候选在新进程重算 896 份保存的机器码仿真观测全部一致，4 个契约单测通过；这一步没有重新执行原 PE 或 CPU 仿真。[最终验证收据](../artifacts/native/private-followup-verification-20261020.json) 记录命令、原始输出和文件身份。两页分析仍有五个未采集的系统模块 DWORD 及其他环境指针依赖；没有将磁盘 DLL 导入名或静态分支写成实际 API 调用，见 [私有页分析](../artifacts/research/vmde/private-closure/analysis/README.md)。

上一阶段最终产品回归 **402/402 通过，0 跳过**，类型检查与构建通过；[完整验证收据](../artifacts/native/runtime-verification-20261020.json)、[测试原始结果](../artifacts/vmde-runtime-reviewed-vitest.json) 和 [独立目录核验](../artifacts/native/vmde-restoration-copy-verification-20261020.json) 保留。历史 63 项完整规格门禁没有被改写为通过。

最新一轮把可选 `module` 范围纳入现有 `binary trace` / MCP：每个阶段重新解析实际已加载模块，保存基址、大小和绝对读取地址；模块缺失、歧义、越界或读取失败均保留错误，主模块旧范围保持兼容。所有地址同时经过采集端与主机侧实际 PE32/64 宽度校验，取消检查点及独立导出保留模块身份。产品类型检查、构建及 **498/498 回归测试通过，0 跳过**；[原始测试 JSON](../artifacts/vmde-module-memory-vitest.json) 保留。

通过公共 CLI 的新作业 `job_e69e896b39cd4341941ab2464afced8d` / 结果 `binary_trace_9195e2c5b6cc463784830e8eda508c69` 实际完成 60 秒无断点、无 API hook 的运行。[原始采集收据](../artifacts/research/vmde/module-slots/run-ezesyU/receipt.json) 保存 16 份成功快照、源码身份和四项真实清理确认。五个 KERNEL32 相对 DWORD 的实读值如下；这些值仅代表对应采样时点，采样并非原子的。

| KERNEL32 RVA | initial DWORD | final DWORD |
| --- | --- | --- |
| `0x817fc` | `0x76166210` | `0x76166210` |
| `0x817bc` | `0x76166100` | `0x76166100` |
| `0x80f74` | `0x761624e0` | `0x761624e0` |
| `0x82358` | `0x76f8f650` | `0x76f8f650` |
| `0xb07b4` | `0x00000000` | `0x0159c710` |

本次 KERNEL32 两个采样阶段的基址均为 `0x75e20000`；不能将此地址当作下一次运行的不变量。guard DWORD 的实际变化说明末态分支条件不能直接套用到启动时或另一个采样时点。另实读其 `RVA 0x64300` 起的 512 字节代码窗口、完整主模块 14,561,280 字节以及两个私有执行页共 8,192 字节，均保留实际覆盖记录。主图 SHA256 为 `bf12e55a738142829469454ad12f281daf5a55b42766f72973aeddc82faeb333`。本次 CRT caller 的私有目标变为 `0x062d0431`；没有混用上一轮的 `0x062d0356`。

[独立工件审计](../artifacts/research/vmde/module-slots/audit/run-ezesyU/README.md) 的 26 项检查通过；[冻结分析](../artifacts/research/vmde/module-slots/analysis/README.md) 登记 64 份输出及 45 项输入，独立文件复核通过。新私有目标有 328 个保守解码起点，依据明确 call/pop 关系收窄后为 324 个；这是静态可能路径，尚非实测执行轨迹。五个已采样 RVA 仍为本次代码的实际操作数；四个指针值与对应磁盘 EAT 的精确 RVA 相符，API 名称仍以加载实现身份未知为限制。三个 DLL 出口均落入本轮 512 字节窗口；对磁盘窗口应用 16 个 HIGHLOW 重定位后，两阶段均完全匹配。这只验证这段窗口，不能认证整 DLL。新发现的 `0x81f18/0x81f20/0x8206c/0x82198` 四个间接槽仍未采集，`0x644fe` 起的指令缺末字节；guard 指向的数据、寄存器/FS/堆/被调效果也仍未知。

主图与窗口经精确 100ns 创建 FILETIME 关联，追加为新不可变结果 `binary_trace_evidence_5c2f0bb5c52c4eedbf2eee652737612f`，父作业和结果未覆盖。[本轮产品导出](../exports/vmde-module-memory-20261020/report.md) 保存模块快照、主图及窗口的文件闭包；文件一致性验证不会执行 PE，也没有证明整个启动或业务等价。

另外把先前三轮已接受的 14 个业务 listing 与本次完整主图逐条比较，共 1,906 个旧指令窗口：9 个范围字节全部相同，5 个范围合计出现 22 个变化窗口，均位于旧 `FF 15` 导入调用位置，本次为 `E8 + NOP` 或 `NOP + E8`。此前越界的 `0x42ce10` 仍被拒绝，未重新纳入。`0x498a50` 的 637 字节仍精确匹配已进行 896 例 CPU 回放的机器码。独立复核重算了上述数量；[完整差异及输入身份](../artifacts/research/vmde/module-slots/fresh-business-code.json) 保留。该比对支持代码字节在本次内存中存在，没有证明这些函数已执行，也没有把变化位置的旧 API 注释直接升级成当前调用语义。

[下一轮计划](superpowers/plans/2026-10-20-module-tail.md) 已准备为独立文件并通过公共请求验证：8 个范围、每阶段 1,147 字节，补四个 DWORD 和窗口末字节，同时保留当前 caller 与 guard。该计划尚未提交执行；成功采样也不能替代调用现场、栈/ABI、FS/堆数据或正常图像矢量输出验证。

本轮 [完整证据包](../exports/vmde-module-memory-20261020/FOLLOWUP.md) 保持原产品 50 文件及其 manifest 不变，补充采集、私有页、26 项审计、冻结分析及业务字节差异，共登记 148 个文件。打包首版在首次写入前拒绝了系统 DLL 的正常双硬链接；原脚本及失败记录均保留。修订仅对三个固定路径及 SHA 的只读系统输入允许稳定硬链接，项目/工具/导出仍要求单链接；作者 14 项及独立 15 项文件边界检查通过。源目录和新的独立复制目录均复核通过 50/148 文件身份；[最终验证收据](../artifacts/native/module-memory-verification-20261020.json) 记录真实执行命令和源码身份。整个复制验证未执行 PE，`runnable_verified=false`。本阶段能力已完成，整程序还原目标保持进行中。

## 可复用采集与补齐指令尾部

本轮将自有 CLI 任务、主图、私有区域和窗口观察串成通用 `tools/native-trace/acquire.mjs`，从同一新作业的有效检查点取得 PID，绑定精确创建 FILETIME、工作副本和冻结源码。普通观察器错误保留失败并等待自然结束；身份矛盾请求本次 CLI 自身取消，宽限后才终止自有进程树。源码类型检查、构建与 **707/707 产品回归通过，0 跳过**，[原始回归 JSON](../artifacts/vmde-owned-acquisition-vitest.json) 保留。复审修复了写入失败仍被计为观测、私有分配清单可被清空以及损坏 CLI 输出仍被标为成功等问题。

新作业 `job_7b490148d31343b1aa47f56f90452ecc` / 原结果 `binary_trace_77bc99ada0444078bf28e186740384e8` 自然完成。本次 [原始收据](../artifacts/research/vmde/module-tail/run-owned-20261020-a/receipt.json) SHA256 为 `40d5bf033938dbb5fae7cf3472bb5bcf730957379122efceb6b3a48865c50689`，PID 12664 / 创建 FILETIME `134369128310367119`。主图 14,561,280 字节和两个私有页 8,192 字节均读全，16 份初末快照成功、43 个窗口元数据关联、四项清理确认全真且错误列表为空。主图 SHA256 为 `08bfd8cde01e3e5ef60b15b60215352f0317d1f4f29eabf640d003e6b0404ea1`，源与采集源码均未改变。

| 本次 KERNEL32 RVA | 初值 / 末值 | 条件性磁盘 EAT 关联 |
| --- | --- | --- |
| `0x81f18` | `0x76f8ebb0` / 相同 | 三个同址别名：RtlFreeAnsiString、RtlFreeUTF8String、RtlFreeUnicodeString |
| `0x81f20` | `0x76fb5ad0` / 相同 | RtlUnicodeStringToAnsiString |
| `0x8206c` | `0x76f8ebe0` / 相同 | RtlFreeHeap |
| `0x82198` | `0x77004540` / 相同 | RtlRaiseStatus |

上表关联来自本次模块清单及固定磁盘导出表，不能据此认定实际调用或整 DLL 身份。`0xb07b4` 初末由 0 变为 `0x016d94b8`，所指数据仍未知。此前四个旧槽位本次未重采，其当前指针值保持 `null`，没有混用前一进程数据。

本次 `0xb10c8` 的实际目标重新派生为 `0x062d00a2`，未沿用旧入口。新私有候选有 369 个保守指令起点，按明确 call/pop 关系收窄后为 346；这仍是静态可能路径。KERNEL32 的 513 字节窗口初末均为 SHA256 `ba1f63533543deba1aca5ab47af6de848915414d081f57d06e918a14fe9f32f1`，此前截断的 `0x644fe` 实际三字节为 `C2 04 00`（`ret 4` 编码）。16 处 HIGHLOW 重定位后该窗口与磁盘字节全部吻合；尚未观测此返回指令被执行或证明调用栈、返回地址与 ABI。

[冻结分析](../artifacts/research/vmde/module-tail/analysis/README-release.md) 登记 66 份输出、76 项必需输入；[独立审计](../artifacts/research/vmde/module-tail/audit/SUMMARY.md) 两次各 10 项通过，9 份审计文件与 94 项实测输入身份保存。运行时工具身份单列为外部元数据。已有网格核的 637 字节仍精确匹配，但本轮没有新增原生函数调用或图像矢量化验证。

新 [标准报告包](../exports/vmde-owned-acquisition-final-20261020/report.md) 使用通用清单附件登记私有页、原始收据、冻结工具、分析和审计，保存 160 个产品清单文件；managed wrapper 仅对工具生成的明确 ArtifactRef 建立闭包，外部原始 JSON 保持不透明。最终结果为 `binary_file_evidence_e5e50c3feb3046d788aae7bd4e99efe8`，父作业与旧结果保持不变。产品 manifest SHA256 为 `3a075eb94cf9452cd4551a52a6dbb334d28238213269705fb429445f22c4fffb`。

[独立产品副本](../exports/vmde-owned-acquisition-final-copy-20261020/report.md) 复核 160/160；另一个 [结构化证据副本](../exports/vmde-owned-files-final-copy-20261020/analysis/README-release.md) 恢复 181 项登记文件，并通过显式输入映射复核全部 66 份分析输出与 76 项必需输入。[复制验证收据](../artifacts/native/owned-acquisition-final-copy-verification-20261020.json) 保存三个实际进程的命令、输出与退出码。首轮分析复验触发 30 秒预算；原校验器自然运行 42.345 秒后仍通过。新缓存工具复用同一固定 SHA 的证明代码，每个唯一文件先稳定读取、结束后逐一重验，最终复本约 7.7 秒完成；没有延长这项调用的 30 秒预算。原超时、未发布候选、旧导出与首轮副本均保留。新增附件、缓存及失败进程记录分别经 26、18、8 项定向测试及独立复审。文件一致性与合成契约验证不建立原程序可运行性或整程序等价。

本阶段停止继续追逐静态 API 链。下一项实验是 [受限网格核原生回放](superpowers/plans/2026-10-20-native-kernel.md)，先验证显式合成对象/ABI 的局部调用，再与已冻结候选比较；自然应用调用状态、启动/OEP、完整业务输入输出和独立可运行重建仍未完成。

可复用的产品能力已增加 [原生运行采集](NATIVE-TRACE.md)：有界计划、隔离工作副本、显式 API 状态、内存读取失败、源码身份、原子检查点、取消后证据恢复、模块相对读取及独立导出。Handwired 仍用于给定计算结构上的参数学习；此次运行观测和脱壳不由 Handwired 承担。

## 网格核原生调用验证

本次以公共 `binary trace` 作业分别创建自有源码正控、vmde 边界样本及 vmde 完整样本三个工作副本。正控程序由本机 MSVC 编译为 x86，两个独立构建目录产物 SHA 相同；显式 thiscall probe 验证 ECX 对象、栈上传入的 tag 与返回值。随后使用固定 73 字节自有包装器设置 CLD，记录每次原函数调用前后的 ESP、EBX/ESI/EDI/EBP 和 EFLAGS，原目标指令未修改。

| 作业 | 实际调用 | 与冻结候选匹配 | 失败 / 未执行 |
| --- | ---: | ---: | ---: |
| 自有编译正控 | 8 | 8 | 0 / 0 |
| vmde 边界样本 | 8 | 8 | 0 / 0 |
| vmde 完整输入集 | 896 | 896 | 0 / 0 |

原程序共 **904/904** 次局部调用匹配；全零候选在全部样本上被拒绝。两次 vmde 主图基址均为 `0x400000`，每次调用前后的 RVA `0x98a50` / 637 字节 SHA 均为 `65d46a13deb731ea75b91fd29baf96dc614da6ad8bfcf48805aba748a139f70c`。固定对象字段、尺寸 2..16、步长和有符号 int32 标签均经过主机及 agent 校验。四个独立三页分配带不可访问的保护页、A5 前缀和只读输入；主机重建全部输入/输出页面哈希。真实寄存器、原始输出字节、返回状态和输入不可变性逐次保存，四项进程/会话/Job 清理确认均为真且无错误，原文件与冻结工具未变。

完整 896 样本的公共 CLI 实际耗时约 40.6 秒，包含启动、正文就绪等待、调用、证据保存及清理；逐次调用和捕捉合计约 16.5 秒，并非纯函数执行基准。追加日志有 1,792 条开始/返回记录，完整收据 2,916,470 字节，SHA `53d5fd5a4394e1b4dd95b2a90ba51492a81cacef0f56362529008ecba6d52cc3`。[原始阶段摘要](../artifacts/research/vmde/native-kernel/native-summary.json) 保存三个真实作业、PID、时间和文件身份。独立审查使用边界坐标编号及四标签集合大小重新计算输出，未载入候选实现，仍得到 vmde 904/904 匹配。

新增 `tools/native-kernel/` 将固定目标原生调用、正控门禁、逐次日志和离线比较沉淀为独立工具。超时由宿主关闭自有 Job；取消 RPC 等待不被当成目标终止。原生异常后保存可读的部分输出，未写入的寄存器槽保持未知，后续样本停止。产品类型检查、构建及 **720/720 回归通过，0 跳过**；独立 Python 43 项与 JavaScript 25 项检查通过。审查暴露并修复了正控仅凭状态通过、异常丢证据、Windows stat/fstat 时间字段混用、清理遗漏和截止瞬间误报成功等根因。

结果类型为 `native_inprocess_kernel`，契约是人工构造的独立对象和缓冲区。它验证了这个网格编号函数的实际原生行为。自然调用者、真实对象生命周期、启动/OEP、正常图像到矢量输出以及独立可运行重建仍是后续工作；全部样本一致不等于整程序等价。交付脚本从标准报告的 artifact blob 恢复具名证据，并以离线工具重新检查收据、日志、字节身份和输出；复制复验结果单独写入 `artifacts/research/vmde/native-kernel/copy-verification.json`，不在复制检查中再次执行 PE。
本阶段的 [标准报告](../exports/vmde-native-kernel-20261020/report.md) 与 [独立产品副本](../exports/vmde-native-kernel-copy-20261020/report.md) 均复核 **134 个清单文件**；从产品 artifact blob 恢复的 [具名证据副本](../exports/vmde-native-kernel-files-copy-20261020/release.json) 包含 **118 项登记文件**。复制版 Python 工具约 1.5 秒完成 912 条记录（904 原内核、8 正控）的离线复验，未打开原始绝对路径或再次执行 PE。[实际复制收据](../artifacts/research/vmde/native-kernel/copy-verification.json) 保存三个进程的真实命令、输出与退出码；release SHA 为 `b849bc614033d5ff769e7bd50163a329015f894e882c27720e9ff8e11fd2d54e`，产品 manifest SHA 为 `cdfc1b9f9cac7dd6d39d7e80b75612b38404bf2403a1719c417d174fbcf91302`。整程序目标保持进行中。

## 调用者与返回值契约补齐

继续沿已确认的静态链 `436bc0 → 46e0e0 → 499eb0 → 498a50` 分析，确认网格核的 EAX 是已编号逻辑节点数，后续 caller 保存并传给 `484e60`。此前 v1 采集元数据写作 `semantic_return:void`，这是原函数语义描述不完整；包装器自身返回 void 仍可行，因为它另行保存了原始 EAX。历史收据和导出未改写。[返回值审查](../artifacts/research/vmde/caller-layout/kernel-return-review.json) 对 904 条既存原始寄存器记录重新核对，全部匹配 `2*(W+H)+四邻标签不全相等的内部点数`，没有补造数据或再次执行目标。

通过项目既有 Ghidra 有界工具新增分析 `481950`：46 条指令、118 字节，反编译 PC 全部落在实际 listing 内，两个出口都是 `RET 8`。描述符的 `+0/+4/+8` 是数据指针和两维；尺寸相同完全不操作，即使指针为空。尺寸变化时调用两个外部依赖，其具体实现仍未知，不能直接命名 new/delete。原 x86 算术存在低 32 位乘积及字节数溢出边界；恢复组件只接受已经验证的小尺寸域，不复制这些不安全边界。caller 正常有效路径构造节点行宽 `W+1`；此前合成实验允许 padding，是更宽的人工契约，不能当成已观测的自然对象。

邻近 `484e60`（13 条指令、29 字节）正常返回路径把计数交给 `482c30`，再保存到该对象 `+0x30`；`46a860`（41 条指令、149 字节）涉及字符串及未知依赖，没有形成图像到标签 descriptor 的已验证写入链。自然对象初始化、真实图像输入及矢量输出、启动/OEP 和独立可运行重建仍未完成。恢复组件与实际回归结果另见 [调用者阶段记录](../artifacts/research/vmde/caller-layout/README.md)。

## 节点记录与像素导出边界

本轮恢复了独立的 [40 字节记录写入模型](../tools/node-record/README.md)，实际执行原始 104 字节的 CPU 仿真 **31/31 匹配**，相邻记录、未知字段、栈和 x87 状态均留有观测；两项错误模型对照各 31/31 被拒绝。纯模型及回放器边界测试 34/34，通过两个启动问题修复后才执行真实回放。该结果没有新增原生调用，也没有验证完整轮廓状态。

新增 [通用有界 Ghidra 工具](../tools/ghidra/README.md) 已通过 26 项测试和真实 Windows headless 分析。大函数 0x4f02c0 的反编译失败被保留为 partial。实际 BGRA 参数和 ExportImagePixels 字符串把一条先前候选收窄为像素导出链，尚非标签生成器；0x488d20 的分割分派已取得新 listing，但自然对象及输出标签关联仍未知。[本轮记录](../artifacts/research/vmde/node-records/README.md) 链接原始收据与修正说明。整程序目标保持进行中。
