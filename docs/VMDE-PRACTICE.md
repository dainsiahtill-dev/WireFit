# vmde.exe 实战与 Wirefit 实用性改进

此页保留早期解包及失败分析；后续运行采集、完整内存和当前验证结果见 [持续还原进度](VMDE-RESTORATION.md)。

本轮已交付可用的 PE 检查、壳识别和显式外部解包工作流，并对用户指定文件完成一次真实的解包转储。**产物可以用于继续分析，直接启动失败，尚未恢复成可独立运行的程序。** 原文件始终未覆盖。

## 直接查看

- 分析产物：[unpacked_vmde.exe](../exports/vmde-20261020/unpacked_vmde.exe)，相邻 DLL、原始运行记录和诊断材料也位于同目录。
- [产物质量](../exports/vmde-20261020/quality.json)；[启动实测](../artifacts/research/vmde/dump-startup.json)；[Windows 崩溃事件](../artifacts/research/vmde/dump-crash-event.json)。
- [原始 PE 反汇编](../artifacts/research/vmde/entry-disassembly.json)；[实际 Ghidra 局部反编译](../artifacts/research/vmde/entry-noanalysis.c)；[完整证据总表](../artifacts/research/vmde/result.json)。
- 产物目录的 `verify.mjs` 只校验文件身份，不执行 EXE，也不证明其可运行。

## 原目标与真实结果

| 项目 | 实测 |
| --- | --- |
| 原文件 | `E:\Vector Magic 2021\vmde.exe`，6,516,736 bytes，PE32 / x86 |
| 原文件 SHA256 | `9a0fa724e4a2f189da4cafdd700842d5b6c7aa6c571269500e5eb56cc3fa9a5d` |
| 壳检测 | Detect It Easy 3.21：Themida/Winlicense 2.0.1.0–2.1.8.0；本文件不是本轮 VMP 研究样本 |
| 实际后端 | 独立 Unlicense 0.4.0 x86，针对工作副本执行 |
| 后端结果 | 退出码 0，耗时 422.9 秒，317 个潜在导入包装器，报告恢复 1,603 个导入符号 |
| 转储文件 | 14,454,272 bytes，SHA256 `50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992` |
| PE 检查 | 普通导入表解析完整，257 个描述符、1,603 个符号，未报告当前解析器覆盖的结构异常 |
| 入口 | 后端选择 VA `0x4B12BC`，RVA `0xB12BC`；仍未建立其作为真实程序启动入口的有效性 |
| 受控启动 | 约 3 秒内退出，`0xC0000005`，故障 VA `0x4B12D6` |
| 最终质量 | `analysis_dump`，`runnable_verified=false`，行为等价性未建立 |

257 是导入描述符数，不是 257 个不同 DLL。导入表结构完整也不证明所有运行时调用、TLS、重定位或保护状态已正确恢复。转储仍包含保护相关区域，没有完成 VM 去虚拟化或原始源码恢复。

成功作业为 `job_6be5437c256a46bf9bf060424a18e4e6`，结果为 `binary_unpack_ac3f5da5bdec428088899e267f17d078`，案例为 `cases/vmde-unpack-20261019`。输入、依赖、工具身份、实际参数、标准输出/错误及产物都保留在案例中。

## 启动失败的定位

反汇编显示入口包含 `mov eax,[esp+0x10]`、`sub esp,eax`，接着在 `push ebx` 处崩溃，并读写 `fs:[0]` 的异常链。这段代码具有 MSVC SEH prolog 辅助函数的特征；它需要调用者准备参数及栈。程序中也找到七处指向它的直接 call。将这种辅助函数当作 loader 入口会使用不匹配的启动栈，这与故障位置一致。真正的 CRT/业务启动路径仍需独立确定，不能把此地址的出现写成 OEP 已正确恢复。

真实 REA/Ghidra 的默认全局分析在 240 秒预算内没有完成；该失败与已恢复的空证据包保留在 [采集摘要](../artifacts/research/vmde/dump-validation/summary.json)。没有为它补写成功伪代码。

随后直接调用本机 Ghidra 12.1.4，使用 `-noanalysis` 和 [局部入口探针](../artifacts/research/vmde/WirefitEntryProbe.java) 完成指定地址的反汇编、建函数和反编译；[日志](../artifacts/research/vmde/entry-headless.log) 包含 `WIREFIT_ENTRY_PROBE_COMPLETED`。它得到带栈跟踪警告的实际伪代码，支持继续定位辅助函数。**这次直接 Ghidra 局部探针不算 REA 默认全局分析通过，也不构成完整函数恢复或可运行性验证。**

下一项具体技术缺口是恢复真实启动路径与其所需的初始化/保护状态，再复核未恢复的间接调用和导入。当前没有用猜测入口、跳过初始化或改许可逻辑来提升产物质量结论。

## 已完成的产品改进

| 能力 | 实现与验证 |
| --- | --- |
| 静态 PE 检查 | 独立、有界的 PE32/PE32+ 字节解析器；精确地址、节信息、抽样熵、入口、普通导入和显式诊断 |
| 壳识别与解包 | 显式配置 DIE / Unlicense；检测类型与后端不匹配时拒绝；对输入及相邻 DLL 建立快照 |
| 可审计执行 | 记录工具哈希、参数、日志、时间、退出状态和产物；超时、取消及失败保留结果 |
| 产物归属与质量 | 排除检测器生成的文件、输入依赖和硬链接冒充输出；后端成功但无新 PE 仍为失败 |
| CLI / MCP | `binary inspect`、`binary unpack`；增加两个异步 MCP 工具，总数 15，支持现有查询与取消 |
| 真实兼容性修复 | 由本机实测发现精简环境遗漏 CPU 架构变量，修复后 32 位后端通过实际执行；保留失败前史 |

命令和工具来源见 [本机二进制工具](BINARY-TOOLS.md)、[CLI/MCP](cli.md#binary-inspection-and-explicit-unpacking) 与 [PE 边界](PE-INSPECTION.md)。通用数学实验的 `report export` 与本次研究转储目录分别处理；本次转储由保留的 `artifacts/research/vmde/export-dump.mjs` 从已校验的案例 artifact 导出。

最初四分钟试跑超时；首次产品集成因架构环境变量缺失退出码 3。两次记录均保留，没有覆盖成成功结果。最终成功转储使用修复后的环境和十分钟后端预算。

## 质量检查与组件贡献

本轮完整回归 **208/208 PASS**，类型检查与构建通过；独立复审的三项重要问题已修复，五项定向复审回归通过。详见 [验证收据](../artifacts/practical-binary-verification.json)。这些结果不替代 [历史 63 项规格验收](ACCEPTANCE-RESULTS.md)，也不代表所有平台或所有壳都已通过。

Handwired 独立实测是在**预先给定结构**上进行参数学习：仿射留出 10/10，给定 bitplane 图的 XOR 12/12。它没有承担本次解包，也没有自动发现未知 VM 结构，见 [独立核心实验](HANDWIRED-ABLATION.md)。

另外三个公开 VMP 样本均完成真实 REA/Ghidra 静态采集，但当前入口/跳板分析没有建立其原函数语义恢复；这是同一作者的三个样本，不是三个独立项目，见 [VMP 实测](VMP-REA-TRIAL.md)。现有证据支持 Wirefit 将二进制证据、可学习模型与独立验证连成可追溯流程；尚未证明 Handwired 相比传统逆向工具具有自动脱壳、去虚拟化、恢复率或速度优势。
