# Wirefit 持续改进：2026-10-20

本轮将上次实战中的三项缺口纳入产品流程：通用二进制报告导出、准确的 doctor 状态，以及入口/TLS 自动诊断。没有重跑 Unlicense、重新训练参数或改动历史验收收据。

## 已交付

| 改进 | 当前行为 |
| --- | --- |
| 二进制报告导出 | 现有 `report export` / `wirefit_export_report` 自动分派到独立导出器，保留原结果、失败/取消状态、源输入、产物、DLL、日志与递归证据；复制后可用 Node 独立校验 |
| doctor 状态 | 分开显示当前工具文件、已核对字节的历史局部原生证据和旧完整验收门禁；本机为 `RECORDED_LOCAL_ANALYSIS`，没有声称本次重新运行 Ghidra |
| 入口诊断 | 对已观察到的 x86 SEH helper 字节模式给出启发式提示；不猜测或修改真实 OEP |
| TLS 检查 | 支持 PE32/PE32+、精确 VA、模板、索引和有界回调数组；合法空模板、loader 写入的 .bss 索引可接受，文件数据不足明确标记不完整 |

用法见 [二进制报告导出](BINARY-REPORT-EXPORT.md)、[CLI/MCP](cli.md#binary-inspection-and-explicit-unpacking)、[PE 检查](PE-INSPECTION.md) 和 [doctor 状态说明](NATIVE-SETUP.md#doctor-的当前检查与历史证据)。

## 实际复验

- **304/304 测试通过，0 失败、0 跳过**；类型检查与构建通过。[测试原始结果](../artifacts/practical-followup-vitest.json)、[本轮验证收据](../artifacts/practical-followup/verification.json)。
- 新增测试合计 96 项：二进制报告 16、原生状态 15、PE 诊断 65；已有数学报告和其他产品测试仍通过。
- 独立复审发现三项重要问题：JSONL 容器丢失嵌套证据、空 TLS 模板误读一个字节、TLS 索引错误要求文件字节；均先复现再修复，复审无遗留阻塞。
- 真实 `report export` 对历史 vmde 解包结果生成 [产品报告](../exports/vmde-product-20261020/report.md)，含 36 个 manifest 文件、源快照、一个转储及七个 DLL。复制后的目录独立校验 36/36，原任务状态不变。[复制验证](../artifacts/practical-followup/copied-bundle-verification.json)。
- 本机 doctor 重新核对 8 个保留文件，当前工具文件均在，历史局部分析证据匹配；完整门禁仍作为历史记录标记。[实际输出](../artifacts/native/doctor-20261020.json)。
- 对原始 vmde 与既有转储运行实际 CLI 静态检查；原文件哈希仍为 `9a0fa724e4a2f189da4cafdd700842d5b6c7aa6c571269500e5eb56cc3fa9a5d`。[静态复验](../artifacts/practical-followup/real-inspection.json)。

## 实战边界

转储 `0x4B12BC` 入口现在自动标为 `x86_seh_prolog_helper_like`，依据为 `heuristic`。原文件与转储的非空 TLS 原始模板 `0xA95000..0xA951BC` 都不能完整映射到文件，故 `tls_complete=false`。这说明文件层静态信息不足，不是对运行时保护初始化的完整判断。相关字段含义依照 [Microsoft PE/TLS 格式](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-directory)。

上轮启动测试仍是 `0xC0000005`，没有新可运行性或行为等价证据。当前转储仍为 `analysis_dump`，`runnable_verified=false`；本轮没有覆盖这个失败，也没有把文件身份校验当作脱壳成功。

后续技术缺口是实际启动路径/初始化恢复与受控局部分析配置；默认 REA 全局分析的 240 秒超时仍未解决。Handwired 仍是给定结构的行为模型学习组件，未新增自动 VM 语义恢复声明。[原始实战](VMDE-PRACTICE.md)、[Handwired 独立实验](HANDWIRED-ABLATION.md) 和 [公开 VMP 实测](VMP-REA-TRIAL.md) 继续保留各自范围。
