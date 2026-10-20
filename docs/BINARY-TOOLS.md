# 本机二进制工具与来源

Wirefit 的 PE 检查器直接处理字节；壳识别及动态解包使用独立安装的外部程序。数学证明和 Handwired 训练不依赖这些程序。配置位于 `.local/binary-tools.x86.json`，版本、下载地址及实际哈希见 [安装清单](../artifacts/native/binary-tools.json)。

| 工具 | 本机用途 | 来源与身份 |
| --- | --- | --- |
| Detect It Easy 3.21 x64 | 读取副本，输出检测 JSON | [官方 release](https://github.com/horsicq/DIE-engine/releases/tag/3.21)，下载 ZIP 与发布的 SHA256 一致 |
| Unlicense 0.4.0 x86 | 本机 PE32 的 Themida/WinLicense 动态解包 | [官方 release](https://github.com/ergrelet/unlicense/releases/tag/0.4.0)，ZIP 只记录本地计算的 SHA256，没有独立的作者校验值；参考源码固定在 `95c8dc6a4324ff70c04bceda8bd166be6c5f0c73` |

本机 Unlicense 是 32 位发行包，用于本次 PE32 目标；不能将它的结果泛化为对 PE32+ 的兼容性验证。Wirefit 检查器支持 PE32/PE32+，后端能力取决于所选工具、架构和保护类型。工具作者说明它面向 Themida/WinLicense 2.x/3.x，并提醒转储通常不直接可运行；详情见 [官方说明](https://github.com/ergrelet/unlicense#readme)。

从项目根目录执行：

```powershell
.\wirefit.cmd case create --dir .\cases\binary-demo
.\wirefit.cmd binary inspect --case .\cases\binary-demo --file 'E:\Vector Magic 2021\vmde.exe' --config .\.local\binary-tools.x86.json
.\wirefit.cmd binary unpack --case .\cases\binary-demo --file 'E:\Vector Magic 2021\vmde.exe' --backend unlicense --config .\.local\binary-tools.x86.json --timeout 600000 --target-timeout 60
```

解包在案例中的副本执行，默认复制相邻 DLL。过程记录输入、依赖、工具身份、参数、标准输出/错误和生成产物。取消及超时保留已取得的记录，等待所启动的进程清理。输出标为 `analysis_dump`，`runnable_verified=false`；后端退出成功也必须存在新的、可检查的 PE 才能记为任务完成。具体 API 和资源上限见 [CLI/MCP](cli.md#binary-inspection-and-explicit-unpacking) 与 [PE 检查器](PE-INSPECTION.md)。

这两个工具没有合并进 Handwired 或数学核心。Detect It Easy 引擎采用 MIT，发行包的依赖保留各自许可；Unlicense 采用 GPL-3.0，未修改参考源码及许可位于 `.upstream/unlicense-0.4.0`。本地安装与项目自有 MIT 代码分开记录。

二进制检查与解包结果现在也可通过现有 report export / wirefit_export_report 导出，无需编写研究脚本。命令及文件校验含义见 [二进制报告导出](BINARY-REPORT-EXPORT.md)。
