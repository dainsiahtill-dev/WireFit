# 公开 VMProtect 样本的 REA 静态实测

本次真实 REA/Ghidra 采集完成 **4/4**：一个未保护 `adder` 对照和三个受保护样本。未保护对照可导入一个局部加法表达式；三个保护版均未建立目标语义恢复证据。实验只探查固定入口及其跳板，不是完整 VM 追踪或脱壳实验。这个 **0/3** 只能描述本轮限定流程的结果，不能推出 VMProtect 普遍不可恢复，也不能据此证明 Handwired 对它有效。

证据来自已保存的 [summary.json](../artifacts/research/vmp-rea-trial/run-1eq4GW/summary.json)、各条 acquisition、portable bundle 和伪代码；报告编写期间没有重跑分析或执行目标程序。没有操作用户随后指定的 `vmde.exe`。

## 实验范围与来源

- 输入来自同一作者研究仓库，固定提交 `2fb7ad84a90a73c950c39eccbad81cc2f6c25c33`，均为 Windows x64 PE。下载 URL、文件大小、SHA-256、许可与保护版本声明的边界见 [样本目录](VMP-WINDOWS-SAMPLES.md) 和 [下载清单](../artifacts/research/vmp-windows-catalog/download-manifest.json)。作者文章中的 v3.5.0.1274 声明不能直接当作这三个文件的独立版本识别。
- 唯一运行目录：`artifacts/research/vmp-rea-trial/run-1eq4GW/`，UTC 时间为 2026-10-19 15:46:32 至 15:48:44。bundle 记录 provider 为 **Ghidra 12.1.4**、`ghidra-default` 分析配置、`x86_64` 架构和 `ephemeral-source-immutable` 导入模式。
- [研究脚本](../artifacts/research/vmp-rea-trial/run.mjs) 对四个输入逐一调用真实 `acquireEvidence`，全部指定 `provider:'ghidra'`、`functionAddress:'0x140001000'`，然后从保留的数据流中选择最后一个有标量输出的操作，尝试交给 Wirefit 的 `liftPcode`。
- 这是 **source-known / non-blind** 研究：原作者 C 源码、未保护二进制和目标函数位置事先可见，没有隐藏真值或盲测。仅未保护 `adder` 做了 REA 对照；另外两个未保护文件虽已下载，本轮没有采集，因此不是三对完整比较。
- 本轮没有调用 Handwired、外部去虚拟化器或 unpack 后端；没有目标回放和等价性证明。四条记录的 `target_oracle_calls` 均为 **0**。

## 四条实际结果

操作数指 REA 反编译后保留下来的 high p-code 操作数，不是原始机器指令数或完整虚拟指令数。

| 输入 | p-code 操作数 | 局部导入结果 | 实际边界 |
| --- | ---: | --- | --- |
| `unprotected/adder.exe` | 3 | `LOCAL_EXPRESSION` | 选择 `0x140001014#36`，生成两个 32 位输入的 `bv_add` 与 copy；`execution_guard=unknown`，`targetReplayEligible=false`，没有独立 ABI 返回绑定证明 |
| `adder.vmp.exe` | 7 | `UNSUPPORTED` | `UNSUPPORTED_PCODE_EFFECT`：`CALL at 0x14000508f#6` 未建模；另观察到内存读写 |
| `bitwise.vmp.exe` | 38 | `UNSUPPORTED` | `UNSUPPORTED_PCODE_EFFECT`：`CALL at 0x1401040d6#6` 未建模；另观察到多项内存读写 |
| `multiadder.vmp.exe` | 2 | `NOT_RUN` | 保留的数据流没有标量操作输出，脚本没有调用 lift；记录仍包含 direct call，不应写成一次 lift 拒绝 |

未保护对照的 [伪代码](../artifacts/research/vmp-rea-trial/run-1eq4GW/unprotected_adder_exe.pseudocode.c) 为 `return param_1 + param_2;`；[局部模型](../artifacts/research/vmp-rea-trial/run-1eq4GW/unprotected_adder_exe.local-model.json) 表明支持的直线算术可以从实际 REA 证据进入位向量表达式。模型范围是 `expression/local_value`，并非已验证的整个函数契约。即使它与已知源码吻合，也没有自动消除执行条件、ABI 绑定和原目标保真度方面的缺项。

四条 acquisition 都是 `status=completed`、`persisted=true`、`cleanup.closed=true`；portable bundle 已保存。REA 成功返回和资源关闭证明采集链路完成，不能当成目标恢复成功。四条 summary 的 `semantic_recovery` 都明确是 `NOT_ESTABLISHED`。

三个保护版入口在 bundle 中均被 Ghidra 识别为 **5 字节 thunk**：`0x140001000` 跳向 `0x14000508a`、`0x1401040d1`、`0x1400050f8`。本轮返回的三份伪代码都有 `Control flow encountered bad instruction data` 和 `Bad instruction - Truncating control flow here` 警告，结尾为 `halt_baddata()`。这些局部反编译结果没有展开成完整 VM 解释器，也没有追踪 dispatcher、handler、字节码状态或 VM 退出后的真实返回值。伪代码中的内存操作不能直接解释成原始业务逻辑。

全部保留 flow 的 `truncated=false`，已知遗漏边/输入数和操作遗漏下界为零。这个字段只说明返回的数据流没有报告达到相应保留上限，**不代表反编译器已识别完整运行路径**；它与上述 bad-instruction 警告并不矛盾。

## 无 Oracle 的限制

作者源码的 `main` 固定调用 `20,40` 或 `20,40,60`，丢弃目标函数返回值，随后返回零。程序没有提供可变参数、stdin/stdout 的目标函数 Oracle 界面。本轮也没有构造进程内调用或仿真回放。因此不存在训练输入观测、冻结模型后的独立 holdout 观测，或 protected/unprotected 目标输出对照。

源码已经给出了 `x+y`、最终恒等于 `y` 的逐位表达式，以及三参数加法；照抄或化简这些源码不属于从受保护程序恢复未知语义。主程序退出码零同样不能验证这些函数的恢复。本轮既没有未知语义恢复证明，也没有脱壳产物或产物可运行性证明。

## REA、Handwired 与 Wirefit 各自的实际贡献

| 环节 | 现有实际证据 | 可支持的结论与边界 |
| --- | --- | --- |
| REA / Ghidra | 本轮四个真实 PE 的地址、函数/thunk 分类、伪代码、p-code、调用及内存效果，通过 portable bundle 保留 | 提供机器程序的静态结构证据；本轮保护版分析局限于入口/跳板，没有恢复完整 VM 或其函数语义 |
| Handwired 核心 | 独立 [核心消融](HANDWIRED-ABLATION.md) 直接使用真实 `Circuit`：在给定仿射结构下训练参数，并执行实验者构建的 XOR bitplane、比较及索引图 | 已证明给定图的执行/反传及该仿射任务的参数学习；没有自动发现二进制结构。本轮 VMP 流程未调用它，不能分配给它任何 VMP 恢复成绩 |
| Wirefit 证据与模型层 | 本轮完成采集管理、持久化、来源绑定、状态报告和局部 p-code 导入；未建模 CALL 被明确拒绝，无标量输出时没有发起 lift | 把证据与支持的局部模型连接起来，并保留失败及未知范围。本轮没有执行目标一致性验证、holdout 或数学等价证明，不能把验证接口的存在写成验证已经通过 |
| 独立 unpack 后端 | [接口文档](cli.md#binary-inspection-and-explicit-unpacking) 将显式配置的外部 unpack 程序与 Wirefit 工作流分开；当前文档中的 Unlicense 面向 Themida/WinLicense | 后端承担具体解包机制，Wirefit 管理输入副本、调用、产物检查与报告。**unpack 后端不是 Handwired**；本轮没有运行后端，更没有由此获得 VMProtect 脱壳成功证据 |

[历史 Handwired 比较](benchmarks/handwired.md) 保留了另一项源代码自有 FP32 fixture 实验：reference 与 Handwired 都为 **8/9**，失败的是同一分段任务；同九项任务中 Handwired 的中位拟合耗时更长。历史每组十个标为 holdout 的输入里有三个训练边界复查点，只有七个未见点。独立核心消融采用新的不重合划分，但没有覆盖或修正历史结果。

这些训练实验与本轮 PE 静态采集的任务、输出、预算和证据类型不同，不能拿它们的耗时或通过数直接排名 REA 与 Handwired。已有证据能区分“从机器程序取得结构”和“对给定结构执行或训练”；没有提供某一方能替另一方自动完成未知 VMProtect 恢复的证据。

## 原始记录索引

- [总表](../artifacts/research/vmp-rea-trial/run-1eq4GW/summary.json) 与 [运行脚本](../artifacts/research/vmp-rea-trial/run.mjs)。
- 未保护 adder：[acquisition](../artifacts/research/vmp-rea-trial/run-1eq4GW/unprotected_adder_exe.acquisition.json)、[bundle](../artifacts/research/vmp-rea-trial/run-1eq4GW/unprotected_adder_exe.bundle.json)、[伪代码](../artifacts/research/vmp-rea-trial/run-1eq4GW/unprotected_adder_exe.pseudocode.c)、[局部模型](../artifacts/research/vmp-rea-trial/run-1eq4GW/unprotected_adder_exe.local-model.json)。
- 保护 adder：[acquisition](../artifacts/research/vmp-rea-trial/run-1eq4GW/adder_vmp_exe.acquisition.json)、[bundle](../artifacts/research/vmp-rea-trial/run-1eq4GW/adder_vmp_exe.bundle.json)、[伪代码](../artifacts/research/vmp-rea-trial/run-1eq4GW/adder_vmp_exe.pseudocode.c)。
- 保护 bitwise：[acquisition](../artifacts/research/vmp-rea-trial/run-1eq4GW/bitwise_vmp_exe.acquisition.json)、[bundle](../artifacts/research/vmp-rea-trial/run-1eq4GW/bitwise_vmp_exe.bundle.json)、[伪代码](../artifacts/research/vmp-rea-trial/run-1eq4GW/bitwise_vmp_exe.pseudocode.c)。
- 保护 multiadder：[acquisition](../artifacts/research/vmp-rea-trial/run-1eq4GW/multiadder_vmp_exe.acquisition.json)、[bundle](../artifacts/research/vmp-rea-trial/run-1eq4GW/multiadder_vmp_exe.bundle.json)、[伪代码](../artifacts/research/vmp-rea-trial/run-1eq4GW/multiadder_vmp_exe.pseudocode.c)。
