# 原生运行采集

`binary trace` 对指定 PE 及相邻 DLL 建立不可变快照，再启动工作副本，保存有限的运行事件和内存片段。对应异步 MCP 工具为 `wirefit_trace_binary`，沿用查询、取消及报告导出接口。

本机配置使用独立 Python 3.14 与 Frida 17.2.17，保存在 `.local/native-trace.json`；没有替换 Unlicense 的 Frida 16 环境。工作器和固定 agent 源码位于 `tools/native-trace/`。迁移机器时须重新指定解释器和已安装的 Frida 包目录。

```powershell
cd E:\wirefit
.\wirefit.cmd binary trace --case .\cases\vmde-runtime-20261020 --file "E:\Vector Magic 2021\vmde.exe" --config .\.local\native-trace.json --plan .\.local\trace-vmde-passive-control.json
.\wirefit.cmd report export --case .\cases\vmde-runtime-20261020 --run <结果ID> --out .\exports\trace-report
```

工具配置是显式的 `{command,args}`；命令不通过 shell 执行。计划示例：

```json
{
  "duration_ms": 15000,
  "breakpoints_rva": [],
  "ranges": [{"rva":"0xb0f40","size_bytes":576}],
  "api_hooks": [],
  "max_events": 256
}
```

RVA 相对于实际主模块基址。最多 4 个硬件执行断点，8 段内存、每段 1 MiB、每个采样阶段合计 4 MiB，16 个 API 入口观测，512 条事件；运行窗口为 1–60,000 毫秒，启动及清理另有预算。断点首次命中后在该线程解除，不改通用寄存器、目标字节或内存保护。未命中不证明地址不可达，保护程序也可能影响断点或被插桩改变行为。

本样本的实际对照支持先用空断点和空 API 列表：带正控断点的两轮在结束采集时超时；保持相同 60 秒窗口、移除断点后完成采集，并观测到真实 Qt 主窗口。尚未以线程栈证明具体扰动机制；不可用失败插桩运行替代原程序行为。

采样阶段为 `initial`、`final` 和计划断点对应的 `breakpoint-<十六进制RVA>`。每个初末范围必须有真实字节或明确读取错误。API 模块尚未加载时等待模块观测；已加载模块缺失导出、导出不是可执行函数、挂钩失败均记录错误。结束仍未加载的 API 显式标为 `unobserved`，不冒充已观测调用。

Windows 工作器先创建 kill-on-close Job，向自己新建的暂停进程分配 Job 后才恢复执行；保留进程句柄用于确认清理。调用方不能传入已有 PID。成功采集要求确认目标终止、session 分离、Job 分配和关闭。进程日志保留解释器哈希，协议保留 Frida 版本及加载位置，worker/agent 的实际源码字节、大小和 SHA256 单独作为 artifact 保存。

工作器在状态变化、每份已关闭的内存文件及每 8 条接受事件后原子更新检查点。取消或超时后，主机尝试验证并导入检查点及已提交的文件，保留原失败状态。最多 7 条批次间事件及正在写入的片段可能未持久化；检查点中的清理状态只是最后已知状态，父工作器关闭不能补写为目标清理已确认。自然退出未能完成最终刷新时，遗漏计数和 API 状态的完整性标志保持 false。

原始观察 JSON 使用专用媒体类型保存；导出器不把事件内碰巧形似 `ArtifactRef` 的外部数据作为案例文件引用。只有主机验证过的外层源码及内存 artifact 引用进入导出闭包。独立 `verify.mjs` 校验文件身份，不执行 PE。

完成采集表示有界观测已结束，不等于真实 OEP、可运行脱壳、完整函数恢复或行为等价。内存片段保存在 `snapshots`，不是可执行 PE 的 `outputs`。vmde 具体证据及未解决问题见 [还原进度](VMDE-RESTORATION.md)。

## 一次命令完成自有目标采集

`tools/native-trace/acquire.mjs` 将公共 `case create` / `binary trace` 和只读观察器串成一个可重复流程。它自动从本次唯一作业的有效检查点取得 PID，核对工作副本路径和精确创建 FILETIME，在指定时间采集主图，并可附加私有调用目标与窗口清单。

先运行 `npm run build`。下例要求输出的父目录已存在，`新目录` 本身必须不存在；解释器和 PowerShell 使用显式绝对路径：

```powershell
& ./.tools/runtime/node_modules/node-win-x64/bin/node.exe ./tools/native-trace/acquire.mjs --file 'E:/Vector Magic 2021/vmde.exe' --config ./.local/native-trace.json --plan ./.local/trace-vmde-module-tail.json --out 'E:/wirefit/artifacts/research/vmde/module-tail/新目录' --python 'C:/Users/dains/AppData/Local/Python/pythoncore-3.14-64/python.exe' --powershell 'C:/Program Files/PowerShell/7/pwsh.exe' --capture-at-ms 24000 --caller-rva 0xb10c8 --caller-rva 0x1b8611 --caller-rva 0x1b8682 --caller-rva 0x1b86e5
```

首版支持 PE32/x86、主图不超过 64 MiB、空断点和空 API 挂钩的被动计划。`--capture-at-ms` 相对实际 `job.started_at`；迟到超过 5 秒或错过运行窗口会明确失败。`--caller-rva` 可重复至 16 个，不填则不请求私有区域；不填 `--powershell` 则不请求窗口元数据。不能传入外部 PID、已有 case 或替换 helper。

新目录保存冻结的计划、配置和采集源码、完整命令 stdout/stderr、主图和各观察器收据、真实终态作业及 `receipt.json`。只有 CLI、所有请求的观察器、字节覆盖、身份、源文件和源码稳定性、真实清理记录均通过，才给出 `observations_collected` / 退出码 0。普通观察器失败保存原始证据并等待本次任务自然结束，最终为 `partial_or_failed` / 退出码 1；身份矛盾停止本次生命周期。Ctrl-C 请求公共 CLI 自身取消，超过宽限期才终止其自有进程树，最终是否完成 Windows Job 和目标清理仍以实际协议为准。用户取消为 `cancelled` / 退出码 130，启动前参数错误为退出码 2。

主图、私有页和模块快照分别采集，不能当作同一时刻的进程状态。`observations_collected` 也不证明某个 CALL 被执行、恢复入口正确、程序已可独立运行或整程序等价。

## 完整主模块数据

项目另提供 `tools/native-trace/memory-image.py`，通过只读 Windows HANDLE 采集主模块，适用于需要在被插桩 JS 控制面之外保留证据的情况。它要求调用方明确提供本次自有目标 PID、工作副本路径、精确创建 FILETIME、实际基址和 SizeOfImage；不启动、暂停、调试附加或终止目标。调用方须在该进程仍存活时执行：

```powershell
& 'C:/Path/To/Python/python.exe' -X utf8 -I -S ./tools/native-trace/memory-image.py --pid <本次目标PID> --expected-exe 'E:/绝对工作副本/vmde.exe' --expected-start-filetime '<十进制FILETIME>' --base 0x400000 --size 14561280 --out 'E:/已存在目录/新前缀'
```

上限为 64 MiB；64 KiB 初读不足时按 4 KiB 重试，保留真实部分读及错误。`.bin` 是 flat-RVA 数据，`.json` 明确记录已观测前缀、未知缺口和文件哈希。正常缺口使用零占位，零占位不算观测；输出写入失败时可能明确撤销对应范围的有效性。读取不是原子快照。源文件和保留进程 HANDLE 的路径、创建 FILETIME、生命周期分别核对，FILETIME 以字符串保存。运行时入口及 ImageBase 变化单独记录，不据此推断 OEP。

stdout 是完整 JSON，最大 16 MiB；调用进程应明确配置足够输出预算或读取已保存的 receipt。研究工具 `artifacts/research/vmde/attach-runtime-image.mjs` 对本次 vmde 数据再验证逐范围真实字节、SHA、同一 PID/FILETIME/路径，添加到新的不可变 run 后交给通用导出；原始记录保持不变。

## 主模块外的私有代码

`tools/native-trace/private-regions.py` 接续同一次 PE32 主模块采集：从已观测的 `CALL rel32` 指令推导目标，重新核对同一 HANDLE 上的路径、精确创建 FILETIME 和实时调用字节，再通过 `VirtualQueryEx` 检查目标区域。它不接受待执行代码，不写目标，不启动或终止进程。须在该工作副本仍存活时执行：

```powershell
& 'C:/Path/To/Python/python.exe' -X utf8 -I -S ./tools/native-trace/private-regions.py --receipt 'E:/本轮/main.json' --image 'E:/本轮/main.bin' --caller-rva 0xb10c8 --caller-rva 0x1b8611 --out 'E:/已存在目录/新私有前缀' --timeout-ms 10000
```

最多 16 个唯一调用点、128 个捕获区、全局 4096 次区域查询和 16 MiB 捕获字节；每个 allocation 的元数据扫描跨度也限制为 16 MiB。重复目标按 allocation 去重，包含调用目标的区域优先。只采集 committed、MEM_PRIVATE、可读且可执行、无 guard 的区域；其他区域仍有元数据和未采原因。只读查询 HANDLE 明确包含 `PROCESS_QUERY_INFORMATION` 和 `PROCESS_VM_READ`。

每个新 `*-NNN.bin` 是该区域的平面内存数据；收据逐段记录真实读取、补零缺口、查询属性和写入错误。区域扫描完成、代码字节读全、整个 allocation 的全部字节捕获、程序依赖闭合是不同事项；非执行数据不会因元数据已扫描而被称为已采集。中途失败保留已有字节及失败收据，任一身份矛盾立即停止后续读取并标记失败，即使末尾身份又恢复也不降为部分成功。末尾身份/源文件复核失败同样不能给出正向状态。区域属性会在读取前复核，Windows 对 region 内查询返回的后缀按 allocation、属性与终点比对。

所有输出名必须为新文件。stdout 为完整 UTF-8 JSON，上限 16 MiB；`completed` 或 `partial` 的退出码为 0，必须同时检查 JSON 状态和每个调用点的未知原因，`failed` 为 1。它只扩展分析证据，不生成可执行 PE。

## 模块相对的有界内存采样

`ranges` 的每项可选填 `module`，用于读取本次工作副本已经加载的指定模块。省略 `module` 时仍按主模块 RVA 处理；填写时，RVA 相对于该模块在本次采样阶段的实际基址。例如：

```json
{
  "duration_ms": 15000,
  "breakpoints_rva": [],
  "ranges": [
    {"rva":"0x0","size_bytes":16},
    {"module":"kernel32.dll","rva":"0x1000","size_bytes":16}
  ],
  "api_hooks": [],
  "max_events": 256
}
```

示例中的 RVA 只用于展示范围格式；具体字段或函数的位置须按所用模块版本核对。CLI 将该计划通过 `binary trace --plan` 提交；MCP 在 `wirefit_trace_binary` 的 `plan.ranges` 接受相同格式。工具配置与五个计划字段仍需显式提供，不接受已有 PID。

`module` 是 1–128 个 ASCII 字母、数字、下划线、点或连字符组成的 basename；`.`、`..`、目录路径、驱动器、流名和 NUL 不被接受。范围项仍仅要求 `rva` 与 `size_bytes`，不接受调用方注入 `module_base` 或 `address`。相同 RVA 可以分别用于主模块和其他模块；相同 module/rva/size 的重复范围被拒绝，模块名去重忽略大小写。范围总数仍最多 8 个，每项最多 1 MiB、每阶段合计最多 4 MiB；`rva + size_bytes` 不能超过 32 位 RVA 地址空间。

每个 `initial`、`final` 或断点采样阶段都会重新解析模块及其基址、大小，不复用前一阶段的地址。尚未加载、范围超出当时模块大小或内存无法读取时，原始观察中保留明确的该阶段错误；不会用磁盘 DLL 字节或零填充替代观测。模块在解析后改变或卸载也可能造成读取错误，因此这仍不是原子快照。

成功的 scoped 原始记录及主机保存的 snapshot 附带 `module`、`module_base`、`module_size`、`address`，且 `address = module_base + rva`，整个范围必须在该次模块大小内。失败记录也保留这三个地址元数据字段：模块未解析时三者全为 `null`；已经解析但越界时可保留基址和大小而 `address=null`；已尝试读取或写入片段失败时可保留符合范围约束的实际地址。失败记录没有成功片段的 `file`/`sha256`，原始 artifact 保留错误证据。未填写 `module` 的旧格式记录不新增这些模块地址字段。

模块相对采样只增加本次自有目标的有界内存观察。模块名和可计算地址不证明最终 API 指针、调用行为、完整依赖闭合或可运行还原；后续解释仍须核对实际捕获的字节和该次进程身份。

## 清单附件与复制后复验

`artifacts/research/vmde/module-tail/package/attach-files.mjs` 接受显式 parent 身份和固定 SHA 的文件清单，在只读预检全部通过后取得无恢复 writer lease，再次核对父对象与终态作业，写入新的 immutable run。它不启动目标或接受现有 PID。原始 JSON 使用不透明媒体类型；只有工具生成的引用 wrapper 交给标准 `report export` 建立文件闭包。参数、清单格式和边界见 [附件工具说明](../artifacts/research/vmde/module-tail/package/README.md)。

复制工具 `verify-export-copy-v3.mjs` 要求显式产品与附件 manifest SHA、新的两个输出目录及新的收据路径。它校验标准报告完整文件清单，按逻辑名称恢复附件，并仅为分析清单声明的必需输入生成映射。用于执行的 Python 校验 runner 必须已在该清单中登记；旧目录与旧收据不覆盖。实际示例和参数保存在 [最终复制收据](../artifacts/native/owned-acquisition-final-copy-verification-20261020.json)。

[缓存校验 runner](../artifacts/research/vmde/module-tail/package/VERIFY-ANALYSIS-CACHED.md) 只执行 allowlist 中已复审且显式 SHA 匹配的固定证明脚本。它复用原证明逻辑，按唯一文件缓存首次稳定读取，保留每次调用的字节限制，并在返回成功前逐文件用原 reader 重验；stdout 成功信息在最后复核前不发布。这是文件复核工具，不是任意脚本沙箱。vmde 本轮由原版约 42 秒降至最终复本约 7.7 秒，分析输出与 76 项必需输入校验保持一致。

## 固定内核的原生调用配置

`tools/native-kernel/worker.py` 是独立的主动调用配置，仍通过公共 `binary trace` 提交；它不改变被动采集行为。目标只接受已固定 SHA 的 vmde 或自有 x86 正控，不接受现有 PID、任意 RVA 或代码载荷。配置显式指定 `--profile`、`--corpus`、`--corpus-sha256` 和 Frida `--module-path`；vmde 配置另外要求固定 SHA 的完整正控收据。计划无 hooks、无断点，仅读取固定正文初末快照。正控门禁重验全部八行真实输出、对象页面、寄存器及冻结候选负控。

宿主拥有新建目标和 Job，截止时独立终止目标；每例开始及实际返回追加到 `native-calls.jsonl`，每 16 例更新完整检查点，最终生成 `native-result.json`。原始 Trace 中的扩展 sidecar 元数据标记为 `pending_managed_artifact_registration`，不会自动变成 ArtifactRef。交付时使用清单附件登记完整 sidecar、日志、输入、源码与正控，并由标准导出建立闭包。离线复验只从恢复目录的逻辑名称读取所登记文件，原始绝对路径仅为元数据。

固定样本及比较器说明见 [CORPUS.md](../tools/native-kernel/CORPUS.md)，底层契约见 [ABI.md](../tools/native-kernel/ABI.md)。本次实际原生结果为 vmde 904/904 匹配、自有正控 8/8，通过情况与缺失范围分别记录。离线证据校验不重新执行目标，也不替代自然调用现场或正常图像/矢量行为验证。