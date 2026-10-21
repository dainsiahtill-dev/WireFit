# Wirefit

Wirefit 是在本地运行的软件逆向行为建模与验证工具。它使用 Handwired 的真实 Circuit 和反向传播核心拟合数值函数，并结合 Z3、独立解释器和 REA 证据，帮助恢复、简化和比较程序中的计算逻辑。

| 能力 | 当前实现 |
| --- | --- |
| 整数逻辑恢复 | BV8/16/32/64、Bool 模型，精确解释器、Z3 等价检查、反例和有界候选搜索 |
| 数值行为恢复 | FP32 仿射、仿射加钳位、固定分段模板；真实 Handwired、参考训练器、仿射解析基线 |
| 版本差异分析 | 模型比较，或显式注册的两个可执行目标的采样比较 |
| 逆向证据接入 | REA portable evidence 校验、真实公共 MCP 采集、受限纯直线 p-code 提升 |
| 结果交付 | 独立 JS/TS 候选、回放脚本、原始观测、来源映射、SMT 记录和文件哈希 |
| 二进制实战 | PE32/PE32+ 检查、DIE 识别、显式 Unlicense 解包、Frida 运行及内存采样、[有界 Ghidra 静态分析](tools/ghidra/README.md) |
| 自动化 | CLI，以及 19 个 MCP 工具；核心工作不需要 LLM、API Key 或 GPU |
| 研究实验 | 17 个预注册方向：五阶段协议、冻结划分、独立复算与双实现审计，见 [研究协议](docs/RESEARCH-PROTOCOL.md) |
| IDA 分析 | IDA 9.3 MCP：反汇编、反编译、CFG、交叉引用、字节与类型查询，保留独立证据和真实失败 |
| 可视化 | 本地七页工作台：研究证据、代码与模型、运行时间线、模型实验室、验证比较、IDA 分析和真实任务/报告操作 |

模型证明、数值拟合质量和原目标采样结果分别记录。模型等价证明只覆盖声明的模型与输入域；采样匹配会保留计划数、实际执行数和失败数。

## 在这台机器使用

本目录已安装依赖和项目独立的 Node 24.22.0，Windows 启动器会自动选择它。

```powershell
cd E:\wirefit
.\wirefit.cmd doctor --json
npm run demo
```

可视化入口：运行 `.\wirefit-web.cmd`，打开 <http://127.0.0.1:4318>；停止用 `.\wirefit-web.cmd --stop`。工作台接入真实案例、Handwired/Z3 任务及 vmde 冻结研究证据，完整操作见 [可视化工作台文档](docs/WEB-WORKBENCH.md)。

IDA 9.3 MCP 已接入独立的 **IDA 分析** 页面和 CLI/MCP 任务，支持真实反编译、交叉引用及可校验导出；使用方法和完整 vmde 加载失败边界见 [IDA MCP 文档](docs/IDA-MCP.md)。

演示 A 对混合布尔算术表达式进行真实 Z3 简化证明，并在独立进程中穷举 65,536 对输入检查导出结果。演示 B 调用独立的 Python FP32 目标，使用真实 Handwired 训练、冻结候选，再进行留出验证和新的目标调用。完整记录写入 `artifacts/demo/summary.json`。

演示 B 的目标是本项目提供源码的独立参考程序，属于 `reference_fixture`。Python 仅用于该独立演示目标；可用 `WIREFIT_PYTHON` 指定解释器。Ghidra/JDK 现已安装，真实 PE 反编译、证据导入和局部 p-code 提升已通过。图形界面入口为 `.\ghidra.cmd`，配置与复验命令见 [本机部署记录](docs/NATIVE-SETUP.md)。历史演示 C 的 `BLOCKED` 收据保留；完整函数的 ABI、执行条件及原目标回放仍需单独验证。

## 一个最小分析流程

```powershell
.\wirefit.cmd case create --dir .\cases\first
.\wirefit.cmd model import --case .\cases\first --file .\examples\model.mba-u8.json
.\wirefit.cmd model simplify --case .\cases\first --model mba_u8
.\wirefit.cmd jobs --case .\cases\first
```

简化命令会返回任务、候选和运行 ID。把返回的运行 ID 填入导出命令：

```powershell
.\wirefit.cmd report export --case .\cases\first --run <运行ID> --out .\exports\first
```

导出目录中的 `replay.mjs` 可使用 Node 24 在独立目录回放模型与保存的观测。重新执行原目标需要相应目标及显式调用；导出报告会单独说明是否执行了这种新调用。

输入目标通过 Oracle manifest 显式注册，规定可执行文件、参数、输入输出协议和文件身份。支持采集数据、拟合数值模板、验证候选、比较两个目标，以及保存失败调用和反例。完整命令与 JSON 格式见 [CLI 文档](docs/cli.md)。

## MCP

```powershell
.\wirefit.cmd mcp --case .\cases\investigation --create
```

这是供 MCP 客户端启动的 stdio 服务。客户端可提交异步任务、查询进度、读取结果和请求取消；它会等待自己启动的工作进程清理。前台 CLI 使用 Ctrl-C 请求取消，案例数据保存在指定目录。

## 在其他目录安装与构建

需要 Node 24.x 和 npm。所有依赖版本记录在 `package-lock.json`。

```powershell
npm ci --ignore-scripts
npm run build
npm test
```

若 Windows 的全局 Node 版本较旧，可先安装本目录专用运行时，再执行构建和检查：

```powershell
npm install --prefix .tools/runtime --ignore-scripts --save-exact node-win-x64@24.22.0
npm ci --ignore-scripts
npm run build
```

CLI 和 npm 脚本均优先使用上述本地运行时。REA 服务是可选的独立依赖，本目录已安装锁定的 `rea-agents@6.7.0`；迁移时可安装：

```powershell
npm install --prefix .upstream/rea-runtime --ignore-scripts --save-exact rea-agents@6.7.0
```

REA 自身的分析提供者仍需分别配置。`doctor` 可以检查本地能力，证据采集命令见 CLI 文档。

## 检查与已知边界

```powershell
npm run typecheck
npm test
npm run demo
npm run acceptance -- --demos --install-smoke
npm run benchmark
```

验收记录见 [ACCEPTANCE-RESULTS.md](docs/ACCEPTANCE-RESULTS.md)，包含全部 63 个门禁的状态及证据。验收命令遇到 `FAIL` 返回非零；构建和单元测试通过不代表全部规格门禁通过。

现有性能实验中，参考训练器和 Handwired 各完成 8/9 个任务，均有一个分段任务没有达到固定误差要求，未证明 Handwired 有速度优势。历史性能数据中的边界复查点与训练集有重合，详情见 [性能记录](docs/benchmarks/handwired.md) 和验收报告。独立演示 B 使用通过跨分组检查的留出数据。

Windows Ghidra/JDK 安装与局部原生分析已通过，完整函数 ABI/执行条件验证尚未完成。含无法可靠关联前驱的 phi 节点会明确拒绝提升。实际 Linux 主机、真实求解器 UNKNOWN 和外部客户端集成等未执行项目会分别列明。当前产品提供 CLI/MCP 和本地可视化工作台；任意二进制自动恢复及通用内存、调用和循环语义尚未实现。

## 二进制实战与核心边界

vmde 持续还原的最新证据见 [还原进度](docs/VMDE-RESTORATION.md)：被动运行进入真实 Qt 界面，取得完整主模块 14,561,280 字节及两个私有执行页共 8,192 字节；可复用采集命令已在新工作副本实测，本轮补齐另外四个系统 DWORD 和一条返回指令的缺失字节，私有入口均按本次调用重新定位。新增 [原生运行采集](docs/NATIVE-TRACE.md)、私有区域只读采集和有界 Ghidra 工具已实用验证；该采集阶段产品回归 707/707 通过。网格节点编号已实现为 [独立候选](artifacts/research/vmde/kernel-replay/README.md)，与 896 组原始机器码仿真匹配；合成契约、原生程序和整图输出分别记录。可运行重建和完整业务算法还原仍未完成。

前阶段 [持续改进记录](docs/CONTINUOUS-IMPROVEMENT-20261020.md)：二进制报告纳入通用 CLI/MCP 导出，新增入口/TLS 诊断并修正 doctor 状态；当时 304/304 测试通过。可用 [独立报告包](docs/BINARY-REPORT-EXPORT.md) 交付完整文件和证据。

本轮实战与实际失败边界见 [vmde 实战报告](docs/VMDE-PRACTICE.md)：已生成分析转储，直接运行仍崩溃。

本机已配置检查与动态解包工具，命令见 [二进制工具](docs/BINARY-TOOLS.md)。`binary inspect` 支持静态 PE 检查及显式壳识别；`binary unpack` 调用独立后端，保留输入身份、依赖、日志和分析转储。产物可运行性和行为一致性仍需独立验证。

真实 Handwired 核心在给定仿射结构上完成参数学习，独立留出 10/10；给定 bitplane 图的 XOR 为 12/12。它尚未从未知二进制自动发现 VM 结构，详情见 [核心消融](docs/HANDWIRED-ABLATION.md)。三个公开 VMP 样本均已通过真实 REA/Ghidra 采集，但当前入口分析没有建立受保护原函数的语义恢复，见 [实测报告](docs/VMP-REA-TRIAL.md)。

## 仓库内容

Git 仓库包含源码、界面、工具脚本、自有测试样例、依赖锁文件和文档。本机运行环境、`.local/` 配置、`artifacts/` 研究输入与证据、`cases/` 案例及 `exports/` 导出包保留在本地，不随源码发布。

文档中的本机实测记录描述开发机器上的结果；其中指向上述目录的链接需要相应的本地证据。克隆后按“在其他目录安装与构建”安装依赖；IDA、Ghidra/JDK 等可选后端及其实测状态需要在目标机器重新配置和验证。
## 项目资料

- [Handwired 集成与真实运行记录](docs/handwired-api-map.md)
- [CLI、MCP 和输入示例](docs/cli.md)
- [报告与独立导出](docs/report-export.md)
- [架构决策](docs/adr/0001-project-layout.md)
- [依赖与来源锁定](upstream-lock.json)
- [第三方许可](THIRD_PARTY_NOTICES.md)

原有 `CODEX_START.md`、`TASKS.md`、`IMPLEMENTATION_PLAN.md`、语义和 contracts 规格保留，实施包原首页备份于 [IMPLEMENTATION-KIT-README.md](docs/IMPLEMENTATION-KIT-README.md)。原 `MANIFEST.json` 描述交接规格文件。产品名称为 Wirefit；既有 `wirefix.*.v1` 数据契约命名空间保留以兼容实施包。

Wirefit 自有代码使用 MIT 许可；第三方源码保留各自的许可和来源记录。

vmde 的网格核已通过真实进程验证：公共作业管理的 8 个边界样本加 896 个完整样本，与冻结独立实现 **904/904 匹配**；自有编译正控另 8/8 通过，产品回归现为 720/720。可复用工具见 [native-kernel](tools/native-kernel/README.md)，逐次字节、寄存器、缓冲区和失败证据见 [实战记录](docs/VMDE-RESTORATION.md)。这项结果覆盖显式合成对象下的局部函数，整程序还原目标仍在推进。

随后补齐原网格核的返回值语义：EAX 是已编号节点数，旧采集器的 void 元数据已在 ABI 文档勘误。新增可独立运行的 [网格恢复组件](tools/recovered-grid/README.md)，同时返回节点数组和节点数；它在既存 904 条原生观测上联合匹配，属于回归验证。新增 22 项组件、6 项比较器及 8 项交付检查通过，独立副本再次运行 22＋6 项测试。三份新有界函数证据及未完成的自然输入、对象容量和启动问题见 [调用者阶段](artifacts/research/vmde/caller-layout/README.md)；[阶段终态](artifacts/native/caller-layout-verification-20261020.json) 保持整程序可运行性未验证。
