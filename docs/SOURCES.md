# 来源、已知边界与 M0 核查清单

阅读日期：**2026-10-19**。本文件服务于 WireFix 实施规格，区分上游事实、本方案的设计决定和仍需实际验证的事项。

下列 `main` / `master` 链接用于定位来源，会随上游变化。本次未取得可作为依赖锁使用的完整 commit SHA，也没有在本实施包中运行 REA/Ghidra、Handwired 或 Z3 集成。M0 必须以实际源码、发布包和运行身份生成 `upstream-lock.json`；不能把本来源表或未解析的模板当成依赖已经锁定或测试已经通过。

## 1. 主来源索引

S1–S8 与 `IMPLEMENTATION_PLAN.md` 中的编号一致。

| 编号 | 一手来源 | 在本方案中支持的内容 |
| --- | --- | --- |
| S1 | [REA 仓库与 README](https://github.com/morluto/rea) | 本地 CLI/MCP、分析后端与外部 agent 的关系 |
| S2 | [REA native-investigation.md](https://github.com/morluto/rea/blob/main/docs/native-investigation.md) | high-p-code、静态值流、原生入口观察与平台边界 |
| S3 | [Handwired execution-model.md](https://github.com/chenglou/handwired/blob/main/docs/execution-model.md) | FP32、CPU evaluator、宏、梯度、声明与缓冲区合同 |
| S4 | [Z3 官方 TypeScript bindings 文档](https://github.com/Z3Prover/z3/blob/master/src/api/js/PUBLISHED_README.md) | `z3-solver`、WASM、初始化、并发与线程清理 |
| S5 | [REA mcp-contracts.md](https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md) | 工具发现、Evidence、连接归属、分页、错误与取消 |
| S6 | [Handwired package.json](https://github.com/chenglou/handwired/blob/main/package.json) | private 包标记和 Bun 开发脚本 |
| S7 | [REA LICENSE](https://github.com/morluto/rea/blob/main/LICENSE) | REA 根许可证原文 |
| S8 | [Handwired LICENSE](https://github.com/chenglou/handwired/blob/main/LICENSE) | Handwired 根许可证原文 |
| S9 | [REA package.json](https://github.com/morluto/rea/blob/main/package.json) | 包身份、Node 要求、bin、依赖与验证脚本 |
| S10 | [REA evidence-workflows.md](https://github.com/morluto/rea/blob/main/.agents/skills/reverse-engineer-anything/references/evidence-workflows.md) | 已有比较、unknown 与有限重建检查工作流 |
| S11 | [REA src/domain/evidence.ts](https://github.com/morluto/rea/blob/main/src/domain/evidence.ts) | canonical schema、profile 一致性与语义 ID 检查 |
| S12 | [REA ghidra-provider.md](https://github.com/morluto/rea/blob/main/docs/ghidra-provider.md) | Ghidra 提供方的覆盖、截断与真实验证范围 |
| S13 | [REA testing.md](https://github.com/morluto/rea/blob/main/docs/testing.md) | 单元、MCP 边界、验收与真实引擎测试的区别 |
| S14 | [REA THIRD_PARTY_NOTICES.md](https://github.com/morluto/rea/blob/main/THIRD_PARTY_NOTICES.md) | 上游第三方通知定位 |
| S15 | [REA scripts/rea.mjs](https://github.com/morluto/rea/blob/main/scripts/rea.mjs) | 公共可执行入口与 CLI/MCP 分派 |
| S16 | [REA src/cli.ts](https://github.com/morluto/rea/blob/main/src/cli.ts) | 内部 CLI factory 与共享应用工作流组合 |
| S17 | [Ghidra P-Code Reference Manual](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html) | raw P-code、分析后图、Varnode 和操作语义 |
| S18 | [REA process-capture.md](https://github.com/morluto/rea/blob/main/docs/process-capture.md) | 过程观察的用途、宿主范围与非沙箱边界 |
| S19 | [Z3 LICENSE.txt](https://github.com/Z3Prover/z3/blob/master/LICENSE.txt) | Z3 根许可证原文 |
| S20 | [Ghidra LICENSE](https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE) | Ghidra 根许可证原文 |

## 2. 已核查的上游事实

### 2.1 REA

- **产品形态：** REA 提供独立的本地 CLI/MCP；外部 agent 调用分析工具。Ghidra、Hopper、IDA 等是分析提供方，不能把 REA 整体等同于某个 GUI 插件。[S1](https://github.com/morluto/rea)
- **版本观察：** 阅读时 `main` 的 `package.json` 写有 `rea-agents` **6.7.0**。这是主分支文件的观察值，不是本机安装版本、已锁发布包或所有功能已发布的证明。该文件的 Node 要求为 `^22.19.0 || ^24.11.0 || >=26.0.0`。[S9](https://github.com/morluto/rea/blob/main/package.json)
- **复用接口：** 公共 bin 经 `scripts/rea.mjs` 分派 CLI/MCP。源码中的 `createCli` 是内部 factory；已查看的包文件没有 `exports` 声明，未据此确认稳定的外部 TypeScript SDK。[S15](https://github.com/morluto/rea/blob/main/scripts/rea.mjs)、[S16](https://github.com/morluto/rea/blob/main/src/cli.ts)、[S9](https://github.com/morluto/rea/blob/main/package.json)
- **会话合同：** `tools/list` 提供工具定义；`binary_session` 描述身份和当前 availability。Retained ID 归属于当前连接；`close_binary` 清除其 retained Evidence。跨连接使用完整、受支持的记录或 bundle，关闭前导出。[S5](https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md)
- **结果合同：** 成功 Evidence 包含 `normalized_result` 和身份；错误走 `isError` 加文本 JSON diagnostic。分页取尽不等于生产者完整观察；回复级不可信内容元数据需要单独保留。[S5](https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md)
- **内容身份：** Evidence schema 严格校验 envelope 和 profile，并核对语义 ID。保留文件 hash 不能代替这些检查；通过内容身份检查也不等于证明原程序语义正确。[S11](https://github.com/morluto/rea/blob/main/src/domain/evidence.ts)
- **已有 IR：** Ghidra dossier 提供有界 high-p-code 和 def-use。文档列出每函数最多 3,000 个操作、每操作 64 个输入及 12,000 条边，并报告遗漏；`trace_native_values` 组合静态已解析调用的参数和返回依赖。别名、副作用、运行时状态及缺失绑定仍有限制。[S12](https://github.com/morluto/rea/blob/main/docs/ghidra-provider.md)、[S2](https://github.com/morluto/rea/blob/main/docs/native-investigation.md)
- **Oracle 边界：** `observe_native_calls` 的该路线观察原生函数入口，不收集返回值、浮点/栈参数等全部调用信息。它不是任意函数的完整数值输入输出 Oracle。[S2](https://github.com/morluto/rea/blob/main/docs/native-investigation.md)
- **已有验证：** `verify_reconstruction` 已存在，检查有限 typed claims；通过不等于全程序等价。`compare_functions` 的文本/结构比较不能替代可执行数值等价检查。[S10](https://github.com/morluto/rea/blob/main/.agents/skills/reverse-engineer-anything/references/evidence-workflows.md)、[S5](https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md)
- **执行与测试：** Process capture 运行调用者选定命令，记录有限过程证据；它不是安全沙箱。官方测试文档区分注入 provider 的测试与真实引擎验收，本包没有继承这些测试的通过状态。[S18](https://github.com/morluto/rea/blob/main/docs/process-capture.md)、[S13](https://github.com/morluto/rea/blob/main/docs/testing.md)

### 2.2 Handwired

- **依赖形态：** `package.json` 标记 private，开发脚本使用 Bun；不能据此假设有受支持的 `npm install handwired` 公共库。[S6](https://github.com/chenglou/handwired/blob/main/package.json)
- **执行模型：** source cells 使用 `Float32Array`；运算有明确的 FP32 舍入与顺序。`src/runtime` evaluator 在 CPU 上执行；名称含 Tensor 不代表自动使用 GPU。[S3](https://github.com/chenglou/handwired/blob/main/docs/execution-model.md)
- **训练边界：** 反传针对意图中的实数运算，不是字面浮点舍入导数；梯度到 boolean atom 默认抛错，离散 index 另有选项。[S3](https://github.com/chenglou/handwired/blob/main/docs/execution-model.md)
- **宏和声明：** 普通 min/max、ReLU clamp 有范围与舍入限制；精确选择宏仍有零符号和有限操作数边界。range/grid/bit 声明是调用者前提。[S3](https://github.com/chenglou/handwired/blob/main/docs/execution-model.md)
- **缓冲区：** `createTensorEvaluator` 复用结果数组，后续求值会覆盖它；保留历史结果需要复制。[S3](https://github.com/chenglou/handwired/blob/main/docs/execution-model.md)

### 2.3 Z3 与 Ghidra

- **Z3：** 官方 `z3-solver` 提供 TypeScript 高低层绑定及 WASM。文档说明长调用涉及后台线程；同一 module 的并发和退出清理有约束。实际包的初始化、清理 API 与行为须在 M0 验证。[S4](https://github.com/Z3Prover/z3/blob/master/src/api/js/PUBLISHED_README.md)
- **Ghidra：** 官方手册区分 raw P-code 和分析后增加的操作，`MULTIEQUAL` 等属于后者；Varnode 的空间、偏移、大小及 opcode 解释都影响语义。该手册不证明 REA 导出已包含执行 phi 所需的全部字段。[S17](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html)
- **Provider：** REA 文档给出 Ghidra/JDK 与宿主边界，包含真实提供方验证说明。WireFix 仍需在自己的固定安装和 fixture 上完成原生链验收。[S12](https://github.com/morluto/rea/blob/main/docs/ghidra-provider.md)

## 3. 本方案的设计决定，不作为上游既有功能宣传

| 决定 | 原因和验收边界 |
| --- | --- |
| 独立 sidecar，公共 CLI/MCP 与 portable bundle 优先 | 将上游采集和本项目候选/验证分开；不 deep import 私有 `dist`，不从零复制分析平台 |
| Offline 与 live 分路 | 离线操作使用已锁 adapter/schema；只有创建 live 连接才发现服务器，绑定目标后更新 availability |
| 新建 Oracle JSONL 合同 | 首版依赖明确 wrapper 与输入绑定；不将入口观察冒充返回值采集 |
| 有界 P-code lift | 只接受必要字段完整的已支持切片；缺 guard、定义链、类型或 phi 映射时保留证据并拒绝相应提升 |
| Handwired 数值 Worker | 参数走 source wires；host 分支选择、局部梯度、范围验证和稳定数组快照由 adapter 明确实现 |
| Z3 子进程 Worker | 每个 module 同时处理一个任务；核查线程清理、取消与超时，不把进程隔离宣传成任意目标沙箱 |
| Node 24 / npm workspaces 为默认 | 锁定满足依赖条件的精确补丁版本。pnpm 仅作为模板预留的替代工具字段，切换需记录 ADR |
| 模型、目标回放和拟合分别报告 | SMT 只检查声明模型；样本一致不证明唯一源码恢复，Handwired 收益另行实测 |

这些决定的完整语义与接口以 `IMPLEMENTATION_PLAN.md`、`docs/SEMANTICS.md` 和 `docs/INTERFACES.md` 为准。

## 4. 许可证记录

已读 REA 与 Handwired 根 LICENSE 均标明 MIT。[S7](https://github.com/morluto/rea/blob/main/LICENSE)、[S8](https://github.com/chenglou/handwired/blob/main/LICENSE)

复制源码时保存该提交的原版权、许可证与随附通知；记录复制路径和本地补丁。Z3、Ghidra 的根 LICENSE 以及 REA 的第三方通知分别列在 S19、S20、S14。M0 按实际选中的源码/包收集文件摘要和通知，不把某个仓库的根许可证视为所有运行环境、附带依赖或外部工具的统一授权。本文件不作未经验证的许可证兼容性或使用权结论。

## 5. M0 待核查清单

| Lane | 实际核查 | 必须保存的结果 |
| --- | --- | --- |
| M0-core | 实际 Node 版本、架构、可执行文件；选择 npm，或以 ADR 明确更换 pnpm；建立工作区锁文件 | 精确版本、路径、文件摘要、锁文件摘要、环境报告 |
| M0-z3 | 从官方仓库/registry 解析版本和源码对应关系；核对 WASM/worker assets；运行 SAT、UNSAT、UNKNOWN/预算失败、退出与取消路径 | 包完整性、源码 SHA、API 映射、worker 资源摘要、独立 smoke 记录 |
| M0-handwired | 用真实 git/API 解析 commit，读取所需源码闭包及导出；用上游需要的 Bun 验证开发路径，再验证 Node 产品编译路径 | commit、构建命令、Bun/Node 版本、复制清单、补丁、API map |
| M0-handwired | 校验 FP32 舍入、零符号、范围前提、连续参数梯度、host gate 与数组生命周期 | 独立参考结果；不同输入连续求值后旧结果未被覆盖的记录 |
| M0-rea | 核实包版本与源码 SHA，不把本表的 6.7.0 当锁；获取实际 `tools/list` 和 `binary_session` | 包摘要、服务器身份、工具 schema、catalog/profile/availability 快照 |
| M0-rea | 验证成功、文本错误和回复元数据；验证受支持 portable envelope、语义 ID 与引用；测试关闭前导出和跨连接交接 | 完整 fixture bundle、拒绝案例、导入/导出与恢复记录 |
| M0-native | 记录实际 Ghidra/JDK/native decompiler、宿主和目标架构；对源码自建 fixture 获取真实值流 | provider 版本/文件摘要、analysis profile、编译器参数、目标 hash |
| M0-native | 核查 opcode、输入顺序、宽度、常量、Varnode/SSA 身份、参数/返回绑定、guard、遗漏；需要 phi 时验证入边槽位 | 字段映射、支持/拒绝清单；缺字段保持 unsupported，不能补猜测值 |
| 各 lane | 收集所选版本 LICENSE/NOTICE；记录真实命令、开始结束时间、结果和 artifacts | PASS/FAIL/NOT_RUN/SKIPPED/BLOCKED/INCONCLUSIVE 分开的验收记录 |

外部 lane 不可用时，继续不依赖它的工作；未通过的 lane 不进入已支持功能列表。`upstream-lock.template.json` 中的 null 是待解析值；只有真实来源与验证记录完整的已选组件才可转为 resolved。未选的 pnpm、可选 Bun 运行路径或其他 provider 不应伪造安装结果，也不应阻塞无依赖的核心工作。
