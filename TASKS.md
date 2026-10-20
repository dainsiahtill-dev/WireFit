# Codex 分阶段任务清单

所有任务初始状态为 TODO。本清单描述待实施工作，不表示软件已实现。完成标准以真实命令和 artifacts 为准。M0 的各 lane 独立推进；一个外部依赖阻塞不阻止无关任务。

## M0 依赖和接口冻结

| ID | 任务 | 依赖 | 完成条件 |
| --- | --- | --- | --- |
| T01 | 建立 TS/ESM/npm 工作区、基础构建和文档目录 | 无 | 锁 Node/TS/测试工具，build/typecheck 命令可运行；记录实际环境 |
| T02 | 固定 Z3，验证真实 BV SAT/UNSAT 和线程退出 | T01 | 有真实 solver 日志、锁定版本、WASM 身份；子进程退出不挂起 |
| T03 | 固定 Handwired commit、源码闭包与许可证 | T01 | 不使用同名替身；建立真实 build/evaluate/backprop smoke 和 API map |
| T04 | 固定 REA，获取实际 MCP schema/profile | T01 | 公共 MCP 建连，版本与能力快照；用真实 fixture 检查 high-p-code 字段 |
| T05 | 记录 ADR 与 upstream-lock | T01；各 lane 成功部分 | 各依赖状态独立；未验证版本不能写 resolved；记录 Node/Bun 数值 Worker 决定 |

M0-core 对应 T01，M0-z3 对应 T02，M0-handwired 对应 T03，M0-rea 对应 T04。T05 可持续更新，不构成全通道共同阻塞。

## M1 契约和离线核心

| ID | 任务 | 依赖 | 完成条件 |
| --- | --- | --- | --- |
| T06 | 导入本包 schemas，生成/校验类型，实现 typed-value codec | T01 | BV64 无 Number 往返；FP32 位模式保持 ±0；坏输入拒绝 |
| T07 | 实现 case-store、对象摘要和原子写入 | T06 | 单 case 单写者；冲突/崩溃/重启状态明确；源 Evidence 不变 |
| T08 | 实现 job 状态机、Worker supervisor 和取消 | T07 | 前台 CLI 可 Ctrl-C；MCP 实例内可取消；迟到结果不覆盖终态 |
| T09 | 实现 model validator 和输入域校验 | T06 | 闭合/拓扑/类型/op attrs/宽度/domain 风险全部检查 |
| T10 | 实现 BigInt BV evaluator | T09 | SEMANTICS 全操作、宽计数 guard、BV8 穷举和宽整数边界通过 |
| T11 | 实现 FP32 模板参考 evaluator | T09 | 舍入点、clamp 边界、piecewise 区间、finite policy 明确 |
| T12 | 做一个离线 CLI 薄切片 | T07–T11 | import model → evaluate/记录 → export；无需 REA/LLM/网络 |

T08 是后续所有外部执行的共同基础，不能每个 adapter 独立创建不可取消的长调用。

## M2 精确候选与验证

| ID | 任务 | 依赖 | 完成条件 |
| --- | --- | --- | --- |
| T13 | 实现 BV→Z3 编码与 domain/签名检查 | T02、T09、T10 | 空域、domain 不包含、同名中间变量、移位不同位宽全部有回归 |
| T14 | 实现 SAT/UNSAT/UNKNOWN 结果与具体反例回放 | T08、T13 | 每个 SAT 在独立 evaluator 复现；不复现报内部错误 |
| T15 | 实现可审查规则重写、常量折叠与成本函数 | T10、T14 | 每条规则有语义前提；拒绝实数恒等式误用到 BV |
| T16 | 实现预算内候选枚举和样本过滤 | T15 | 支持未找到/多候选/预算耗尽；不能按样本指纹当全域等价 |
| T17 | 实现模型 CEGIS 与候选分歧选样 | T14、T16 | 反例驱动一次真实候选修正；holdout 不进入搜索 Worker |
| T18 | 实现 BV 模块导出与 fresh-process 检查 | T10、T14 | 导出代码含必要 helper；65,536 BV8 输入对比较真实通过 |

## M3 Oracle 和 Handwired 数值通道

| ID | 任务 | 依赖 | 完成条件 |
| --- | --- | --- | --- |
| T19 | OracleManifest 绑定、JSONL fresh-process runner | T06–T08 | 实際 original/reference target，身份/协议/日志/超时可追踪 |
| T20 | 数据集导入/采集、确定性检查、split 冻结 | 导入：T06、T07、T09；采集另需 T19 | 计划/尝试/完成/失败分母完整；目标样本与候选样本分离 |
| T21 | 简单数值基线与模板搜索 | T11、T20 | affine 代数/最小二乘；clamp/piecewise 的固定结构求参；留出验证独立 |
| T22 | Handwired adapter 与 host-gated 数值 Worker | T03、T08、T11、T20 | 真实参数梯度；gate/舍入/零符号/前提/缓冲区寿命有具体合同 |
| T23 | 冻结候选验证、三维结果派生与数值导出 | T21；Handwired 候选另需 T22 | 训练状态不改 model_check；实际导出模块对原始观测比较 |
| T24 | 双 Oracle 差分与反例回放 | T19、T20、T23 | 两个真实 fixture 目标在边界输入出现差异；缺样本结果为 partial |

若 T03/T22 被外部依赖阻塞，T19–T21 与其它已支持后端继续；Handwired lane 标 BLOCKED，不使用替身转成 PASS。

## M4 REA 适配

| ID | 任务 | 依赖 | 完成条件 |
| --- | --- | --- | --- |
| T25 | 受支持版本 portable bundle validator/parser | T04、T06、T07 | 验证 canonical 身份/引用；保留未知与回复元数据；无 live 依赖 |
| T26 | live REA client、acquire_evidence 和持久化后关闭 | T04、T08、T25 | 自有连接；绑定后能力刷新；关闭后 portable 文件可独立使用 |
| T27 | 完整定义链切片及 source map | T09、T25 | cutpoint、missing definition、execution guard、返回绑定区分 |
| T28 | 直线标量 high-p-code→BV DAG | T10、T27 | 来源真实；op/宽度/SSA 不猜测；至少一个 native fixture 可导入 |
| T29 | 条件能力审查：无环 CFG/phi | T28 | 若字段充分则实现完整 gate；否则明确 UNSUPPORTED 并后置，不能影响基本功能验收 |

Portable validator 可复用固定提交中最小、明确许可的 canonical 校验闭包，或独立实现并用官方验证器做对照。不得在运行时 deep import REA 私有 dist；移植的 schema/身份算法要有来源和版本测试。

## M5 产品闭环

| ID | 任务 | 依赖 | 完成条件 |
| --- | --- | --- | --- |
| T30 | 统一 application service、CLI 参数和执行状态 | T12、T18、T23、T24、T28 | 所有公开链路有真实可执行入口；不同模式参数互斥 |
| T31 | MCP server 与有限 run_experiment 联合类型 | T30 | 真实 MCP client 运行任务/读反例；verdict 注入拒绝；不依赖模型 API |
| T32 | 报告和自包含导出闭包 | T30、T31 | 新目录无原 case 访问时可重放历史观测；外部依赖显式 |
| T33 | 三条端到端演示 A/B/C | T18、T23、T26、T28、T32 | 真实日志、输入/目标/依赖摘要、失败和未证明范围齐全 |

## M6 本地开发者版本

| ID | 任务 | 依赖 | 完成条件 |
| --- | --- | --- | --- |
| T34 | 执行 acceptance matrix 和平台矩阵 | T33 | gate 有 PASS/FAIL/NOT_RUN/SKIPPED/BLOCKED/INCONCLUSIVE；无伪绿 |
| T35 | Handwired 与基线公平评测 | T21–T23 | 同任务同预算；正确性、恢复质量、工程收益分开结论 |
| T36 | 安装、故障、支持范围、许可证和交接 | T34、T35 | 新环境安装及 smoke，README/锁文件/ADR/完整报告可交付 |

M6 可以交付“部分功能可用”的版本，但必须按每个 capability 标出真实通过情况。只有 T03/T22 与原生整链 gate 通过，才可宣传它们已集成完成。

## M7 后续任务池

不在首个实施承诺中并行展开：Web 面板、Ghidra/IDA GUI 入口、更多数值模板、内存模型、协议字段推断、状态机学习、GPU 后端。每一项先写新增的语义/证据/验收约束，再扩展接口。

## 阶段提交模板

每次阶段交付写清：完成任务 ID、实现路径、实际命令、关键输出 artifacts、失败与阻塞、哪些 gate 未运行。命令输出中的 completed 或退出码 0 不能代替功能验收。所有可逆且不依赖阻塞的工作继续推进，不逐阶段要求用户确认。
