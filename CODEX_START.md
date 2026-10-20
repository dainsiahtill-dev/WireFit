# 给 Codex 的实施任务

请把本目录中的 WireFix 方案实现为一个可运行的本地逆向分析工具。先完整阅读 `IMPLEMENTATION_PLAN.md`、`docs/SEMANTICS.md`、`docs/INTERFACES.md`、`docs/ACCEPTANCE.md`、`TASKS.md` 及 `contracts/`；再阅读实际工作区的 AGENTS 和既有约束。

目标是从 REA 的证据出发，建立可执行的受限函数模型，完成表达式简化、数值参数恢复、行为差分和可复现报告。产品工作名 WireFix，CLI 为 wirefix。优先交付 CLI/MCP，Web 工作台后置。

## 架构决定

- 独立 TypeScript/Node sidecar。REA 通过公开 MCP 和 portable Evidence bundle 接入，不 fork 全平台，不 deep import 私有 dist。
- 精确 BV8/16/32/64 与 Bool 由 BigInt evaluator 和独立 z3-solver Worker 处理。
- Handwired 固定源码 commit，封装为数值参数拟合 Worker；真实运行 Circuit/backprop，不使用同名替身。
- 复用 REA 已有 high-p-code 来源，先支持完整定义链的直线纯标量切片；缺必要 phi/类型字段则 unsupported，guard 未知时保留 expression 范围并阻止依赖它的目标级提升，不重写通用 bridge。
- Oracle 使用明确的 JSONL 原目标 wrapper。候选不能给自己生成期望输出；原生入口观察不等于完整返回值 Oracle。
- CLI 长任务前台等待，Ctrl-C 取消；MCP server 持有异步 job。首版不做 daemon。

## 执行顺序

从 T01 开始，按 TASKS 推进至 M6。M0-core、M0-z3、M0-handwired、M0-rea 独立记录：外部 lane 被阻塞时继续不依赖它的任务。

先做一个离线 BV 简化闭环，再做 Oracle/数值与真实 REA 链；最后统一 MCP、报告和安装。可以并行独立模块，但契约与语义规范由一个负责人维护，避免相互修改同一接口。

M0 必须核查真实版本和导出/API，不假设上游 main 已发布，不使用浮动 latest。填写真正的 upstream-lock、capability snapshot 与 Handwired API map。可在有具体兼容原因时记录 ADR 调整依赖或数值 Worker 运行时，保留核心语义和验收要求。

## 不得弱化的完成条件

1. 原始 Evidence、模型检查、原目标回放、数值拟合分别记录；没有 binary_proven_equivalent 总开关。
2. Z3 UNSAT 只证明声明模型和域。先查域非空；UNKNOWN/timeout/cancel 不等于 proved。
3. BV64、地址和 typed outputs 不经 Number；保持位宽、符号操作、宽移位计数与舍入政策。
4. 切片 cutpoint、producer 截断、guard 未知和真实函数参数绑定必须区分。
5. train/validation/holdout 固定，最终候选冻结后才能读 holdout；使用 holdout 修正后重新形成独立版本。
6. Handwired clamp/piecewise 用明确 host gate/梯度合同；不为绕过布尔反传打开 STE，不默认 min/max 宏具备所有 FP32 语义。
7. 已生成导出代码必须在新进程验证。复现包携带原始观测输出、helper 和依赖对象闭包。
8. portable Evidence 不依赖另一 MCP 连接的 retained ID；live 关闭前保存需要的 bundle。
9. 真 REA/Ghidra、真 Handwired、真 Z3 gate 与 mock 单测分开。缺工具标 BLOCKED/SKIPPED，不能伪装整链 PASS。
10. LLM 可以提交候选和建议，验证状态只能由 verifier 计算。
11. 输入比较映射必须是保类型双射，输出集合非空；FP32 样本比较强制显式输入集和政策。导入 model 不得携带可信 fidelity，目标验证须绑定语义、来源、Oracle 和政策摘要。

## 工作方式

现在开始实施，不只重复方案或制作占位页面。每完成一个阶段运行相关验收，记录实际命令、输入摘要、输出文件、结果与未运行项，然后继续下一阶段。保留现有用户工作；对必要的常规可逆开发和修复无需逐阶段询问。

遇到真实外部权限、依赖或输入阻塞，先完成不受影响的部分，再说明具体原因与可审查的解决办法。不得编造成功日志、恢复率、性能或未运行平台的支持情况。

最终交付：可运行源码、依赖锁、README、ADR、完整验收矩阵、三条演示 A/B/C、可复现分析导出，以及仍未解决的问题。Handwired 优势需要实测；若没有收益，保留为可选后端并如实报告。
