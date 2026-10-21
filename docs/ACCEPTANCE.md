# WireFix 验收与评测矩阵

本文件的用例均为需要实现的验收目标；实施包不包含 REA、Handwired 或 Z3 的成功运行报告。所附 fixtures 是初始真值材料，必须扩充为真实测试。

## 1. Gate 记录

每条 gate 必有：id、status、scope、command/request、started_at、finished_at、host、dependency identities、input hashes、output artifact refs、actual counts、failure/skip reason。未运行字段可为空，不得编造时间或日志。

status 为 PASS、FAIL、NOT_RUN、SKIPPED、BLOCKED、INCONCLUSIVE。SKIPPED 不参与 PASS 数；“允许缺依赖”只允许明确显示阻塞，不能通过整链支持 gate。

每条 gate 另记录 `unresolved_selectors`：它引用的断言在本次运行中没有任何存活的测试名命中。这表示**证据指针已失效**（测试被改名或删除），此时该 gate 不能主张其范围，矩阵的 `stale_gate_pointers` 汇总全部此类指针。指针里不得写工具数量之类的会变字面量，否则改一次工具集就会让 gate 静默失去证据。

## 2. 核心与存储

| Gate | 检查 | 通过条件 |
| --- | --- | --- |
| C01 | 契约结构 | 全部 schema 可编译，正例通过，额外 verdict/未知字段等反例被拒绝 |
| C02 | 位模式往返 | BV64 大于 2^53、全 1、最高位；FP32 ±0/subnormal 位模式保持 |
| C03 | DAG 校验 | 重复 ID、前向引用、cycle、未知 op、类型错、越界 extract 全部拒绝 |
| C04 | BV8 全域 | add/sub/mul/and/or/xor 等核心二元 op，逐项 65,536 对照通过 |
| C05 | 宽整数 | 16/32/64 边界和固定种子属性测试通过；使用独立参考或真实 fixture |
| C06 | 移位 | w-1/w/w+1、BV64 极大计数；1u8 << 256u64=0；负值 ashift 填符号 |
| C07 | 显式转换 | PIECE 高低位、SUBPIECE 字节偏移、zext/sext 和 Bool/BV 桥接 |
| C08 | case 原子性 | 中断写入不发布半文件；同 case 写冲突明确；旧 artifact 不被改写 |
| C09 | job 生命周期 | 前台 Ctrl-C、MCP cancel、Worker crash、迟到结果、重启 interrupted |

## 3. 模型求解与候选

| Gate | 检查 | 通过条件 |
| --- | --- | --- |
| V01 | 已知等价 | MBA 加法等真实 Z3 UNSAT，scope/hash/SMT-LIB 齐全 |
| V02 | 已知不等价 | 至少一个 SAT 反例经 BigInt evaluator 确认 |
| V03 | 内部冲突 | 人为破坏 translator 后，不能提交不被 evaluator 复现的反例 |
| V04 | 空域 | x=0 且 x=1 返回 DOMAIN_EMPTY，不是 proved |
| V05 | 域差异 | 请求域不包含于双方契约时拒绝；不静默缩域 |
| V06 | 符号隔离 | 两模型临时节点同名不产生额外相等约束 |
| V07 | 不确定求解 | 真实取消/预算失败；UNKNOWN handler 的组件注入另计，不能假称真实 solver 产生 UNKNOWN |
| V08 | Worker 清理 | 正常/超时后进程和 Z3 后台线程不遗留；主 MCP 仍可响应 |
| V09 | 搜索真实性 | 冷种子表达式集，不限于附带单个 MBA 例；搜索预算/未找到/多候选完整 |
| V10 | 指纹冲突 | 构造训练样本同值而未见输入不同的表达式，不能按指纹证明等价 |
| V11 | CEGIS | 一次错误候选→真实反例→新候选；旧 run 保留 |
| V12 | 导出 | fresh Node 进程运行真实导出模块；结果与模型以及携带的观测比较 |
| V13 | 映射非退化 | 输入合并/缺失/类型差异与空输出集合均拒绝；子集比较列未比较输出 |
| V14 | 目标身份与结论 | 导入 fidelity/verdict 不得成为可信值；同语义模型换来源/Oracle 后不复用 sampled_match |

Z3 的 UNKNOWN 分支可用受控注入做组件覆盖，但要标注 injected。真实环境没有产生 UNKNOWN 时记录该集成子项 NOT_RUN，不能伪造。完整产品仍须真实覆盖硬超时/取消，并证明这些路径不会升级 verdict。

## 4. Oracle、样本和数值

| Gate | 检查 | 通过条件 |
| --- | --- | --- |
| O01 | 原目标来源 | wrapper 调用真实原目标或 source-owned fixture，不调用候选生成期望 |
| O02 | 协议 | request_id、typed outputs、坏 JSON/多响应/日志混入 stdout 均正确处理 |
| O03 | 失败分母 | 超时/崩溃/协议错误/域外输入不被删掉；统计可回算 |
| O04 | 重复性 | 同输入重复调用不一致时保持 nondeterministic，不能按纯函数验证 |
| O05 | 身份变化 | target/wrapper 文件摘要变化后旧绑定失效；旧观测仍保留 |
| O06 | holdout | learner 未取得 holdout 输出；最终候选冻结后验证；消耗 holdout 产生新版本 |
| O07 | 双 Oracle | 用边界 100 的两个真实版本得到区分输入；两边调用数与失败计数可查 |
| O08 | 零样本/部分 | 0 个有效成对样本不得 matched；有未完成输入无差异为 partial |
| O09 | 观测来源 | lifted/candidate 数据不增加 original_target 计数；历史与 fresh 回放分开 |
| N01 | FP32 参考 | 每个声明舍入点、clamp 相等分支、piecewise knots、finite policy 正确 |
| N02 | 基线恢复 | affine 代数基线；未知参数不从 ground-truth 文件读取 |
| N03 | Handwired 真调用 | 固定 commit 真实 Circuit 构建、求值和参数 backprop，留实际证据 |
| N04 | 门控与梯度 | host-gated mask 每次参数更新重算；默认无 STE；边界 policy 可查 |
| N05 | 范围前提 | range/grid/bit 的声明在实际 source 值上检查，越界不能继续给完整正确性 |
| N06 | 缓冲区寿命 | 连续两次不同输入后第一份返回结果不变，梯度快照同样检查 |
| N07 | 零符号 | 后端训练政策与最终 bitwise-fp32 区分；不支持负零精确性时不静默放宽 |
| N08 | 独立验证 | 冻结候选对留出和边界输入满足预声明容差，失败样本完整 |
| N09 | 损失与证明 | loss=0 或训练完成不能修改模型证明状态 |
| N10 | 数值模型比较 | 强制显式输入集和政策；逐点公式、±0、非有限/失败计数正确；无 proved |

数值验收目标：affine 先以可准确编码参数的 fixture 检查 bitwise 输出；clamp/piecewise 在固定的 bitwise 或 tolerance 政策下检查。验收关注行为输出，不强求唯一原参数，多个参数化实现可能在声明域行为相同。

## 5. REA 与原生接入

| Gate | 检查 | 通过条件 |
| --- | --- | --- |
| R01 | 离线隔离 | 无 REA 安装/进程/网络时 import 已支持 bundle、模型运算和报告可运行 |
| R02 | 真 MCP | 公共可执行入口启动真实 REA；获取工具 schema、服务器身份、目标绑定后的能力 |
| R03 | Portable 身份 | 受支持 canonical 结构/语义身份/引用关系通过；篡改 record ID/profile 拒绝 |
| R04 | 跨会话 | 新连接直接取旧 ev_ID 失败；portable 完整数据交接可用，不暗用原连接 |
| R05 | 分页与缺口 | transport 页面取完仍保持 producer truncated/unknown，不升级完整度 |
| R06 | 关闭前持久化 | close 后仅凭 case 中的 portable bundle 可继续；失败时标出未保存证据 |
| R07 | 回复契约 | 成功 structuredContent、错误文本 diagnostic、不可信元数据均有真实 fixture |
| R08 | 原生受限 lift | 真实源 fixture→binary→REA/Ghidra→完整定义链→合法 BV DAG |
| R09 | SSA | 同寄存器不同定义保持不同 ID；RETURN 目的地址不当结果；常量不经 Number |
| R10 | cutpoint | 有意切片允许并标 scope；producer 缺失不以自由输入补齐 |
| R11 | guard/绑定 | guard 未知或局部值非函数返回时，不能直接运行函数返回值验证 |
| R12 | 原生整链 | 同一明确目标版本的独立 Oracle 回放 + 导出物回放，分列模型关系与目标样本 |
| R13 | 副作用 | 未支持 LOAD/STORE/CALL/INDIRECT 保留诊断，不删后宣布原函数纯净 |
| R14 | phi 增强 | 有字段才验收；入边槽位、菱形/多返回/平行边等；缺字段为 UNSUPPORTED |

R14 为条件增强，不属于“直线原生表达式支持”的必选发布 gate。宣称支持无环 CFG 时它成为必选。

## 6. 产品与交付

| Gate | 检查 | 通过条件 |
| --- | --- | --- |
| P01 | CLI 闭环 | import/acquire→model/oracle→experiment→report 全部有真实入口 |
| P02 | MCP 闭环 | 真客户端提交任务、取消、查询反例；canonical request 拒绝 verdict 注入 |
| P03 | 独立复现包 | 复制导出目录、移除原 case 访问，带 helper 和历史输出可运行 |
| P04 | 外部依赖 | 未携带原目标时 fresh replay 明确 unavailable/NOT_RUN，不把历史样本当新调用 |
| P05 | 支持矩阵 | 平台/provider/backend 按真实 gate 标记；缺 Ghidra 不阻塞离线功能，但原生 lane 不算 PASS |
| P06 | 三条演示 | A 离线简化、B 数值恢复、C REA 原生整链均有真实结果文件 |
| P07 | 并发和错误恢复 | case 单写者、取消、错误后继续新任务，无陈旧结果污染 |

真实 Codex 客户端未在实现环境提供时，P02 可先用真实官方 MCP client 验收协议，将“Codex 实际客户端”单独标 NOT_RUN。不可把协议测试冒充实际 Codex 集成记录。

## 7. 性能和研究收益

必须比较三种配置：简单基线、普通参考后端、Handwired 后端。相同任务、训练/验证/holdout、参数范围、Oracle 调用上限和结果政策；必要时同时给相同 wall-time 与相同查询预算两种观察。

报告：计划任务数、完成数、验证通过数、失败/未确定数、候选数、真实目标调用次数、不同输入数、建图/编译/拟合/验证总耗时、峰值内存的测量方式。按相同主机冷/热启动分别测量，不宣称未测试 GPU 加速。

首轮至少三类数值模板，每类多个参数种子；表达式集至少包含简单恒等式、边界反例、无法在预算恢复的负例。附带示例只是 smoke，不能独占评测集。

允许最终结论为“Handwired 已正确接入，但这些任务上未发现额外收益”。这是评测结果，不是实现失败；不得人为削弱基线以得到优势。
