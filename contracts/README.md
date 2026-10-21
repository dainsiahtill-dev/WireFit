# 契约实现说明

本目录是拟实现的 JSON Schema 2020-12 契约。所有 `$id` 都使用保留的 `.invalid` 名称作为离线标识；将 14 个 schema 注册到同一 validator 实例，按 `$id` 解析相对 `$ref`，禁止为了校验而请求该域名。M1 必须用真正的 2020-12 validator 编译全套 schema，并把其精确依赖写入锁文件。

## 文件和边界

| 文件 | 边界 |
| --- | --- |
| common.schema.json | typed values、签名、域、映射、来源和计数 |
| model.schema.json | 可导入 BV DAG / FP32 template；不接受 verdict 或 fidelity |
| budget.schema.json | 已解析、全部显式填写的实验预算 |
| oracle.schema.json | 被调用者明确选定的本地 JSONL 执行清单 |
| oracle-request.schema.json | 单条请求；具体输入签名另校验 |
| oracle-response.schema.json | 单条返回；失败没有正常输出 |
| input-sample.schema.json | 计划输入文件的一行 |
| observation.schema.json | 实际观测或明确标记的 expected_fixture |
| dataset.schema.json | 不可变的输入、split、政策和观测文件集合 |
| experiment-request.schema.json | 六种 operation；按 mode/source_mode 继续判别 |
| experiment-result.schema.json | 仅 verifier 生成的结果；绝非可提交的请求 |
| research-direction.schema.json | 17 个方向的可证伪规格；阈值、划分和负控必须先于运行写死 |
| research-request.schema.json | 研究实验请求：单对象 + `direction_id` 枚举 + 已解析预算 |
| research-result.schema.json | 仅研究 verifier 生成的结果；绝非可提交的请求 |

研究契约是独立的一族，**不并入** `experiment-request.schema.json` 的六种 operation 并集：`docs/cli.md` 已明确 binary/trace/ida 属于 "separate job operations，do not extend the canonical mathematical experiment union"，研究实验有独立的规格、判定代数和审计面，塞进并集会迫使 `ExperimentResult` 长出研究维度并污染 `wirefit_run_experiment` 的内联契约。

JSON 语法和 schema 校验成功，只是第一层。以下语义校验是必须实现的第二层；不能以“schema 放行”作为跳过的理由。

## 必需语义校验

1. **ID 与引用：** 模型 input/node ID 唯一且不重叠；output ID 唯一；node args 拓扑闭合；参数、节点、输出、guard 的类型匹配。ID 不是磁盘路径，不直接拼接成文件名。
2. **算子：** 按 SEMANTICS 逐个检查类型、位宽、cast、extract/concat、常量和完整移位计数。未知指令、丢失定义与非法引用拒绝；不补零。
3. **切片：** source_completeness、scope 和 observation_point 是来源声明。真正的 lift-map、SSA/cutpoint 身份和 guard 证据保存为 provenance artifact；导入这些字符串本身不授予函数级 Oracle 绑定。
4. **域：** constraint 名称和类型与输入一致；Bool 只 eq/ne，BV 只 eq/ne/ule/uge/sle/sge，FP32 只 eq/ne/le/ge 且有限。比较前验证请求域非空且包含于双方契约；FP32 的有限区间/排除值也按可表示值处理，不能只看实数区间非空。普通模型导入可以保存空域，但不得给它全域通过结论。
5. **映射：** inputs 覆盖双方全部输入且为保类型双射；outputs 非空、保类型、两侧分别不重复。domain 与 inputs_artifact 使用左侧命名，右侧经同一映射转换。默认映射也要显式落盘，未比较输出要列出。
6. **数值模板：** FP32 输入、参数、固定值和边界都有限；lower <= parameter <= upper。affine/clamp 只 a/b；piecewise 要 2–8 段，恰好 a0/b0 到 aN/bN，N=knots 数，knots 严格递增。clamp lo<=hi。遵守舍入、零符号和非有限中间结果政策。
7. **政策：** decimal 字符串解析为有限非负 Number；学习率另须大于 0（closed_form 除外）。exact-bv 仅 BV/Bool；FP32 政策仅 FP32。tolerance 的逐点公式与零符号规则见 SEMANTICS §9.3，不能自动换政策。
8. **Artifact：** 校验实际字节长度与 SHA-256、相对路径规范和真实路径仍在 case 内；拒绝软链逃逸和路径别名。artifact 的 SHA 仅证明这些字节一致，不认证 REA 记录来源；后者另查 canonical envelope、profile、引用和记录身份。
9. **Oracle：** `cwd` 及 target_files 的相对路径以导入清单所在目录解析，并在绑定记录中保存解析结果；argv 不经 shell。注册时解析实际 executable，核验清单覆盖 wrapper、目标及声明 helper，记录解释器版本/身份、环境、架构和 ABI 绑定；每次运行前后检查。仅导入清单不自动启动目标。batch_resettable 必须已有真实 reset 验证记录。
10. **Observation：** 输入/输出键与签名完全相同，typed values 相容；sample/request/source 身份与 dataset 一致；ok 不允许 error，失败不带正常 outputs。observed 必須有实际时间与非负 duration；expected_fixture 使用 null 时间，不冒充调用。
11. **Dataset：** 样本 ID 全局唯一，split 清单与行内标签、文件摘要一致，输入计划覆盖且只覆盖实际清单，planned 等于计划行数。相同 typed 输入的重复调用必须在同一 split，避免训练/留出泄漏；重复次数不增加独特输入数。source_kind 与每行记录一致，Oracle 绑定不变。
12. **预期材料：** expected_fixture 可用于格式、参考数值和拟合练习；不能计为原目标观测、fresh Oracle 调用或提升 fidelity。只有真实 observed 记录可进入对应目标回放计数。source_kind=reference_fixture 仍必须单列，不能增加 original_target 数。
13. **拟合：** 模板与 dataset 输入/输出同名同类型，域相容；至少有非空 train/validation/holdout。冻结候选和政策后验证。`fit=fitted` 必须绑定有效冻结候选及实际 backend 身份，train 有有效训练数据，预定 validation/holdout 全部完成且有效比较数分别大于零，并达到预先固定的政策。失败、域外和未执行槽位不能通过过滤消失；条件不足时保留候选与日志，fit 不得为 fitted。analytic_baseline + closed_form 首版仅支持 affine；其它模板须用 reference/handwired + adam/sgd。反向组合明确拒绝，不静默换后端。
14. **采样模型比较：** sampled_fp32 强制 sample_source 和政策；inputs 或 dataset 的每个选定输入在请求域内。数据集只提供输入时不会给 sample_comparison 升级为 target_validation。BV exact 模式不接受浮点模型。
15. **候选验证：** verify_candidate 的 mapping 以 candidate 为左侧、dataset/Oracle 为右侧；live Oracle 的签名和 domain 必须与 dataset 对应的目标绑定一致。splits 显式选择并落盘；最终拟合验证使用尚未消耗的 holdout。
16. **查询建议：** suggest_inputs 首版所有模型必须同名同类型签名且域相容；不猜多模型对齐。找到的分歧输入是建议或模型反例，不自动是原目标反例。
17. **预算：** solver_soft_time_ms <= solver_hard_time_ms <= wall_time_ms；所有子任务受总 deadline 约束。每次真实目标调用均占 max_oracle_calls，双 Oracle 每个输入至少占两次，重复性测试同样计入。命令或客户端可以省略配置，但进入 service 前必须展开默认值并落盘。
18. **结果：** 只允许内部 verifier 写 result。proved 必须具有有效模型/域/映射身份、非空域记录和真实 solver artifact；SAT 反例须经独立 evaluator。matched 必须有大于零且完整的有效观测；结果存在也不说明 job 完成。状态与证据互相矛盾是内部错误。
19. **Fidelity：** 由绑定语义摘要、来源包络、Oracle 身份、观察点/参数映射、输入计划和政策的本地有效记录派生；历史外部结论仅为附件。partial 不升级 sampled_match；重新关联来源不能复用旧 target verdict。
20. **身份与版本：** 语义对象按 INTERFACES 的 ASCII 键顺序规范化；原件单独按字节哈希。语义 profile 与 schema 版本未知时拒绝执行；不要网络加载任意外部 schema。

## 计数定义

counts 面向“计划样本槽位”，重复输入的重复请求各占一个槽位。planned 是计划总数；attempted 是开始处理的槽位（含执行前域检查）；completed 是形成有效比较的槽位；matched+mismatched=completed；failed 是开始处理后协议、崩溃、非有限、超时或取消的失败槽位；out_of_domain 单列。终态要求 `completed + failed + out_of_domain = attempted <= planned`。未开始的槽位为 planned-attempted。

真实 Oracle 调用次数、不同输入数、双 Oracle 左右两侧调用数另外保存在执行 artifact；不能从 paired counts 反推。两个目标中一个失败时，该成对槽位为 failed，另一个的成功调用仍完整保存。

## 解析后的默认实验预算

```json
{
  "wall_time_ms": 120000,
  "solver_soft_time_ms": 10000,
  "solver_hard_time_ms": 15000,
  "max_candidates": 50000,
  "max_ast_nodes": 9,
  "max_oracle_calls": 512,
  "max_iterations": 2000,
  "seed": 20261019
}
```

这些是资源配置，不是性能承诺。M1 标准 validator 编译与真实后端 gate 的状态应记录到产品验收文件，不填写在本实施包样例里。
