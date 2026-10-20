# 初始模型、请求和数据材料

这些文件是 Codex 建立实现和验收时使用的合同样例。它们不是已运行的产品结果。根目录是本实施包目录，ArtifactRef 的 relative_path 均相对该根；`contract-fixture-index.json` 指定逐文件/逐行应使用的 schema。

## 模型

| 文件 | 用途 | 期待 |
| --- | --- | --- |
| model.mba-u8.json | `(a xor b) + 2*(a and b)` | 与 BV8 add 在整个输入域等价 |
| model.add-u8.json | 简化候选 `a+b` | 供真实 Z3 验证 |
| model.add-u8-wrong.json | 故意多加 1 的错误候选 | 应产生可回放的模型反例 |
| model.wide-shift-u8.json | BV64 计数控制的 BV8 左移 | count>=8 时为零，256 不先截为零 |
| model.increment-u64.json | BV64 加一 | 全 1 回绕；大于 2^53 的值精确保留 |
| model.affine-initial.json | 可调 a/b 的 FP32 affine 假设 | 不是未知目标的既有真值 |
| model.affine-clamp-initial.json | 固定 [-2,+2] 的 clamp 假设 | a/b 是初始值，等待拟合 |
| model.piecewise-initial.json | 固定零断点的两段假设 | 演示参数命名与固定 knots |

数学上已知的期待只用于设置测试；真正的 `proved/refuted` 必须等产品调用真实 solver 后才出现。手写模型不包含原二进制保真性声明。

## 请求

`request.*.json` 覆盖 simplify、精确模型对比、带显式政策的数值样本比较、Handwired 拟合、历史候选检查与候选分歧选样。每个请求含展开后的预算。

这里的 model_id/dataset_id 是稳定的 fixture ID。测试仓库可按这些 ID 注册对象；实际 CLI 导入返回本地 ID 时，演示驱动必须使用返回的映射更新请求，不能把可读 ID 当内容摘要。外部 artifact 首先经 `dataset import --artifact-root` 或请求附件导入步骤进入 case，不允许在实验中绕过 case 的路径与摘要校验直接读取源目录。

数值样本比较不会产生模型等价证明。`request.verify-initial-recorded.json` 故意检查初始候选，不能假设通过；它使用的 expected_fixture 也不能产生原目标 fidelity。`request.fit-handwired.json` 是拟合配置样例，不承诺给定预算下达到 bitwise 目标；失败或没有额外收益都是应正常保存的结果。

## 数据

`dataset.numeric-expected.json` 引用 32 个不同 FP32 输入，范围 [-4,+4]。train/validation/holdout 分别为 16/8/8，无同输入跨 split。

生成真值定义为 `strict_clamp(f32(f32(1.5*x)+(-0.25)), -2, +2)`。每行均标记 `record_kind=expected_fixture`、`source_kind=reference_fixture`，观测时间和耗时为 null。这是公开的参考素材，没有假装调用过任何原二进制。参数真值单独放在 numeric-reference-definition.json；learner 数据接口不应获得该文件。

原始数值与输出采用 FP32 位模式存储。固定训练/验证/holdout 后，不因结果不好而交换 split、修改容差或删除失败点。更多隐藏种子和样本需由 Codex 在测试环境生成；本包 32 行不足以衡量真实研究收益。

## 可实际调用的自有 Oracle

`oracle.reference-fp32.json` 引用本包 `fixtures/oracle_fp32.py` 的实际 SHA-256。这个 wrapper 实现同一自有夹具，使用 JSONL fresh_process 协议；注册时还要解析并记录当前 Python 解释器的身份。它用于验证 runner，并不意味着实施包已包含 WireFix runner。

应由真正实现的 collect_dataset 再采集一份 `record_kind=observed` 的数据，才能验收实际执行链。source_kind 仍为 reference_fixture。原目标验证需要换成明确选定的实际目标和独立 wrapper，不能只改这个标签。

## 合同反例必须加入实现测试

至少检查：导入模型携带 fidelity/verdict；空输出映射；两个输入合并；数值比较缺输入集或政策；BV64 字符数错误；producer 缺口被补成自由输入；重复输入跨 split；零有效 holdout；expected_fixture 冒充 original_target；篡改 artifact 字节；取消后迟到结果。这些分别由 schema、语义 validator、来源校验与生命周期处理拒绝。

实际检查范围与尚未运行项见 `docs/HANDOFF_VALIDATION.md`。它是实施包质量记录，不能替代产品 `docs/ACCEPTANCE.md` 中的集成 gate。
