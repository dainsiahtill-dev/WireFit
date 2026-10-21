# 研究实验协议（RESEARCH-PROTOCOL）

本文件是**规范性**文档。它同时约束两套独立实现：

- `src/research/recipe.ts`（TypeScript，产品侧 L1 复算器）
- `artifacts/research/vmde/directions/audit.py`（Python，的道侧 L2 独立审计器）

两套实现**不共享任何代码**，只共享本文件的语义。任何一方偏离本文件即为缺陷，
不是风格差异。`tests/research-recipe.test.ts` 与
`tests/research-audit.test.ts` 用同一份固定 fixture 断言两侧输出逐字节相同。

---

## 0. 名词与角色

| 名称 | 含义 |
| --- | --- |
| 方向（direction） | 一个可证伪的研究问题，编号 `D01`–`D17` |
| 规格（spec） | 方向的事先注册文档：假设、对照、划分、阈值、检查、否定声明 |
| 计划（plan） | 冻结的规格，其 `plan_sha256` 进入结果 |
| 语料（corpus） | 已存在的证据文件，按角色（role）寻址 |
| 角色（role） | 证据或产物的稳定名字；检查只引用角色，不引用路径 |
| 观察（observation） | 由派生式（derivation）复算出的标量值 |
| 判定（verdict） | `supported` / `refuted` / `inconclusive` / `not_run` |

`refuted` 是**完成的分析**，不是进程失败。被证伪的主张仍然是有效科学产出，
CLI 退出码保持 0。

---

## 1. 五阶段与顺序

```
plan → develop → freeze → evaluate → recheck
```

| 阶段 | 输入 | 输出 | 不可逆约束 |
| --- | --- | --- | --- |
| `plan` | 方向 id | 冻结规格、`plan_sha256`、划分校验 | 阈值在此之后不得修改 |
| `develop` | `{train, validation}` | 候选（candidate）+ 开发产物 | **看不到 holdout** |
| `freeze` | 候选 | `frozen_candidate_sha256` + 冻结产物 | 之后候选不可变 |
| `evaluate` | holdout + 冻结候选 | 逐行评估产物 | 只能读冻结候选 |
| `recheck` | 已存产物 | L1 复算结论 | 只读，不重跑实验 |

审计器必须能断言 `develop.finished_at <= freeze.started_at <= evaluate.started_at`。

### 1.1 划分的诚实边界（不得宣称"物理隔离"）

第一道闸门是**结构性不披露**：`develop` 阶段的上下文类型里**不存在**
`holdout` 属性（不是 `undefined`，是这个属性根本不在类型上）。实现无法通过
上下文意外取到 holdout 行标识。

**这不是操作系统级隔离。** 一个直接 `readFile()` 打开语料文件的实现可以绕过
第一道闸门。因此第二道闸门才是真正的判定：审计器扫描 `develop` 阶段产物，
**若其中出现任何 holdout 行标识，该方向判为 `inconclusive`，阻塞码
`SPLIT_LEAKAGE`**（不是 `refuted`：泄漏使证据不可信，而不是使主张为假）。

行标识按**记号边界**匹配：命中位置的前后字符不得是 `[A-Za-z0-9_-]`。朴素的
子串搜索会在一个标识是另一个标识的前缀时误报（例如 `four-cell-1` 是
`four-cell-100` 的子串），这类误报会把正确的实验判成泄漏。

本文件明确禁止在任何报告、README 或结论中把该机制描述为"物理隔离"。

---

## 2. 划分规则

规则与种子**归规格所有**，请求不得修改。

```
bucket = sha256(seed + "\0" + row_id) 的前 4 字节，按大端解释
bucket 0,1 → train
bucket 2   → validation
bucket 3,4 → holdout
```

- `seed = 20261019`
- 摘要输入是 UTF-8 字节串 `seed` 的十进制表示 + `U+0000` + `row_id`。
- `row_id` 的比较不做任何归一化：按原始字符串参与摘要。

预注册计数（运行器重算；不符 ⇒ `SPLIT_COUNT_MISMATCH` ⇒ `inconclusive`）：

| 划分单元 | 总行数 | train | validation | holdout |
| --- | --- | --- | --- | --- |
| `grid` | 896 | 332 | 177 | 387 |
| `accepted_functions` | 14 | 4 | 4 | 6 |
| `segmentation_scenarios` | 12 | 4 | 4 | 4 |

计数已用上述规则在本仓库实测确认。

### 2.1 划分单元

| 划分单元 | 行标识来源 | 行标识字段 | 总行数 | train | validation | holdout |
| --- | --- | --- | --- | --- | --- | --- |
| `grid` | `kernel-replay/run-t48nkuwa/observations.jsonl` | `id` | 896 | 332 | 177 | 387 |
| `accepted_functions` | `module-slots/fresh-business-code.json` | `candidates[*].entry_va` | 14 | 4 | 4 | 6 |
| `segmentation_scenarios` | `segmentation-results/run-label-replay-20261020/result.json` | `scenarios[*].id` | 12 | 4 | 4 | 4 |
| `kernel_layout_offsets` | `grid-kernel-analysis/facts.json` | `kernel_layout[*].offset` | 15 | 4 | 5 | 6 |
| `module_image_intervals` | `module-image/vmde-main-v2-20261020.json` | `coverage.pages[*].rva` | 223 | 79 | 50 | 94 |
| `private_closure_instructions` | `private-closure/analysis/062d0356.callpop.json` | `listing[*].pc` | 308 | 128 | 73 | 107 |
| `module_slot_events` | `module-slots/run-ezesyU/receipt.json` | `trace_raw.events[*]`（数组下标） | 15 | 7 | 2 | 6 |

划分单元与它的证据角色由目录 `src/research/corpus.ts` 的 `CORPUS_UNITS` 表定义；
方向必须在自己的 `evidence_pins` 中声明该角色，否则运行器报
`SPLIT_SOURCE_UNDECLARED`。

---

## 3. 受限路径语言

```
path    := segment ('.' segment)*
segment := NAME | NAME '[' '*' ']' | NAME '[' INT ']'

NAME := [A-Za-z_][A-Za-z0-9_]*
INT  := [0-9]+（十进制，无符号，无前导零以外的限制）
```

示例：`groups[*].cases[*].matched`、`functions[*].outside_body_count`。

### 3.1 求值语义

路径从文档根开始求值，**当前值是一个候选节点列表**（初始为 `[root]`）。

对每个 segment：

1. `NAME`（无下标）：对每个候选节点，要求它是**对象**（非数组、非 null），
   且拥有 `NAME` 属性；取其值作为新的候选节点。
2. `NAME['*']`：先按第 1 步取 `NAME` 属性，要求其值是**数组**；把数组的每个
   元素按原顺序展开为候选节点。
3. `NAME[INT]`：先按第 1 步取 `NAME` 属性，要求其值是**数组**且
   `INT < length`；取第 `INT` 个元素作为候选节点。

路径求完后，**候选节点列表就是被选中的节点集合**。

任何一步的类型不符、属性缺失或下标越界 ⇒ `RECIPE_PATH_INVALID`，
该检查降级为 `inconclusive`。

### 3.2 标量与 `field`

选中节点的值：

- `derivation.field` 存在：每个选中节点必须是对象且拥有该属性，取其值。
- `derivation.field` 缺省：选中节点本身就是值。

取到的值必须是**标量**（字符串 / 数字 / 布尔 / null），否则
`RECIPE_VALUE_TYPE_MISMATCH`。

### 3.3 规范化

数字若是有限整数则规范化为整数（`1.0` 与 `1` 等价）。Python 实现必须把
`float` 且 `is_integer()` 的值折叠为 `int`，否则两侧的集合比较会不一致。

---

## 4. 内核（kernel）

方向只提供**数据**（`derivation` + `expected`）；算法全部在这里。
**17 个方向的审计代码量为 0。**

| kernel | 定义 | 返回类型 |
| --- | --- | --- |
| `row_count` | 路径选中的节点数 | number |
| `distinct_count` | 选中节点的 `field` 值的**不同标量值**个数 | number |
| `field_count` | 选中节点中 `field == value` 的个数 | number |
| `field_sum` | 选中节点中 `field` 为整数的和 | number |
| `field_min` | 选中节点中 `field` 为整数的最小值 | number |
| `field_max` | 选中节点中 `field` 为整数的最大值 | number |
| `all_equal` | 选中节点**非空**且全部 `field == value` ⇒ `true` | boolean |
| `any_equal` | 至少一个选中节点 `field == value` ⇒ `true` | boolean |
| `set_equality` | 见 §4.1 | boolean / string |
| `file_sha256` | 被钉文件字节的 sha256（小写 hex） | string |
| `byte_pattern_count` | 被钉二进制中 `pattern_hex` 字节序列的出现次数（**重叠计数**） | number |

补充规则：

- `field_sum` / `field_min` / `field_max` 要求**所有**选中值都是整数；
  出现任何非整数值 ⇒ `RECIPE_VALUE_TYPE_MISMATCH`。选择集合为空 ⇒
  `RECIPE_EMPTY_SELECTION`。因此不提供 `field_mean`：浮点均值在两种实现之间
  可能产生跨实现差异。
- `all_equal` 在空集合上返回 `false`（不是错误），并记录 `selected:0`。
- `any_equal` 在空集合上返回 `false`。
- `distinct_count` / `field_count` 在空集合上返回 `0`。
- `byte_pattern_count` 的 `pattern_hex` 必须是偶数长度的 hex；空模式返回 `0`。

### 4.1 `set_equality` 的两种形态

由**第二个角色是否出现**唯一决定，不存在歧义：

1. **出现 `second_artifact_role`（且 `second_path`）**：取 A 路径上的
   `field` 值集合与 B 路径上的 `field` 值集合，返回
   `A == B`（**布尔**）。此时比较器用 `eq` / `ne`。
2. **不出现 `second_artifact_role`**：返回 A 路径上 `field` 值集合的
   **序列化字符串**。此时比较器用 `identical_set` / `subset` / `superset`。

### 4.2 集合的序列化

集合成员用**带类型前缀**的编码，转义歧义：

| 值 | 编码 |
| --- | --- |
| `null` | `z:null` |
| `true` / `false` | `b:true` / `b:false` |
| 整数 `n` | `n:<十进制>` |
| 字符串 `s` | `s:<原字符串>` |

集合 = 编码去重后的集合，按**码点序**升序排列，用 `|` 连接。空集合 = 空字符串
`""`。两侧实现都必须按码点序排序（Python 默认字符串序即码点序；TypeScript
必须用码点比较，不得用 UTF-16 码元默认序）。

---

## 5. 比较器

| 比较器 | 语义 |
| --- | --- |
| `eq` | 观测 `==` 期望（数字按数值比较；类型不同 ⇒ `false`） |
| `ne` | `eq` 的取反 |
| `gte` / `lte` / `gt` / `lt` | 数值比较；任一侧非数字 ⇒ `false` |
| `identical_set` | 两侧按 §4.2 解析为集合后相等 |
| `subset` | 观测集合 ⊆ 期望集合 |
| `superset` | 观测集合 ⊇ 期望集合 |

`identical_set` / `subset` / `superset` 的两侧都按 `|` 分隔解析（空串为空集合）。

---

## 6. 判定代数

### 6.1 主张级

设某主张的检查按 `role` 分成 `primary` 与 `negative_control` 两组。

```
若存在外部阻塞码            ⇒ inconclusive
若存在无法求值的检查        ⇒ inconclusive（阻塞码为求值错误码）
若 primary 组非空           ⇒ inconclusive（NO_NEGATIVE_CONTROL）
若存在 primary 检查未通过   ⇒ refuted
若存在 negative_control 通过 ⇒ inconclusive（NEGATIVE_CONTROL_DID_NOT_FAIL）
否则                         ⇒ supported
```

顺序如上：先判阻塞，再判负控数量，然后才是"未通过 ⇒ refuted"。

### 6.2 负控约定（关键）

**负控检查必须失败。** 负控构造为"在被故意破坏的产物上，本应得到的正确值
不得出现"：即 `expected` 取"若度量被错误接受就会出现"的那个值，而实际观测是
度量**拒绝**该产物后的值，因此比较结果为"未通过"。

于是：

- 负控**未通过** = 期望行为 = 支撑 `supported`。
- 负控**通过** = 度量接受了它本应拒绝的产物 = 度量**无判别力** ⇒
  `inconclusive`，**不是** `supported`。

负控检查不参与"至少一条检查未通过 ⇒ refuted"的规则——否则
"全部 primary 通过且负控按预期失败"将是自相矛盾的状态。

### 6.3 方向级

方向判定 = `primary_claim_id` 指向的那个主张的判定。

**不使用"取最差"规则**：辅助主张被证伪不会拉低方向判定。次要主张的判定照样
记录在结果里。

### 6.4 外部阻塞码

| 阻塞码 | 触发条件 |
| --- | --- |
| `EVIDENCE_PIN_MISMATCH` | 稳定语料的实测摘要与规格声明不符（证据变了，不是科学结论被推翻） |
| `SOURCE_CHANGED` | 读取期间证据被改写 |
| `SPLIT_COUNT_MISMATCH` | 划分实算计数与预注册计数不符 |
| `SPLIT_LEAKAGE` | develop 产物中出现 holdout 行标识 |
| `BUDGET_EXHAUSTED` | 预算耗尽，评估未完成 |
| `AUDIT_METRIC_MISMATCH` | 复算与记录不一致（证据不自洽） |
| `NO_UPSTREAM_IMAGE_OBSERVATION` | 需要上游图像观测但没有 |

---

## 7. 证据钉（pin）

两类钉：

| 类别 | 例子 | 策略 |
| --- | --- | --- |
| 稳定语料 `stable_corpus` | `exports/vmde-20261020/unpacked_vmde.exe`、`module-image/vmde-main-v2-20261020.bin`、`startup-compat/build/candidate.exe` | `expected_sha256` **强制** |
| 道产物 `lane_artifact` | `native-kernel/observations-legacy896.json`、`caller-layout/kernel-return-review.json` | `expected_sha256: null`，只记录实测摘要 |

原因：道会重跑并覆盖自己的产物，把道产物的摘要钉死在产品里会让产品一遇到
道重跑就失效。稳定语料是 write-once 的，必须钉死。

解析顺序：

1. **路径白名单**：默认 `artifacts/`、`exports/`、`fixtures/`、`tools/`。
   拒绝绝对路径、盘符、反斜杠、`..`、NUL。
2. `stat`：必须是常规文件，且 ≤ 64 MiB。
3. **读前**摘要：与 `expected_sha256` 不符 ⇒ `EVIDENCE_PIN_MISMATCH`。
4. 读取 `size + 1` 字节以发现并发增长。
5. **读后**再摘要一次，并比对 mtime/size ⇒ 不符 ⇒ `SOURCE_CHANGED`。

---

## 7.1 独立性声明（对计划的有意偏离）

计划的原始表述是「17 个方向各自独立实验目录 + **一个** 共享审计器」，并把
独立性放在**实验级**而不是目录级。本实现遵循该偏离，在此显式声明：

- **实验级独立**：17 个方向各自作为独立实验。每个方向有自己的 `plan.json`
  （自己的假设、对照、划分单元、预注册阈值、负控）、自己的运行产物、自己的
  报告和自己的判定。任何一个方向的重跑**不会**改动其他方向的结论。
- **目录级共享**：17 个方向共用一个 `directions/` 目录与**一个**审计器。
  原因是审计器必须逐字实现同一份受限路径语言与内核语义（本文件），17 份
  独立审计器会产生 17 份可能互相漂移的规范实现，这正是本协议要避免的风险。
  **17 个方向各自需要定制审计逻辑的代码量为 0**：方向只提供数据
  （`derivation` + `expected`），算法全部在审计器的内核解释器里。

审计器与清单复核器的**源文件**在产品树内（`tools/research/audit.py`、
`tools/research/verify-manifest.py`），冻结的道携带它们的副本并由道清单钉住
其摘要：审计器本身被改动也会使道失效。

---

## 8. 三层审计

| 层 | 实现 | 语言 | 作用 |
| --- | --- | --- | --- |
| L1 | `src/research/recheck.ts` | TypeScript | 从 case 内已存产物复算，检出 case 内篡改（便利层） |
| L2 | `artifacts/research/vmde/directions/audit.py` | Python（仅标准库） | **按本文件独立重实现**，从磁盘原始产物重算（**权威层**） |
| L3 | L1 ↔ L2 | — | 两者 `observed` 不一致 ⇒ 该主张降级为 `inconclusive` |

L2 **只读、绝不重跑实验**，只从"冻结计划 + 已记录产物"重新派生。
实现形态：**一个** `audit.py` + 内嵌内核解释器，循环跑 17 份独立的
`plan.json` + `checks.json`——不是 17 个定制审计器，是一个通用解释器跑 17 份数据。

### 8.1 审计判定

对每条检查：

```
复算一致  且  观测 满足 期望  ⇒ 通过
复算不一致                     ⇒ AUDIT_METRIC_MISMATCH ⇒ 主张降级为 inconclusive
```

**审计不一致绝不能被静默修掉。** 复算失败必须写进 `limitations`。

---

## 9. 结果结构

```
verdict / verdict_reason / primary_claim_id
claims[]      每条含 hypothesis、control、failure_condition、metrics、checks、limitations、not_claimed
identity      request_sha256、plan_sha256、frozen_candidate_sha256、corpus_row_counts、corpus_holdout_row_ids_sha256
counts        planned/attempted/completed/matched/mismatched/failed/out_of_domain
evidence_pins[] / phases[] / artifacts[] / audit / limitations[] / error
```

`counts` 的研究侧映射：

| 字段 | 含义 |
| --- | --- |
| `planned` | 划分单元的总行数 |
| `attempted` | 求值的检查数 |
| `completed` | 成功求值的检查数 |
| `matched` | 通过的 `primary` 检查数 |
| `mismatched` | 未通过的 `primary` 检查数 |
| `failed` | 无法求值的检查数 |
| `out_of_domain` | 恒为 0（研究实验不做域外计数） |

---

## 10. 共同声明（所有方向）

任何方向都**不**主张：

- 自然应用输入被复现；
- 整程序等价；
- `runnable_verified`；
- 原实现被复原（等价重构 ≠ 实现复原）。
