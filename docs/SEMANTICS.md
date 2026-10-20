# WireFix 语义与验证规范

本文件是实现时的规范性约束。JSON Schema 只负责结构；下面的跨字段、操作和证据规则必须由程序执行校验。首版规范版本为 `wirefix.bv.total.v1` 和 `wirefix.fp32.templates.v1`。

## 1. 观察范围

一个 model 只定义明确声明的输入到输出的关系。首版观察对象为 `declared_outputs`，不包含时间、异常、持久内存、全局状态、系统调用和并发行为。

来源范围分别为：

- `expression`：纯表达式，可能包含显式切片输入。
- `exported_model`：从 provider 的完整受支持表示导出的模型。
- `trace_slice`：特定轨迹或条件下的局部模型。
- `behavior_model`：根据样本或假设建立的候选行为模型。

原二进制保真度另设 `unvalidated / sampled_match / sampled_mismatch / unavailable / not_applicable`，但它是本地验证记录的派生显示值，不属于可导入 model 的可信字段。新导入对象从 unvalidated（有原目标来源）或 not_applicable（仅自定义数学表达式）开始。导入文件、LLM 和原始 Evidence 中的历史结论只能作为未经信任的来源声明保存。来源范围、模型证明、原目标样本和数值拟合互不自动升级。

## 2. 类型和线上值

### 2.1 位向量

V1 的宽度只允许 8、16、32、64。中间值也必须满足这个集合；最终是 64 位并不使 BV128 中间值自动受支持。

同一 BV 位模式没有默认的有符号含义。有符号解释由 `bv_slt`、`bv_sle`、`bv_ashr` 和 `bv_sext` 等操作明确指定。

线上值采用：

```json
{"kind":"bv","width":64,"bits":"0x0020000000000001"}
```

`bits` 必须是小写、带 `0x`、长度恰为 `width / 4` 的十六进制字符串。任何读取、缓存、摘要、排序和序列化过程都不能把 BV64 先转成 JS Number。地址和 source varnode offset 也使用字符串。

### 2.2 Bool

```json
{"kind":"bool","value":true}
```

Bool 与 BV8 不可隐式互换。`bv_nonzero` 明确把非零位向量转换为 Bool；`bool_to_bv` 明确输出 0 或 1。Ghidra 字节分支条件为非零即真，不能只判断等于 1。

### 2.3 FP32

```json
{"kind":"fp32","bits":"0x80000000"}
```

上例为负零。普通 JSON number 无法作为浮点位模式的规范存储。FP64 只可作为保留的原始观测类型；V1 数值模板不自动接受 FP64 执行语义。

首版数值模型只接受声明域内的有限 FP32 输入，并要求实际执行的中间结果满足有限性约束。遇到 NaN、Infinity 或溢出必须按政策返回不支持/失败观测，不能删掉该数据点再报告满分。

## 3. BV DAG 操作表

以下 `w` 是输出/数值操作位宽，`u_w(x)` 是对 `2^w` 取模后的无符号表示，`s_w(x)` 是同位模式的补码有符号解释。

| op | 输入 | 结果规范 |
| --- | --- | --- |
| `const` | 无，attrs.value 为 typed value | 原样的类型化常量 |
| `copy` | T | 相同 T |
| `bv_add` / `bv_sub` / `bv_mul` | BVw, BVw | `u_w(a+b)` / `u_w(a-b)` / `u_w(a*b)` |
| `bv_neg` | BVw | `u_w(-a)` |
| `bv_and` / `bv_or` / `bv_xor` | BVw, BVw | 对固定 w 位运算 |
| `bv_not` | BVw | `u_w(~a)` |
| `bv_eq` / `bv_ne` | 同宽 BV | Bool |
| `bv_ult` / `bv_ule` | 同宽 BV | 无符号比较，Bool |
| `bv_slt` / `bv_sle` | 同宽 BV | 补码有符号比较，Bool |
| `bool_and` / `bool_or` | Bool, Bool | Bool |
| `bool_not` | Bool | Bool |
| `bv_nonzero` | BVw | `a != 0`，Bool |
| `bool_to_bv` | Bool | 输出类型声明的 BVw，值为 0 或 1 |
| `select` | Bool, T, T | 相同类型的 true/false 值 |
| `bv_shl` | BVw, BVk | 计数按完整无符号值解释；计数 >= w 时 0，否则 `u_w(a << count)` |
| `bv_lshr` | BVw, BVk | 计数 >= w 时 0，否则逻辑右移 |
| `bv_ashr` | BVw, BVk | 计数 >= w 时全符号位，否则对 `s_w(a)` 算术右移后归一化 |
| `bv_zext` | BVn | 输出 w > n，用零扩展 |
| `bv_sext` | BVn | 输出 w > n，用符号扩展 |
| `bv_extract` | BVn | attrs.low 给出低位索引，取输出宽 w 位；要求 `0 <= low` 且 `low+w <= n` |
| `bv_concat` | BVa, BVb | 第一个输入为高位，输出宽 a+b，且宽度仍在支持集合 |

除法、余数、指针、数组、LOAD/STORE、调用、未知 intrinsic 和 FP 运算不属于这个 profile。未支持 opcode 不能降低成 0、COPY、任意 uninterpreted function 或无约束常量后继续声称原模型完整。

Carry/overflow 在后续子任务中可降低为本表操作的明确表达式；V1 schema 不把它们列为独立 op。降低规则必须先验证，不能按机器 flags 名字猜测。

### 3.1 移位的关键规则

先比较完整计数，再做任何变宽处理：

```text
shl(BV8(1), BV64(256)) = BV8(0)
ashr(BV8(0x80), BV64(256)) = BV8(0xff)
```

不允许先将 BV64(256) 截为 BV8(0)。不自动附加 `& 31` / `& 63`；目标 ISA 的计数掩码必须由所采用的语义显式表达。BigInt 也必须先 guard，避免对巨大计数执行实际左移。

Z3 要求移位操作数适配同一 bit-vector sort 时，也先用完整计数表达 `count >= w`，再在受保护分支中扩展/截取计数。

### 3.2 p-code 映射需要核查的细节

- `INT_2COMP` 对应 `bv_neg`；`INT_NEGATE` 对应 `bv_not`。
- `INT_LESS` 与 `INT_SLESS` 分别对应 unsigned 与 signed 比较。
- `INT_RIGHT` 与 `INT_SRIGHT` 分别为逻辑与算术右移。
- `PIECE` 的第一个输入是高位。
- `SUBPIECE` 的偏移按字节，不按位；转换到 `bv_extract.low` 要乘 8。
- 比较的 p-code 输出通常是字节，内部 Bool 必须显式桥接。
- `CBRANCH` 的条件以非零为真。
- raw RETURN 的 input0 是返回目的地址，不能当作函数返回值。HighFunction 恢复的返回值必须按实际字段取得，缺失就保持缺失。
- `INDIRECT` 携带未知修改关系，不能按 COPY 消除。

官方依据：[p-code operations](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html)、[additional operations](https://ghidra.re/ghidra_docs/languages/html/additionalpcode.html)。最终 mapper 必须针对锁定版本的实际序列化字段测试。

## 4. 模型结构校验

1. `schema_version` 和 `semantics_profile` 受支持。
2. Input ID 与 node ID 全局唯一，输出引用存在。
3. 节点依拓扑顺序保存，args 只引用输入或已出现节点，无循环。
4. 操作数数量、输入类型、输出类型、位宽和 attrs 严格匹配操作表。
5. 常量位宽、字符数与值范围正确；Bool 常量不接受 0/1 代替 boolean。
6. `copy` 不承担隐式 cast；`select` 不做分支类型提升。
7. Domain 约束只绑定已声明输入，typed value 与输入类型相容；不得依赖候选输出。
8. 最大输入、输出、节点和文件规模在预算内。
9. 没有来源定义的值不能自动补零。
10. 被 producer 截断或缺失定义造成的空洞必须报 incomplete evidence；不得自动变成自由输入。

**显式切片 cutpoint 是另一种操作：** 用户或分析算法有意选择完整图中的一个既有 varnode 作为切片边界。它成为新的 model input 时，须保留原 SSA 身份、来源位置和已知相等关系，scope 改为 expression。这个 model input 未经验证不能充当原函数 ABI 参数。它不能修复 producer 丢失的图。

同一存储位置的不同 SSA 版本不合并；不同内存读也不因地址文本相同就当同一个值。别名信息不足时保留未知。

切片要保存所选源操作、观察位置、execution_guard 或显式 unknown，以及是否绑定函数返回值。数据流闭合不等于控制流闭合。即使可以对抽象切片证明恒等式，guard 未知也不能推导原函数对这些输入会执行该片段。只有符合观测点的 Oracle 绑定才允许目标回放。

## 5. CFG 和 phi 的增强 gate

首版必选直线表达式；无环 CFG 增强只有满足下列条件才可启用。未满足不阻塞其它产品场景，但该能力不得列为已支持。

- 入口唯一；所有控制流引用闭合；无 SCC 循环；终结行为已知。
- 每条边保留 source block/out slot、target block/in slot、条件角色。
- phi 的参数按 incoming edge slot 绑定，不按地址排序。
- 平行边、缺失条件、BasicBlockModel 与 high-p-code block 无法对齐时拒绝。
- 普通定义支配使用；phi 参数定义支配对应前驱边。
- 所有可达叶块具有受支持、同签名的返回。
- 在删除与输出无关节点前检查可达副作用。不能依靠 `is_dead` 忽略未知 STORE/CALL。
- 由入口和条件递推边 guard，再将 phi 降为 select。不得创建未受约束的 reachability 自由变量。

纯 BV DAG 的 select 两侧均为 total function，因此可安全求值。此结论不扩展到内存访问或有异常副作用的分支。

HighFunction 中没有 LOAD/STORE，并不证明原始机器指令没有栈访问或副作用。原始指令与反编译模型之间的对应记录只提供 provenance；没有独立的 ABI/原始语义审核，fidelity 仍从 unvalidated 开始。

## 6. 输入域

V1 的 domain 是对输入的约束合取。支持 BV 的 eq/ne、unsigned <=/>=、signed <=/>=；Bool 只支持 eq/ne；FP32 数值通道支持数值 eq/ne/<=/>=，有限性由 profile 强制。

空约束数组表示全类型域。BV 的值域已包含固定位宽边界。Float 的“全域”仍受 finite-only profile 限制。

模型自身契约 domain、用户请求比较 domain 分开保存。比较先验证请求 domain 非空，并验证它包含于两侧 model domain；不满足返回 `DOMAIN_MISMATCH`。只有显式请求新的缩小域才可继续，并产生新 run/domain 摘要。

不使用“现有正样本集合”偷偷替代用户要求的全域；若用户明确选择只比较样本，输出只能是样本结论。

## 7. 精确模型检查

设两个模型在共同输入上为 R(x)、C(x)，请求域为 D(x)，输出对齐映射为 O。

1. 校验 signature、input/output mapping、语义 profile 和 source scope。V1 输入映射必须覆盖两侧全部输入、保持类型且为双射；不允许缺失输入、隐式常量绑定或将独立输入合并。双方 domain 必须通过同一映射转换到公共输入空间。
2. 用独立 query 检查 D 非空；UNSAT 为 `DOMAIN_EMPTY`，UNKNOWN 为 inconclusive。
3. 验证 D 满足双方契约；无法证明包含关系则停止这项检查。
4. 构造 `D(x) AND OR_o(R_o(x) != C_o(x))`。
5. UNSAT -> `model_check.status = proved`，scope 只包含模型、域和这些输出。
6. SAT -> 导出完整 typed 输入，执行具体回放。
7. UNKNOWN/timeout/cancel/crash -> inconclusive；保留实际原因。

输出比较集合必须非空，每对类型相同且两侧均不重复。只比较部分输出时，报告同时列出所选和未比较输出。空输出集合返回请求错误，不能构造空 OR 后得到 proved。

两侧输入按明确 mapping 共享 Z3 变量；中间节点直接编译为表达式或用独立命名空间。不得因同名临时变量产生额外相等约束。每个任务用新 solver，不继承前次断言。

保存 SMT-LIB、Z3/WASM/adapter 版本、两侧 model hash、domain hash、输出映射、选项、耗时和求解状态。`proved` 是受信求解器对该模型问题的结果，不是经过独立 proof checker 验证的证书。

## 8. 反例回放

SAT 输入必须先在独立 BigInt evaluator 上确认：域成立，两侧输出不同。若不成立，返回 `INTERNAL_CONSISTENCY_ERROR`，不得把它提交为有效反例。

有原目标 Oracle 时另行回放：

| 观测 | 处理 |
| --- | --- |
| 原目标等于参考模型，且不同于候选 | 保存经原目标确认的候选反例 |
| 原目标不同于参考模型 | 报告提升或绑定不一致；不撤销数学模型事实，但阻止目标等价结论 |
| 没有原目标 Oracle | 保存模型反例，target_validation 为 unavailable |
| wrapper 协议错误、目标超时、身份变化 | 保存失败，不能当正常数值差异 |

反例缩减按指定输入域寻找更简单输入，每次都重新检查相关比较关系。仅做到局部缩减时称为“较小反例”，不能称“全局最小反例”。

## 9. 数值模板语义

### 9.1 明确舍入顺序

`wirefix.fp32.templates.v1` 固定为 IEEE binary32、roundTiesToEven、保留 signed zero、gradual underflow，不启用 flush-to-zero。`f32` 是按该规则向 binary32 舍入；每个声明的舍入点独立执行，不融合。实际目标采用其它模式时不属于这个 profile，不能自动声称一致。初始模板：

- affine：`y = f32(f32(a * x) + b)`。
- affine_clamp：先按 affine 算出 t，再执行 `t < lo ? lo : t > hi ? hi : t`；lo、hi 是固定 FP32 值，要求 lo <= hi。相等时返回 t，保留 t 的零符号。
- piecewise_affine：knots 固定且严格递增；区间按左闭右开选择，最后区间右侧延伸；每段计算 `f32(f32(a_i*x)+b_i)`。是否连续不是默认假设。

固定分段点之外的输入遵循第一段或最后一段。每个模板的参数顺序、区间边界和输出 ID 必须写进 adapter map；不能依赖 JS 运算重排。

Handwired 首版采用 host-gated 的训练实现：host 按参考 FP32 规则选择 piecewise 区间、计算 clamp 饱和 mask；对连续有效分支求参数梯度，再按完整 batch 分母聚合。clamp 的 mask 每次参数更新后重新计算：门控导数 dy/dt 在饱和区和恰在边界时约定为 0，仅 lo < t < hi 时为 1；它不是参数梯度本身。内部区间的实数意图参数梯度仍为 dy/da=x、dy/db=1，再乘损失的上游梯度。此约定不改变前向相等分支。不要把普通 min/max 宏直接当作精确 FP32 min/max，不为绕过 boolean atom 打开 STE。

训练输出的 backend_semantics 与最终候选语义分别记录。若某宏不保持零符号，bitwise-fp32 后端一致性检查应失败或标为不支持；可以按预先声明的训练策略比较数值，但不能据此放宽最终目标验证。所有上游 range/grid/bit 前提实际校验，返回缓冲区在边界复制为稳定快照。

不启用 fast-math，不融合两个声明为独立舍入的操作。以实际 profile 和参考 evaluator 校验 Handwired 构造，必要时使用保留舍入的构建方式。不能从“CPU 和 Handwired 一致”直接推导目标原始 float64 或机器 FP 行为一致。

### 9.2 梯度与离散选择

训练损失可以使用 JS float64 累计，但冻结候选的参数和执行语义须重新按 FP32 编码。

Handwired 反传针对所建模型的实数运算意图。它不是 literal rounding 的导数，也不提供黑盒原程序的真实梯度。默认拒绝未声明的 boolean/index 梯度策略；硬阈值、未知分段结构由显式搜索负责。

梯度 sanity check 在非边界连续点与合适步长的实数参考比较；FP32 输出量化平台不应被当作梯度实现错误，也不能反过来宣称 literal FP32 可微。

拟合达到阈值后冻结模型与其摘要，再执行独立 holdout 和导出物验证。数据划分、容差、参数范围变化均产生新实验版本。

### 9.3 数值比较政策

FP32 模型之间的比较必须携带不可变的输入 artifact 或 dataset 和显式 comparison_policy。只对这些输入报告模型输出差异；不设置 model_check=proved。数值模型的抽样结果另存 sample_comparison，不冒充原目标验证。

- `bitwise-fp32`：比较 32 位位模式；+0 与 -0 不同。
- `tolerance-fp32`：对两个有限 FP32 输出 a、b，按 float64 计算 `abs(a-b) <= atol + rtol * max(abs(a), abs(b))`。atol、rtol 为有限非负配置值；+0 与 -0 相等。每个输出均通过才算该样本通过。
- `exact-bv`：BV/Bool 输出类型和位模式相同；不得对其使用浮点容差。

失败观测、缺少输出、非有限值与域外输入不得进入上述公式后变成通过。记录逐样本结果与计划分母；政策确定后不得按结果自动切换。数值阈值写为规范十进制字符串，解析为有限 Number 后检查；它们不是 typed FP32 位模式。

## 10. 结果状态的派生规则

结果的三个维度由 verifier 计算，不接受 LLM 提交的 verdict：

- `model_check`: proved/refuted/inconclusive/not_run。
- `target_validation`: matched/mismatch/partial/unavailable/not_run。
- `fit`: fitted/failed/not_run。

`target_validation=matched` 要求所选计划输入全部形成有效成对观测，数量大于 0，且没有差异。存在有效差异时为 mismatch；没有差异但计划执行不完整时为 partial。没有可用目标来源时为 unavailable。历史原目标样本重放与重新采样分别用 `mode=recorded/live` 标记。

所有计数保留 planned、attempted、completed、matched、mismatched、failed 和 out_of_domain。失败、超时、重复性异常不能从分母中消失。

`fit=fitted` 要求有冻结的有效候选、真实 backend 身份和有效训练数据；预定 validation/holdout 验证全部完成、分别有大于零的有效比较，并满足预先固定的政策。空的有效比较集合、失败/域外数据或未执行输入不能经忽略分母后变成拟合成功。训练正常退出本身只影响 job 状态。

模型 UNSAT 与原目标 sampled_mismatch 可以同时出现；报告应解释对应关系不一致。拟合 loss=0 不能更改 model_check。

目标验证及 fidelity 的身份至少绑定：model semantic hash、source-envelope hash、Oracle/目标身份、观察点与输入绑定摘要、dataset/input-plan hash、comparison policy hash。只因模型语义相同，不能把另一个原目标的 sampled_match 复用到当前来源。验证器检查绑定记录与本地观测后才派生 fidelity；partial 不升级为完整 sampled_match。数学模型检查可按自己的完整查询身份缓存，但不得代替这个目标验证身份。
