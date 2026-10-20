# Handwired 核心独立消融实测

本次结果：直接调用真实上游 `Circuit` 的 forward/backprop，在**预先提供运算结构**的条件下，可以学习简单仿射参数；也可以执行给定的逐位 XOR、比较和索引读取图。这不构成未知二进制逻辑发现、VMProtect 去虚拟化或脱壳成功的证据。本次未读取、分析或执行 `vmde.exe`，没有下载或执行 VMProtect 样本。

实验只新增研究脚本和结果，没有修改 `src`、`vendor`、产品测试、配置或历史 benchmark。所有文字读写均显式 UTF-8。

## 可复现入口和来源

在 `E:\wirefit` 执行：

```powershell
& ./.tools/runtime/node_modules/node-win-x64/bin/node.exe ./artifacts/research/handwired-ablation/run.mjs
```

脚本使用 Node 24 的原生 TypeScript 类型擦除，直接导入 vendored 上游模块，不依赖 tsx、Wirefit 的拟合接口、REA 或 Z3。动态 module load hook 记录的唯一非 Node 模块为 `vendor/handwired/src/runtime/numeric-ui-core.ts`；同时断言该核心没有静态外部 import。静态依赖均为 Node 内置模块，清单保存在结果中。

本次唯一训练运行：`artifacts/research/handwired-ablation/results/2026-10-19T15-30-05-033Z/`。

- 环境：Node `v24.22.0`，Windows x64，AMD EPYC 7K62。
- 上游锁定 commit：`257856e3b221140acb4cc4460626b850c0bd4ff1`。
- 核心 SHA-256：`00c081d7438088894b85e2a3e78a5df763a44cb41ebbf538e9dbf6d4521aedd2`。
- 实验脚本 SHA-256：`c88b03982ed58ae9f706a339e449ba824f9222119f1f1acfc61348aee77cbef9`。
- 固定实验计划 SHA-256：`b572ff4674f88dd560fbeee1d82944730313a8598508ea45e08ac78a6840bd95`。

每次复现创建独立带 UTC 时间的目录，使用 `wx` 拒绝覆盖；失败实验也写入 artifact 并使进程返回非零。本次五个实验全部完成。默认反传拒绝属于预期边界观测，原始错误消息保留。

## 1. 只用核心训练已知结构的参数

结构由实验者给定：源单元 `[a,b,x]`，`multiply(a,x)`，随后 `roundAffine(product+b)`，产品和加法各保留 FP32 舍入点。图有 3 个输入源、4 个运行时操作、3 个编译层；训练实际执行 reference stream。目标为源代码自有 fixture `f(f(1.75*x)-0.625)`，`f=Math.fround`；没有原目标 Oracle 调用。

固定初值 `[-0.5,0.75]`，参数边界 `[-4,4]`，输入声明范围 `[-8,8]`，full-batch SGD 学习率 `0.04`，严格执行 800 次更新，无重启、候选筛选或提前停止。每次 17 个实际图 forward/backprop，共 13,600 次训练图反传；宿主仅汇总梯度和更新参数，没有用手写导数、解析拟合或 Wirefit `fitNumeric` 替代 Circuit 反传。

划分在 `plan.json` 预先固定：17 个训练输入、8 个 validation 输入、10 个 holdout 输入，按 FP32 输入位身份检查三组两两不重合。所有 800 步的参数、原始 MSE、实际梯度均在 `affine_core_only.json` 的 `traces` 中。

| 观测 | 实测 |
| --- | ---: |
| 初始训练 MSE | 32.265625 |
| 最终参数 a | 1.75 |
| 最终参数 b | -0.6249997019767761 |
| a 的绝对参数误差 | 0 |
| b 的绝对参数误差 | 2.980232238769531e-7 |
| 最终训练 MSE | 1.4085464820656104e-13 |
| 最终 validation MSE | 1.247890679678676e-13 |
| 最终 holdout MSE | 1.4281908988778015e-13 |
| validation 通过数 | 8/8 |
| holdout 通过数 | 10/10 |
| 三组最大绝对输出误差 | 4.76837158203125e-7 |

通过阈值预先固定为 `abs(error) <= 0.00002 + 0.00002*abs(target)`。800 次更新后，将最终模型写入 `frozen-affine.json` 并计算 SHA-256，之后才构建 holdout 的目标输出；评估后再次检查冻结文件未变化。本次没有消费 holdout 后改阈值、换数据或重新训练择优。目标公式和 holdout 输入事先可见，目标源码由实验者提供，因此这是一项结构已知的能力消融，不是对未知目标的盲测。

本次 affine 整个实验约 47.68 ms，包含图构造、所有训练和各组评估；只有一次、仅一个 workload，不能与历史 worker 拟合耗时直接比较，也不能据此宣称速度优势。

## 2. 离散能力与默认反传边界

| 给定图 | 真实 forward 结果 | 真实反传结果 |
| --- | --- | --- |
| 32 位 XOR 的 bitplane 图 | 12/12 组 uint32 对完全一致 | 默认反传可运行；最低位两输入梯度符合 `1-2*b`、`1-2*a` |
| `boolean(source)` | 7/7，包含 0.5 的上下相邻 FP32 值；0.5 输出 1 | 默认及显式 reject 均抛 `cannot backpropagate through a boolean atom`；显式 straight-through 的源梯度为 1 |
| `indexRead` | 整数索引 -1,0,1,2,3 的 clamp/zero 两种策略全部正确 | 默认抛 `cannot backpropagate into the index of an index read; pass indexGradient`；显式 zero 与 backward-difference 返回不同且已验证的梯度 |
| `emitCompare(a,'>',b)` | 7/7，覆盖正负端点、相等、相邻 FP32 和正负 `2^-149` | 本次默认比较图由 16 个算术操作构成，0 个 boolean atom；不能将 boolean atom 的拒绝推广成所有离散运算均拒绝 |

XOR 表示方式必须准确理解：宿主把两个 uint32 拆成 64 个 0/1 源单元，实验者为每一位提供 `a+b-2*a*b` 图，32 个输出位再由宿主组装为 uint32。整个 Circuit 为 64 个操作。这没有测试将完整 32 位整数作为单个 FP32 标量的精确运算，没有自动发现 XOR 结构，也没有 lifting 机器指令。

索引测试表为 `[11,22,33]`，索引 1 时显式 `indexGradient:'zero'` 的源梯度为 `[0,0,1,0]`，`'backward-difference'` 为 `[11,0,1,0]`。另保留了重要边界：1.5 在 forward 中读取 floor 后的第 1 项 22，但 `validateIndexReads` 明确拒绝违反整数索引契约的输入。因此调用方必须验证声明；forward 返回值并不表示输入满足声明。

STE 和 backward-difference 是调用方明确选择的代理梯度；不能把它们称为离散跳变的真实导数，也不能由“forward 能执行”推导“能有效学习任意位运算、索引或控制流”。算术图可以表示离散行为，而自动找到图、给它稳定训练信号，是不同问题。

## 3. 与传统逆向 / REA 的区别

本实验隔离了上游 Circuit 的贡献：它对**已构造的图**提供执行和反向传播，参数优化器仍由研究脚本提供。Circuit 本身在这里没有读取 PE、识别壳入口、解密代码段、恢复导入表、发现 VM dispatcher、解释虚拟指令或推断控制流。

传统逆向与 REA 的证据链负责从实际程序获得地址、指令或反编译结构、数据流及来源约束。Wirefit 的 REA 适配器消费其证据并对支持的局部 p-code 做映射；精确整数语义、Z3 证明、数值拟合和样本比对属于后续不同环节。参见 [REA 映射](rea-api-map.md) 和 [Handwired 映射](handwired-api-map.md)。

因此，仅从一组输入输出拟合 `a*x+b`，无法证明已经恢复目标的机器代码结构，更无法证明已脱壳。若真实壳处理链路先获得可验证的运算区域，再把图交给 Handwired，Handwired 可能承担其中的参数学习；该作用需要目标级证据和独立回放另行验证。本次没有提供这些证据。

本次未运行新的 REA 对照或 reference-vs-Handwired 性能矩阵。已有 [历史比较](benchmarks/handwired.md) 的结果原样保留：reference 与 Handwired 都是 8/9，失败的是同一分段任务；Handwired 在该矩阵较慢。历史 10 点 holdout 中有 `-4`、`+0`、`+4` 三个训练边界复查点，只有其余 7 个输入未见。新实验三组不重合，不会修正或覆盖历史 artifact，也不能凭单个简单 affine 任务宣称 Handwired 优于传统方法。

## 原始记录

- [复现实验脚本](../artifacts/research/handwired-ablation/run.mjs)
- [固定计划](../artifacts/research/handwired-ablation/results/2026-10-19T15-30-05-033Z/plan.json)
- [完整结果、依赖加载记录和来源哈希](../artifacts/research/handwired-ablation/results/2026-10-19T15-30-05-033Z/result.json)
- [每步训练损失、参数与所有观测](../artifacts/research/handwired-ablation/results/2026-10-19T15-30-05-033Z/affine_core_only.json)
- [冻结模型](../artifacts/research/handwired-ablation/results/2026-10-19T15-30-05-033Z/frozen-affine.json)
- [32 位 XOR](../artifacts/research/handwired-ablation/results/2026-10-19T15-30-05-033Z/xor32_given_bitplanes.json)
- [boolean](../artifacts/research/handwired-ablation/results/2026-10-19T15-30-05-033Z/boolean_atom.json)
- [index read](../artifacts/research/handwired-ablation/results/2026-10-19T15-30-05-033Z/index_read.json)
- [比较与 subnormal 边界](../artifacts/research/handwired-ablation/results/2026-10-19T15-30-05-033Z/comparison_given_graph.json)
独立记录审计也已通过：`verify.mjs` 未重新训练，重新计算了 13,635 次独立双舍入 FP32 预测，核对全部 800 次参数更新和 10 个 holdout 观测，并核对源文件、计划与冻结模型哈希。见 [审计脚本](../artifacts/research/handwired-ablation/verify.mjs) 和 [审计收据](../artifacts/research/handwired-ablation/results/2026-10-19T15-30-05-033Z/audit.json)。`node --check run.mjs` 返回 0。