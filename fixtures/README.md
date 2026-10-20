# 自写参考夹具

本目录是为 WireFix 实施包新写的参考源码、期望值与开发检查工具，按本目录 `LICENSE` 的 MIT 条款提供。它们没有复制第三方目标程序，也不是 REA、Ghidra、Handwired、Z3 或已实现 WireFix 的输出。

`reference_vectors.jsonl` 是参考算法生成的理论期望，不能作为“已经调用原目标”的 observation。`validation/local-validation.json` 单独记录本机真实执行过的 C 和 Python 夹具检查；其中上游集成全部保持 `NOT_RUN`。该文件的 PASS 只适用于所列编译器、主机、源文件摘要和测试输入。

## 文件与用途

| 文件 | 用途 |
| --- | --- |
| `behavior_fixtures.h`、`behavior_fixtures.c` | 有清楚函数名与类型绑定的 C11 参考目标；用于编译、值流提取和独立回放 |
| `fixture_probe.c` | 真正调用上述 C 函数的简单驱动器，支持单条命令与同进程 batch |
| `oracle_fp32.py` | 自包含的 `fresh_process` JSONL 参考 Oracle，固定 affine 后 clamp[-2,+2] |
| `reference_verify.py` | Python 标准库参考值生成和 C/Python 实际执行核对；开发辅助工具 |
| `reference_vectors.jsonl` | 小规模初始参考向量，带 `is_upstream_observation: false` |
| `validation/local-validation.json` | 有日期、主机、命令、源摘要、实际数量和失败详情的本地检查记录 |
| `build/`（运行检查后生成） | 本地构建二进制；本实施包不携带，可按本机工具链重新构建 |

Python 用于这些自写参考素材和示例 Oracle，不应因此成为 WireFix 的确定性 Node 核心或 Handwired worker 的运行依赖。用户可以替换为实现同一协议的其它可执行目标。

## 1. 位向量参考目标

| C 函数 | 输入 → 输出 | 理论期待及验收用途 |
| --- | --- | --- |
| `fixture_bv8_mba_original` | BV8 x、y → BV8 | `(x XOR y) + 2*(x AND y)`，最终模 256 |
| `fixture_bv8_mba_simplified` | BV8 x、y → BV8 | `(x+y) mod 256`；与上一函数在全部 65,536 输入对相等 |
| `fixture_bv64_add` | BV64 x、y → BV64 | `(x+y) mod 2^64`；全 1 加 1 为 0 |
| `fixture_bv64_mul` | BV64 x、y → BV64 | `(x*y) mod 2^64`；`0x8000000000000000 * 2` 为 0 |
| `fixture_bv8_*_wide` | BV8 value、BV64 count → BV8 | `shl`、`lshr`、`ashr`；先比较完整 64 位计数 |
| `fixture_bv64_*_wide` | BV64 value、BV64 count → BV64 | 同上，数值宽度为 64 |
| `fixture_boundary_v1` | BV32 x → BV8 | 无符号 `x < 100 ? 1 : 0` |
| `fixture_boundary_v2` | BV32 x → BV8 | 无符号 `x <= 100 ? 1 : 0`；两个版本仅在 x=100 不同 |
| `fixture_side_effect` | BV32 x、隐藏持久计数器 → BV32 | 每次先递增全局计数器，再返回 x+counter；这是纯函数导入的负例 |

所有加乘的回绕都是显式无符号语义。BV8 运算先扩为安全的 32 位中间量，再截回 8 位，避免依赖 C 的有符号整数溢出。算术右移通过无符号逻辑移位和符号填充实现，不依赖 C 对负数右移的实现定义行为。

移位函数都有真实的 `count >= width` 分支。在该分支中，左移／逻辑右移返回 0；算术右移返回全符号位。进入实际 C 移位运算之前，计数已证明小于值宽度；先处理 count=0，避免构造 `1 << 64` 或 `mask << 64`。因此 `shl8(1, 256)=0`、`ashr8(0x80, 256)=0xff`，计数不会先截成 0，也不会隐式加 `&31`／`&63`。

副作用负例必须在**同一个进程**中重复调用。先 reset 为 0，两次 `fixture_side_effect(5)` 依次为 6、7。每次重启进程都会重置计数器，可能掩盖这一性质；这也是不能只凭 fresh-process 重复值就证明原函数无状态的例子。负例的 STORE/LOAD 不能因为“只关心返回值”而被删掉并升级为完整纯函数。`fixture_side_effect_reset` 仅供参考测试控制状态，不自动构成产品已验证的 reset 协议。

## 2. 数值参考目标

本目录的规范是 **IEEE binary32、roundTiesToEven、保留零符号、渐进下溢、禁止融合声明为两步的乘加**。只接受有限输入，且每个声明的中间舍入点也必须有限；溢出不是可被 clamp 隐藏的正常值。

### 固定规则

- affine：`t = f32(f32(a*x) + b)`。目标参数 a=1.5、b=-0.25，均可由 binary32 精确编码。
- 固定 affine-clamp：先计算上述 t，再以 lo=-2、hi=+2 执行 **`t < lo ? lo : t > hi ? hi : t`**。
- 通用 clamp 的相等分支返回原 t，保留其位模式。例如 `clamp(-0,+0,+0)` 必须返回负零，`clamp(+0,-0,-0)` 必须返回正零；不能直接用 min/max 宏替代。
- piecewise-affine：固定 knots 为 -1、+1；区间左闭右开，最左／最右区间向外延伸，不假定连续。

| 区间 | a | b |
| --- | --- | --- |
| x < -1 | 0.5 | -0.25 |
| -1 <= x < 1 | -1.5 | 0.5 |
| x >= 1 | 2 | -1 |

C 目标通过分开的乘／加函数、volatile float 舍入存储及严格编译选项保留两个舍入点。驱动器会真实检查 binary32 位表示、舍入模式、负零、subnormal 输入和下溢结果；检测到 FTZ/DAZ 等不支持的执行环境时返回 `UNSUPPORTED_FP_ENVIRONMENT`，不只相信编译宏。浮点位模式用 `memcpy` 传递，避免指针别名违规。

Python 参考使用标准库整数和 `Fraction` 精确解码、运算与 ties-to-even 舍入，没有用宿主 float64 近似代替 binary32 真值。零的符号另行维护。参考 wrapper 和参考生成器共用这一实现，因此它们互相一致不能算独立数学验证；独立证据来自 C 真实执行的逐位对照，以及手写的 RNE／subnormal／负零／不融合乘加 golden expectations。

## 3. 构建与检查

从本目录运行：

```bash
python3 reference_verify.py generate
python3 reference_verify.py verify --cc cc --ubsan
```

第二条命令实际构建并运行 O0、O2、O1+UndefinedBehaviorSanitizer 三种配置，写入 `validation/local-validation.json`。命令失败或缺少编译器时不能把历史报告沿用为当前通过。可删除 `build/` 后重跑。

等价的单次 GCC/兼容编译器构建示例：

```bash
cc -std=c11 -O2 -g -Wall -Wextra -Werror -pedantic \
  -fno-fast-math -ffp-contract=off -frounding-math -fno-lto \
  behavior_fixtures.c fixture_probe.c -lm -o fixture_probe
```

这些是 GCC/兼容工具链建议，不是已经验证的 Windows 或任意编译器命令。`__declspec(noinline)`／`__attribute__((noinline))` 只阻止常见内联，不保证函数内部表达式形状，也不保证任何分析后端的字段。

### 允许编译器改写

优化编译器可能把 MBA 直接改为加法，可能改变基本块、使用条件移动，或者合并看起来相同的代码。此时观察到已简化函数是合法编译结果，不能宣称 WireFix 自己完成了搜索。`-g` 和关闭 LTO 有助于定位，但不锁住原始机器指令形状。

O0 也可能引入栈 LOAD/STORE，使首版受限 lift 拒绝；这应保留为 unsupported，不能为了夹具通过而删除来源副作用或补造 p-code。宽移位的防护分支、边界条件和数值函数中的 CALL 可能需要额外 CFG/调用支持；它们是语义测试素材，不保证全部属于“首版直线原生通道”的正例。

真实 REA/Ghidra 整链应优先从 `fixture_bv64_add` 等简单标量函数开始，在选定编译器／选项的**真实输出**上检查支持范围。必须锁定二进制摘要和原函数输入／返回绑定，才可关联回放。源码、编译结果和参考值均不能伪装成已经取得的 high-p-code。

### 本地验证具体覆盖

- 两个 MBA 函数各 65,536 个 BV8 输入对。
- BV64 边界值、超过 2^53 的值和固定种子样本。
- BV8 的所有 256 个值，以及 BV64 边界／固定种子值，配合 width-1、width、width+1、256、2^53+1、2^64-1 等完整计数。
- 100 前后边界与两个版本的输出。
- 同进程隐藏计数器递增、显式 reset 与无符号回绕。
- binary32 舍入中点、负零、subnormal、渐进下溢、clamp 相等分支、piecewise knots、溢出和非有限值拒绝。
- fresh-process JSONL wrapper 的成功、目标域错误和协议错误。

穷举只覆盖明确列出的 BV8 MBA 对；随机和边界检查不能升级为 BV64／FP32 全域证明。UBSan 没有报告错误只代表这些真实执行路径未触发已启用的检查，不是全程序形式化保证。

## 4. C 探针协议

`fixture_probe.c` 使用简单的命令参数或空白分隔行，输出一行 `OK <type> <hex>` 或 `ERROR <CODE>`。它不是主方案 JSONL Oracle 协议；编写正式 wrapper 时仍需实现 request_id、类型契约、身份记录和预算。退出码 0 不代表每条响应都是成功。

```bash
build/fixture_probe_O2 mba_original 0xff 0x01
build/fixture_probe_O2 shl8 0x01 0x0000000000000100
build/fixture_probe_O2 --batch <<'PROBES'
side_reset 0x00000000
side_effect 0x00000005
side_effect 0x00000005
PROBES
```

操作名为 `mba_original`、`mba_simplified`、`add64`、`mul64`、`shl8`／`lshr8`／`ashr8`、`shl64`／`lshr64`／`ashr64`、`boundary_v1`／`boundary_v2`、`side_reset`／`side_effect`、`f32_env`、`f32_add`／`f32_mul`、`f32_affine`、`f32_clamp`、`affine_target`、`clamp_target`、`piecewise_target`。参数顺序见函数原型；移位第二个参数始终为 BV64，浮点参数全部传 8 位十六进制位模式。

## 5. 可直接运行的 fresh-process FP32 Oracle

`oracle_fp32.py` 是自包含、只依赖 Python 标准库的**自写 reference_fixture**。每次启动只读取一行请求、输出一行响应并退出；调用者必须每个请求新建进程，监督超时和输出上限。

```bash
python3 oracle_fp32.py <<'JSON'
{"protocol_version":1,"request_id":"q0001","inputs":{"x":{"kind":"fp32","bits":"0x3f800000"}}}
JSON
```

该输入 x=1，结果为 1.25：

```json
{"protocol_version":1,"request_id":"q0001","status":"ok","outputs":{"result":{"kind":"fp32","bits":"0x3fa00000"}}}
```

正常成功不含 error。输入非法、NaN／Infinity 或声明的中间步骤溢出时，返回 `status: error`、`outputs: {}` 及包含 `code`、`message`、`scope`、`retryable`、`artifacts` 的结构化 error。request_id 遵守主方案的字符范围；若坏 JSON／缺失 ID 使合法关联 ID 无法恢复，使用 `unbound_request` 标识无可用关联。Supervisor 必须把这种回复作为关联或协议失败处理，不能增加原目标有效样本数。

注册清单应记录此脚本的实际 SHA-256、解释器身份、argv 与 `source_kind=reference_fixture`。wrapper 的源码和参数公开；拟合 worker 的输入只应包含分配给它的训练数据，不应包含这个脚本或 truth 参数文件。单机同用户隔离不是密码学隐藏；本素材没有实施 holdout 隔离、模型训练或防硬编码评测。

## 6. 如何计入总验收

本地夹具检查为 C04/C05/C06、N01 的实现提供参考输入和真实 C 观测，但没有验收尚未实现的 BigInt evaluator、Z3 translator、Handwired adapter、Oracle supervisor 或报告系统。

`reference_vectors.jsonl` 使用自己的 `wirefix.fixture-vector.v1` 结构，保留 probe 操作名和位模式参数，不是正式 Dataset；导入主系统时需要显式类型／名字映射，并保留“参考期望”来源。实际 C 或 JSONL wrapper 调用可以作为 `reference_fixture` 观测，不能改标为第三方 `original_target`。历史本机回放不等于后来某次原目标新调用。

REA、Ghidra、Handwired、Z3、WireFix 产品和 Codex MCP 的验证仍需按 `docs/ACCEPTANCE.md` 在实施时执行；本目录没有提供这些工具的成功证据。
