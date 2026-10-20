# WireFix 接口与数据流

本文件中 `wirefix`、类型名、MCP 名称和 worker 协议为拟实现契约。REA 的真实字段由 M0 schema snapshot 与 adapter map 决定。首版传输版本统一为 1。

## 1. 组件职责

| 组件 | 输入 | 输出 | 不可跨越的边界 |
| --- | --- | --- | --- |
| case-store | 可验证对象和文件 | artifact/object ID、不可变版本 | 不修改原始 Evidence |
| rea-adapter | portable bundle 或自有 live session | ImportedEvidence、能力与来源 | 不解析伪码文本来伪造原生 IR |
| model-ir | 结构模型、typed inputs | 校验后的模型、来源映射 | 不猜缺失变量或隐式类型 |
| exact-evaluator | BV DAG、typed input | typed output 或结构错误 | 不经 Number 计算 BV 值 |
| synthesis | 模型/数据、词汇和预算 | 候选列表及搜索记录 | 不输出验证 PASS |
| oracle | 显式清单、输入序列 | 原始 observation | 不引用候选生成期望输出 |
| numeric-models | 模板、数据和后端 | 候选参数及训练日志 | 不直接写最终验证状态 |
| verification | 冻结候选、数据、模型、政策 | 三维结果与反例 | 不依赖 LLM 叙述 |
| reporting | 已存结果、证据索引 | JSON/Markdown/模块/用例 | 不提高结论强度 |

## 2. Artifact 和身份

`ArtifactRef = { sha256, relative_path, media_type, size_bytes }`。路径相对于 case；解析后必须仍在 case 内。外部输入首次导入时复制到 case 的不可变区并哈希，后续任务通过 ArtifactRef 或本地 object ID 引用。

`ReaSourceRef = { bundle_sha256, evidence_id, provider_id?, analysis_profile_digest?, target_sha256?, location? }`。这些字段来自真实原记录；未知为 null 或显式 unavailable，不能伪造。原始 REA 对象独立保存，不转换其身份计算。

模型语义摘要基于 `{schema_version, kind, semantics_profile, inputs, nodes/definition, outputs, domain}`；不包括显示标题、时间和 provenance。来源包络单独哈希。规范化对象键和 ID 限定 ASCII，键按 ASCII 升序递归排列，数组保持顺序，UTF-8 编码且无空白；字符串按 JSON.stringify 的 JSON 转义，数字只允许安全整数。非 ASCII 的标题和原始元数据不进入这个语义对象，原件按字节哈希。typed values 已避免精度丢失。该规范版本一旦改变，摘要命名空间随之改变。

schema 中的 ID 允许稳定的人类可读 fixture ID；生产模式生成带类型前缀的 ID，并单独保存 SHA-256，不能把 ID 字符串当作已验证的内容摘要。

## 3. Model

`contracts/model.schema.json` 包含两个变体。

### 3.1 bv_dag

保存 inputs、按拓扑序排列的 nodes、outputs、domain、scope 和 provenance。node 有 id/op/type/args/attrs。操作规范见 SEMANTICS，schema 不替代每个 op 的语义校验。

scope 仅包括来源范围、观察项、声明的源完整度、execution_guard 声明和观察点；不接受 fidelity、verdict 或 proof 字段。原程序保真度由本地 verifier 按完整绑定记录派生，不能由导入 model 声明。producer 截断导致不能导入时，不产生一个“完整模型”；可另导入原证据供报告。来源声明不等于已校验的 Oracle 绑定。

### 3.2 numeric_template

首版一个 FP32 输入、一个 FP32 输出。definition 包含：

- template：affine / affine_clamp / piecewise_affine。
- parameters：名称到 FP32 typed value 的 map。
- fixed：lo/hi 或 knots 等固定值。
- parameter_bounds：与可训练参数一一对应的有限范围。

affine 与 affine_clamp 使用 a、b。clamp 固定 lo/hi。piecewise 使用 a0/b0 至 aN/bN，N 等于 knots 数；段数最多 8。模板 validator 检查参数 key、knots 顺序和范围，不接受未使用参数。

所有拟合尝试和最终候选保存同一模型格式，参数变化产生新语义摘要。随机种子、优化器和训练次数属于 experiment 配置，不能混入函数本身的执行语义。

## 4. Domain

`{ constraints: [{ input, op, value }] }`，所有约束为 AND。空数组表示 profile 允许的全输入域。op 与 typed value 的兼容性由语义 validator 检查。

线上实验请求总是保存显式 mapping。CLI 可在双方输入/输出名称与类型完全相同的情况下生成并展示这个映射，不按反编译文本顺序推断。输入映射必须覆盖双方全部输入且为保类型双射；禁止合并独立输入或隐式绑定常量。输出映射非空、保类型且两侧均不重复，未选输出必须在报告列明。domain 使用左侧/公共输入命名，右侧约束通过同一映射转入公共空间。

## 5. OracleManifest

参见 `contracts/oracle.schema.json`。

manifest 至少指定：`oracle_id`、来源种类、可执行 argv、cwd、输入/输出签名、目标文件列表与文件摘要、协议版本、reset 策略、请求/batch 超时和允许的环境键。

注册时校验路径和摘要，生成实际绑定记录。示例清单中的待构建路径不能直接运行；doctor 应报告 `ORACLE_NOT_BUILT`。从 case 导入的 manifest 默认状态为未绑定；只有用户/调用者显式选定该执行目标，register 才能使其可用。

执行模式：

- `fresh_process`：每个请求一个进程；最容易明确初始状态，成本较高。
- `batch_resettable`：一个 batch 复用进程，但必须有经过测试的 reset 协议；不支持时拒绝。

首版 fixture runner 至少支持 fresh_process。批模式作为性能选项，不应让初始版本先陷入进程调度优化。

### 5.1 JSONL 请求响应

```json
{"protocol_version":1,"request_id":"q0001","inputs":{"x":{"kind":"bv","width":8,"bits":"0xfa"},"y":{"kind":"bv","width":8,"bits":"0x0a"}}}
```

```json
{"protocol_version":1,"request_id":"q0001","status":"ok","outputs":{"result":{"kind":"bv","width":8,"bits":"0x04"}}}
```

非 ok 响应须包含结构化 error，outputs 必须为空。wrapper 的格式错误、超时、崩溃由 supervisor 生成失败 observation，不伪造成目标的合法业务返回。

不允许缺 request_id、重复响应、额外输出、类型不匹配或非协议 stdout。超长行、超时和输出上限触发有界失败；日志只保留预算内内容，同时记录是否截断。

## 6. Dataset

manifest 见 `contracts/dataset.schema.json`；单条观测见 `contracts/observation.schema.json`。

Dataset 是签名、Oracle 绑定、比较政策、采样计划、split 和 observations 文件摘要的不可变集合。读取时验证每个 observation 的签名、source kind、oracle ID 和输入域。

`import_dataset` 接收 manifest 与显式 artifact_root；外部引用先在该 root 下校验路径与摘要，再复制到 case 的不可变区，生成本地引用、ID 映射和来源包络。保留原文件，不原地改写其 SHA。它不启动 Oracle；collect_dataset 才执行已绑定的目标。expected_fixture 是预期材料，不能冒充实际调用或原目标回放。

split 为 train/validation/holdout；不能只按行号隐式划分。每条数据有 sample_id。相同输入的重复调用用于测确定性，不能假装新的输入覆盖；报告同时给出观测数和不同输入数。

训练 Worker 只获得 train 的 artifact。验证 Worker 读取冻结模型和 holdout。所谓隔离是接口和目录传递边界；同一宿主用户仍能读文件，不声称密码学隐藏。CI 可使用独立 fixture seed 和评测集合来检出针对公开例子硬编码的实现。

固定失败计数和失败原因，任何记录过滤都要说明 reason。普通数据清洗不能把目标失败静默删除。

## 7. 实验请求联合类型

规范 schema 见 `contracts/experiment-request.schema.json`。

| operation | 必要引用 | 作用 |
| --- | --- | --- |
| simplify | reference_model_id、预算 | 重写/枚举候选并在可用精确模型上检查 |
| compare_models | left_model_id、right_model_id、domain、mapping、mode | mode=exact_bv 可求解；mode=sampled_fp32 另必须有 sample_source 与 comparison_policy |
| compare_oracles | left_oracle_id、right_oracle_id、inputs_artifact、comparison_policy | 对相同输入调用两个原目标并报告观测差异 |
| verify_candidate | candidate_model_id、dataset_id，可选 oracle_id | 对历史独立观测或 fresh target run 验证 |
| fit_numeric | dataset_id、template_model_id、backend、预算 | 用 train 拟合，选择/冻结后验证 |
| suggest_inputs | model_ids、domain、预算 | 找候选分歧和边界，输出 typed 查询点 |

同一个请求只匹配一种 operation，不接受另一种 operation 的多余字段。`compare_oracles` 从不设置 model_check=proved；如果没有明确的精确模型，本来就没有 SMT 证明对象。

`sample_source` 是 `inputs_artifact` 或 `dataset_id` 的互斥变体。`sampled_fp32` 只使用其中输入，样本比较另列 sample_comparison；只有与原目标独立观测成对验证才可生成 target_validation。比较公式、零符号和失败分母见 SEMANTICS §9.3。`verify_candidate` 必须保存模型与 dataset/Oracle 签名的显式双射 mapping；从名称相同生成的映射也要落盘。

fit_numeric 的训练/验证/holdout 来源、policy 与 domain 使用 dataset 中已固定的版本。引用的模板输入/输出必须与 dataset 签名完全同名同类型，训练参数集合和边界由 template validator 检查；不同签名先显式生成适配后的新对象。

### 7.1 Oracle 对比的统计

对每个选定输入分别调用 left/right，使用相同签名、明确的输入映射和相同 per-request 预算。记录两侧 attempted/completed/failed；只有两侧有效返回才进入数值比较。

正常返回值不同为真实观测差异。超时、协议错误和无法加载目标保留为实验失败，不自动称为函数不等价。若用户显式把可观察的合法 target error 纳入契约，可以单独比较该状态；V1 默认只比较正常 typed outputs。

没有差异但有未完成输入时 `partial`。两个接口都没有产生有效样本时不得显示 matched。

CLI 对应扩展：

```bash
wirefix compare --case ./cases/demo --left-oracle <id> --right-oracle <id> --inputs ./inputs.jsonl --policy ./policy.json
```

它与模型 `--left/--right` 形式互斥；共享同一 verification service。

## 8. Worker 协议

使用版本化 JSONL over stdio。请求包含 protocol_version、job_id、operation、artifact refs 和 deadline_ms。结果包含 job_id、status、result artifact 或结构化 error。stdout 仅用于协议。

重型 Worker 从 case 的已校验文件读取模型/数据，父进程按摘要校验引用。每个 Z3 Worker 仅执行一个任务，不共享全局 solver。取消后迟到结果必须按 job 状态丢弃，不能覆盖 cancelled。

Numeric Worker 可以按 backend 选择 reference 或 handwired，但同一次 run 记录实际使用后端的 identity。失败后若切换 backend，必须产生新尝试记录，不能沿用 handwired 标签。

父进程拥有生命周期；正常关闭先通知，预算到期终止所拥有进程，保留 cleanup 状态。并发上限从 1 开始，只有真实测量和隔离测试通过后增加。

## 9. Application service

建议核心服务入口：

```ts
interface WireFixService {
  capabilities(): Promise<Capabilities>;
  importEvidence(req: ImportEvidenceRequest): Promise<ImportEvidenceResult>;
  acquireEvidence(req: AcquireEvidenceRequest): Promise<JobRef>;
  importModel(req: ImportModelRequest): Promise<ModelRef>;
  liftModel(req: LiftModelRequest): Promise<LiftResult>;
  registerOracle(req: RegisterOracleRequest): Promise<OracleBinding>;
  importDataset(req: ImportDatasetRequest): Promise<DatasetRef>;
  collectDataset(req: CollectDatasetRequest): Promise<JobRef>;
  submitExperiment(req: ExperimentRequest): Promise<JobRef>;
  getJob(id: string): Promise<JobState>;
  cancelJob(id: string): Promise<JobState>;
  readReport(req: ReportPageRequest): Promise<ReportPage>;
  exportReport(req: ExportReportRequest): Promise<ExportManifest>;
}
```

case 在 service 实例或每请求上下文中显式绑定；不能使用未验证的全局 current binary。CLI/MCP 负责参数解析和展现，不复制分析算法。

## 10. CLI/MCP 的完整用户链路

1. 创建 case，doctor 记录能力。
   离线 doctor 不启动 REA；live acquire 读取服务器身份，绑定目标后刷新 provider 能力。
2. import evidence/model；返回本项目 local_record_id 或 model_id。
3. lift 时指定 local_record_id 和来自证据的 output ID；无需猜字段。
4. register Oracle 后返回绑定 id；从 manifest 导入不等于已经授权执行其它路径。
5. collect 或 import dataset，固定 split 与比较政策。
6. submit experiment 返回 job_id。
7. get_job 查询过程，读取 result_id；cancel_job 可结束长任务。
8. get_report 按 section/offset/limit 返回证据摘要。
9. export_report 输出独立复现包。

MCP 参数仅允许 source/candidate/config，不提供 verdict、proof 或 covered=true 之类可由模型伪造的写入字段。目标携带的源码字符串、注释和原始日志均作为不可信分析数据保留；它们不能改变任务权限或代码执行策略。

CLI 默认前台拥有长任务，Ctrl-C 取消；不提供后台 daemon 或跨进程 PID kill。MCP server 持有异步任务并通过同服务实例取消。最小 job 状态机和 cleanup 在 M1 实现，不能让各通道各写一套。

Portable 导入验证 canonical 结构、引用和语义身份；不把文件 hash 当作 REA record 的认证。Live 路径在关闭前导出所需 bundle；取消或错误时使用有界恢复预算，记录未保存证据和实际清理状态。

上游成功 structuredContent、错误文本 diagnostic 与回复级不可信标记分开解析、保存。原 bundle 可能不含原二进制字节。未知上游 schema/profile 仅可作为附件保存，不能通过猜字段继续 lift。

## 11. 发布接口的兼容政策

Schema 变更需要版本号、迁移或明确拒绝。旧结果保持可读；不能以当前依赖版本重标历史结果。涉及语义 profile 的修正必须使旧模型/结果过期或产生新摘要，而不能只更改显示字符串。

所有错误都保留 code、message、scope、retryability、artifact refs 和可用的 partial data。部分结果不能放进与完整成功相同的无区别返回形状。
