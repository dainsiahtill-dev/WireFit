# ADR 0001: 独立 TypeScript sidecar、可复查身份与按实际范围交付

状态：已实施；实际平台记录由 `upstream-lock.json` 与 `docs/ACCEPTANCE-RESULTS.md` 生成。

产品名与可执行入口采用 **Wirefit / wirefit**。既有规范中的 `wirefix.bv.total.v1`、`wirefix.fp32.templates.v1` 及 Schema `$id` 是持久化协议身份，继续原样保留，避免把重命名误当作语义迁移。原始实施计划、验收要求和 unresolved lock 模板保留。

源码位于 `src/`，受限数值与精确求解在 `src/workers/`。根目录 TypeScript 配置将项目与许可源码闭包编译为 `dist/src/`、`dist/vendor/`；CLI/MCP 的 npm workspace launcher 位于 `apps/`。因此 build、doctor、demo、acceptance、benchmark 的 npm scripts 指向 `dist/src/`。纯运行时不 deep import REA 私有 dist，真实 REA 接入通过公开 MCP 可执行入口和 portable Evidence。

Node 24 为当前选定运行时。此 Windows 工作区使用 `.tools/runtime/node_modules/node-win-x64/bin/node.exe` 的实际镜像，版本和 SHA-256 从执行环境读取。它由带完整 integrity 的 npm 分发包安装，锁文件会如实记录镜像源；不声称独立验证 Node 官方发布签名。npm 的真实入口可能在用户 roaming 安装中，不能把 PATH 中 Node22 附带的 npm10.9 当成此次使用的 npm11.16。便携部署须在自身主机重新执行安装与验收；未运行的 Linux/macOS 不自动得到支持状态。

精确 BV/Bool 的独立 BigInt evaluator 与真实 z3-solver/WASM Worker 分离，模型 UNSAT 只覆盖非空声明域。Handwired 使用固定完整 commit、原始 MIT 核心依赖闭包与逐文件 SHA-256；实际参数是 Circuit source cells，真实 backprop 与独立 FP32 最终 evaluator 分离。数值运行时细节见 `0002-handwired-numeric-runtime.md`。源码、上游依赖身份、原目标来源与三个 verifier 维度均不互相升级。

`CaseStore` 保持单写者、不可变内容 artifact 与 jobs 专用可变生命周期记录。JobManager 先持久化请求再创建可执行 job，逐 entry 排序状态快照；文件系统失败必须结算为明确失败，不能留下悬空 wait。显式失败/取消结果可携部分 run ID，取消后的隐式成功被拒绝。Oracle 使用显式 argv、受控环境和 fresh process；绑定摘要包括运行时/文件内容以及声明路径和 argv 路径的真实解析，防止 junction 改向复用旧身份。异步调用前复制输入和 binding，确保记录输入就是实际发送输入。

验收程序执行真实 build/typecheck/全量 product Vitest，并保留 JSON reporter 与 stdout/stderr。63 个规范 gate 逐项记录；只覆盖部分条件时为 INCONCLUSIVE，真实外部缺依赖为 BLOCKED，未执行为 NOT_RUN。故障注入组件证据、历史真实 REA 捕获和此次运行分别标识。真实 Ghidra 原生链、Linux 平台、实际 Codex 客户端、真实 UNKNOWN 和 CFG/phi 不能被 mock 或退出码 0 代替。

可选 `--demos` 执行编译后的三条演示；演示 C 缺真实 native prerequisites 时保留 BLOCKED。可选 `--install-smoke` 在工作区内唯一临时目录复制完整源/许可闭包及 npm lock，用同一 Node 执行 `npm ci --ignore-scripts`、build 和 doctor。删除前验证绝对路径仍在 `.tmp/acceptance-install-*` 下，拒绝替换为链接的目标。该 smoke 不包含第二份上游开发 checkout，也不把历史 REA 数据当成新的 Ghidra 调用。

固定研究基准未显示 Handwired 速度或恢复率优势；失败的 piecewise seed 保留，不通过消耗 holdout 后修改预算/政策来制造收益。验收 runner 的 harness 成功仅表示命令与证据生成过程成功；完整交付状态由所有 gate 决定，不能以完成日志替代。
