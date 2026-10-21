# Wirefit 实际验收记录

运行：run-20261021151055366-QhjcBL。开始 2026-10-21T15:10:55.366Z，结束 2026-10-21T15:12:28.070Z。
主机：win32/x64，Node 24.22.0。
命令执行状态：PASS；完整规范交付状态：PARTIAL。

完整机器可读证据：[matrix.json](../artifacts/acceptance/run-20261021151055366-QhjcBL/matrix.json)。依赖身份：[upstream-lock.json](../upstream-lock.json)。

门禁状态来自真实执行日志、具体断言与保留的历史捕获。INCONCLUSIVE 表示仅部分组件已覆盖；BLOCKED 和 NOT_RUN 不计入 PASS。

| Gate | Status | 已验证范围 | 限制或原因 |
| --- | --- | --- | --- |
| C01 | PASS | Offline contracts, verdict injection and operation separation | All required assertions for the stated scope passed in the recorded run. |
| C02 | INCONCLUSIVE | Exact BV64 strings and FP32 zero/subnormal evaluation | No complete dedicated codec round-trip matrix for all required BV64 bit patterns. |
| C03 | INCONCLUSIVE | DAG topology/type/attrs and direct evaluator validation | Dedicated duplicate-ID and invalid-extract adversarial cases are not all independently evidenced. |
| C04 | INCONCLUSIVE | 65,536 BV8 MBA addition input pairs | Full 65,536-pair independent enumeration for every listed binary opcode was not run. |
| C05 | INCONCLUSIVE | Literal opcode boundary cases and exact BV64 arithmetic | No complete fixed-seed BV16/32/64 property campaign artifact. |
| C06 | INCONCLUSIVE | Full-width large shift counts and literal signed shifts | The complete w-1/w/w+1 matrix for every supported width is not separately evidenced. |
| C07 | PASS | Explicit BV/Bool bridges, extensions, concat/extract and synthetic-schema p-code byte offsets | All required assertions for the stated scope passed in the recorded run. |
| C08 | INCONCLUSIVE | Writer leases, immutable artifacts and traversal rejection | No actual interrupted-write/abrupt-power-loss publication test. |
| C09 | INCONCLUSIVE | Owned cancellation, late-result rejection and persisted restart state | CLI Ctrl-C and an abrupt owning-process crash are not both independently exercised. |
| V01 | PASS | Real isolated Z3 UNSAT for MBA model, explicit model/domain identity | All required assertions for the stated scope passed in the recorded run. |
| V02 | PASS | Real SAT with independent BigInt counterexample replay | All required assertions for the stated scope passed in the recorded run. |
| V03 | NOT_RUN | Translator corruption rejection | Translator-corruption fault injection was not performed. |
| V04 | PASS | Nonempty-domain pre-query and DOMAIN_EMPTY rejection | All required assertions for the stated scope passed in the recorded run. |
| V05 | PASS | Explicit domain containment and no implicit shrinking | All required assertions for the stated scope passed in the recorded run. |
| V06 | PASS | Real Z3 same-named intermediates remain separate | All required assertions for the stated scope passed in the recorded run. |
| V07 | INCONCLUSIVE | Real cancellation and hard-deadline paths | A genuine solver UNKNOWN and an injected UNKNOWN component campaign were not run. |
| V08 | PASS | Z3 child close on normal/deadline/cancel and continued MCP polling | All required assertions for the stated scope passed in the recorded run. |
| V09 | INCONCLUSIVE | Real bounded search and explicit exhaustion | A broad independent cold-seed expression research set is not available. |
| V10 | PASS | Observationally equal candidate is refuted on unseen input | All required assertions for the stated scope passed in the recorded run. |
| V11 | INCONCLUSIVE | Real counterexample-driven candidate refinement | Separate persisted old/new application run versions are not asserted by this component test. |
| V12 | PASS | Fresh-process exact/FP32 code and standalone recorded-observation replay | All required assertions for the stated scope passed in the recorded run. |
| V13 | INCONCLUSIVE | Input merge/empty-output rejection and mapping typing | All missing-input/type-difference/subset-uncompared-output reporting cases are not separately evidenced. |
| V14 | INCONCLUSIVE | Imported verdict rejection and bound export semantic identity | Full cross-Oracle/source verdict-cache nonreuse campaign was not run. |
| O01 | PASS | Actual fresh-process independent source-owned fixture Oracle | All required assertions for the stated scope passed in the recorded run. |
| O02 | PASS | Real JSONL protocol and typed-output failures | All required assertions for the stated scope passed in the recorded run. |
| O03 | PASS | Real timeout/crash/domain failures and unattempted collection slots | All required assertions for the stated scope passed in the recorded run. |
| O04 | INCONCLUSIVE | Contradictory imported repeats are nondeterministic | A fresh live nondeterministic target repeat integration test was not run. |
| O05 | PASS | File and argv-junction identity changes plus immutable evidence | All required assertions for the stated scope passed in the recorded run. |
| O06 | PASS | Learner rejects holdout and service freezes before access/reuse | All required assertions for the stated scope passed in the recorded run. |
| O07 | PASS | Boundary 100, paired real source-owned Oracle calls | All required assertions for the stated scope passed in the recorded run. |
| O08 | PASS | Zero/partial counts and retained uncompleted original observations | All required assertions for the stated scope passed in the recorded run. |
| O09 | INCONCLUSIVE | Expected fixtures excluded from independent target observations | Lifted/candidate/history/fresh source count combinations are not all separately exercised. |
| N01 | PASS | Independent literal FP32 rounding/zero/subnormal/knots/overflow | All required assertions for the stated scope passed in the recorded run. |
| N02 | PASS | Observation-only bounded affine least squares | All required assertions for the stated scope passed in the recorded run. |
| N03 | PASS | Real vendored pinned Circuit build/evaluation/parameter backprop | All required assertions for the stated scope passed in the recorded run. |
| N04 | PASS | Recomputed host clamp masks and actual source gradients | All required assertions for the stated scope passed in the recorded run. |
| N05 | PASS | Actual range declarations checked; adapter makes no grid/bit assumptions | All required assertions for the stated scope passed in the recorded run. |
| N06 | PASS | Stable copied forward and source-gradient snapshots | All required assertions for the stated scope passed in the recorded run. |
| N07 | PASS | Explicit signed-zero training discrepancy and exact final export | All required assertions for the stated scope passed in the recorded run. |
| N08 | FAIL | Frozen candidates under the fixed research holdout policy | Preserved research benchmark contains 2 failed backend/task configurations under its fixed holdout policy; no retuning performed. |
| N09 | PASS | Numeric fit dimensions stay separate from SMT model proof | All required assertions for the stated scope passed in the recorded run. |
| N10 | PASS | Explicit sampled numeric comparison/policy, signed zero and failures | All required assertions for the stated scope passed in the recorded run. |
| R01 | PASS | Offline authentication of captured real REA portable JavaScript Evidence | All required assertions for the stated scope passed in the recorded run. |
| R02 | PASS | Historical real public REA MCP discovery | Historical real public-entrypoint REA capture records server identity, 207 tools and target-bound capability probe; raw capture is retained. |
| R03 | PASS | Actual captured portable envelope plus canonical/record/profile tampering checks | All required assertions for the stated scope passed in the recorded run. |
| R04 | PASS | Historical real cross-session retained-vs-inline check | Historical actual fresh REA connection rejected retained ID and accepted complete inline Evidence. |
| R05 | INCONCLUSIVE | Producer unknown/truncation semantics | Complete transport Evidence pagination with a truncated producer was not exercised. |
| R06 | INCONCLUSIVE | Persist-before-close recovery is component-tested | This lifecycle test is synthetic MCP; the real native continue-from-case gate is blocked. |
| R07 | PASS | Captured real replies and synthetic hostile metadata/error parsing | All required assertions for the stated scope passed in the recorded run. |
| R08 | BLOCKED | Real native Ghidra scalar lift | GHIDRA_INSTALL_DIR not configured; Matching Ghidra native decompiler not available; No usable Java runtime found by real REA provider probe; pwntools binary-layout lane supports Linux x64 only |
| R09 | INCONCLUSIVE | Synthetic actual-schema SSA and RETURN rejection | No real native p-code fixture was produced. |
| R10 | INCONCLUSIVE | Synthetic cutpoint versus producer-hole distinction | No real native cutpoint provenance fixture was produced. |
| R11 | PASS | Unknown-guard local slices cannot gain target fidelity | All required assertions for the stated scope passed in the recorded run. |
| R12 | BLOCKED | Real native lift + original Oracle + exported module | GHIDRA_INSTALL_DIR not configured; Matching Ghidra native decompiler not available; No usable Java runtime found by real REA provider probe; pwntools binary-layout lane supports Linux x64 only |
| R13 | INCONCLUSIVE | Synthetic unsupported side-effect rejection | Real native instruction side-effect/ABI correspondence is not independently established. |
| R14 | NOT_RUN | Conditional CFG/phi enhancement | CFG/phi capability is explicitly unsupported; no real incoming-edge-slot gate. |
| P01 | INCONCLUSIVE | Real CLI import/acquire, Oracle collection/compare, simplify/fit and report export | Complete CLI Oracle/REA acquire-to-fit-to-export paths are not all independently exercised. |
| P02 | INCONCLUSIVE | Official MCP SDK client: schema, asynchronous jobs, cancel, counterexample retrieval | Required evidence was not run or not captured. |
| P03 | PASS | Copied self-contained replay after original case removal | All required assertions for the stated scope passed in the recorded run. |
| P04 | PASS | Recorded observations stay separate from unavailable fresh target replay | All required assertions for the stated scope passed in the recorded run. |
| P05 | PASS | Explicit actual-host/backend/provider support matrix | This report explicitly separates Windows tested, Linux/macOS not run, native blocked, optional backend outcomes and unsupported CFG/phi. |
| P06 | BLOCKED | Three demos A/B/C | GHIDRA_INSTALL_DIR not configured; Matching Ghidra native decompiler not available; No usable Java runtime found by real REA provider probe; pwntools binary-layout lane supports Linux x64 only |
| P07 | PASS | Single writer, cancellation, persistence recovery and no late result upgrade | All required assertions for the stated scope passed in the recorded run. |

## 已知缺口

- 真实 Ghidra/Java/native decompiler 前提未满足，R08/R12 与演示 C 保持 BLOCKED。
- Linux/macOS、真实 solver UNKNOWN、实际 Codex 客户端与 CFG/phi 不冒充已运行。
- 保留的研究基准每10个 holdout 点中有3个训练边界复查点，只有7个未见 typed 输入；不把全部10点称作独立未见样本。
- 固定数值基准：reference 8/9，Handwired 8/9；失败记录保留，不声称速度收益。
- 干净安装 smoke：NOT_RUN。

每个 gate 的命令、请求、时间、主机、依赖身份、输入摘要、输出引用、计数与具体失败信息见 matrix.json；完整 Vitest JSON 与 stdout/stderr 均保留。
