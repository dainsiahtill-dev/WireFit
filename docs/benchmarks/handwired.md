# Handwired comparison: recorded results

Run artifact: `artifacts/acceptance/handwired-benchmark.json`. Native Node 24.22.0, Windows x64; CPU and runtime details are recorded in the artifact. The full run took 32.65 seconds. These are synthetic, independently implemented source-owned FP32 fixtures, with zero original-target Oracle calls. No original-binary fidelity or GPU speedup is claimed.

The fixed plan contains affine, affine_clamp and piecewise_affine, each with three distinct parameter seeds. All supported configurations receive identical initial models, parameter bounds, seeded batch plans, restarts, 2,400 total optimizer iterations, 15-second wall budgets, candidate limits and comparison policy (`atol=0.00002`, `rtol=0.00002`). Baseline uses its legitimate closed-form algorithm. Each configuration runs in a new child process: the first fit is cold, the second warm. Candidate and optimizer state reset between trials; runtime/module/JIT state is warm. Cold timings include first-use schema compilation; parent process wall timings are separately retained.

| Backend | Planned task configurations | Passed in both cold/warm trials | Failed | Unsupported |
| --- | ---: | ---: | ---: | ---: |
| analytic_baseline | 9 | 3 | 0 | 6 |
| reference | 9 | 8 | 1 | 0 |
| handwired | 9 | 8 | 1 | 0 |

The official analytic baseline supports affine/closed_form only. Its six non-affine entries are explicitly unsupported, not failed optimizer attempts and not substituted with a weaker pseudo-baseline. All three affine tasks recover successfully. The gradient backends both fail the same piecewise task, parameter seed 1: 7/16 validation and 4/10 holdout points mismatch; maximum holdout absolute error is `0.0011614561080932617`. Neither the policy nor the budget was changed after holdout consumption. The benchmark command exits 1 to retain this real recovery failure.

| Backend/task set | Median cold fit ms | Median warm fit ms |
| --- | ---: | ---: |
| analytic_baseline, affine only (3 tasks) | 335.88 | 6.40 |
| reference, all templates (9 tasks, including failure) | 791.44 | 457.45 |
| handwired, all templates (9 tasks, including failure) | 1083.15 | 713.27 |

Baseline and gradient medians cover different task sets. Directly comparing the two gradient backends on these same nine tasks found equal recovery counts and slower Handwired fits. This measurement supports retaining Handwired as an optional backend; it does not show additional recovery or speed benefit for this workload. It does not predict results for larger circuits.

Raw train/validation observations, post-freeze holdout observations, immutable input/output identities, target fixture parameters, source hashes, optimizer settings, complete denominators, candidate hashes, actual backend identities, convergence logs, graph-gradient counts, timing and memory measurement methods are preserved in the JSON. Holdout observations are materialized only after each learner call returns a frozen candidate. The learner receives only train and validation arguments.

Memory uses before/after RSS checkpoints and OS process-lifetime `maxRSS`. Warm process maxima include the prior cold trial; they are not isolated per-fit peaks. No stronger memory claim is made.

Reproduce after building:

```powershell
& ./.tools/runtime/node_modules/node-win-x64/bin/node.exe --import tsx ./src/numeric-benchmark.ts
# Or npm run benchmark with Node 24 available on PATH after npm run build.
```

The benchmark smoke test runs three affine configurations and checks both real cold/warm results and post-freeze holdout. It does not replace the full matrix artifact above.


历史数据划分的额外限制：每个标为 holdout 的10点集合包含训练中已出现的 `-4`、`+0`、`+4` 三个 typed 输入，作为边界复查；只有其余7个 typed 输入未在训练中出现。此事实不改变已保留的任何数据、阈值或失败，也不能被描述成10个独立未见点。所有后端使用同一固定集合，因此比较公平，但泛化结论受到这项限制。实际 Demo B 使用严格跨 split 检查的数据集，其独立留出验证单独记录。
