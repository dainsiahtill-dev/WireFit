# Handwired numeric runtime adapter map

Pinned upstream: `https://github.com/chenglou/handwired`, commit `257856e3b221140acb4cc4460626b850c0bd4ff1` (2026-10-16). The unmodified, import-free dependency closure is `vendor/handwired/src/runtime/numeric-ui-core.ts`; MIT license and byte SHA-256s are in `vendor/handwired/LICENSE` and `vendor/handwired/manifest.json`. Tracked source was clean in the upstream checkout. Local untracked launcher files were not included.

Actual runtime gate: native Node **24.22.0**, Windows x64. The repository-local Node executable is `.tools/runtime/node_modules/node-win-x64/bin/node.exe`. Bun is neither required nor used by this adapter. Upstream demos use Bun, but the vendored Circuit module has no Bun dependency.

| Real upstream API | Wirefit use | Runtime contract |
| --- | --- | --- |
| `new Circuit(3)` | Source cells `[a,b,x]` for each fixed segment | Parameters are source cells, so backprop differentiates parameters |
| `source(i)` | Source wires 0,1,2 | Index validated by upstream |
| `assumeRange(wire,min,max)` | Declared finite FP32 parameter bounds; actual training input min/max | Declared before readers; every actual source checked by `evaluateReference` |
| `multiply(a,x)` | Dynamic product, marked as a rounding point | Actual upstream ReGLU expansion/multiply macro; no substitute arithmetic engine |
| `roundAffine([[product,1],[b,1]])` | Addition after the product rounding point | Preserves operation and term boundaries; final candidate independent evaluator retains exact zero sign |
| `markRoundingPoint(wire)` | Product and addition | No affine reassociation across the declared profile points |
| `compileTensorProgram([output])` | Compile real graph and report layer count | Runtime fitting uses reference stream to preserve stored operation rounding |
| `evaluateReference(Float32Array)` | Real graph forward on actual `[a,b,x]` | Finite source and intermediate checks; numeric agreement against two-rounding FP32 formula |
| `backpropagateReference(values,seeds,{booleanGradient:'reject',indexGradient:'reject'})` | Real parameter backprop, output seed = masked MSE upstream derivative | No STE, no trainable index; returned source gradients and forward arrays are copied |

Template mapping: affine and affine_clamp parameter order `[a,b]`; piecewise order `[a0,b0,a1,b1,...]` with exactly `knots.length+1` segments. The single input/output IDs remain the validated model IDs. Knots are fixed, strictly increasing finite FP32 values. At a knot, the segment on its right is selected. Inputs outside knot endpoints use the first/last segment.

The host computes the independent two-rounding FP32 affine value before clamp. It recomputes the clamp mask at every evaluated parameter state: `lo < t && t < hi` gives 1; saturation and equality give 0. Loss uses the whole minibatch denominator, including saturated samples. Piecewise selection is fixed from the input. Only the selected segment receives gradients. These are real arithmetic intent derivatives, not derivatives of the literal rounding function.

The upstream multiply/affine stream can canonicalize negative zero. The adapter checks forward equality numerically and counts every signed-zero bit discrepancy as `bitwise_discrepancies`. Its `training_comparison` explicitly states this policy. It does not claim bitwise backend parity, and does not use upstream min/max as the final clamp. Final candidate execution, comparison, holdout verification and standalone export always use `wirefix.fp32.templates.v1`, including signed zero and gradual underflow. Finite overflow is rejected before clamp can hide it.

`src/numeric.ts` supplies the independent FP32 evaluator, bounded centered affine least squares, seeded reference SGD/Adam, and real Handwired SGD/Adam. `analytic_baseline` accepts only affine with `closed_form`; other combinations are explicit unsupported errors. Candidate selection uses train/validation only. A frozen semantic hash is returned before the parent is allowed to read holdout. All invalid/failed training observations reject the run; no samples are removed to improve a denominator.

The numeric worker accepts exactly one UTF-8 JSONL request, bounded to 32 MiB: `{protocol_version:1,job_id,template,train,validation,options}`. It returns one line with `status:'completed'` and `result`, or `status:'failed'` and a structured `error`. Parent process supervision owns timeout, cancellation, output limits and holdout. The worker rejects extra envelope/options fields and wrong split labels.

Actual verification command:

```powershell
& ./.tools/runtime/node_modules/node-win-x64/bin/node.exe ./node_modules/vitest/vitest.mjs run tests/numeric.test.ts tests/numeric-handwired.test.ts tests/numeric-fit.test.ts tests/numeric-process.test.ts
```

Coverage includes independent FP32 rounding literals, overflow hidden by clamp, negative zero, subnormals, knot boundaries, invalid bounds/parameter sets, real graph gradients, copied snapshot lifetimes, actual source range violations, bounded LS slope constraints, clamp mask updates, holdout-output access rejection, reference/Handwired parameter recovery, and fresh-process standalone source execution. Passing tests establish these model-level contracts; they do not establish arbitrary original-binary fidelity.
