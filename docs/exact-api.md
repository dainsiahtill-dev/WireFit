# Exact BV API

The product name is Wirefit. Existing contract identifiers remain `wirefix.bv.total.v1`. All APIs use the unmodified JSON contracts in `contracts/`; imported claims cannot set a proof or target validation state.

`src/types.ts` contains the shared TypeScript contracts. `values.ts` validates canonical typed values and provides `bv(bigint,width)`, `bool(boolean)`, `fp32Bits(number)`, `fp32Number(value)`, `sameType` and `valueEquals`. BV bit patterns never pass through Number. FP32 conversion uses a DataView and retains signed zero.

`validateBvModel(unknown): BvModel` in `model.ts` performs JSON Schema and semantic validation: unique IDs, topological closure, exact operation attributes, operand/output types, extension/extraction/concatenation widths, output references, execution guard references and domains. `validateDomain(domain,ports)` returns a validated Domain. `validateInputs(ports,values)` requires exactly the declared ports. `domainContainsPoint(domain,values)` evaluates an already validated conjunction. `validateMapping(left,right,mapping)` requires a type preserving complete input bijection and nonempty output selection; outputs cannot repeat. `defaultMapping` accepts only matching names/types and still validates the generated mapping.

`evaluateBv(model,inputs): ValueMap` in `bv.ts` runs an independent BigInt evaluator after model/input/domain validation. `evaluateNode(op,type,args,attrs)` provides the same scalar semantics with runtime type and attribute checking. The full profile operation table is implemented, including mixed-width full-count shift guards, signed comparisons, extensions and extracts. Unsupported operations are rejected.

```ts
compareBv(left, right, domain, mapping, budget, signal?): Promise<ExactCheck>
```

`solver.ts` runs actual pinned `z3-solver` in a fresh Node child process using the shared process supervisor. The process closes before the parent accepts its result. Deadline/cancellation terminates the owned process tree. Each query uses a new solver; the child makes no synchronous Z3 call while an asynchronous check is pending. Model intermediates use separate namespaces, while mapped inputs share symbols.

Three independent queries check requested-domain satisfiability, containment in both model contracts, and output disequality. Empty domains throw `DOMAIN_EMPTY`; failed containment throws `DOMAIN_MISMATCH`, each carrying completed query records. Ordinary outcomes are `proved`, `disproved`, or `inconclusive`. The service maps internal `disproved` to the contract's `refuted`. Timeout, cancellation, UNKNOWN and worker failure remain inconclusive. A SAT result is replayed by the concrete evaluator, including both domains and selected outputs; disagreement with the solver raises `INTERNAL_CONSISTENCY_ERROR`.

Each check returns `queries` with kind/status/SMT-LIB/duration and optional reason, plus `metadata`: semantic and source hashes, requested-domain hash, actual mapping, unselected outputs, options, Z3/package/WASM/Node identity and worker cleanup. A typed `domain_witness` is independently validated when available. An inconclusive process failure preserves submitted SMT-LIB and completed protocol records when captured by the supervisor. Proof covers only these declared models, domain and selected outputs. It does not establish binary fidelity or provide an independently checked proof certificate.

```ts
simplifyBv(model, budget, signal?, {
  domain?, grammar?, constants?
}): Promise<{ candidate, check, search }>
```

`synthesis.ts` first applies auditable copy/idempotence/zero/self-cancellation rules, constant folding, common subexpression elimination, dead node pruning, and the fixed-width identity `(a xor b) + 2*(a and b) = a+b`. Every rewrite result is checked exactly. This rewrite pass always runs; `grammar` and `constants` control subsequent enumeration. The default grammar includes the requested arithmetic/bitwise/unary/shift/comparison/select operators. Bool inputs and Bool comparison results are preserved.

Enumeration is bounded by wall time, candidate count, AST node count and solver iteration count. It handles one output; multiple outputs receive the certified rewrite pass. A model-dependent execution guard also limits processing to rewriting, so its original guard cannot be silently discarded. Zero-input seeds only reject obvious mismatches. Surviving candidates go through Z3; replayed counterexamples refine the sample set. Sample equality never supplies a proof. The result records actual grammar/constants, generated/rejected/checked counts, refinements, counterexamples, rule names, costs and stop reason. A requested narrowed domain is saved on the returned candidate and used explicitly in its check. Search can exhaust its grammar or budget without discovering a cheaper candidate.

```ts
suggestBvInputs(models, domain, budget, signal?, {
  strategy?: 'disagreement' | 'boundaries', max_inputs?: number
}): Promise<SuggestionResult>
```

Suggestions require two to sixteen same-signature BV models. Disagreement points are solver counterexamples already replayed by the evaluator. Boundary points combine a satisfiable typed witness with legal zero/extreme/signed-boundary/domain-endpoint values and neighboring values, keeping only in-domain inputs. Results contain `inputs: [{inputs,reason,models?}]`, checks, domain, complete/partial status and stop reason. They are proposed inputs, not target observations or coverage claims.

`exportModelSource(model, language = 'js')` in `export-model.ts` emits a standalone ESM module. Select `ts` for strictly typed standalone TypeScript; use `.mts` or an ESM package when compiling it. Both export `model`, `evaluate(inputs)` and the default evaluator. The source contains its BigInt helpers, input validation and domain checks. It uses generated local identifiers and serialized data, with no eval, subprocess or runtime repository dependency. Export verification executes a fresh Node process. Tests exhaust all 65,536 BV8 input pairs and check every opcode against literal expected results through the concrete evaluator, actual Z3 encoding and standalone code. The TypeScript test also verifies that generated code does not suppress compiler diagnostics.
