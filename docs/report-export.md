# Standalone report export

`exportReport(store, runId, outDir)` exports a stored verifier result and its
evidence closure. The destination must be absent or empty. Existing files are
never replaced; symlink and junction components are rejected. Artifact reads
use the case store's size, path and raw-byte SHA-256 checks. The exporter also
checks the request digest and each model's semantic and source-envelope digests
against the identities saved by the verifier.

The package contains:

- `report.md`, the unchanged `result.json`, the original `request.json`, and the
  stored run record.
- Model JSON plus standalone JavaScript and TypeScript modules. When present,
  the frozen candidate is also exposed as `candidate.mjs` and `candidate.ts`.
- The stored dataset, explicit policies and domains, immutable input plans,
  observations, counterexamples, solver records, original portable bundles and
  referenced raw observation artifacts.
- `replay-data.json`, with independent evaluator snapshots explicitly labeled
  `reference_model`, `lifted_model` or `candidate_model`. Generated model smoke
  cases are never labeled original-target observations.
- `replay.mjs`, `replay-verification.json`, `manifest.json` and
  `manifest.sha256`.

The manifest records raw-byte hashes and lengths. The returned receipt adds
`manifest_sha256`, computed over the exact final `manifest.json` bytes, and the
output directory. That digest is not embedded into its own preimage. Artifact
references keep their relative paths. The original imported dataset manifest is
an opaque historical attachment; the stored local dataset supplies its actual
artifact closure.

Run with a compatible Node runtime:

```sh
node replay.mjs
```

The helper uses only the exported directory and built-in Node modules. It checks
all listed file hashes before importing generated model modules. It reports
separate results:

- `export_consistency` compares generated modules with snapshots from Wirefit's
  independent model evaluator. Expected model execution failures are retained
  and counted separately as `model_error_cases`.
- `recorded_target_comparison` compares a candidate with actual retained
  `observed` / `original_target` rows under the explicit output mapping and
  comparison policy. It preserves failed and out-of-domain denominators. A
  planned observation that was never completed remains in the denominator. A
  reproduced candidate mismatch remains `mismatch`, while export consistency
  can still be `matched`.
- `recorded_source_counts` keeps expected fixtures, reference fixtures, lifted
  models and original targets distinguishable.
- `fresh_target_replay` remains `unavailable`; the helper makes no new original
  target call. `solver_replay` remains `not_run`; historical solver artifacts
  are included without claiming a new proof.
- `original_verifier_result` preserves the original model-check, target, fit
  and fidelity statuses.

REA-derived local expressions, unknown/control-dependent execution guards and
local-value observations do not authorize original-function comparison in the
helper. Their module consistency can still be reproduced. Missing candidate,
policy or binding yields unavailable target comparison rather than a pass.

Original Oracle targets, wrappers and runtimes are external dependencies by
default. Their declared files/hashes, binding identity, protocol and environment
key requirements are listed. Actual environment values are not included. A
source target known only through portable Evidence is also listed by its actual
recorded identity; the portable bundle does not imply inclusion of that target.
A package can replay historical observations without having access to the
original process, case directory, REA or Wirefit installation.

Every export runs its helper in a fresh owned process before returning a
receipt. `replay-verification.json` contains the actual process outcome and
separated replay results. A module inconsistency prevents successful export;
an honestly reproduced original-target mismatch does not.

Automated tests exercise a copied export after deleting the original case,
an independently executed target fixture whose candidate is deliberately wrong,
module tampering before execution, nonempty destinations, Windows junctions,
missing candidates, post-verification model changes, REA guard restrictions,
FP32 signed zero and strict compilation of the exported TypeScript module.

## Binary workflows

The same CLI/MCP report export entry dispatches inspect_binary/unpack_binary records to a separate binary exporter. Its package runs verify.mjs for file identity only; it does not use the mathematical model-replay verdict. See [binary report export](BINARY-REPORT-EXPORT.md). Existing model schema validation and proof/replay behavior above remain strict.
