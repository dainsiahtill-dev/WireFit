# Bounded Ghidra functions

`functions.mjs` consolidates the existing bounded research runners. It imports a
PE byte copy into a fresh Ghidra project, disables auto-analysis and uses the
fixed `WirefitBoundedFunctions.java` script. It never executes the input image.
Old research runners, Java source and evidence remain unchanged.

Use Node 24 and an already built checkout (`dist/src/process.js`, `pe.js` and
`shared.js` must exist). The native installation JSON supplies only `java_home`
and `ghidra_install_dir`; other values, including `previous_user_environment`,
are not copied into output. The configuration's byte identity is recorded.

```powershell
& '.\.tools\runtime\node_modules\node-win-x64\bin\node.exe' `
  'tools/ghidra/functions.mjs' `
  --input 'E:\wirefit\exports\vmde-20261020\unpacked_vmde.exe' `
  --request 'E:\wirefit\requests\bounded-functions.json' `
  --out 'E:\wirefit\artifacts\research\vmde\bounded-functions-new' `
  --native 'E:\wirefit\.local\native-installation.json'
```

The request must contain exactly these five fields. Set `expected_sha256` to the
actual input file's SHA-256; this example selects one bounded candidate address.
The source file and request parent paths must already exist. The output's parent
must exist and the output itself must be absent.

```json
{
  "schema_version": 1,
  "expected_sha256": "50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992",
  "entries": [{"va": "0x482c30", "max_bytes": 2048}],
  "decompile_seconds": 5,
  "script_seconds": 40
}
```

Requests are strict UTF-8 JSON, at most 32 KiB. Duplicate object keys (including
escaped spellings), nonfinite numbers, extra fields, repeated numeric addresses
and address overflow are rejected. There must be 1–5 unique VA32 entries, each
with 1–2048 guarded bytes; decompilation allows 1–5 seconds per function and the
script 1–45 seconds. All selected guards must map uniquely to executable,
file-backed bytes in the PE. The source file is bounded to 128 MiB. Symlinks,
junctions, path aliases and hardlinked input files are rejected.

The public CLI accepts only the four required path options. It has no custom
executable, script, extra headless argument, PID or timeout override. The child
has a fixed 60-second process deadline and `-max-cpu 1`. `-noanalysis`,
`-readOnly` and the SHA-pinned Java script are always selected. Windows uses
PowerShell with `-NoProfile -NonInteractive`, a UTF-8 BOM launcher and escaped
single-quoted arguments. Batch expansion characters `% & ! ^ ( )` are rejected
in Windows paths/arguments. `JAVA_HOME` selects the configured JDK; Java option
environment variables are cleared. POSIX directly spawns `support/analyzeHeadless`
with the same explicit argv and environment. **The POSIX Ghidra path has not
been exercised here.**

Each new output retains:

- `inputs/analysis-input.exe`: the exact source byte snapshot.
- `inputs/request-original.json`: exact supplied request bytes;
  `inputs/request.json`: normalized equivalent JSON consumed by Java.
- `inputs/WirefitBoundedFunctions.java`: the fixed script bytes.
- `launch.ps1` or `launch.sh`, explicit argv, selected Java/headless identities,
  stdout/stderr, Ghidra logs when produced, and generated analysis files.
- `analysis/summary.json`: the original Java summary, when produced.
- `receipt.json`: actual child PID/code/signal, initial and final file identities,
  validation results, per-function acceptance and the first failure plus later
  errors. All files are created exclusively; previous output is never replaced.

Source, request, script/tool code, selected Java/headless files and staged copies
are rechecked after execution. This records pairwise observations, not an atomic
snapshot or a guarantee about later changes. Java/headless identities identify
the selected installation files; the full SDK/JAR/cache closure is **not**
verified. Ambient import/prototype metadata may still influence decompilation.

Summary validation independently checks input/request identity, disabled
analysis, `target_executed:false`, all requested entries, staged PE guard and
instruction bytes, listing/body byte accounting, per-entry JSON equality and
raw/high-p-code PC scope. It derives the top status from per-function results.
An exit-zero child can therefore produce a partial or failed receipt.
`scope_rejected` retains diagnostic `.scope-rejected.c` while exposing no
accepted C file; incomplete decompilation also stays partial. Calls and unknown
guard exits are retained as observations. Even `completed` means the requested
bounded observations passed these checks; it does not establish a function ABI,
complete function boundaries, external dependencies, runtime behavior or a
runnable reconstructed image. Decompiled C is an analysis aid.

The CLI exits 0 only for `completed`, 1 for partial/failure, and 130 for a recorded
signal cancellation. `runProcess` bounds and closes its owned child/tree on
timeout or cancellation. That child-close evidence is not target-process cleanup
evidence: the input image is never launched. Failures after exclusive output
creation retain their receipt and any generated files. Preflight failures leave
the output absent. If the filesystem refuses the final receipt write, the CLI
reports `receipt_saved:false`, `log_error`, the preserved first error, later
errors, actual child execution and stdout/stderr locations. It leaves any
colliding receipt unchanged and cannot promise an on-disk receipt in that case.

Run the scoped tests without Ghidra or a target executable:

```powershell
& '.\.tools\runtime\node_modules\node-win-x64\bin\node.exe' `
  --test 'tools/ghidra/functions.test.mjs'
```

The tests use real Node child fixtures through the programmatic `run` port and
mark `execution_backend: "injected_run_port"`. They do not claim Ghidra ran.
`bounded-files.mjs` owns file identities and exclusive writes;
`bounded-protocol.mjs` owns strict JSON/request/PE/scope validation;
`functions.mjs` owns the fixed launch and failure/receipt lifecycle.
