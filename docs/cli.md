# Wirefit CLI and MCP

Wirefit runs locally. The CLI writes one JSON result to stdout and JSON progress events to stderr. Model proofs, original-target observations and numeric fit quality remain separate fields. A refuted model comparison is a completed analysis, not a process failure.

On Windows use `./wirefit.cmd` or `./wirefit.ps1`. Other systems can run `node apps/cli/bin/wirefit.js`. The launchers prefer this checkout's pinned Node 24 runtime on Windows; otherwise the system runtime must be Node 24.x. They use compiled `dist/src` entries after `npm run build`, with a source/tsx fallback when no build exists. They never download dependencies, install an MCP configuration or start a daemon. Rebuild after source changes.

```powershell
npm ci
npm run build
./wirefit.cmd doctor --json
./wirefit.cmd case create --dir ./cases/demo
./wirefit.cmd model import --case ./cases/demo --file ./examples/model.mba-u8.json
./wirefit.cmd model import --case ./cases/demo --file ./examples/model.add-u8.json
./wirefit.cmd compare --case ./cases/demo --left mba_u8 --right add_u8
./wirefit.cmd model simplify --case ./cases/demo --model mba_u8
```

Doctor inspects local capabilities without acquiring a case writer lease or starting REA. Imported model IDs come from validated model files; fitted, simplified and lifted candidates receive new IDs. Foreground experiment results include `job`, the stored `result`, and `candidate_model_id`/`dataset_id` when applicable. Use the returned candidate ID for the next step.

CLI jobs stay in the foreground until their owned workers close. Ctrl-C requests cancellation and waits for cleanup; exit code 130 denotes cancellation. There is no cross-process PID cancellation or detached CLI mode. MCP owns asynchronous jobs for clients that need polling. Normal exit is 0, validation/execution failure is 1, and command syntax errors use 2. Inspect the result dimensions even when the command exits 0.

## Models and comparisons

`model evaluate --case CASE --model ID --inputs FILE` accepts a JSON typed-input map for one evaluation, or `.jsonl`/`.ndjson` planned samples for multiple evaluations. BV64 values stay fixed-width hexadecimal strings.

```json
{"a":{"kind":"bv","width":8,"bits":"0xfa"},"b":{"kind":"bv","width":8,"bits":"0x0a"}}
```

`compare --left ID --right ID` compares exact BV models by default. `--domain domain.json`, `--mapping mapping.json` and `--budget budget.json` are optional. The default domain is the left model's declared domain; no hidden intersection is taken. A default mapping is generated only for matching input/output sets, names and types, printed to stderr and persisted. Renamed ports need an explicit mapping. The exact verifier checks nonempty domain and containment in both contracts before checking equivalence.

```json
{"inputs":[{"left":"a","right":"x"},{"left":"b","right":"y"}],"outputs":[{"left":"result","right":"out"}]}
```

FP32 comparison uses `--mode sampled_fp32`, an explicit `--policy`, and exactly one of `--inputs samples.jsonl` or `--dataset ID`. It produces a sample conclusion. FP32 policy kinds are `bitwise-fp32` or `tolerance-fp32` with explicit string tolerances and `nonfinite: "reject"`.

`model simplify` accepts `--domain`, `--budget` and `--search search.json`. Search has `grammar`, typed `constants`, and `objective: "node_count"`. Certified rewriting always runs; grammar/constants control bounded enumeration. No cheaper candidate or budget exhaustion is an ordinary search outcome. See `exact-api.md` for the supported search scope.

## Explicit targets and datasets

```powershell
./wirefit.cmd oracle register --case ./cases/demo --manifest ./oracle.json
./wirefit.cmd dataset collect --case ./cases/demo --oracle TARGET_ID --inputs ./samples.jsonl --policy ./policy.json --max-calls 512
./wirefit.cmd dataset import --case ./cases/demo --manifest ./dataset.json --artifact-root ./dataset-bundle
./wirefit.cmd compare --case ./cases/demo --left-oracle LEFT_ID --right-oracle RIGHT_ID --inputs ./samples.jsonl --policy ./policy.json
```

Oracle registration binds an explicitly selected executable, wrapper, file identities and environment policy. Collection and comparison actually execute those registered targets through the fresh-process JSONL protocol. Merely importing an Oracle manifest in a dataset does not register or execute it. Model comparison flags and Oracle comparison flags are mutually exclusive. External comparison inputs are validated and copied into the case before scheduling the canonical request.

Each planned JSONL row includes its split:

```json
{"sample_id":"q1","split":"train","inputs":{"x":{"kind":"fp32","bits":"0x3f800000"}}}
```

```powershell
./wirefit.cmd model fit --case ./cases/demo --dataset DATASET_ID --template-model TEMPLATE_ID --backend handwired --budget ./budget.json --training ./training.json
```

Backends are `handwired` (the CLI default), `reference`, and `analytic_baseline`. The analytic baseline supports affine templates with `closed_form`; clamp and piecewise templates use Handwired or reference training. Defaults use Adam with learning rate `"0.001"`; provide training settings for the task. An analytic selection defaults to `closed_form`. A training file is explicit:

```json
{"optimizer":"adam","learning_rate":"0.03","loss":"mse","batch_size":32,"restarts":1,"validation_interval":20}
```

Budgets may be partial on CLI convenience commands; defaults are resolved before the canonical request is saved. Fitting uses fixed train/validation observations, freezes the candidate, then checks the independently declared holdout. A consumed holdout cannot support repeated tuning. Expected fixtures never become original-target observations.

## Binary inspection and explicit unpacking

```powershell
./wirefit.cmd binary inspect --case ./cases/demo --file ./target.exe
./wirefit.cmd binary inspect --case ./cases/demo --file ./target.exe --config ./binary-tools.json --timeout 120000
./wirefit.cmd binary unpack --case ./cases/demo --file ./target.exe --backend unlicense --config ./binary-tools.json --timeout 120000 --target-timeout 10 --no-copy-dependencies
```

Both commands require an existing explicit case and use its durable jobs and reports. Inspection reads PE32/PE32+ metadata, imports, section entropy and conservative packing indicators. Omitting `--config` performs static inspection; an absent detector is reported as `not_configured`. Inspection does not run the selected executable.

`--config` selects a UTF-8 JSON toolchain containing only the optional `detector` and `unpackers.unlicense` commands. Each command has a required executable `command` and an optional string-array `args`; Wirefit appends the workflow's arguments. Use explicit paths for the separately installed, pinned tools:

```json
{
  "detector": { "command": "C:/Tools/die/diec.exe", "args": [] },
  "unpackers": { "unlicense": { "command": "C:/Tools/unlicense/unlicense.exe", "args": [] } }
}
```

Arguments are passed directly without a shell. Executable paths and individual arguments are limited to 4096 characters without NUL; argument arrays have at most 128 entries. Unknown configuration fields and backends are rejected. `--timeout` sets the external process budget in milliseconds (1..600000): the detector for inspection, or the backend for unpacking. Unpacking grants its detector a separate budget capped at 120 seconds. Snapshotting and owned cleanup add time beyond these process budgets. `--target-timeout` is the Unlicense target wait in seconds (1..600). `--no-copy-dependencies` disables dependency copying for this run and takes no value.

Unpacking requires both `--backend unlicense` and `--config`; it explicitly executes the configured external backend against a copy of the input. Unlicense targets Themida/WinLicense. A detector result identifying a different family blocks that backend. An unconfigured detector leaves applicability unconfirmed; selecting a backend does not establish that it supports the file.

The case retains source snapshots and hashes, tool identities, arguments, logs, PE inspection artifacts and any validated output artifacts. The original input is preserved. Results include `validation.source_unchanged` and `validation.runnable_verified`; each output has `quality: "analysis_dump"` and `runnable_verified: false`. An analysis dump has no runnable, behavior-equivalence or devirtualization claim. Missing or invalid output and tool failures produce failed jobs with retained records. Independent execution and behavior checks are needed before making stronger claims.

The foreground JSON contains `job` and the compact stored `result`. Use `job.result_id` with `report show --section result` or `show --kind runs --id RUN_ID`; the `inspection_artifact` and output artifact references point to the full metadata and derivatives within the case. These workflows use separate binary job operations and do not extend the canonical mathematical experiment union.

Binary runs also support the existing `report export --case CASE --run RUN_ID --out DIRECTORY` and `wirefit_export_report` MCP tool. The standalone package includes source/derivative/DLL snapshots, logs and the recursive JSON/JSONL artifact closure; `node verify.mjs` checks file identity without executing any PE. Failed and cancelled operation states remain unchanged. See [binary report export](BINARY-REPORT-EXPORT.md) for the directory format and verification scope.

PE metadata now includes `entry_assessment`, `tls` and `tls_complete`. The observed x86 SEH-helper entry signature is explicitly heuristic; unavailable TLS bytes produce incomplete metadata. Doctor separately reports current configured tool-file presence, validated retained local native evidence and historical full-acceptance status; it performs no native execution.

## Bounded native tracing

```powershell
./wirefit.cmd binary trace --case ./cases/demo --file ./target.exe --config ./trace-tool.json --plan ./trace-plan.json
```

Tracing explicitly runs a copied PE through the configured native worker. It creates a new owned process; the interface cannot attach to an existing PID. `--config` and `--plan` are required UTF-8 JSON files. The trace config is only `{ "command": "ABSOLUTE_WORKER_EXECUTABLE", "args": ["EXPLICIT_WORKER_ARGUMENT"] }`, with `args` optional; it is not the inspection/unpacking toolchain object. Arguments pass directly without a shell. The supplied Python worker is `tools/native-trace/worker.py`; select an explicit Python executable, absolute worker path and isolated pinned Frida module directory. For this checkout, a trace-tool config can use:

```json
{
  "command": "C:/Path/To/Python/python.exe",
  "args": ["-X", "utf8", "-I", "-S", "E:/wirefit/tools/native-trace/worker.py", "--module-path", "E:/wirefit/.tools/analysis/frida-python"]
}
```

Replace the paths with the selected local installation. The worker requires the pinned Frida 17.2.17 package inside the explicit module directory. These entrypoints do not install Python or Frida.

A trace plan declares all five fields:

```json
{
  "duration_ms": 1000,
  "breakpoints_rva": ["0x1000"],
  "ranges": [{ "rva": "0x1000", "size_bytes": 64 }],
  "api_hooks": [{ "module": "kernel32.dll", "symbol": "ExitProcess" }],
  "max_events": 128
}
```

Duration is 1..60000 milliseconds. Plans admit at most four breakpoints, eight ranges, sixteen API hooks, and 1..512 events. RVAs are `0x`-prefixed hexadecimal strings of at most eight digits. Each memory range is at most 1 MiB and the combined range budget is at most 4 MiB. Empty selector arrays are permitted. RVA selectors must fit the inspected PE image. API modules are basenames of at most 128 letters, digits, dots, underscores or hyphens (excluding `.` and `..`); symbols are bounded export names of at most 256 characters. Unknown fields, process IDs, output manifests and supplied verdicts are rejected before scheduling.

The CLI waits for the trace job and owned process cleanup, with the same Ctrl-C lifecycle as other foreground jobs. MCP `wirefit_trace_binary` accepts `{file,tool,plan}` directly and returns a job ID for `wirefit_get_job`, `wirefit_cancel_job` and `wirefit_get_report`. Trace is a separate `trace_binary` job operation, outside canonical mathematical experiments.

The stored report retains source identity, PE inspection, process logs, the worker protocol as `trace_artifact`, and validated memory `snapshots`. Snapshot entries reference case artifacts; memory snapshots are not PE outputs. Reports keep `runnable_verified: false`. A recorded event or memory snapshot does not establish complete behavior, a recovered algorithm, or equivalence. Synthetic protocol tests verify transport and lifecycle only; they are not original-target observations.

## Evidence

```powershell
./wirefit.cmd evidence import --case ./cases/demo --bundle ./portable-evidence.json
./wirefit.cmd model lift --case ./cases/demo --evidence LOCAL_RECORD_ID --output SOURCE_OUTPUT_ID
./wirefit.cmd evidence acquire --case ./cases/demo --target ./target --provider ghidra --procedure 0x401000
```

Acquisition defaults to the separately installed pinned public REA entrypoint. `--config rea.json` accepts only `command`, `args`, `cwd`, `env`, `target`, `provider`, `functionAddress`, `timeoutMs` and `recoveryTimeoutMs`. Override individual CLI fields with `--command`, `--args argv.json`, `--cwd`, `--target`, `--provider`, `--procedure` or `--timeout`. Arguments are arrays; no shell command string is evaluated. Without a target/procedure, acquisition performs discovery and saves an authenticated empty export; it does not analyze a binary.

Acquisition stdout contains a compact summary, saved bundle/record references, cleanup status, tool count and a `raw_artifact` reference. The raw artifact preserves the full tool catalog, replies, capability snapshots and untrusted metadata. `show --kind runs --id RUN_ID` reads the stored run envelope; resolve its artifact path within the explicit case. A native provider that is unavailable remains blocked. Synthetic scalar lift tests and real public REA transport tests do not establish a working Ghidra/native chain.

Use returned local evidence record IDs and source output IDs. Retained IDs from another MCP session require a portable bundle. `model lift --cutpoints cutpoints.json` accepts an explicit JSON string array. Missing definitions, producer truncation, unsupported phi/operations and unknown guards retain their distinct diagnostics/scope.

## Jobs, reports and canonical requests

```powershell
./wirefit.cmd jobs --case ./cases/demo
./wirefit.cmd job show --case ./cases/demo --job JOB_ID
./wirefit.cmd show --case ./cases/demo --kind models --id MODEL_ID
./wirefit.cmd report show --case ./cases/demo --run RUN_ID --section counterexamples --offset 0 --limit 100
./wirefit.cmd report export --case ./cases/demo --run RUN_ID --out ./exports/demo
./wirefit.cmd experiment run --case ./cases/demo --request ./experiment.json
```

Jobs/show/model evaluation/report inspection open the case read-only, so they work while an MCP instance holds its writer lease. Inspection does not recover, cancel or relabel the owning instance's jobs. Report exports verify their standalone modules in a fresh process and retain independent observations and external dependency identities.

`experiment run` accepts the exact finite union in `contracts/experiment-request.schema.json`: simplify, model/Oracle comparison, recorded/live candidate verification, fitting, and input suggestions. Unknown fields, injected verdicts, empty output maps and invalid input bindings are rejected. It provides access to advanced operations without adding hidden CLI semantics.

## Research experiments

```powershell
./wirefit.cmd research list
./wirefit.cmd research spec --direction D07
./wirefit.cmd research run --case ./cases/research-vmde --direction D01
./wirefit.cmd research recheck --case ./cases/research-vmde --run RUN_ID
./wirefit.cmd report export --case ./cases/research-vmde --run RUN_ID --out ./exports/research-D01
```

`research list` and `research spec` read the seventeen pre-registered direction specifications that are compiled into the product. They need no case and open no case: they are the catalogue, not an experiment.

`research run` runs one direction through the five research phases: plan, develop, freeze, evaluate, recheck. It is a writer: it produces a job, a stored run and exportable artifacts. It takes the writer lease on the case, so it cannot run while an MCP instance owns the same case.

`research recheck` recomputes every recorded observation from the stored artifacts and the pinned evidence. It is read only and opens the case without the writer lease, so it can run against a case an MCP instance owns.

A research run never lets a caller set the verdict. The verdict is one of `supported`, `refuted`, `inconclusive` or `not_run` and is produced by the verifier alone. `refuted` is a completed analysis, not a process failure: the exit code stays 0 and the verdict is reported in the result field.

Every threshold, data split expectation and negative control is fixed in the frozen specification before the run; the specification digest is recorded as `plan_sha256`. The develop phase never sees the holdout rows: the develop context has no holdout accessor at all. This is a structural non-disclosure, not an operating system isolation, so the auditor additionally scans the develop artifacts for holdout row identifiers and reports `SPLIT_LEAKAGE` if any appear. See [RESEARCH-PROTOCOL.md](RESEARCH-PROTOCOL.md) for the full protocol, the restricted path language and the kernel semantics.

`report export` on a research run writes the lane package: `plan.json`, `checks.json`, `receipt.json`, `report.md` and `manifest.json`, plus the run artifacts under `artifacts/`. The manifest pins the product sources the package depends on, so a lane re-run that changes a pinned product source invalidates the package.

The frozen vmde lane is built and audited with:

```powershell
npm run research:lane -- --case ./cases/research-vmde
python artifacts\research\vmde\directions\audit.py --all
python artifacts\research\vmde\directions\verify-manifest.py
```

`audit.py` is the authoritative audit layer: a Python implementation of the recipe kernels that shares no code with the product and only reads the frozen packages. `verify-manifest.py` re-checks every file identity and every pinned product source. Both are read only, and both are frozen copies of the source-controlled scripts in `tools/research/`. See [RESEARCH-PROTOCOL.md](RESEARCH-PROTOCOL.md) for the protocol, the restricted path language and the kernel semantics.


## Native function emulation

`src/emulation/x86.ts` is a bounded 32-bit x86 interpreter. It lets the product call a native function without an external wrapper process, which is the missing link between "the function exists in the binary" and "the function's behaviour can be observed, modelled and verified".

It is deliberately small and explicit:

- It implements the integer 32-bit subset that recovered kernels use and refuses everything else with a concrete fault code (`EMULATION_UNSUPPORTED_OPCODE`, `EMULATION_UNMAPPED_READ`, `EMULATION_UNMAPPED_WRITE`, `EMULATION_ACCESS_DENIED`, `EMULATION_EXECUTION_DENIED`, `EMULATION_BUDGET_EXHAUSTED`, `EMULATION_FAULT`).
- It never executes native code. The target bytes are read from a file and interpreted.
- Every access is checked against a declared region and against the caller's read and write policy, so an emulation run cannot reach outside the synthetic buffers it was given.
- The instruction budget is enforced, and a repeated string instruction repeats the instruction, so the executed sequence matches the hardware.

A native function is called from a **declarative manifest** rather than from a wrapper script. `contracts/emulation-request.schema.json` names the code bytes and their digest, the memory regions the function may see, how the caller's arguments are placed into memory, how the results are read back, the access policy and the instruction budget. The manifest is data: it cannot execute anything.

```powershell
.\wirefit.cmd binary emulate --case .\cases\vmde --manifest .\cases\vmde\grid-kernel.json --corpus .\cases\vmde\corpus.jsonl --out .\exports\vmde\observations.jsonl
```

`tests/fixtures/emulation-vmde-grid-kernel.json` is the manifest of the vmde grid kernel (`0x498a50`). It reproduces the recorded native calls of that kernel inside the product, which is what lets the recovery pipeline treat a native function as an observation source instead of a bespoke script.

The interpreter is verified against an independent reference emulator rather than against itself. `tests/emulation.test.ts` replays the vmde grid kernel (`0x498a50`, 637 bytes of the analysis dump `50b6bb68...6992`) and asserts that every register and every flag of all 207 executed instructions equals the recorded reference trace in `tests/fixtures/emulation-reference-trace.json`, and that the produced node grid equals the recorded native observation. The same kernel is the subject of the D01 and D02 research directions, so a change in the interpreter changes the audited lane and forces the lane to be rebuilt and re-signed.


## MCP

Start the stdio server from an MCP client:

```text
node apps/mcp/bin/wirefit-mcp.js --case /absolute/path/to/case
```

Use `--create` explicitly to create a missing case. An existing case opens normally with that flag. `wirefit mcp --case CASE --create` is equivalent. All tools remain bound to this case; no global current binary is selected. Stdout is exclusively MCP protocol traffic. Errors/startup diagnostics go to stderr. Shutdown cancels owned jobs and closes the case.

The server uses the official MCP SDK and advertises these nineteen tools:

| Tool | Arguments |
| --- | --- |
| `wirefit_capabilities` | `{}` |
| `wirefit_import_evidence` | `{file}` |
| `wirefit_acquire_evidence` | `{command,args?,cwd?,env?,target?,provider?,functionAddress?,timeoutMs?,recoveryTimeoutMs?}` |
| `wirefit_inspect_binary` | `{file,toolchain?,timeout_ms?}` |
| `wirefit_unpack_binary` | `{file,backend:"unlicense",toolchain,timeout_ms?,target_timeout_seconds?,copy_dependencies?}` |
| `wirefit_trace_binary` | `{file,tool:{command,args?},plan:{duration_ms,breakpoints_rva,ranges,api_hooks,max_events}} |
| `wirefit_analyze_ida` | `{file,queries:[{kind,...}],timeout_ms?}` — bounded static queries, using the installed local IDA MCP configuration |
| `wirefit_import_model` | `{model}` or `{file}` |
| `wirefit_lift_model` | `{evidence_id,output_id,cutpoints?}` |
| `wirefit_register_oracle` | `{manifest}` |
| `wirefit_import_dataset` | `{manifest,artifact_root}` |
| `wirefit_collect_dataset` | `{oracle_id,inputs,comparison_policy,max_calls?}` |
| `wirefit_run_experiment` | Raw canonical ExperimentRequest object |
| `wirefit_research_directions` | `{direction_id?}` |
| `wirefit_run_research_direction` | `{direction_id,budget?}` |
| `wirefit_get_job` | `{job_id}` |
| `wirefit_cancel_job` | `{job_id}` |
| `wirefit_get_report` | `{result_id,section?,offset?,limit?}` |
| `wirefit_export_report` | `{result_id,out}` |

Tool inputs are strict JSON Schemas, including nested binary toolchain commands. MCP binary tools accept the toolchain object directly; the CLI reads the same object from `--config`. The complete canonical experiment union and its contract references are inlined into `tools/list`; clients do not need to resolve `wirefix.invalid` URLs. MCP canonical experiment requests include the complete resolved budget. Collection/acquisition/binary workflows/experiments return a job ID immediately. Poll `wirefit_get_job` until terminal, then use its `result_id` with reports. `wirefit_cancel_job` returns a cancellation request state; poll until cleanup reaches a terminal state. It can cancel only work owned by this running service.

Successful responses provide `structuredContent` and a JSON text representation. Tool errors set `isError: true` and include structured `error` fields. Capability/job/report reads advertise read-only annotations. Imports and execution tools advertise their writes, and target-executing tools advertise open-world behavior. Output claims are calculated by the verifier; tool arguments cannot set them.

Verified on Windows with Node 24.22.0: actual CLI BV proof/evaluation, explicit target collection/differential comparison, affine fitting, synthetic portable import/lift, public installed REA discovery/export, report export, and official MCP client catalog/job/poll/counterexample/cancellation. Native Ghidra and interactive Windows console Ctrl-C are separate gates; automated process-owned cancellation is covered, while a terminal Ctrl-C keystroke was not simulated in CI.




