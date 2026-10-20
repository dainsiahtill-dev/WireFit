# vmde runtime investigation plan

> **For agentic workers:** Use superpowers:subagent-driven-development / executing-plans; UTF8 explicit throughout.

**Goal:** Advance actual vmde startup recovery through reusable Wirefit runtime evidence.
**Architecture:** shared binary snapshots, external owned Frida worker, independent binary job/report operations.
**Tech:** Node24/TypeScript, Python3.14, Frida17.2.17, Windows Job handles, Vitest.
**Spec:** docs/superpowers/specs/2026-10-20-vmde-runtime.md

## Constraints and review focus
- Preserve source, historical receipts, model semantics and unknown scope.
- Fixed agent, bounded requests/events/memory and stdout; no externalPID attach.
- Stage input/DLLs with hashes; memory errors and missing hits remain visible.
- Worker timeout/cancellation must close an owned target using Job handle, not a guessed process name.
- Never take a SEH helper, tool exit0, or memory capture as a true OEP or recovered program.

## Tasks
- [x] Root: extract shared binary-file snapshot/staging helpers without changing existing behavior; tests remain green.
- [x] Worker agent: tools/native-trace/worker.py,agent.js and worker boundary tests; controlled Frida protocol/cleanup.
- [x] Root: src/native-trace.ts strict validation/jobs/capture artifact retention; test fake worker protocol, malformed input, snapshot failure, original unchanged and cancellation.
- [x] Entry agent: CLI/MCP submit/query/cancel integration and tests, tool count16.
- [x] Root: extend binary report dispatch to trace_binary without changing math schemas.
- [x] Actual probes through production command: observe planned candidates and missing hits, runtime module bases and TLS bytes; no guessed entry patch. Passive run reaches Qt UI; true CRT entry remains unknown.
- [x] Independent review and first full regression372/372; persistent restoration evidence ledger. New helper additions require their own final regression below.
- [x] Bounded Ghidra research: four scope-checked C observations, one scope escape rejected; independent hash/byte/p-code audit.
- [x] Read-only window inventory with expected process path/lifetime binding; nested hidden-window fixture validates actual parents.
- [x] External owned-handle memory-image collector: source/path/creation-time binding, coverage errors and no runnable promotion;29 scoped tests and independent review.
- [x] Actual complete-module data acquisition during passive Qt UI run:14,561,280observed bytes,0unknown,223extents; separate512B private call-target capture.
- [x] Final integration checks:402/402,0skipped,typecheck/build; immutable attachment55-file export and copied55/55 file verification; artifacts/native/runtime-verification-20261020.json.

## Restoration objective remains incomplete
- [ ] Establish the actual startup transfer, required ABI/stack state and protection bootstrap; runtime EntryPointRVA0 is not a usable OEP.
- [ ] Close private executable/data dependencies. Captured target06180000..061801ff is truncated; Qt wrapper also has uncaptured private targets.
- [ ] Continue algorithms from verified callsite49a0bc→4999d0; reconstruct data layout and callee semantics before claiming recovered behavior.
- [ ] Establish original image-input/vector-output observations through normally usable functionality, then verify reconstructed modules on fresh inputs.
- [ ] Produce and independently run a reconstructed program. No current dump or flat memory artifact satisfies this gate.

## Follow-up: private dependencies and grid kernel
- [x] Extend the existing read-only collector workflow with bounded VirtualQueryEx metadata and executable private-region capture derived from verified direct CALL sites. Bind PID, exact creation FILETIME, source and live caller bytes on one retained HANDLE; do not change the target or stable main-image helper.
- [x] Test source/caller rejection before private reads, region permissions/overflow, shared allocations, byte budgets, partial output and late identity failures. Independently reviewed final helper d55539bf;31/31 scoped PASS. A transient identity contradiction is fatal even if final identity recovers.
- [x] Reproduce a passive 60-second Wirefit job and capture a new main image, private executable regions and window metadata in its owned process. run-zLdNvF completed, main14561280/private8192 observed bytes/0gaps,22 independent audit checks PASS; metadata closure and byte coverage do not establish dependency closure or runnability.
- [x] Run one bounded Ghidra round from 0x4999d0, recover only demonstrable field/index operations and identify unresolved callees/ABI. Five scopes and 48-file manifest pass; constructor state at use remains unknown.
- [x] Restore the no-external-CALL integer grid operation at 0x498a50 as a bounded independent candidate. Frozen candidate matches 896 original-machine-code Unicorn replay cases with 203/203 instruction-start coverage; synthetic layout/DF0/disjoint-buffer assumptions remain explicit and no original-target Oracle is claimed.
- [x] Record actual results, current regression433/433 and limitations without superseding historical verification receipts. Product export52files and combined supplement94files verified in a separate copied directory; exported candidate re-evaluated against896retained machine observations in a fresh Python process. New receipt:artifacts/native/private-followup-verification-20261020.json.

The reconstruction gates above remain open. The next minimal private-data request is five actual system-module DWORD values derived from the newly observed wrapper, with the same process/source/creation-time binding. This does not remove the separate real startup/ABI and normally usable image/vector Oracle requirements.

## Ledger
- Baseline previous iteration304/304, typecheck/build PASS.
- Parallel read-only static research found concrete CRT/Qt/application addresses; these remain candidates, not executable entry claims.
- First full runtime integration regression372/372 PASS, typecheck/build PASS; independent trace review68/68 scoped.
- Two positive-control hardware breakpoints really hit, but two60s traces with hardware breakpoints timed out during finish, even without API hooks. No confirmed thread-stack deadlock cause.
- Same60s window without API hooks/hardware breakpoints completed:15events/16snapshots/43finalmodules, real Qt main and activation windows observed. All four cleanup flags true. Do not use instrumented failure as original program startup behavior.
- Passive runtime still has incoherent CRT prefix at4b0f64 and protected branch42474f→d2ed39→aa35de. Main-module-only capture cannot establish runnable reconstruction; observed runtime CRT also calls a private executable thunk outside all enumerated modules.
- Historical304-test and63-gate receipts preserved. No complete source/algorithm/OEP/runnability/behavioral-equivalence claim.
- Memory capture initially rejected runtime EP mutation; preserved oldreader9745... and explicitly labeled incomplete failure summary. Newreadere2f062a4... records EP/ImageBase differences, other identity checks remain enforced; actual runtimeEP0 observed.
- New memory-image attachment preserves oldrun/job; store.openWithoutRecovery closes the RO-check/writer-recovery race, actual temporary-case regression verifies no oldjob mutation.
- Final current source/test/file identity receipt and independently copied export pass; restoration objective above remains open.

