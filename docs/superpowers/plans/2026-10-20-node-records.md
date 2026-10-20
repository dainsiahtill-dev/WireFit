# Node record restoration and reusable bounded analysis

Previous goal turn: progress. The actual final record is
artifacts/native/caller-layout-verification-20261020.json; 904 existing native
records matched nodes plus count, and independent copies were executed/verified.
The full vmde restoration goal is still active, with natural image/vector I/O,
object state, original startup/OEP and runnable reconstruction unverified.

This step follows actual caller dependencies 482c30 and47e450, then recovers the
already listed480230 record writer. Preserve all frozen earlier code and reports.
Use separate evidence labels for static listing, CPU emulation, original native
calls and natural application calls. Reuse previously verified infrastructure.

- [x] Run one finite project-owned Ghidra batch:482c30 guard1024 and47e450 guard512,
  readOnly/noanalysis, decompile<=5s, process<=60s. Hash-bind all source bytes.
- [x] Independently inspect capacity/size/stride and constructor dependencies;
  verify actual PC scope/stack/calls. Do not infer allocator identities.
- [x] Consolidate the duplicated research launch flow into tools/ghidra/functions.mjs,
  with separate protocol/file units as needed. Explicit input/request/new output/
  native config, fixed Java source hash and bounded invocation, retained failure
  evidence. RED/GREEN meaningful tests, independent review, then a real analysis.
- [x] Independently restore the480230 byte patch under small-grid synthetic input,
  preserving all unknown record bytes. Candidate frozen before new cases.
- [x] Run <=128 guarded Unicorn2.1.4 cases using original byte identity, explicit
  FPU/control/stack contract, actual output and negative control. Never describe
  CPU emulation as original native execution or full caller recovery.
- [x] Connect verified fields and record writes to the caller's node numbering.
  Execute relevant tests; record actual progress and remaining requirements.

Ruling: these reversible local analyses and tools are already authorized by the
continuing goal; there is no additional user approval stage. Text I/O is explicit
UTF-8. The old repeated research launcher is used once to keep analysis moving
while the reusable tool is developed; earlier frozen launchers remain unchanged.

Following work still required: natural image-to-label production and object
initialization/lifetime; normal vector output; startup/OEP and runnable recovery.

Observed follow-up: five initializer/copy functions, the constructor iterator,
pixel-export wrapper and segmentation dispatch were inspected through the new
tool. The large 4f02c0 export function remains partial: computed switches and
an out-of-guard edge; decompilation failed with a flow limit. Actual BGRA map
and ExportImagePixels/source-path strings correct the earlier possible-label
producer interpretation. This is pixel export; the label producer is still open.

Actual CPU execution: 31/31 completed and full-storage matched; both negative
controls rejected31/31, 0 failed/unattempted; actual process exit0, PID20932,
1896.8573ms. New native calls0. Independent observation review completed in cpu-observation-review.json;
root verification only recomputes saved bytes and file identities.

Next finite business study: 488d20 caller receiver is a fresh P2+0x930.
Its second stack flag is1 at46e037, so the normal tail includes488c70(P2+0x930).
Study that direct result path and4891f0 under its explicitly tested first flag;
no branch is assumed natural or label-producing without data/state evidence.
