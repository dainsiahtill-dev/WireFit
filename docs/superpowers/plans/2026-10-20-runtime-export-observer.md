# Read-only live export observer

Purpose: diagnose the original-QSettings hook failure without changing the
frozen native worker/agent or assuming a transient failure. User's existing
authorization covers this reversible local tool work and owned experiments.
Whole vmde restoration remains the goal; this tool is a necessary diagnostic.

The failed control's compound guard does not identify which export-type,
mapping or execute-permission predicate failed. EAT does not itself encode
function/data type. Frida enumeration type remains unknown to an RPM observer;
runtime section flags and VirtualQueryEx protection are separate evidence.

Design:
- New tools/runtime-exports/model.py is pure, portable PE32 flat live-RVA
  parsing, with injected read_rva/query_va callbacks. No disk raw mapping,
  Windows import, foreign code execution, or guessed unreadable bytes.
- inspect_exports(read_rva,query_va,module_base,module_size,requested_symbols,
  *,query_struct_size,target_prefix_bytes=16) accepts a page-aligned module<=64MiB and
  bounded32-bit range, at most8 unique printable ASCII names<=256, with strict
  bool/int/bytes callback checks. Native VQE ABI size is explicitly28/48.
- Model caches at most256 exact4KiB pages/1MiB per sample. Failed/partial
  actual reads remain evidence and never zero-fill tables. Name prefixes need
  only maxRequestedLength+1 bytes to prove non-equality. Any unreadable name
  could hide a duplicate; preserve observed matches as indeterminate rather
  than calling them unique/absent. Direct, forwarded, zero RVA, ambiguous,
  missing and unknown states must remain distinct. No forwarded DLL loading.
- Record actual name/ordinal/EAT cells, section attributes, original VQE
  fields, executable tri-state and at most16 real prefix bytes. No unsupported
  function/data semantic classification. A ready permission does not prove a
  completed hook or original function call.
- New observe.py supplies a Windows adapter. Reuse pinned cached UTF-8 source
  of existing memory-image.py and private-regions.py definitions, preserving
  __file__, to reuse one retained read-only0x410 HANDLE with identity/RPM/VQE.
  Do not reuse private-region-only rejection rules for legitimate MEM_IMAGE.
  Add bounded Toolhelp module selection with exact loaded DLL path identity.
- Validate exe path/PID/exact creation FILETIME/alive before and after samples,
  exact module path and SizeOfImage, source identities, and current module
  base/range. One retained HANDLE, no arbitrary PID reopen, debug attach,
  suspension, protection changes, target writes or process termination.
- Every RPM, including EAT/table pages, must first avoid uncommitted,
  unreadable or PAGE_GUARD pages. Preserve the query and policy refusal; do not
  invent an OS error code or pretend bytes were attempted/observed.
- At most8 explicit offsets through8000ms and tool deadline10000ms. New-only
  outputs, each sample separately persisted with raw page evidence. First
  primary error is locked before persistence; recording failures separate.
  Later unattempted rows remain unattempted. Check all source hashes at end.
- Root-owned wrapper uses existing acquireNativeEvidence with a passive20s
  public CLI lifecycle. Bind the trusted owned_cli_ready event PID/job/output,
  the exact new staging path, the owned-ready.json handoff, and the actual
  identity-probe stdout retained in host memory. Compare the exact creation
  FILETIME and reconcile the final owner. Hash staged exe and QtCore4 against
  fixed original sources. It awaits both helper and owner.
  Only ownership contradictions cancel this own job; ordinary observation
  failures are retained while the owner reaches natural bounded cleanup.

Work split and evidence:
- [x] exact_core: only model.py/test_model.py/model-test-log.json, meaningful
  pure RED/GREEN. Boundary/forwarder/duplicate/partial/unreadable/guard tests.
  Actual22/22 PASS; independent22/22 PASS and model-review.json archived.
- [ ] vmde_dynamic_design: Windows adapter and scoped tests after handoff API,
  independent files. Reuse reviewed identity/read implementation; test the
  scheduling, binding and persistence logic with fake readers, no native run.
  Author28/28 PASS after final-publication/failed-status fault regressions;
  independent release is pending. No target has been executed for this phase.
- [ ] Root: owned lifecycle integration and documentation, code inspection,
  required independent review and one bounded original live observation after
  tests/review. Root alone executes real PE/CPU/Ghidra/process observers.
- [ ] Review observed metadata before deciding any hook-readiness state change
  or retry policy. No executable/readiness/function-call equivalence shortcut.

Existing source/receipts stay immutable, including native14source pins and
old helper checker. No re-run of904 native calls,720 product tests, or copies
unless new changes actually require them. All text IO explicitly UTF-8.
