# Reusable owned native acquisition

The continuing vmde investigation requires a fresh eight-range trace for four
previously unobserved system slots and one truncated instruction byte. Existing
research runners duplicate the same ownership and observer flow. Keep those
immutable; put the reusable flow in Wirefit and use its public CLI for each case
and trace. This is a bounded extension of the existing acquisition workflow,
covered by the user's continuing local development and controlled-copy scope.

`tools/native-trace/acquire.mjs` is a thin entry to typed orchestration. Required
flags: `--file`, `--config`, `--plan`, `--out`, `--python`, `--capture-at-ms`.
Optional `--powershell` requests window metadata; repeat `--caller-rva` (0..16)
to request private-region collection. Other/duplicate scalar flags, malformed
RVA/timing, existing or aliased output paths and invalid inputs fail before any
child starts. Python and optional PowerShell executables are explicit absolute
paths; a trace backend command is not assumed to be Python.

Initial profile: PE32/x86 executable, SizeOfImage <=64MiB, passive trace only,
max_events >=2, capture offset inside its duration. Public trace request limits
remain unchanged. Omitted private/window observers are explicitly not requested,
and never counted as completed. Main capture is always requested. No PID or
replacement CLI/helper path is accepted from the public arguments.

Create exactly one new output directory and one new case. Freeze config, plan
and fixed observer helper bytes using create-new files before invoking the
public CLI. Record source and tool identities. Use only a read-only CaseStore
observer. Bind the unique trace job/request/source/tool/plan, its unique staged
directory and validated live checkpoint before deriving a PID. Validate the
checkpoint using the production protocol validator with actual PE32 width.
Source hash, actual image size, bounded current base, passive ready metadata and
the staged executable basename must agree. Track the live child handle until
close; a polling delay is not termination.

Probe the owned process identity read-only, binding staged path and precise
100ns creation FILETIME to the job lifetime. Main/private observers use their
retained HANDLE identity checks; window results must also match that exact
creation token and actual job time bounds. Record requested and actual capture
timing using monotonic elapsed time. Check child/job lifetime before starting
each observer. Use the current main bytes for each private caller; never inherit
private addresses from previous runs.

Nonfatal observer failures retain their own status, stdout/stderr and receipts
while the owned CLI completes naturally. Ownership/identity failures and user
cancellation stop the owned CLI. An optional bounded IPC cancellation mechanism
in the existing process supervisor requests the CLI's own foreground cancel
handler; after its grace period the supervisor can terminate only its owned
tree. Hard stop, child close, Windows Job cleanup and raw target/session cleanup
are distinct facts. Never manufacture cleanup confirmations. Ordinary process
callers retain current behavior when IPC cancellation is not configured.

All trace startup and observer work is inside finalization. Independently retain
CLI output, terminal job/result/raw trace, source/code stability and reader close
errors. Success requires the public trace and all requested observers to finish
with valid identity/coverage, the requested error-free initial/final snapshots,
four actual raw cleanup confirmations, unchanged source/code and no outstanding
errors. Partial/failed/cancelled evidence does not become success from file hashes.
Every text read/write explicitly uses UTF-8, and existing evidence is not replaced.

Tests first: strict arguments/preflight before writes/spawn, exact FILETIME and
request/checkpoint binding, actual public CLI synthetic-worker lifecycle, real
child IPC cancel/grace fallback, observer errors/early exit and evidence retention.
Synthetic observers must be clearly separate from native target results. Then
run typecheck/build/full product regression and independent review, acquire one
fresh vmde copy with the prepared module-tail plan, audit the actual values and
513-byte tail, export and verify a copied package. Stop static API chasing after
those observations. Registers, stack/ABI/SEH, FS/heap state, actual dispatch time,
normal image/vector behavior and runnable reconstruction remain separate gaps.
