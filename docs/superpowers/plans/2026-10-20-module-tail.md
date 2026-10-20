# Follow the remaining bounded startup observations

The overarching vmde restoration goal remains active. The preceding module-slot
phase established five DWORD observations, current private callers and a bounded
DLL code window. Four further IAT values and the last byte of one return
instruction remain unknown. Completing this next phase will not restore native
startup state or the application.

- [x] Prepare a separate plan without changing prior acquisition inputs:
  `.local/trace-vmde-module-tail.json`, eight ranges/1,147 bytes per phase,
  60 seconds, no hardware breakpoints or API hooks.
- [x] Generalize or reuse an independently reviewed owned public CLI acquisition
  orchestrator with explicit plan/output arguments. Preserve the prior runner and
  immutable receipts; do not clone a growing set of subtly divergent collectors.
- [x] Collect from one fresh staged target through production Wirefit commands,
  binding main/private/window observations to the same owned PID, exact creation
  FILETIME, staged path and active job lifetime. Derive all four private targets
  again from actual current caller bytes.
- [x] Read the four new scoped DWORDs and 513-byte window. Decode the former
  `0x644fe` boundary only from actual bytes; do not assume its missing immediate.
- [x] Stop static API chasing after these bounded observations. If current code,
  module bases/exits or coverage no longer fit the plan, retain explicit unknowns
  and failure evidence. Do not silently widen capture or reuse old pointers.
- [x] Review and export the new evidence: standard final export 160 files,
  restored logical evidence 181 files, all 66 analysis outputs and 76 required
  inputs verified in a fresh copy. Preserve the first timeout and old copies.
- [ ] Separately design how to observe natural transfer/register/stack state
  with a controlled instrumentation comparison; previous hardware-breakpoint
  runs perturbed the target, so zero hits and interrupted traces cannot select
  an OEP. The next local experiment is specified in
  `2026-10-20-native-kernel.md`; its synthetic native-call contract must remain
  distinct from naturally observed application calls.

Remaining gaps after successful sampling: loaded implementation identity and
callee effects, registers/EFLAGS/DF at dispatch, FS/PEB/heap objects and aliases,
stack/return state and ABI, exception handling, observed execution path/time,
normal image input/vector output and a runnable reconstructed application.
Endpoint samples cannot select a branch during a separate non-atomic capture.

Evidence basis: `module-slots/analysis/analysis.json`, `additional-facts.json` and
frozen manifest SHA256
`a6ad3df7bd191637705d340f85a8e6d996a9a1dd2c3a87fe65151a4b8aa932c0`.
