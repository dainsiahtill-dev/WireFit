# Practical Binary Inspection and Unpacking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the current Windows target analyzable through an auditable binary workflow and truthfully establish Handwired/REA roles.
**Architecture:** pure bounded PE parser; independently supervised external detector/unpacker; existing durable case/job system; thin CLI/MCP.
**Tech Stack:** Node24, TypeScript, Vitest, pinned external Detect It Easy and optional documented Unlicense backend.
**Spec:** docs/superpowers/specs/2026-10-19-practical-binary.md

## Global Constraints
- All text IO explicitly UTF8; preserve original binary and user specs.
- No shell-built external commands, guessed ABI proofs, silent dropped failures, or dump-to-runnable status promotion.
- Strict independent mathematical contracts remain unchanged.
- Each implemented unit follows meaningful RED/GREEN and typecheck; final independent review and real CLI/MCP/target evidence.

## Review Focus
- Malformed headers/counts/RVAs cannot create unbounded reads.
- Mutable caller input and target path aliases cannot change recorded identities.
- Timeout or backend success with missing output cannot become completed unpack.
- Unknown family or absent tool cannot be reported as supported automatic recovery.
- Generated files are analysis derivatives until independent execution/behavior checks establish stronger claims.

## Tasks
- [x] Task1: src/pe.ts + tests/pe.test.ts, pure PE metadata and conservative packing evidence. Tests cover PE32/PE32+, high addresses, malformed offsets/counts, virtual tails, imports and actual fixtures.
- [x] Task2: src/binary-service.ts + tests/binary-service.test.ts, toolchain validation, snapshots, owned external processes, output artifact discovery/PE checks, complete/partial/failure accounting. Root implements and runs actual vmde tools.
- [x] Task3: src/cli.ts,src/mcp.ts,tests/binary-entrypoints.test.ts,docs/cli.md: binary inspect/unpack and strict async MCP integration without weakening existing request contracts. Independent agent owns entry files.
- [x] Task4: real detector + documented matching unpacker on copied target, input hash recheck, inspect derivatives, import successful analysis artifact into REA when feasible. Keep failures and remaining requirements.
- [x] Task5: independent review, complete tests and real CLI/MCP smoke; deliver actual target findings, public VMP catalog, Handwired isolated experiments and remaining limitations.

## Execution ledger
- Baseline refreshed: typecheck PASS;153/153 product tests PASS; fresh real REA/Ghidra C fixture import PASS.
- Independent Handwired research: provided-structure affine validation8/8 holdout10/10; bitplane XOR12/12. No unknown-VMP graph recovery claimed.
- Public corpus:3 protected/unprotected PE pairs pinned and hashed, no variable-input Oracle; not a recovery success.
- Original target static metadata captured at artifacts/research/vmde/initial-pe.json.

- Independent review: three important findings reproduced and fixed; five focused reviewer regressions PASS; no remaining blocking finding.
- Final regression after implementation: 208/208 tests PASS (artifacts/practical-binary-vitest.json), typecheck PASS, build PASS. Real production CLI inspection of vmde completed, detector Themida/Winlicense 2.0.1.0-2.1.8.0; original hash unchanged.
- Public REA probe: 4/4 real Ghidra acquisitions completed, but protected original function semantics not established in 3/3. One unprotected local expression lifted with guard/ABI limitations retained.

- Actual unpack result: backend exited 0 after 422.9 seconds, 14,454,272-byte analysis dump, ordinary imports parsed (1,603 symbols), source unchanged. Controlled startup FAILED 0xc0000005; output is NOT runnable-verified. Selected entry has SEH-helper stack contract; true startup remains unresolved.
- Dump REA full analysis timed out at 240s with retained failure; separate direct Ghidra -noanalysis entry probe completed. No promotion to full REA success or behavioral recovery.
