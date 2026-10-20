# Practical follow-up implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkboxes.

**Goal:** Replace research-only binary delivery with verified product export, fix stale doctor output, and diagnose observed entry/TLS risks.
**Architecture:** Existing CaseStore/report interface and PE parser; isolated native status loader.
**Tech Stack:** Node24, TypeScript, Vitest. No new product dependencies.
**Spec:** docs/superpowers/specs/2026-10-20-practical-followup.md

## Global constraints
- Text reads/writes explicitly UTF-8; no modifications to source target or historical evidence.
- Six canonical mathematical operations and proof semantics unchanged.
- No guessed executable entry repair; no runnable/equivalence verdict from metadata, receipt presence or backend success.
- No Git checkout exists. Separate source ownership replaces worktree isolation.

## Review focus
- Binary input/dependency names must not overwrite result/manifest/helper or collide case-insensitively.
- Nested artifact closures must be complete and bounded; malformed refs/cycles/tampering fail.
- Copied export must verify after original case removal and reject tampered/link-aliased files.
- Doctor must distinguish recorded evidence from current installation and historical gates.
- TLS virtual-only/unmapped pointers and unterminated arrays must preserve incomplete status; PE64 addresses never lose precision.

## Tasks
- [x] Binary export (root): tests/binary-reporting.test.ts RED through existing exportReport on a real inspect job and synthetic derivative provider; assert copied standalone verification, retained partial/failure status, nested dependency closure, tampering and invalid/conflicting names. Implement src/binary-reporting.ts and thin operation routing in src/reporting.ts. Keep math exporter strict.
- [x] Native status (agent): src/native-status.ts, tests/native-status.test.ts, capabilities region in src/service.ts, docs/NATIVE-SETUP.md. RED/GREEN for current installation, valid scoped receipt, missing executable/evidence, malformed/oversized receipt. No live processes.
- [x] PE diagnostics (agent): src/pe.ts, tests/pe.test.ts, docs/PE-INSPECTION.md. RED/GREEN for observed helper pattern and benign entry, PE32/PE32+ TLS callbacks, malformed/unmapped/bounded callbacks with exact addresses. No other module changes.
- [x] Integrate: inspect all changes, update docs/CLI, run targeted checks and independent review; resolve findings at their cause.
- [x] Final: full tests/typecheck/build; actual vmde original/dump static inspection, doctor and portable CLI export verification; record receipts and unresolved startup gap without modifying old artifacts.

## Ledger
- Baseline from prior iteration: 208/208 tests, typecheck/build and review passed. Actual dump startup failed 0xc0000005 at SEH-helper-like selected entry; no runnable claim.

- Completed: binary reporting 16/16 targeted, native 15/15, PE 99/99. Independent reviewer reproduced three Important findings; fixes passed re-review. Full integrated suite304/304, zero skipped; typecheck/build PASS.
- Production CLI exported actual prior vmde run (36 manifest files); copied standalone package verified36/36. Fresh CLI inspection recognized heuristic SEH helper and non-file-backed nonempty TLS template. Doctor validated8 retained files and separately reported present tool files, without native execution.
- Remaining actual-target gap stays recorded: previous dump startup0xc0000005, true startup/init unresolved, default REA full analysis timeout unresolved. No OEP or runnable/equivalence promotion.
