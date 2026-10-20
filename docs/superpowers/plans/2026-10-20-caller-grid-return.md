# Caller layout and returned node count

The continuous goal is complete vmde restoration through WireFit. This bounded
step follows the actual incoming call chain of the already validated kernel.
A source-level void signature inferred without callers is incomplete: existing
original EAX captures must be checked, never synthesized or rerun unnecessarily.

Design: preserve every earlier native receipt and exported snapshot. Add an
independent portable pure grid component returning both nodes and node_count,
under the existing W/H 2..16 and disjoint-buffer test domain. Recover adjacent
object fields with finite evidence-seeded Ghidra queries; external dependencies
and natural application calls remain separate unknowns. This is a bounded
extension of the existing recovered-grid flow, not a whole-program completion.

Files: tools/recovered-grid/model.py (pure contract); grid.py (strict UTF-8 JSON
CLI); test_grid.py (meaningful unit and actual CLI checks); README.md (usage).
Research findings, manifests and replay comparison belong in
artifacts/research/vmde/caller-layout. Frozen previous native-kernel source and
candidate remain unchanged; current documentation receives an explicit return
semantics correction referring to new evidence.

- [x] Inventory existing incoming edges and context anchors without blind scans.
- [x] Check returned EAX from raw wrapper state for all 904 saved original calls.
- [x] Run one existing project-owned bounded Ghidra probe for helper 0x481950,
  guard 512 bytes, noanalysis/readOnly; preserve receipt and unchanged input.
- [x] Independently audit helper fields, arithmetic boundaries and RET 8.
- [x] RED then GREEN portable nodes-plus-count model and strict JSON CLI.
- [x] Compare the independent model against all 904 stored native outputs and
  raw EAX; explicitly reject nodes-correct/count-wrong and count-correct/
  nodes-wrong mutants. Reuse of these inputs is regression, not unseen holdout.
- [x] Probe evidence-seeded consumer 0x484e60 (512 bytes) and success gate
  0x46a860 (2048 bytes) once. Scope failures remain recorded failures/partial;
  no automatic scope expansion, target execution or allocator implementation
  guessing. Each function has a 5 second decompiler budget; process 60 seconds.
- [x] Review new code independently, run relevant tests and verify a separate
  copy of the new portable component/evidence without executing the target.
- [x] Publish actual findings and unresolved natural image/descriptor/lifetime,
  OEP and runnable reconstruction criteria. Keep the total goal active.

Ruling: the user has already authorized continuing the restoration and creating
needed tools; routine reversible analysis and implementation proceed without
another approval gate. All text reads/writes use explicit UTF-8. There is no Git
checkout in this workspace; new components and artifacts are isolated by path.

Actual outcome: 904/904 existing original captures match the independent model
jointly in node bytes and returned count; both mutants rejected for all904.
Model/CLI22, comparator6 and delivery8 tests passed independently. Two owned
Ghidra processes exited0 and observed3 bounded functions/100 instructions/296B.
New immutable attached result binary_file_evidence_192f514fd93a4f9fb9b1bbb5f778746a.
Release6962fe70..., product manifest6d92cb5f..., 195 product files and183 logical
files. Source/copy verifiers and the copied comparison actually exited0. Copied
component22 and comparator6 tests then ran again and exited0; all183 registered
bytes and14 original native pins were rechecked. Actual final record:
artifacts/native/caller-layout-verification-20261020.json (8cc5d970...).
The exported plan is its earlier preparation snapshot; this current working
plan has advanced after verification. No historical artifact was rewritten.

Following work, not yet achieved:
- [ ] Recover evidence-seeded 482c30 capacity/element semantics and47e450 W/H
  effects, then connect480230 node-record writes to the caller.
- [ ] Establish natural image-to-label descriptor writes and real object state.
- [ ] Verify ordinary image/vector I/O, original startup/OEP and a standalone
  runnable restoration. The overall goal remains active.
