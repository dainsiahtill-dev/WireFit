# WireFit Workbench Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development with parallel file ownership and final independent review. User requested full implementation; execute continuously.

**Goal:** Deliver the complete local visual reverse engineering workbench with real vmde evidence and executable model/task/report workflows.
**Architecture:** Browser ES modules consume a loopback Node HTTP API. Separate research adapters and workspace service adapters reuse existing proof/training/job/export logic.
**Tech Stack:** Node24, TypeScript, HTML/CSS/ES modules, SVG, Vitest and Playwright browser verification.
**Spec:** ../specs/2026-10-20-web-workbench.md

## Global Constraints

- UTF-8 explicit for all text IO; no overwrite of frozen tools/evidence.
- No runtime frontend dependencies or remote assets; existing Node24 runtime.
- Loopback127.0.0.1:4318; token and same-origin mutations;1MiB JSON.
- User's full delivery instruction authorizes implementation and local startup.
- No Git metadata exists; separate agent-owned files, no fabricated commits.

## Review Focus

- Historical case reads must not recover or change their job lifecycle.
- Unexpected artifact paths and external symlinks never become file servers.
- Foreign jobs cannot be cancelled; server shutdown awaits owned work cleanup.
- Unknown/failed/fixture data cannot become native success or whole equivalence.
- Rapid navigation/selection cannot replace a new view with an older response.

### Task1: Workspace, actions and model laboratory
Files: src/web/workspace.ts, actions.ts, lab.ts and tests/web-workspace.test.ts,
web-actions.test.ts,web-lab.test.ts. Shared types owned by root.
Produces WorkbenchWorkspace API described in types.ts and spec.
- [x] Write failing integration tests for readonly historical discovery, actual
  model evaluation/fit/simplification, foreign cancellation and safe exports.
- [x] Implement using CaseStore/WirefitService and existing binary operations.
- [x] Run scoped tests and typecheck; inspect first-error and cleanup paths.

### Task2: Research evidence adapters
Files: src/web/research.ts,research-*.ts,tests/web-research.test.ts.
Produces ResearchArchive overview(),function(id),trace(id,query),validation(id,
query),evidence(id). Fixed curated source registration and real file identities.
- [x] RED tests with bounded fixtures: mixed-run isolation, failed/missing data,
  native-vsCPU labels, paging and unsafe paths.
- [x] Implement real vmde native904, source/function records, startup traces
  and live export points without executing source scripts.
- [x] GREEN scoped tests plus validate actual local dataset counts.

### Task3: Browser workbench
Files: apps/web/public/index.html,style.css,app.js,api.js,components.js and
views/*.js; tests/web-view-model.test.ts for meaningful data transformations.
- [x] Implement six complete routes with shared request/error/selection state.
- [x] Wire all actions to frozen endpoint contracts, no simulated success.
- [x] Exercise fixtures for empty/error/unknown labels and stale response guard.
- [x] Root browser tests cover desktop/mobile navigation and actual actions.

### Task4: HTTP and launch integration (root)
Files: src/web/server.ts,src/web/main.ts,src/web/types.ts,apps/web/bin,
wirefit-web.cmd,package scripts,tests/web-server.test.ts and browser tests.
- [x] RED HTTP tests for token/Host/Origin, body bounds, traversal, route methods,
  real evaluate/tasks/export and static asset MIME/security headers.
- [x] Implement bounded routing and graceful lifecycle; add start/stop commands.
- [x] Integrate all three lanes, build and run scoped/full product tests.
- [x] Real browser tests: vmde views, inputs, actual fit/simplify, cancel, export,
  mobile, display injection, no console/runtime errors; capture screenshots.
- [x] Independent whole-change review, fix material findings and reverify.
- [x] Start installed local service; write docs/WEB-WORKBENCH.md and honest
  final verification receipt; link URL/launcher and scope limitations.
