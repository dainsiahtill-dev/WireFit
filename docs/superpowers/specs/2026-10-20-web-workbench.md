# WireFit local visual workbench

The user approved the proposed five views and explicitly requested full delivery.
Implement all views and real task execution, cancellation and report export in
E:/wirefit. This is a local application backed by existing services. No hosted
site or external account is involved. The vmde restoration goal remains active;
the interface does not turn partial recovery into full-program equivalence.

## Product

A polished Chinese desktop workbench: dark navy sidebar, warm light canvas,
teal emphasis, compact readable tables and monospaced code. Local SVG icons,
graphs and charts; no network fonts/assets or decorative bitmap dependency.
Six navigation destinations: overview, code/models, runtime timeline, model
laboratory, validation comparison and task centre. Responsive at1280px desktop
and usable at390px. Keyboard navigation and labels, loading/empty/error states.

Overview opens the real vmde research archive. Show verified local results,
known gaps and recent runs, using actual receipts and identities. No invented
restoration percentage. Labels distinguish native observation, CPU replay,
model proof, fitted/expected fixtures, failed and unattempted.

Code/model view links a function or model selection to bounded source/listing,
an SVG dependency/call graph and evidence details. Do not fabricate address to
node correspondence. Model laboratory evaluates typed inputs through existing
interpreters, supports numeric parameter previews and bounded output curves.
Numeric fitting, simplification and verification launch existing experiment
jobs. Clearly label reference fixtures and parameter previews.

Timeline selects one actual run and PID, filters API/breakpoint/exception/
module events and exposes registers/stack/code/snapshots. Runs are not combined
into a fictional trajectory. Validation provides counts, scope, failure rows,
and original/candidate output details from existing records.

Task centre supports supplied experiment presets and JSON requests, static PE
inspection and bounded native traces with server-selected installed profiles.
Cancellation uses only jobs owned by this server. Reports use existing export
closure and write new packages under exports/workbench. Display saved folder
and provide downloads. Existing cases and research evidence are never rewritten
by merely viewing them; mutable experiments use the workbench case by default.

## Architecture

Native Node24 HTTP server, existing TypeScript service layer and job manager.
Browser ES modules/HTML/CSS need no build framework or CDN. Add src/web modules
and apps/web/public assets. Keep contracts in src/web/types.ts. Root owns HTTP,
launch/integration and browser verification; independent agents own UI,
workspace actions/lab and research normalization. No Git repository exists;
work in place with file ownership rather than creating a phantom worktree.

Only127.0.0.1, default port4318. Validate Host/Origin and require a per-session
token for mutations. Limit JSON requests1MiB and paginate data. No browser
provided shell command/config executable. No arbitrary file serving: evidence
and downloads use registered case/artifact or curated evidence IDs. Render
untrusted text with textContent; reject path traversal/reparse aliases.
All text IO explicitly UTF-8. Preserve all frozen native tools and evidence.

## API contract

Successful JSON uses {data:...}; failures use {error:{code,message}}.
GET /api/bootstrap returns product/version/token/cases/defaultCaseId/
writableCaseId/profiles/presets/research. GET /api/cases and POST /api/cases
create a new case from a bounded label. GET /api/cases/:id returns models,
jobs,runs,datasets,oracles; GET /api/cases/:id/models/:modelId returns model.
POST that model's /evaluate accepts inputs, optional FP32 parameters and
optional sweep; returns outputs, bounded typed trace and curve. POST
/api/cases/:id/models imports an explicit model. POST /api/cases/:id/tasks
accepts {kind:'experiment',request} or {kind:'inspect'|'trace'|'unpack',file,
profileId,plan?}. GET /jobs/:jobId and POST /jobs/:jobId/cancel manage jobs.
POST /api/cases/:id/exports accepts {runId}; GET /api/exports/:exportId/file
serves only that registered package's bounded relative filename. GET
/api/cases/:id/artifacts/:sha reads a registered artifact as bounded text/hex.

GET /api/research returns the curated vmde overview/functions/traces/validation
catalog. GET /api/research/functions/:id returns source/listing/graph/evidence.
GET /api/research/traces/:id accepts offset/limit/type/q and returns bounded
normalized events. GET /api/research/validation/:id accepts offset/limit/status
and returns actual comparison rows. GET /api/research/evidence/:id returns
bounded UTF-8 or hex with actual file identity. Unknown/missing data remains
explicitly unavailable. Research adapters do not execute targets or scripts.

## Acceptance

All six destinations backed by real data and APIs; model input changes produce
real interpreter results; at least one Handwired fit and exact simplification
through UI; run ownership/cancellation and a real report export exercised.
Malformed inputs, cross-origin mutations, traversal and display injection
rejected/tested. Run typecheck/build/full regression, scoped HTTP/data tests
and real-browser desktop/mobile flows. Save screenshots and verification
receipt. Install/start the workbench and provide its local URL and launcher.
