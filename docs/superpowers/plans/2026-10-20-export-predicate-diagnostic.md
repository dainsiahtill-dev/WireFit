# Direct Frida export-guard diagnostic

Purpose: determine which predicate failed in the original QSettings hook
control. The new read-only RPM observer completed its one owned20s run: first
four points through1000ms did not find QtCore; points2000/4000/6000/8000ms
resolved both requested EAT entries and observed executable MEM_IMAGE regions.
This did not observe a nonexecuting-to-executing transition and cannot report
Frida's enumeration type or classify the exact earlier compound-guard failure.

Design decision: preserve the original guard and all hook/lifecycle behavior.
Create a new diagnostic agent from the exact pinned frozen source; only enrich
the existing guard failure message with bounded JSON containing the already
queried target, export presence/type/address and range base/size/protection.
Do not retry, delay, load a DLL, relax function checks or install an otherwise
rejected hook. An expected API_HOOK_FAILED is diagnostic evidence, not a fix.

Implementation:
- New tools/export-predicate/agent-variant.mjs is a pure bounded exact-source
  transformation. It must reject other source identities, missing/duplicated
  guard anchors and excessive input. No evaluating target code in pure tests.
- A small new builder pins original worker and agent, writes exact worker
  bytes plus the diagnostic agent and explicit config into a new directory.
  Old tools/native-trace files,14native pins and all executed evidence stay
  unchanged. Worker behavior/protocol and public binary trace remain the same.
- Target error text remains under2048UTF8 bytes for the fixed bounded fields;
  preserve the original error even if diagnostic formatting fails. Do not add
  unobserved OS metadata, EAT conclusions or target bytes.
- Pure tests compare all other source slices/functions and guard semantics,
  and exercise function/variable/missing export and mapped/unmapped/nonexec
  range cases using fake Frida objects. Meaningful RED/GREEN before real use.
- Root owns final builder/experiment integration and independent review. Use
  one fresh original-source publicCLI case, the same two QSettings requests
  and two established kernel startup hooks, noHW and a bounded15s plan.
  Retain actual CLI failure/stdout/raw trace, source hashes and cleanup; no
  existing PID, source patch, candidate overwrite or retry policy is allowed.
- Only after reading the exact direct predicate may another design choose a
  hook lifecycle change. Whole vmde restoration remains active and unfulfilled.

Existing broad user authorization covers these local reversible tools and
owned experiments. No additional user confirmation is required.
