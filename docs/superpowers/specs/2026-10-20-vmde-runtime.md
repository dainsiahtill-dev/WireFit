# vmde restoration: runtime evidence and tools

User requires vmde reversal/reconstruction through Wirefit, enriching reusable tools during the work. Objective is evidence-backed restoration, not a promise of original-source identity. Preserve source SHA256 9a0fa724e4a2f189da4cafdd700842d5b6c7aa6c571269500e5eb56cc3fa9a5d and every prior failure.

Observed: Unlicense first native transition stops in SEH helper0x4b12bc, not verified startup. Static candidates CRT body0x4b0f96, Qt wrapper0x5b85e0, application init0x424650; business init crosses protector0xd2ed39 ->0xaa35de. TLS raw template0xa95000..0xa951bc absent from dump file, callback array at0xa21154 starts with null in dump. Preserved DLL pointers may match preferred bases, not automatically invalid. Dynamic execution must establish actual module bases and state before repair.

New capability: explicit owned Frida worker, independent of unchanged Unlicense16 backend. Pin separate Frida17.2.17 and Python interpreter. CLI binary trace --case CASE --file FILE --config CONFIG --plan PLAN; MCP wirefit_trace_binary. Config {command,args?} starts fixed project worker with --module-path optional local dependency path. Canonical math contracts remain unchanged.

Host API submitBinaryTrace(service,input) with BinaryTraceRequest={file,tool:{command,args?},plan:{duration_ms,breakpoints_rva,ranges:[{rva,size_bytes}],api_hooks:[{module,symbol}],max_events}}. Strict unknown-field rejection; duration1..60000ms, <=4 RVA hardware breakpoints, <=8 ranges each<=1MiB and total<=4MiB, <=16 module/symbol hooks, event budget1..512. RVAs exact hex strings32bit and proven in image bounds. Snapshot target and adjacent DLLs, execute only staged copy. No attach to userexistingPID and no arbitrary supplied agentJS. Worker stdout is bounded final JSON, raw process logs persisted.

Worker stdin {schema_version:1,target:absoluteStagedExe,...plan}. Agent performs hardware breakpoints, reads register/stack/caller bytes and requested memory, and observes API onEnter return addresses. It never alters general registers, bypasses TLS, changes memory protection or uses SEH-helper onLeave. Initial/breakpoint/final memory bytes are optional observations, inaccessible ranges are explicit failed snapshots. Event truncation has omitted count. Source, dependency, worker/agent/tool identities, timings, captures and actual cleanup remain auditable.

Worker result {schema_version:1,status,frida_version,pid,events,snapshots:[{file,rva,size_bytes,sha256,phase}|{rva,size_bytes,phase,error}],cleanup:{owned_pid_terminated,session_detached,windows_job_assigned?},error}. Fixed basename output files created wx, read back bounded and hashed. Windows kill-on-close Job assigned to owned suspendedtarget before resume; preserveprocesshandle to verify closure, fail honestly if assignment fails. Parent process deadline includes startup/cleanup allowance; cancellation waits for ownedprocess cleanup. No runnable/equivalence verdict derived from trace.

Stored trace result follows binary snapshot envelope, operation trace_binary, outputs[] (memory isn't PE), trace_artifact and snapshots artifact refs, logs, source unchanged, runnable false and explicit limitations. Extend binary report routing/parser/helper only for this operation; model exporter stays strict.

Ruling: existing CODEX_START continuous local authorization plus explicit new user directive authorize implementation and controlled execution against copies. No external publication, original overwrite or guessed protection/entry patches. No Git checkout exists; ownership boundaries isolate parallel code.

Restoration evidence gates: immutable inventory; reproducible original execution observations; verified startup/runtime initialization; complete analysis image and named partial functions; recovered business modules; fresh input/output regression on documented functionality. None may be marked complete solely because a tool runs or a dump exists.

