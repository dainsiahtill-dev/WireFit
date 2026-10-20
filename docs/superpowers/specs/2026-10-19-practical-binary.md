# Practical Windows binary workflow design

User intent: unpack `E:\Vector Magic 2021\vmde.exe` and improve Wirefit according to real practice, while measuring independent Handwired capabilities and comparing with REA. Original target remains unchanged; all derivatives and logs remain reviewable in a case. No arbitrary scope expansion into universal devirtualization is promised.

Current evidence: PE32 x86, 6,516,736 bytes, SHA256 9a0fa724e4a2f189da4cafdd700842d5b6c7aa6c571269500e5eb56cc3fa9a5d, high-entropy RWX sections and packed entry. Family is not yet confirmed. Use a pinned external detector to identify family before choosing an unpacker. Real external runs and genuine failures remain recorded.

Architecture: independent pure PE parser (`src/pe.ts`); binary workflow orchestration (`src/binary-service.ts`) using existing CaseStore, JobManager and owned runProcess; CLI/MCP only translate requests. No changes to the six canonical mathematical experiment schemas. Binary workflows use their own job operations and compact `runs.result` records like existing REA acquisition.

PE inspection API: `inspectPe(bytes: Uint8Array): PeInspection`, exported from src/pe.ts. Required fields schema_version:1, sha256, size_bytes, format:'PE32'|'PE32+', architecture:string, image_base:string hex, entry_point:{rva:number,va:string,file_offset:number|null,section:string|null,bytes_hex:string}, sections:[{name,rva,virtual_size,raw_offset,raw_size,entropy,characteristics:number}], imports:[{library,symbols:...}], diagnostics:[{code,message}], indicators:{packed_suspected:boolean,reasons:string[]}. Additional fields are allowed; document types. Address values that can exceed JS exact integer range remain hex strings. Every offset/count/string/table walk is bounded; virtual-only data does not become file-backed.

Workflow API exported from src/binary-service.ts:
`submitBinaryInspection(service: WirefitService, request: BinaryInspectRequest): Promise<JobState>`;
`submitBinaryUnpack(service: WirefitService, request: BinaryUnpackRequest): Promise<JobState>`.
`BinaryCommand={command:string,args?:string[]}`.
`BinaryToolchain={detector?:BinaryCommand,unpackers?:{unlicense?:BinaryCommand}}`.
`BinaryInspectRequest={file:string,toolchain?:BinaryToolchain,timeout_ms?:number}`.
`BinaryUnpackRequest={file:string,backend:'unlicense',toolchain:BinaryToolchain,timeout_ms?:number,target_timeout_seconds?:number,copy_dependencies?:boolean}`.

Detection is optional static metadata; missing external detector is explicitly unavailable. Dynamic unpack runs only an explicitly selected, configured backend. The initial backend is a pinned separate Unlicense process for its documented Themida/WinLicense scope if the actual detector confirms applicability. It is not part of the Wirefit mathematical core. Input/dependency snapshots, tool identities, argv, timing, stdout/stderr, source and output SHA256, PE validation and cancellation cleanup are persisted. Never use shell interpolation. Never overwrite source. Reject output path aliases and limit file sizes and counts. An analysis dump is not claimed runnable, equivalent, or devirtualized; missing/invalid output is failure. Keep partial records after backend errors.

CLI: `binary inspect --case CASE --file FILE [--config TOOLCHAIN] [--timeout MS]`; `binary unpack --case CASE --file FILE --backend unlicense --config TOOLCHAIN [--timeout MS] [--target-timeout SECONDS] [--no-copy-dependencies]`.
MCP: `wirefit_inspect_binary`, `wirefit_unpack_binary` use strict equivalent request fields and existing async jobs/result/cancellation. Static capabilities list optional binary facilities separately from model proof/fitting. Existing imported verdict and mathematical schemas stay strict.

Verification: malformed/truncated PE, 32/64 bit, RVA virtual tails, imports, external provider failure, explicit backend selection, source immutable, output/lease/path consistency. Run genuine detector/unpacker on the selected target; preserve failures. Review scope and executable validity independently. Compare Handwired actual-core results, source-known fixture behavior, public VMP cases and user protected application without merging their evidence classes.

Ruling: user implementation kit explicitly authorizes continuous execution and the latest message authorizes practical enrichment; routine implementation/design choices proceed without repeated stage questions. No Git checkout exists, so ownership boundaries protect shared source and original user specifications remain untouched.
