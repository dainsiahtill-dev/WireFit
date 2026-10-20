# Owned runtime export observer

This independent Python stdlib observer reads a host-validated public CLI target.
It does not start a target, use Frida, attach a debugger, call an export, modify
memory, change page protection, suspend/resume a process, or terminate a target.
The public job remains the sole owner of its Windows Job and cleanup.

The host must obtain PID, staged executable path and exact creation FILETIME
from its live validated public CLI handoff, confirm the job is still running,
and supply the source SHA already verified by that owner. A request document is
provenance, not independent proof that a public job owns a process: this helper
does not open or recover a CaseStore. Do not use it with unrelated existing PIDs.

## Interface

Use 64-bit Windows Python for the current PE32 target:

~~~powershell
python -X utf8 -I -S tools/runtime-exports/observe.py --request E:\owned\request.json --out E:\owned\new-export-observation
~~~

Only these two options are accepted; duplicates and unknown options fail.
The UTF-8 request must be at most 64 KiB, with no duplicate keys, NaN, Infinity,
unknown fields or boolean substitutes for integers:

~~~json
{
  "schema_version": 1,
  "pid": 12345,
  "expected_executable": "E:\\owned\\case\\.binary-work\\binary_trace_0123456789abcdef0123456789abcdef\\vmde.exe",
  "expected_creation_filetime": "134369128310367119",
  "source_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "expected_module_file": "E:\\owned\\case\\.binary-work\\binary_trace_0123456789abcdef0123456789abcdef\\QtCore4.dll",
  "module_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "symbols": [
    "??0QSettings@@QAE@W4Scope@0@ABVQString@@1PAVQObject@@@Z",
    "??0QSettings@@QAE@PAVQObject@@@Z"
  ],
  "sample_offsets_ms": [0, 25, 100, 500, 1500, 5000],
  "timeout_ms": 8000
}
~~~

Replace the example identities with the actual owner handoff. FILETIME remains
a decimal string because it exceeds JavaScript's exact integer range. Up to
eight distinct exact ASCII names (1..256 bytes) and eight strictly increasing
offsets are permitted. Offsets start at zero, are at most 8000 ms, and precede
the deadline (at most 10000 ms). Timing starts after the retained process HANDLE
passes its initial identity check; it is not a DLL-load or process-spawn anchor.
Each sample records actual offset, lateness and UTC.

The output directory must be new, its parent ordinary and present. Local drive
paths reject alternate streams, device/UNC forms, dot segments, trailing dots
or spaces, Windows reserved names, symlinks and reparse ancestors. Input files
are single-link, bounded stable reads. Staged executable and expected DLL files
are SHA-bound using retained read-only disk handles without write/delete sharing.

## Observation and evidence

The observer compiles only cached UTF-8 bytes of these fixed reviewed sources,
preserving their original __file__ and a non-main __name__:

* native-trace/memory-image.py: e2f062a4b2d72bc67de793a9afe6068336f5bd99ccf1b9d51b647320e719ec38
* native-trace/private-regions.py: d55539bf335b55b848b53e4449f25f53c7443e0ff18cffaa5cc375ed0535e111
* runtime-exports/model.py: f3d0e19585530335f6d77f92ba099262151719eedc1d56417864847fdf9e590a

Their CLI/main routines do not run. WindowsRegionReader opens exactly one
PROCESS_VM_READ | PROCESS_QUERY_INFORMATION (0x410) HANDLE. Its reviewed identity,
RPM, VQE and close operations share that HANDLE. PID, full staged image path and
creation FILETIME are checked initially, around module snapshots, and before
each RPM. A mismatch stops further reads; ordinary sample errors do not kill the
target. No PROCESS_VM_WRITE, debug privileges or target execution are requested.

Every sample takes a new Toolhelp module snapshot and resolves exactly one
matching DLL basename plus the expected full path. No base, export address or
page cache survives between samples. Enumeration is capped at 256 modules.
ERROR_BAD_LENGTH is retried at most three times within the deadline; incomplete,
ambiguous or failed enumeration cannot establish module absence or uniqueness.
Toolhelp structures use native ctypes layout, verified against Windows SDK
10.0.26100.0 um/TlHelp32.h; there is no hand-written target padding.
The current native64 MODULEENTRY32W is 1080 bytes, with modBaseAddr at offset24;
native MEMORY_BASIC_INFORMATION is 48 bytes even for the PE32 target.

Every actual ReadProcessMemory call is preceded by VQE for the entire requested
interval. It requires MEM_COMMIT, MEM_IMAGE, the same allocation base, readable
protection and no PAGE_GUARD/NOACCESS. Policy rejection is explicitly
read_not_attempted with no invented native Winerror. Real RPM success, transfer
count, error and actual prefix bytes remain unchanged. Partial transfers are
never zero-filled. The target's separate VQE query can record non-executable or
unreadable pages without attempting RPM. Metadata is read at base+RVA in memory,
not through disk raw offsets.

PE EAT has no function/data type field. frida_export_type is always null.
Direct RVA, forwarder, unassigned/invalid target, section flags and current VQE
protection are separate observations; forwarders are not recursively resolved.
The on-disk DLL SHA binds metadata identity, not equivalence to decoded runtime
code. All sampling is cooperative and non-atomic; VQE-to-RPM races remain possible.
A transition is supported only by actual observations of the same module epoch
and export. Absence of an observed transition does not rule out an earlier one,
and this tool does not identify which predicate failed in an old Frida guard.

## Outputs and lifecycle

Each attempted point creates sample-NNN.json exclusively. It contains the full
model inspection, actual page/read bytes, raw VQE metadata, adapter policy-query
logs, identity observations and errors. Where an adapter read exactly matches a
model transcript (RVA, requested length, transferred length, SHA and hex), its
duplicate hex is replaced by an explicit actual_bytes_reference to
inspection.reads[N].hex. Actual bytes remain once in the same JSON; unmatched or
late-failure bytes remain inline. There is no reference to unobserved bytes.

progress.json is a small atomic UTF-8 index, replaced only inside this fresh
directory using a create-new temporary file. result.json is written once after
process/disk handles and source/tool checks finish. Each sample is at most 4 MiB;
index/result at most 4 MiB; cumulative writes are at most 32 MiB. The pure model
also enforces its independent per-sample 1 MiB read and 256-page limits.
Checkpoints persist after each completed sample, so a forced observer exit may
lose the current sample but preserves earlier sample files and their index.
No atomicity or persistence guarantee is claimed for an interrupted disk write.

Stdout is one UTF-8 JSON summary (at most 64 KiB) with sample identities, first
error, cleanup and saved result identity, never large page hex. Exit0 means all
scheduled observations completed; it does not mean an export is hookable or that
the application is usable. Exit2 is partial (including early target exit or
ordinary unreadability). Exit1 is failed, including identity/source/tool
contradictions and unconfirmed local handle cleanup. Future points remain
explicitly unattempted after a stopping error. Earlier errors survive cleanup
errors, which are listed separately.
Final index/result publication errors also remain separate. Even when a final
create-new result file is blocked, stdout retains the real sample index,
identity/cleanup outcome and original first error; result_file is null unless
that complete file was actually saved. An already failed identity verdict is
never downgraded by a later generic identity-query error.

The host must impose an independent process deadline (helper timeout+2s is the
intended allowance). Python's cooperative deadline cannot interrupt a blocked
Win32 syscall. A host timeout may terminate only its observer child; the public
owner independently retains target Job authority and cleanup.

## Scoped verification

~~~powershell
python -B tools/runtime-exports/test_observe.py
~~~

Tests use synthetic readers/module APIs and owned temporary files; no target
Win32 APIs are called. One real Python CLI validation child exits before any
Win32 access. Tests cover fixed request identity, strict paths/JSON, bounded
Toolhelp retry/inventory, native ABI layout, same-HANDLE VQE-before-RPM policy,
actual partial prefixes, sticky identity changes, per-sample ASLR resolution,
first-error preservation, deadlines/unattempted points and late cleanup errors.
No PE, CPU emulator, Ghidra or application is executed by these tests.

Primary API references:
[Toolhelp snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot),
[MODULEENTRY32W](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32w),
[VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex),
[PE export tables](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table).
