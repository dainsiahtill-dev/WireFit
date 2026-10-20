# Bounded native grid experiment

Caller-derived correction: the original grid function returns its numbered-node
count in EAX. The v1 `semantic_return: "void"` metadata and `eax_incidental` field
name predate this incoming-caller evidence. Actual EAX was captured unchanged;
all 904 saved original values match the count. See [ABI.md](ABI.md) and the new
[portable nodes-plus-count component](../recovered-grid/README.md). Earlier
receipts and exported code remain historical snapshots.

This Windows x86 profile compares vmde's original in-process grid kernel with a
frozen independent implementation. The target is fixed by file SHA, main RVA and
637-byte body SHA; no existing PID, replacement code or arbitrary function address
is accepted. All target execution belongs to a public `wirefit binary trace` job.
The passive native-trace profile remains separate.

The recovered behavior numbers the two outer columns, the remaining top/bottom
boundary nodes, then internal nodes whose four neighboring labels differ. An
internal node with four equal labels receives -1. Output padding is zero. This is
a small grid-topology kernel, not the complete image-to-vector algorithm.

Read `ABI.md` for the observed machine-code contract, `CORPUS.md` for frozen inputs
and comparison scope, and the native-kernel design under `docs/superpowers/specs`.

`control.cpp` and `control.def` build a source-owned x86 positive control. The
builder currently pins the installed MSVC14.44/WindowsSDK10.0.26100 toolchain;
its receipt records actual compiler/linker identities but does not establish a
complete SDK/header dependency closure. Two independent build directories must
produce the same executable SHA before positive-control execution.

`agent.js` invokes a fixed 73-byte owned x86 wrapper. It clears DF immediately
before calling the known function with ECX=context, observes return stack balance
and callee-saved registers, and returns through a cdecl Frida interface. Original
code is never patched. Separate page-multiple allocations contain read-only
context/header/source pages and writable output, surrounded by inaccessible pages
and prefix canaries. The host independently reconstructs expected page hashes.
These checks do not trace every native read or prove arbitrary memory safety.

Failed calls preserve readable output and raw register-state bytes. Unwritten
state slots are unknown, not register observations. A native exception, byte or
canary failure halts further calls. The host terminates its own Windows Job on a
deadline independently of RPC cancellation; output persistence and cleanup are
separate facts.

Run pure/synthetic checks without executing any PE:

```powershell
& .tools/runtime/node_modules/node-win-x64/bin/node.exe --test tools/native-kernel/agent.test.mjs tools/native-kernel/agent-runtime.test.mjs
& C:/Users/dains/AppData/Local/Python/pythoncore-3.14-64/python.exe -X utf8 -B -I -S -m unittest discover -s tools/native-kernel -p 'test_*.py' -v
```

Native execution follows this order: compiled positive control; eight vmde edge
cases; declared 896-case corpus; frozen-candidate comparison and zero-candidate
negative control; managed attachment; standard report export and copied-package
verification. A completed synthetic call is labeled `native_inprocess_kernel`.
It does not show that the application naturally invoked this function or prove
its real object allocation, normal UI, OEP, image/vector I/O or runnable rebuild.
## Offline release validation

`audit-release.py` validates a named evidence directory and an explicitly pinned
managed-file release. It reads only `root/<registered-name>` plus its release
file; original absolute paths remain provenance metadata. The target source blobs,
compiled control, actual 912 recorded calls (904 vmde), public trace/snapshot
references, journal records, register states, synthetic page bytes and candidate
comparison must all agree. Only the exact reviewed worker and candidate source
bytes execute as pure Python validation/calculation. No Frida session or PE starts.
All files are rechecked before a verified result is published, and unexpected
files, links, traversal or collisions fail the check.

```text
python -X utf8 -B -I -S tools/native-kernel/audit-release.py \
  --root ABS_LOGICAL_FILES --release ABS_LOGICAL_FILES/release.json \
  --release-sha256 EXPLICIT_SHA256 --out ABS_NEW_OUTSIDE_ROOT_JSON
```

The final result is `verified_native_evidence` with `native_reexecution:false`;
validation of saved observations does not establish a new target run or natural
application behavior. The auditor's 17 directed tests include a fully
self-consistent modified output, late file mutation and an unknown worker whose
release hash was recomputed. Source acquisition/contract tests separately total
43 Python and 25 JavaScript checks, with 720/720 product regression tests.