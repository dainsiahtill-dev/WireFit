# Loaded export readiness and protected construction control

Full vmde restoration remains active. Current candidate reaches CRT, Qt wrapper,
qmain and returns from QApplication construction, but does not produce a usable
UI. Actual protected transition42474f -> D2ED39 pushes102bfb5c and jumpsAA35DE.
VM exit remains unobserved; different runs fault in QtCore or the protected area.
Do not replace this block merely from one constructor hypothesis.

Current immutable partial-startup verification:
artifacts/native/compat-startup-verification-20261020.json SHA256
fb79dc6aacbe5aed0a891e32d7fcc906b7b5ebf8a4074b1dabd648f56d4b30bf.
Independent transition review d32bf234edb2811b6c01dd1424df54d0a83b480c9d1e6200cef5d3dd91ab0f27.
Independent Qt import/export review7f5d0ecbe5b4aff4c682083a039f0c7d7635bd53db51bfa83c813f6829d72416.

An additional actual original-source9a0... API-only control, no HW BP,
job_a0873f2c7b6e49b19e6b34ca1d15f52d / binary_trace_0e296cf314ab4899ab5fc23246f1f346,
failed with API_HOOK_FAILED before a QSettings call was collected. Raw SHA256
4f664f8bea6156274f222bdea0ca1ce52eea2b935149d21880744d55c0019ac3.
QtCore starts pending_module; first parent-ctor hook then reports
"Requested export is not an executable function". This is a compound guard:
enumerated export absent/type not function/range absent/not executable. The
current message does not identify the failing predicate. Module initialization
timing is a hypothesis, not a verified cause. Worker stops and all cleanup true.
Partial15 API observations do not establish a natural QSettings control result.

Exact narrow symbols from fixed DLL EAT/new analysis IAT:
- ??0QSettings@@QAE@PAVQObject@@@Z : RVAa44a0 / IAT11e3934.
- ??0QSettings@@QAE@W4Scope@0@ABVQString@@1PAVQObject@@@Z : RVAa43f0 / IAT11e38b0.
Old global6fa754 contains670e9870, which is QVariant destructor,
??1QVariant@@QAE@XZ, not a constructor. Keep that correction explicit.
The original PE statically imports neither constructor; loaded export hooks
are separate observations. QtCore disk .vmp code/raw-unbacked pages cannot
substitute for live code. One unrelated non-ASCII EAT name stays unknown.

- [ ] Obtain bounded evidence of the exact loaded-export predicate and its
  address/type/memory-range/protection at relevant module phases. Prefer a
  narrow read-only inspection before changing retry or fatal-error behavior.
  Preserve raw data and failures; no guessed executable permission or target.
- [ ] If temporal initialization is demonstrated, design a bounded readiness
  state with an explicit deadline and diagnostic. Keep true missing-name,
  data-export and invalid-range conditions distinguishable; do not silently
  treat all failures as transient. Add new capabilities through maintainable
  shared code; preserve historical executed source identities and receipts.
- [ ] Add focused RED/GREEN and review for any actual product/tool change.
  Test changed permissions, no module, nonfunction export, permanent absence,
  timeout/cancellation, first-error preservation and actual source provenance.
  Run appropriate product checks if core protocol/code changes; no repeated
  old package/export copying and no unneeded native-kernel904 reruns.
- [ ] Run one newly owned original control after the readiness issue is
  resolved, with exact source/hash and narrow ctor hooks. Bind observed caller
  bytes, stack/ECX and return-site metadata. No hit or disturbed execution is
  inconclusive. Do not interpret onEnter as proof of return.
- [ ] Only then formulate a VM-block reconstruction experiment with explicit
  input/output/register/stack/memory contracts and independent counterexamples.
  Whole program, remaining VM paths, normal image/vector I/O remain mandatory.

These are authorized reversible local analysis/tool improvements. No new
permission stage. Text IO explicit UTF-8. Old worker is among14 frozen native
source pins; do not silently mutate it and claim old/current closure unchanged.
