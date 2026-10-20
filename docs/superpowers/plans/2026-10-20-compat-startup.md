# Compatibility CRT startup experiment from actual API frames

This is follow-up work toward the unchanged full vmde restoration goal, not a
claim to have recovered the original OEP or protected 50-byte prefix.

New original public-CLI job: job_6efd881ed9a64bd9aa028ead3b5809f1,
result binary_trace_75e8258aa9194da6b4df028bbbc14310,
raw SHA2f2b78100f916076a81eab7fa058404cfcd36c455e5e85713cc40da8d0526d91.
Independent review startup-context/api-frame-review.json SHA
2926b9795e54ae17bbdffa80d6a81b7d50fe59a10f99bef8ad02217a9edcefdf.
Both APIs were observed, no hardware breakpoint, omitted0, four cleanup true.

Observed events50/51: GetStartupInfoA returns4b10cd, GetModuleHandleA returns
4b10e3, same thread36480, EBP19fef8. Actual saved frame DWORDs include
[EBP-10]=19ffcc,[-c]=4b1308,[-8]=8e02b8,[-4]=0,[-18]=19fe68.
Both 256-byte stacks and caller-code bytes are complete. The source table at
8e02b8 has DWORDs ffffffff,4b112a,4b113e (map/hash must be rechecked).
If the exact helper4b12bc created this frame and the saved-SP field did not
change, its layout implies local allocation0x74: (EBP-savedSP)-0x1c.
This is a conditional constraint. The protected prefix at4b0f64..95 remains
unrecovered; do not replace that fact with the derived value.

Proposed testable hypothesis: a new compatibility prefix can establish the
required frame and enter the already decoded CRT body4b0f96 on an immutable
copy of fixed analysis image50b6... (not the original protected executable).
The old dump entry4b12bc wrongly enters a helper requiring caller parameters.
A compatible prefix is a functional reconstruction experiment, not a true-OEP
identification or proof of the original prefix's exact semantics.

- [x] Revalidate source/raw-frame/review/current tool identities. Parse the
  actual PE32 import table to obtain the unique loader IAT slot for
  kernel32!GetModuleHandleA; never reuse a captured heap thunk or system VA.
  Check preferred base/DYNAMIC_BASE/relocation assumptions explicitly.
- [x] Create a concrete new-file builder with fixed source SHA and fixed patch
  bounds, pure RED/GREEN tests, before/after bytes and SHA receipts. Preserve
  original and old dump. Reject ambiguous imports, changed prefix/body/headers,
  overlapping patch ranges and existing outputs.
- [x] Candidate: entry RVA b0f64; only its 50-byte protected prefix plus the PE
  entry field are changed. Use CLD/push0x74/push8e02b8/call4b12bc; zeroEBX and
  [EBP-20] (quote-state local); loadEDI from the new IAT; GetModuleHandleA(NULL),
  derive NT headers ECX and OptionalMagic EAX, then jump4b0f96. Fill unused
  prefix bytes explicitly: 41B stub and 9B CC. CLD actively establishes DF=0;
  EFLAGS were not captured in the real API frame, so this is an explicit
  compatibility choice, not a recovered original-prefix instruction.
  These choices need instruction/ABI review before
  any target execution; do not silently assume other protected setup absent.
- [x] Verify builder and candidate instruction bytes/stack contract, ideally
  compare a synthetic helper-frame run to the observed invariants. This only
  tests the compatibility hypothesis, not original-prefix equivalence.
- [ ] After review, run one new owned public CLI trace of the candidate,
  bounded no hardware breakpoints, retained actual failures/cleanup. Observe
  loader outcome, CRT APIs and owned windows. A local startup success still
  does not satisfy normal image/vector I/O or whole-program equivalence.

No new approval required for these already-authorized reversible local copies
and owned runs. UTF-8 explicit. Do not weaken completion requirements or call
an analysis dump runnable merely because its PE header and imports parse.

Independent design/frame/TLS review:
startup-context/compat-startup-abi-review.json, SHA256
4fe20007ff33ca34de1facbb78dfd9343348ec36c881ae8bb092da4dc918257c.
The exact helper layout supports EBP=S0-4 and savedESP=EBP-90h under
the stated allocation hypothesis. The existing TLS diagnostic concerns a
virtual zero-fill template without file backing, present in both original
protected file and analysis dump; it is not evidence of a new loader failure.
The builder will not silently alter it. Original trace also contains 11
native exception events; instrumentation had two API hooks and no HW BP.

Actual follow-up: 19 builder tests passed; candidate SHA256
6fb89bd01d8dfaaba8bd1924393548431b001d3a5c0cdb3f78d0cb1dd6e12169,
52 bytes changed within54 permitted. Two actual synthetic helper cases passed,
34 instructions each, DF0/1 and actual FS/stack verified. Seven owned public
CLI candidate spawns include one unsupported-export pre-resume failure and
six resumed traces; actual wrapper/qmain/QApplication return observed, but
no ready UI or normal image/vector I/O. The final plan checkbox remains open
for that unverified window/usable-program outcome. Old script firsterror
ordering flaw fixed in a new v2 with4 pure tests and independent review;
historical successful CPU evidence stays immutable.

Current frontier: actual42474f JMP D2ED39, which pushes102bfb5c and jumpsAA35DE.
Correct return and remaining protection initialization are not recovered.
Root verification artifacts/native/compat-startup-verification-20261020.json
SHA256 fb79dc6aacbe5aed0a891e32d7fcc906b7b5ebf8a4074b1dabd648f56d4b30bf
rechecks171 file identities and14 old native source pins. Full goal active.
