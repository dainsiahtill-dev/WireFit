# Static ABI contract for the bounded grid kernel

`abi-review.json` is a read-only review of 637 bytes at original VA `0x498a50`,
main RVA `0x98a50`, SHA-256
`65d46a13deb731ea75b91fd29baf96dc614da6ad8bfcf48805aba748a139f70c`.
The pinned Ghidra listing has 203 contiguous instruction starts. Independent
Capstone 5.0.6 decoding matched every start and byte; all 24 direct branch targets
stay inside that set. The bytes also match the pinned analysis dump and the
fresh module-tail main image. The JSON retains their exact identities and code
bytes. No PE or native kernel was executed for this review.

The instruction contract is consistent with a no-stack-argument ECX-object call;
it does not by itself verify a named C++ ABI or a native-call API. Entry
`MOV EDX,ECX` preserves the context pointer in EDX. The sole return is `C3 RET`,
without an immediate stack pop. With a valid return slot, final ESP is entry
ESP+4. The prologue reserves eight local bytes and pushes EBX, EBP, ESI, EDI;
the epilogue pops EDI, ESI, EBP, EBX, releases eight bytes and returns. At least
24 writable bytes below entry ESP and the readable return slot are required.
EAX returns the number of numbered logical nodes in the declared domain; ECX,
EDX and arithmetic flags are scratch. The original source-level integer type
is not recovered. See the caller-derived correction below.

`REP STOSD` at `0x498a64` uses ES:EDI, with no preceding CLD or other DF setup.
DF=0 and flat DS/ES addressing are explicit preconditions. A source-owned positive
control and an audited invocation wrapper must verify their own register/stack
convention and establish DF. The body has no external CALL, system instruction,
FS access, x87 or SIMD instruction. These static facts do not establish that a
natural application caller met this contract.

The context must expose these little-endian, aligned 32-bit fields:

| Offset | Meaning under this synthetic contract |
| --- | --- |
| `0x00` | writable node-buffer pointer |
| `0x04` | node stride in int32 elements |
| `0x08` | node row count, exactly H+1 |
| `0x0c` | readable source-descriptor pointer |
| `0x94` | width W |
| `0x98` | height H |

The descriptor reads only `+0` (source pointer) and `+4` (source stride in int32
cells). Its historical `+8` height field is not read by this body. The context
therefore needs at least 156 readable bytes; the descriptor at least eight.
The declared domain is W,H in 2..16, node stride W+1..W+8, source stride W..W+8,
and signed-int32 labels. All addresses and their extent ends must fit 32 bits,
without wrapping. Context, descriptor, source, node buffer, code and stack must be
disjoint, and every buffer must be suitably aligned and large enough.

The initial clear writes every cell of `node_stride*(H+1)`, including row padding.
Subsequent updates and numbering stay within active columns 0..W and rows 0..H.
Source reads use rows 0..H-1 and columns 0..W-1; source padding is not an input to
the computation. At maximum declared dimensions/strides, source allocation is
1,536 bytes and node allocation 1,632 bytes. Apart from locals/saved registers,
all data writes address the node buffer. The context, descriptor and source are
immutable under the disjoint-buffer contract.

The next native experiment must separately validate positive control, fresh body
identity before/after each call, actual buffers and canaries, immutable inputs,
register/ESP observations and owned-process cleanup. A native match would support
this local synthetic contract. Natural caller objects, heap/aliasing, image to
vector behavior, startup/OEP and runnable reconstruction remain unverified.

## Caller-derived return correction

The caller at `0x499eb0` saves the kernel's EAX at `0x499f1f`, then passes it to
`0x484e60` at `0x499f59`. EAX is the count of numbered logical nodes:
`2*(W+H) + interior points whose four labels are not all equal`. Output padding
is excluded from that count. All 904 previously saved original raw register
states agree with this count and the independently reconstructed node array.
This is an offline recheck of existing samples, not 904 new native executions.

The v1 capture field `setup.semantic_return: "void"` is an incomplete description
of the original function's semantics. Its wrapper itself may return void because
it separately stores the actual EAX at offset 48 of its 52-byte raw state. That
capture is retained as `registers.eax_incidental`; the historical field name does
not make the original value semantically incidental. Earlier receipts, code and
exported snapshots are preserved. The v1 release auditor checked node output;
it did not claim to check this caller-derived return contract.

See `artifacts/research/vmde/caller-layout/kernel-return-review.json` and the new
`tools/recovered-grid/` component, whose contract returns both nodes and count.
Natural caller execution and whole-program restoration remain unverified.
