# Native execution of the bounded restored grid kernel

The user has authorized continued local vmde analysis and WireFit improvements.
This experiment implements the already recorded native-kernel plan. The complete
application restoration objective remains active.

Use the existing public binary trace job and staged-input ownership. A separate
explicit worker profile performs active synthetic calls; passive acquisition is
unchanged. The worker pins the original vmde file, fixed RVA 0x98a50, body size
637 and SHA256 65d46a13deb731ea75b91fd29baf96dc614da6ad8bfcf48805aba748a139f70c.
Neither caller-supplied addresses, arbitrary code nor existing PIDs are accepted.

First build the source-owned 32-bit MSVC control with explicit object offsets,
exported thiscall methods, no CRT and a waiting entry. Verify thiscall with an
explicit context pointer and stack tag. A fixed 73-byte source-owned x86 wrapper
clears DF directly before CALL, places context in ECX, and observes stack balance,
EBX/ESI/EDI/EBP and EFLAGS before/after. It changes no original instruction. Its
bytes are independently decoded and hashed, and it must pass the compiled control
before original calls are allowed. EAX is incidental; the semantic return is void.

Freeze the independent candidate source before input construction. Start with
8 explicit edge cases, then the 896 previously declared inputs only after the
edge run passes. The candidate is never used by the acquisition agent or to fill
missing outputs. A separate comparator accepts only actual observed outputs and
retains failed, unattempted and counterexample rows. Its origin-verified flag stays
false; the host is responsible for runtime identity, guards and ownership.

Each case allocates separate three-page blocks for context/header/pixels/nodes.
The data sits at the end of the middle page, between inaccessible guard pages;
unused prefix bytes contain canaries. Context/header/source pages become read-only.
Dimensions 2..16, strides and signed int32 labels are validated independently by
host and agent. Every protection result and actual page protection is checked.
Per-call identity binds live main base, known entry and body bytes immediately
before/after. Buffer hashes, actual output bytes, addresses, registers and timing
are evidence. After native exceptions or failed postchecks, capture readable
components independently, preserve the first error and halt subsequent calls.
Guard pages/canaries do not establish every native read or arbitrary memory safety.

Host deadline cancellation must close the owned Job independently of RPC wait.
Cancelling a Frida RPC is not native function termination. Persist checkpoints
before/after each attempted call, preserve the whole declared denominator, and
report actual target/Job/session cleanup separately. No cleanup flag is inferred
from an output file or parent-worker exit. Event groups stay within public trace
limits; full native-result evidence is attached as opaque managed files.

Tests: contract invalid inputs; compiled ABI positive control; failure retention;
strict host schema/body/source binding; first-error timeout and ownership cleanup;
partial evidence and missing output comparisons. Review before vmde execution.
Then actual 8+896 calls, negative candidate control, managed attachment, standard
report export and independent copied-package verification. Scope label is
native_inprocess_kernel under synthetic objects, never a natural application call,
full image/vector behavior, true OEP or runnable reconstruction.