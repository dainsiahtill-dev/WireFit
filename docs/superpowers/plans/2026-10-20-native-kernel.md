# Native replay of the bounded grid kernel

The whole vmde restoration goal remains active. Module-tail sampling has closed
four specific pointer observations and one instruction byte, not startup or the
application. Stop following more static API chains in this phase.

The existing independent grid candidate matched 896 Unicorn cases. The latest
main image still contains the same 637 bytes at main RVA 0x98a50, SHA256
65d46a13deb731ea75b91fd29baf96dc614da6ad8bfcf48805aba748a139f70c.
`artifacts/research/vmde/module-tail/kernel-identity.json` binds that comparison to
the new receipt. Presence of these bytes does not establish an original native
call. Test that separate question through a project-owned workflow.

- [x] Inspect the existing 203-instruction listing and explicit synthetic object
  contract again. Verify the x86 calling convention with a source-owned compiled
  positive control before using a native-call API. No guessed signature is a
  verified ABI.
- [x] Design a separate opt-in experiment profile, outside the passive acquisition
  profile. Accept a source/body hash and bounded validated inputs, never an
  existing external PID or arbitrary executable payload. A public Wirefit job
  must own the staged target and its entire lifecycle.
- [x] Freeze the candidate before constructing fresh samples. Start with a small
  edge-case set and a negative candidate control; expand to the declared 896-case
  corpus only after the positive control and bounded original calls work.
- [x] For every call, independently allocate the synthetic context/header/source/
  destination buffers; verify 32-bit addresses, alignment, dimensions 2..16,
  strides, int32 labels, disjointness and output bounds before executing. Record
  writable regions, immutable input checks and canaries. Do not claim that these
  checks observe every native read or prove arbitrary memory safety.
- [x] Bind the original function bytes and current main base immediately before
  each call and recheck afterwards. Preserve actual output bytes, return/error,
  timing and all failed/unattempted calls. Candidate values must never populate
  missing native outputs.
- [x] Enforce a host-side deadline and close the owned process/Job on a blocked
  native call. A native-call exception, timeout or partial result stays failed;
  saved files and final cleanup confirmations remain separate facts.
- [x] Compare the frozen candidate with actual native outputs and retain a
  counterexample on disagreement. Export the input/output/byte-identity closure
  with the standard report mechanism and verify a separate copy.

Label the result `native_inprocess_kernel` under a declared synthetic object and
call contract. It would strengthen the local kernel result beyond CPU emulation;
it would not establish that the application naturally made that call, supplied
those objects or followed the same path. Natural caller state, registers/flags,
stack/SEH/FS/heap, image-to-vector behavior, actual OEP and runnable reconstruction
remain separate acceptance criteria. If the positive control or original byte
contract fails, save that evidence and investigate before broadening the profile.

Native execution outcome: compiled positive8/8, vmde edges8/8 and full896/896; original904/904, zero failures/unattempted, zero mutant rejected for every case. Source/body/candidate unchanged; real cleanup confirmed. Product720/720 plus Python43 and JavaScript25 checks. Delivery registration/copy verification follows these native results and has its own receipt. The overall restoration goal remains active.

## Following restoration work

- [ ] Resolve incoming call/reference sites and owning class/context from the
  existing analysis dump, binding each candidate to bytes rather than a guessed
  name. Recover caller-side width/height/stride allocation and object lifetime.
- [ ] Observe an original caller and its actual context/registers/stack through
  a newly owned job when that application path is reachable. Keep synthetic calls
  and naturally triggered calls as different evidence kinds.
- [ ] Expand from this leaf kernel into its nearest image-processing caller,
  recording every external dependency and new state precondition before calls.
- [ ] Establish a normal image-input/vector-output corpus, true startup path and
  standalone reconstruction. These acceptance criteria are still unmet; the
  native-kernel phase does not close the overall restoration goal.
Delivery outcome: 118 registered files in release b849bc..., 134 files in the standard product cdfc1b..., and both independent copies verified. Three actual verifier processes exited 0; the offline check validated 912 records, including 904 original-kernel calls, without opening original paths. The actual receipt is artifacts/research/vmde/native-kernel/copy-verification.json. The full restoration criteria above remain open.
