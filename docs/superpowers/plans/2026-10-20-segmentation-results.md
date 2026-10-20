# Segmentation result stores and owner identity

Previous goal turn: progress. Actual record
artifacts/native/node-records-verification-20261020.json
SHA256 c4b58429b95e95606a957c4ac57cd4d51d47f7ce8952c3bd5858a05f61abcf58.
31 original-byte CPU writer samples and 60 scoped tests passed. This is not
native segmentation or whole-program restoration. Full user goal stays active.

Current evidence: 46df50 calls473850 pixel export, reloads P2, then calls
488d20(P2+930, EBX, 1, EBX). The tail has three real stack flags, contrary to
its generated C signature. The second flag1 gates488c70(receiver);4ab710
(receiver+4) is a normal predecessor and4891f0(*[receiver+114]) is conditional
on the first flag being0. No natural traversal, descriptor alias or output
label interpretation is assumed. Preserve the failed4f02c0 C attempt.

- [x] Revalidate selected current code/receipt identities and use the existing
  public bounded Ghidra runner for488c70/4891f0/4ab710 only, process<=60s,
  readOnly/noanalysis, guards<=2048, decompile<=5s. Preserve partial evidence.
- [x] Independently inspect actual stores/calls/stack and distinguish S+14/S+18
  record ownership from the existing initializer/caller listing. No wide scan.
- [x] Follow only a concretely evidenced result-store dependency if required
  to identify the next label descriptor and actual dimensions/payload writes.
- [x] Recover an independently verifiable local operation if the observed body
  admits a bounded contract; otherwise keep unknowns and follow the business
  path. Add reusable code only when an actual need is demonstrated, with TDD
  and review. Do not change frozen native/recovered-grid/node-record tools.
- [x] Record actual observations, corrections, source identities and remaining
  full-goal requirements. No repeated export/copy cycle without new need.

Already-authorized reversible local research; no new approval stage. Explicit
UTF-8 text I/O. Only root starts actual Ghidra/target/CPU processes; delegated
lanes perform read-only independent study and nonconflicting file outputs.
Normal image-to-label-to-vector I/O, natural state, startup/OEP, and standalone
runnable reconstruction remain unmet. This plan does not narrow completion.

Actual result: 11 listings / 1000 instructions / 2989 bytes; 10 C scopes
accepted and 4ab710 rejected. Three no-CALL label methods recovered;
32 scoped tests and 26 actual bounded CPU calls passed. Independent actual
state recomputation and 166 current file identities are retained in
artifacts/native/segmentation-results-verification-20261020.json, SHA256
d5b15304b0b98660e4da64dfd26f0badf622d03178fa681ce28efd9bae61b065.
One new original public-CLI target produced 54 API observations and real CRT
frames; it also recorded 11 native exception events. No natural processing,
true OEP, protected-prefix reconstruction or runnable proof follows.
