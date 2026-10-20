# REA portable identity and owned MCP sessions

Status: implemented for the pinned 6.7.0 portable contract; native integration
and CFG/phi lifting remain unavailable until their own gates pass.

REA's package has a public executable and MCP surface, but no advertised stable
library export. Wirefit therefore owns a public stdio MCP connection for live
acquisition, and treats exported canonical Evidence as the offline boundary.
The source commit is `27dc42d10249f0410904a75c0997842eb03b931c`, resolved from npm
SLSA provenance. The later main branch retains the same package version, so
matching package versions alone is insufficient. Live analysis also checks the
captured combined catalog digest.

The unchanged minimum validator import closure is vendored with its MIT
license, upstream third-party notices and per-file hashes. This validates the
actual canonical envelope, analysis-profile commitments, record semantic IDs
and unknown-ledger reference constraints. It avoids runtime private `dist`
imports and keeps offline work independent of an installed REA process. The
fixed parser can accept arbitrary JSON payloads only within the actual canonical
contract; an incompatible envelope or identity is an attachment, not an IR.

One connection owns retained IDs. Wirefit exports first, authenticates the
result, awaits case persistence, then closes its own binary binding. After
cancellation it attempts export with a fresh bounded request. Cleanup and save
failures remain visible in the acquisition result. A fresh connection cannot
silently reuse an old retained ID; complete portable data is required.

High-p-code output IDs and explicit def-use operand slots preserve SSA.
Missing producer facts are rejected before cutpoint slicing. The release does
not expose incoming-edge slots for phi, a complete control guard, or a checked
function-return/ABI binding. Current lifts therefore describe local expressions
with unknown execution guards and cannot authorize original-function replay.
This preserves useful offline model reasoning while leaving native fidelity
unvalidated.

The real Windows MCP run, cross-session check, source archive/provenance and
official CLI validator outcomes are recorded under `artifacts/rea`. The lack of
a configured Ghidra/JDK/decompiler blocks the native gate; synthetic mapper
fixtures do not satisfy it.
