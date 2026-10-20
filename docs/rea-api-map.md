# REA adapter map

The production adapter is pinned to `rea-agents@6.7.0`, release commit
`27dc42d10249f0410904a75c0997842eb03b931c`. This is the commit named by the npm
package's SLSA provenance. The repository's later `main` also reports 6.7.0;
matching a version string alone does not establish matching source.

Primary sources:

- [Published release source](https://github.com/morluto/rea/tree/27dc42d10249f0410904a75c0997842eb03b931c)
- [Public executable](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/scripts/rea.mjs)
- [MCP contract](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/docs/mcp-contracts.md)
- [Evidence identity implementation](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/evidence.ts)
- [Native value-flow schema](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/native/nativeValueFlow.ts)
- [Ghidra operation semantics](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html)

## Public boundary

REA does not advertise a stable external TypeScript SDK through package
`exports`. Wirefit uses an official MCP client and the public executable
`node scripts/rea.mjs --mcp`. It does not deep import installed private `dist`
modules. The independent offline validator is a licensed, unchanged source
closure in `vendor/rea`; `UPSTREAM.json` lists all 18 files and hashes. MIT and
the release's third-party notices are retained there. Runtime dependencies for
this closure are `zod` and `canonicalize@3.0.0`.

The actual Windows run discovered 207 tools. The raw advertised schemas and
server replies are in `artifacts/rea/live-discovery.json`. Its catalog identity:

```text
tools:    af39310c9591bb981893ec0d2188b1bcf6e9cc8ba3ac513d5bbefc8ddcb85639
combined: 96d8f6e6ea1b1ba13557216624a3461c738729d53c79b4b0100d1f3a3a32441c
```

The live adapter checks both package version and combined catalog digest before
analysis. The server-reported build commit was null; package provenance supplies
the separately recorded source commit. These are separate observations.

| Tool | Actual request fields used | Wirefit behavior |
| --- | --- | --- |
| `binary_session` | `expected_package_version`, `expected_catalog_digest` | Save identity/availability before and after binding; refresh after failed binding during recovery. |
| `open_binary` | `path`, optional `provider_id` | Use the caller's absolute target and chosen provider. |
| `analyze_function` | `procedure` | Request one name/address; do not infer a function return from raw RETURN. |
| `export_evidence_bundle` | `path`, `overwrite:false` | Export to the caller's absolute destination before close; refuse replacement. |
| `close_binary` | `{}` | Close the owned binding only after export/persistence attempt; preserve cleanup errors. |
| `tools/list` | optional transport cursor | Fetch all pages with repeated-cursor and tool-count guards. |

Success is read from `structuredContent`. Error diagnostics come from JSON text
when `isError:true`; errors can omit structured content. The complete reply and
`_meta` remain attached separately. Target-content metadata is not a trusted
instruction or a model verdict.

## Offline API

```ts
importPortableEvidence(bundle: unknown, bundleSha256?: string): ImportedEvidence
liftPcode(record: unknown, outputOperationId: string, cutpoints?: readonly string[]): PcodeLift
acquireEvidence(options: ReaAcquireOptions, signal?: AbortSignal): Promise<ReaAcquisition>
```

The actual canonical portable bundle has seven arrays: `artifacts`, `providers`,
`environments`, `scenarios`, `captures`, `unknowns`, `records`. It has no top-level
version field. A future or incompatible envelope is retained as
`attachment_only` with no liftable records, rather than guessed into this shape.

The validator authenticates strict envelopes, subject formats, analysis-profile
commitments and matching providers, record `evidence_id` semantic commitments,
canonical ordering/manifests, duplicate IDs, residual-unknown histories and
their Evidence/unknown references. Display subject name/path are excluded by
the upstream Evidence identity algorithm; other semantic fields follow the
upstream implementation unchanged. Wirefit's own semantic hashing must not be
substituted for REA's canonical hashing.

Pass the hash of the actual imported bytes as `bundleSha256` to bind provenance.
The importer seals records and remembers this association. A standalone record
can be authenticated and lifted, but cannot invent its original bundle hash;
its model `source_ref` stays null. Case services should reload and authenticate
the saved bundle before selecting its record by `evidence_id` or stored index.

## P-code mapping and limits

The mapper consumes `normalized_result.native_value_flow`, authenticated by the
record identity and checked with the real release schema. Outputs are selected
by `operations[].id`. A graph edge is exactly
`{definition, use, input_index}`. SSA identity comes from those operation IDs,
not a register/location string. Parameters require `parameter_uses` and matching
declared ordinals. Constants use `constant_hex` with byte widths 1, 2, 4 or 8;
64-bit values never pass through JavaScript Number.

| P-code | Wirefit operation |
| --- | --- |
| COPY | copy |
| INT_ADD/SUB/MULT | bv_add/sub/mul |
| INT_2COMP / INT_NEGATE | bv_neg / bv_not |
| INT_AND/OR/XOR | bv_and/or/xor |
| INT_LEFT/RIGHT/SRIGHT | bv_shl/lshr/ashr, retaining the full unsigned shift count |
| INT_ZEXT/SEXT | bv_zext/sext |
| INT_EQUAL/NOTEQUAL/LESS/LESSEQUAL/SLESS/SLESSEQUAL | Corresponding typed comparison followed by explicit bool_to_bv to the one-byte p-code output |
| PIECE | bv_concat with input0 as high bits |
| SUBPIECE | bv_extract; constant byte offset is multiplied by eight |

The complete selected definition closure is checked before applying deliberate
cutpoints. Missing definitions, duplicate definitions, cycles, detached selected
definitions, producer truncation and any nonzero omission count are rejected.
Cutpoints reference existing operation outputs; repeated uses retain one source
SSA identity. They are expression inputs, not verified ABI arguments.

LOAD, STORE, CALL, CALLIND, CALLOTHER, INDIRECT and indirect branches are rejected
throughout the supplied flow, including dead or output-unrelated operations.
Reported unsupported effects are also rejected. Unknown required opcodes,
unsupported widths, implicit casts and missing bindings cannot turn into zeros
or unconstrained inputs. BOOL operations, division and carry/overflow operations
are currently unsupported. Constant-only models are rejected because the V1
model contract requires at least one genuine input.

The release has no high-p-code predecessor/incoming-edge slot mapping, no
executable guard field and no independently checked function-return binding.
MULTIEQUAL therefore returns `UNSUPPORTED_PHI_MAPPING`. Lifted results are local
expressions with `execution_guard:unknown`; `targetReplayEligible` is false.
No native whole-function equivalence follows from a successful local lift.

## Live lifecycle and observations

`ReaAcquireOptions` accepts `command`, optional `args/cwd/env`, optional absolute
`target`, `provider`, `functionAddress`, required absolute `destination`, request
and recovery timeouts, and an optional async `persist(imported,bytes)` callback.
The callback is awaited before `close_binary`. Cancellation does not reuse the
aborted signal for export recovery. Recovery and close calls have independent
bounded request timeouts; failure to save is explicit
`REA_EVIDENCE_NOT_PERSISTED`. Incomplete provider cleanup prevents a completed
status. A rejected client promise does not establish that upstream work stopped.

The actual Windows run successfully analyzed the small source fixture under
`artifacts/rea/target-js` and exported `real-js-bundle.json` before closing.
A new connection rejected its old retained Evidence ID, while accepting the
complete inline record. The exported file authenticates offline. The official
public `inspect-evidence-bundle` CLI accepted it (exit 0) and rejected the saved
intentional semantic-ID tamper (exit 1).

Native acquisition is **BLOCKED** in this environment: the real REA diagnostic
reports no configured Ghidra installation, no matching decompiler and no usable
Java runtime. Its pwntools layout lane reports Linux x64 only. No Ghidra run or
native whole-chain lift was performed. P-code unit tests use explicitly labeled
synthetic records matching the real schema. Synthetic MCP lifecycle tests cover
cancellation/recovery, unavailable binding, catalog drift and cleanup failure;
they are not provider integration evidence.

Reproduce public discovery after installing the pinned package locally:

```powershell
npm.cmd install --prefix .upstream/rea-runtime --ignore-scripts --no-audit --no-fund rea-agents@6.7.0
node artifacts/rea/discover.mjs
```

Use the pinned Node 24 runtime for the recorded environment. The discovery
script is development evidence tooling; its `overwrite:true` exports are
restricted to its own artifact paths. Product acquisition always uses
`overwrite:false`.
