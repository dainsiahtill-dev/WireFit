# Static PE inspection

`src/pe.ts` exports `inspectPe(bytes: Uint8Array): PeInspection`. It inspects a byte snapshot synchronously. It does not read files, launch processes, load an image, execute code, or modify the input image. SHA256 and all decoded metadata describe the same owned snapshot; a caller-supplied Buffer or byte view is copied before parsing.

`PeInspection` contains:

- `schema_version: 1`, `sha256`, `size_bytes`, `format: 'PE32' | 'PE32+'`, and `architecture`.
- `image_base` and `entry_point.va` as hexadecimal strings, including values above JavaScript's exact integer range. Existing entry metadata contains `rva`, nullable `file_offset` and `section`, and up to 16 file-backed bytes as `bytes_hex`.
- `entry_assessment: PeEntryAssessment`: `kind`, `basis`, and the bounded observation-window length `inspected_bytes`. The assessment does not change the declared entry metadata.
- `sections`: name, RVA, virtual size, raw offset, declared raw size, characteristics, entropy, and `entropy_sample_bytes`.
- `tls: PeTls | null` and `tls_complete`: ordinary TLS directory metadata and a bounded callback list, with completeness semantics below.
- `imports`: `{library, symbols}` records. A symbol is `{name, hint}` or `{ordinal}`. `imports_complete` says whether the declared ordinary import table was decoded completely.
- `diagnostics`: `{code, message}` records; and `indicators: {packed_suspected, reasons}`.

The exported interfaces are `PeInspection`, `PeSection`, `PeImport`, `PeImportSymbol`, `PeDiagnostic`, `PeEntryAssessment`, `PeTls`, and `PeTlsCallback`. Unknown machine codes remain explicit strings such as `unknown_0x1234`. The parser follows the DOS/COFF/optional header layouts, ordinary import descriptors, and TLS directories described in the [Microsoft PE format reference](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

## Failure and completeness

Unusable core headers throw `PeFormatError`, whose `code` is `INVALID_PE`. Examples include missing signatures, unsupported optional header magic, truncated fixed headers/section tables, an empty image, overflowing virtual address ranges, and invalid section counts. Supported input is at most 512 MiB with 1–96 sections.

Recoverable structural anomalies remain visible in diagnostics: `HEADER_SIZE_INVALID`, `SECTION_RAW_TRUNCATED`, `SECTION_VIRTUAL_RANGE_INVALID`, `SECTION_VIRTUAL_OVERLAP`, `ENTRY_POINT_NOT_FILE_BACKED`, `DIRECTORY_COUNT_INVALID`, `IMPORT_DIRECTORY_INVALID`, and `TLS_DIRECTORY_INVALID`. A successful function return means the file is inspectable; it does not certify loader validity, runnable code, or equivalent behavior. Consumers validating unpacker output must assess these diagnostics separately.

Every file-byte RVA mapping stays inside SizeOfImage, a unique mapped region, the declared raw section range, and available bytes. A section's virtual-only tail has no file offset. Overlapping regions are ambiguous and cannot be selected by section order. Entry bytes and names stop before another mapped region begins. A zero entry RVA is treated as an absent entry point.

Ordinary imports are transactional: a malformed descriptor, thunk, name, or unterminated table clears the entire import list and sets `imports_complete: false` with `IMPORT_DIRECTORY_INVALID`. This prevents an apparently complete prefix from hiding later damage. The lookup table falls back to FirstThunk when OriginalFirstThunk is zero. Bound IAT addresses that cannot be interpreted as lookup entries are reported incomplete. Reserved name/ordinal bits are checked, and library/symbol names must be printable ASCII and null terminated.

Import walks allow at most 4,096 descriptors and 65,536 total symbols. Each string is bounded to its mapped region and 4,096 bytes; cumulative scanned string bytes are limited to 4 MiB. The declared import-directory size must contain its null descriptor. Missing ordinary imports are a complete empty result. Delay imports, resource contents, signatures, and overlay classification remain outside this API's scope.

**Strings and exports are now in scope.** The inspection reports the printable strings found in the file backed parts of the image (`strings`, with the encoding, the file offset, the RVA and the virtual address of each) and the symbols an image exports (`exports`, with the name, the ordinal, the RVA, the virtual address and any forwarder). A section that hits the per section string limit is named in `strings_truncated_sections` and `strings_complete` becomes false, so a truncated list is never presented as a complete one.

## Entry assessment

The assessment examines a window of at most 64 bytes beginning at the declared entry, bounded by the same unambiguous file mapping as entry bytes. Its `kind` is `absent` for zero entry RVA, `unmapped` when no file-backed mapping exists, or `unclassified` for other bytes. Those states have `basis: 'none'`; absence or an unavailable mapping has `inspected_bytes: 0`. An unclassified entry is not evidence of a correct startup entry.

For PE32 with x86 machine type, a complete observed 27-byte sequence beginning `push imm32; mov eax,fs:[0]; push eax; mov eax,[esp+0x10]; mov [esp+0x10],ebp; lea ebp,[esp+0x10]; sub esp,eax; push ebx` produces `kind: 'x86_seh_prolog_helper_like'`, `basis: 'heuristic'`, and `ENTRY_POINT_SEH_PROLOG_HEURISTIC`. The immediate operand may vary; the remaining bytes must match. Truncated signatures and matching bytes in another architecture do not trigger the diagnostic.

This is an SEH-helper-like byte observation. It does not identify an actual original entry point, prove a helper's calling convention, recover startup state, repair an executable, or establish runnability. The declared entry and input bytes remain unchanged.

## TLS metadata

TLS is directory index 9. A present directory must declare at least 24 bytes for PE32 or 40 bytes for PE32+, and its entire declared range must map to unambiguous available file bytes. The parser retains:

- `directory_rva` and `directory_size`.
- Exact hexadecimal VA strings `start_address_of_raw_data`, `end_address_of_raw_data`, `address_of_index`, and `address_of_callbacks`.
- Numeric `size_of_zero_fill` and `characteristics`.
- `callbacks: PeTlsCallback[]`, each with an exact `va`, numeric `rva`, and `file_offset`.

VA arithmetic uses BigInt before conversion of validated image-relative addresses to numbers. Nonzero raw-template endpoints must be ordered and stay within the image; the end VA is exclusive. A nonempty template must describe one file-backed mapped range. Equal nonzero endpoints describe an empty template: the address may lie anywhere from ImageBase through the exclusive image-end boundary, inclusive, and no file or virtual byte is dereferenced. Addresses outside that closed interval are invalid. Both endpoints may be zero for an absent template.

A nonzero index VA identifies loader-written ULONG storage. Its complete four-byte range must fit within one unambiguous virtual image region, including a section's zero-fill tail or an entirely virtual .bss section. File bytes are unnecessary for that destination. A range crossing a region or image boundary, an unmapped gap, or an overlapping region is rejected, including overlaps beginning after the first index byte. Zero index and callback-array addresses are retained as zero metadata. SizeOfZeroFill is reported without allocating memory. These distinctions follow the initialized template and loader-written index roles in the [Microsoft TLS directory description](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-directory).

A nonzero callback-array VA and every pointer-width array slot must map to file bytes. Every nonzero callback target must map inside the image to at least one unambiguous file-backed byte. There are at most 64 callbacks, followed by a mandatory zero pointer; the walk reads at most 65 slots. Virtual-only targets, out-of-image addresses, ambiguous ranges, truncated slots, and missing terminators are explicit failures. File backing does not certify executable section permissions or callback behavior.

TLS is transactional independently of imports. Any invalid field or callback clears the entire TLS result (`tls: null`, `tls_complete: false`) with `TLS_DIRECTORY_INVALID`; exact offending VAs remain in pointer diagnostics. A valid callback prefix is never exposed as a complete list. Missing TLS is `tls: null`, `tls_complete: true`. A valid directory without callbacks retains its directory metadata and an empty callback list. An invalid data-directory count gives `tls: null`, `tls_complete: false` with `DIRECTORY_COUNT_INVALID`, because absence cannot be established.

These are static metadata completeness guarantees. They do not establish TLS initialization order, callback safety, relocation correctness, or a runnable dumped image.

## Packing evidence

Entropy is Shannon entropy over available raw bytes, or an evenly distributed deterministic sample of at most 1 MiB per section. `entropy_sample_bytes` exposes the actual sample size; truncated raw ranges never add synthetic zeros. Entropy is descriptive and can reflect compression, encryption, or ordinary data.

A section with at least 512 sampled bytes and entropy at least 7.2 contributes an entropy reason. Writable executable sections contribute another reason. `packed_suspected` requires both kinds of evidence. This heuristic neither identifies a protection family nor establishes that an image is unpacked when false. Public VMProtect examples can legitimately report false because virtualization and packing are different observations.

## Verification

Run `node scripts/run-local.mjs test tests/pe.test.ts` and `node scripts/run-local.mjs typecheck` using Node 24 (the repository scripts select the pinned local runtime on Windows).

Synthetic fixtures cover PE32/PE32+, exact large addresses, imports by name/ordinal, byte views and caller mutation, malformed counts/offsets/strings/tables, virtual tails, overlapping ranges, reserved bits, descriptor limits, and conservative packing heuristics. Entry tests distinguish the observed helper signature from benign, absent, unavailable, truncated, and other-architecture entries. TLS tests cover exact PE32/PE32+ directory fields, file-backed callbacks, missing TLS, empty callback arrays, malformed directories and pointers, discarded valid prefixes, out-of-image high VAs, truncated arrays, and 64 callbacks followed by a terminator. Both formats additionally cover empty-template image and section boundaries, out-of-image empty endpoints, loader-written indices in virtual-only and .bss storage, complete four-byte bounds, unmapped gaps, and overlaps beginning at or inside the index word.

Optional real-fixture tests inspect the locally built native fixture and three public protected PEs pinned at `.upstream/vmp-windows/2fb7ad84a90a73c950c39eccbad81cc2f6c25c33/VMProtect 3`; those tests explicitly skip if the optional local corpus is absent. Fixtures are read without execution.
