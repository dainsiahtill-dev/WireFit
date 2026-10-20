# Experimental compatibility CRT entry

This builder creates a new immutable analysis-image copy with a compatibility
CRT entry. It does **not** restore the original protected prefix, identify an
OEP, execute the PE, or establish that the candidate runs. A completed build
only means the bounded byte/file transaction finished and its inputs stayed
unchanged. `original_prefix_restored`, `oep_identified` and `runnable_verified`
remain false in all receipts.

```powershell
node --test tools/startup-rebuild/test.mjs
node tools/startup-rebuild/build.mjs `
  --input E:/wirefit/exports/vmde-20261020/unpacked_vmde.exe `
  --out E:/wirefit/artifacts/research/vmde/startup-compat/NEW-CANDIDATE
```

Paths must be absolute local paths with ordinary, unaliased ancestors. The
output directory must not exist. The CLI accepts exactly the two named options.
It never reads or writes the original protected vmde executable as a build
source. The only accepted input is the 14,454,272-byte analysis dump with SHA256
`50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992`.

`patch.mjs` exports pure `patchCompatibilityStartup(Uint8Array)`, returning a
new byte array, the two exact patch records, import-slot resolution and explicit
assumptions. It also exports the bounded `parseImportSlots` and fixed-symbol
`resolveGetModuleHandleSlot` parser for reuse with synthetic or raw PE data.
Parsing and patching never load a module or invoke an imported function.

The source is PE32 / I386, preferred base `0x400000`, with `DYNAMIC_BASE` clear,
`RELOCS_STRIPPED` set and a zero relocation directory. The builder checks these
conditions and changes none of them. It reuses `dist/src/pe.js` for inspection,
then maps full byte ranges uniquely through raw headers/sections. The public
parser rejects inputs below 64 bytes or above 64 MiB before making its owned
copy; the fixed patch entry checks its exact source size before copying. It rejects
overlapping virtual or raw sections, invalid bounds, ambiguous named imports,
unbounded descriptors/thunks/strings and non-printable ASCII. Budgets are 1,024
descriptors, 8,192 symbols, 512 bytes per name and 1 MiB total name bytes.

The unique case-insensitive `kernel32.dll` / case-sensitive `GetModuleHandleA`
name determines the loader IAT slot from its descriptor's `FirstThunk` and
lookup index. `OriginalFirstThunk` supplies names where present; FT is accepted
as a name table only for an unbound descriptor with OFT zero. Ordinals cannot
impersonate the named API. A separate OFT's null entry bounds its corresponding
FT span; the parser does not read a retained address or require an invented
zero DWORD after that FT span. The fixed dump's first descriptor has nonzero
data there. The distinction between lookup entries and loader-written IAT
contents follows the [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-lookup-table).

Only these regions may change, totaling 54 permitted bytes:

- The four-byte AddressOfEntryPoint becomes RVA `0xb0f64`.
- VA `0x4b0f64..0x4b0f95` becomes a 41-byte stub followed by nine `0xcc` bytes.

The stub performs `CLD`; pushes local allocation `0x74` and table `0x8e02b8`;
calls helper `0x4b12bc`; zeros EBX and `[EBP-0x20]`; loads EDI from the new
image's unique IAT slot; invokes `GetModuleHandleA(NULL)`; derives the NT header
pointer in ECX and OptionalHeader magic in EAX; then jumps to `0x4b0f96`.
Both relative targets are checked by fixed-byte tests. No captured heap thunk,
system API VA or arbitrary payload is accepted.

Header bytes, the old 50-byte prefix, the following 464-byte CRT body, the
59-byte frame helper and 32-byte scope table have separate exact hashes and
unique mappings. Table DWORDs begin `-1, 0x4b112a, 0x4b113e`. All bytes outside
the two permitted ranges, including recovered label and grid routines, remain
identical to the source. The quote-state local is explicitly zero. `CLD` is
active compatibility initialization; it was not observed in the unrecovered
original prefix.

The fixed `startup-context/api-frame-review.json` SHA256
`2926b9795e54ae17bbdffa80d6a81b7d50fe59a10f99bef8ad02217a9edcefdf`
records two same-frame API observations. Deriving allocation `0x74` from
`(EBP - savedSP) - 0x1c` depends on this exact helper and an unchanged saved-SP
field. The protected prefix may have other initialization effects; this
experiment does not replace that unknown with a claim of equivalence.

The existing strict file-backed TLS diagnostic is retained. A TLS raw-template
virtual zero-fill mapping can be legal, so this diagnostic alone is not an OS
loader-failure prediction. The builder makes no TLS, import-directory,
relocation, dependency or unrelated instruction repairs. The root operator
will perform any separately owned, bounded candidate execution.

`build.mjs` reuses the previously reviewed ordinary-file/UTF-8 helpers. All
fixed byte/import/source/output checks finish before creating the new output
directory. `candidate.exe` and `receipt.json` use exclusive creation. Inputs,
the pinned frame review and source dependencies are stable-read and hashed
before and after the build. Failures retain the first error, any created file
and available partial-file identity; no overwrite or rollback deletion occurs.
Stdout is one UTF-8 JSON receipt and exit status is nonzero on failure. If the
receipt itself cannot be written, stdout retains the failure and file facts.
