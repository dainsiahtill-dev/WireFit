# Binary report export

The existing `report export` command and `wirefit_export_report` MCP tool now accept completed, failed and cancelled `inspect_binary` / `unpack_binary` runs. They dispatch to a separate exporter; mathematical experiment validation and model replay remain unchanged.

```powershell
.\wirefit.cmd report export --case .\cases\vmde-unpack-20261019 --run binary_unpack_ac3f5da5bdec428088899e267f17d078 --out .\exports\my-vmde-report
& .\.tools\runtime\node_modules\node-win-x64\bin\node.exe .\exports\my-vmde-report\verify.mjs
```

The output destination must be absent or empty. A populated destination is never replaced; symlink/junction components are rejected. Existing output names must be portable to Windows and cannot collide case-insensitively. The command does not rerun an unpacker, Ghidra or the target.

## Package contents

- `report.md`, the unchanged `result.json`, `request.json` and complete `run.json`.
- `source/input.pe`: the recorded original input bytes; the original path and identity stay in the result.
- `binaries/`: generated PE snapshots and adjacent DLL snapshots. Failed backends can retain partial derivatives; these keep their original quality and status.
- `artifacts/`: recursively referenced case artifacts, including logs and metadata. JSON, `application/x-ndjson` and `application/jsonl` containers are parsed with strict UTF-8. Invalid rows fail export, including a malformed final row after a valid prefix. A final newline is optional. Other media types are copied as opaque bytes.
- `verify.mjs`, `manifest.json` and `manifest.sha256`: standalone verification using Node built-ins only.
- `verification-receipt.json`: the actual fresh-process verification performed during export. This receipt sits outside the manifest it describes and is never trusted as a substitute for a fresh check.

Manifest `report_kind` is `binary`; `models` is empty and `candidate_module` is null. File hashes identify the local snapshot; they are not publisher authentication or a signature. Export follows at most 8,192 artifact references and 100,000 nodes per reference walk. Structured artifacts are at most 16 MiB each; individual files are at most 128 MiB, with at most 10,000 exported files and 512 MiB of file bytes including convenient duplicate binary copies.

## Verification meaning

The helper checks the detached manifest digest, listed byte lengths and SHA-256 values, portable relative paths and symlink/junction components. It can run from a copied directory without the original case or installed Wirefit.

The output separates:

```json
{
  "file_integrity": {"status":"matched","checked":36},
  "original_operation":"unpack_binary",
  "original_status":"completed",
  "recorded_source_unchanged":true,
  "target_execution":"not_run",
  "runnable_verified":false,
  "behavioral_equivalence":"not_established"
}
```

The shown count is the actual current vmde package, not a fixed package size. A failed or cancelled operation retains that status when file integrity matches. `recorded_source_unchanged` is the original operation's observation, not a new read of an external source path. The helper never executes an EXE, invokes external tools, proves function semantics or upgrades an analysis dump.

The initial research directory `exports/vmde-20261020` and its historical receipt remain intact. The product-generated package is `exports/vmde-product-20261020`; a separately copied directory also verified successfully. See [current iteration](CONTINUOUS-IMPROVEMENT-20261020.md) and [original vmde experiment](VMDE-PRACTICE.md).
