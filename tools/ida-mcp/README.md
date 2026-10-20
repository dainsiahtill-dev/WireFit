# WireFit owned IDA MCP runtime

The local administrator configuration is `.local/ida-mcp.json`. WireFit launches
one dedicated stdio process per job and substitutes only its staged `{input}`
and `{database}` paths. The wrapper opens that one copied input. It never uses
IDA discovery, a GUI connection, the upstream supervisor, a debugger, or target
execution. All analysis methods are the pinned upstream implementations.

Installed and tested on this host:

- IDA Professional 9.3, native library version `(9, 3, 251224)`.
- CPython 3.14.2, `idapro==0.0.11`, `ida-pro-mcp==2.0.0`, `tomli-w==1.2.0`.
- Community upstream revision `c133c3853faa111a9b00ee615c013b720d0c4acd` from
  <https://github.com/mrexodia/ida-pro-mcp>.
- Source-owned x64 and 32-bit x86 fixtures both produced real disassembly and
  Hex-Rays pseudocode. The installed `hexx64.dll` supports both tested inputs;
  the absence of a separate x86-named plugin is not a capability test.

Dependencies live in `.tools/ida-mcp/venv/Lib/site-packages`. The configured
executable is the installed base Python with `-I -X utf8`; the wrapper inserts
only that fixed isolated package directory. This avoids the Windows virtual
environment redirector, which spawns a second Python process. Actual MCP
identity probes verify that the owned native PID equals the directly spawned
PID. `IDADIR` is the supported installation selector. No installed IDA files,
license files, or global MCP configuration were changed.

`owned_stdio.py` reserves stdout for newline-delimited MCP JSON. Python and
native diagnostics go to stderr. Its 20 advertised tools comprise the upstream
read-only allowlist plus `wirefit_identity` and `ida_close`. The latter closes
only this process's database, saves the staged IDB, and returns
`{idb_closed:true,owned:true,pid:...}`. Closing stdin also closes the database and
exits. A force-killed process leaves partial files in its own staging directory;
the adapter must retain that distinction instead of claiming a graceful close.

The wrapper validates a regular single-link input up to 128 MiB, rejects
reparse-point paths, pre-existing IDBs and sidecars, and requires the database
beside the staged input. Its native analysis wait requests cancellation after
60 seconds by default (`IDA_MCP_ANALYSIS_TIMEOUT_SEC`, range 1..120). The owning
adapter's overall process timeout also covers native loading and shutdown.
`analysis_completed` and server health retain incomplete analysis explicitly.

The standard external MCP client example is `.local/ida-mcp-client.json`. It
uses `external_stdio.py` with an administrator-selected source-owned fixture,
copies that source to a fresh owned session directory, and serves the same
allowlist. To change its target, edit the local configured `--source` argument.
This fixed configuration never accepts arbitrary Python, tool names, debugger
commands, or shell arguments from a browser.

Real evidence is under `artifacts/ida-mcp/runtime/`:

- `fixture-verified/`: current-wrapper handshake, exact catalog, identity,
  x64 disassembly/pseudocode/CFG/callers/xrefs/bytes/types, close and clean exit.
- `fixture-x86-verified/`: current-wrapper 32-bit x86 decompilation and static
  query evidence (`fixture-x86/` retains the first successful x86 probe).
- `fixture-eof/`, `fixture-terminate/`: graceful EOF and forced exit probes.
- `external-client/`: real standard-client configuration handshake and queries.
- `vmde-dump/`, `vmde-bounded/`: complete 14 MiB research dump did not reach MCP
  initialization within the bounded 180-second probe; workers were killed,
  sources remained unchanged, and failures are retained. These are not full
  dump analysis successes. These earlier probes did not identify precisely
  which native startup/analysis subphase occupied the deadline.
- `vmde-window/`: bounded startup-function dump derivative at `0x42b560`.
- `vmde-grid-window/`: bounded grid dump derivative at `0x498a50`.
- `probe-receipt.json`: verified fixture capabilities, three hashed samples,
  executable/wrapper/configuration/manifest fingerprints.
- `runtime-hashes.json`: bounded fingerprints of installed Python packages,
  IDA bindings, core native libraries, decompiler and current launch artifacts.

The grid sample is
`artifacts/ida-mcp/runtime/vmde-window-00498000-source/vmde-window-00498000.exe`.
Its adjacent `provenance.json` identifies the complete existing dump SHA-256,
file offset, RVA, VA, exact 4096-byte window hash and derived PE hash. Code
bytes and addresses match the existing dump, while PE loading headers are
synthetic. Full-program imports, types and cross-window references are absent.
Its successful static decompilation is not full vmde loading success or proof
of original-target behavior. Never execute this derivative.

Run independent argument validation with:

```powershell
& 'C:/Users/dains/AppData/Local/Python/pythoncore-3.14-64/python.exe' -I -X utf8 'E:/wirefit/tools/ida-mcp/test_owned_stdio.py'
```

Five tests were run; four passed and the symlink-creation test was skipped
because the current Windows token cannot create symlinks. Hardlink and existing
database/sidecar rejection were exercised. `probe.py` is a real JSON-RPC/MCP
stdio harness and records every raw reply. It does not execute the analyzed
binary. `configure.py` regenerates administrator configs and current receipt
fingerprints from those real fixture reports; it does not invent probe results.
