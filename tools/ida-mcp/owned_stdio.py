"""One owned IDA database over MCP stdio; never discovers GUI sessions.

Run with the pinned isolated Python environment and IDADIR configured. Native
and Python diagnostic output is kept on stderr; stdout carries only MCP JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys
import threading

MAX_INPUT_BYTES = 128 * 1024 * 1024
REVISION = "c133c3853faa111a9b00ee615c013b720d0c4acd"
READ_ONLY_TOOLS = frozenset({
    "server_health", "list_funcs", "func_query", "entity_query", "lookup_funcs",
    "decompile", "disasm", "basic_blocks", "xrefs_to", "callees", "get_bytes",
    "type_query", "type_inspect", "imports", "imports_query", "find_regex",
    "func_profile", "survey_binary",
})


def checked_input(value: str) -> Path:
    candidate = Path(value).absolute()
    details = candidate.lstat()
    if not stat.S_ISREG(details.st_mode) or candidate.is_symlink() or details.st_nlink != 1:
        raise ValueError("Input must be a regular, non-symlink file")
    for component in (candidate, *candidate.parents):
        attributes = getattr(component.lstat(), "st_file_attributes", 0)
        if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError("Input path must not traverse reparse points")
    if details.st_size < 1 or details.st_size > MAX_INPUT_BYTES:
        raise ValueError("Input size must be 1..128 MiB")
    return candidate.resolve(strict=True)


def checked_database(value: str, input_path: Path) -> Path:
    database_path = Path(value).absolute()
    if any(character in str(database_path) for character in ('"', '\r', '\n', '\x00')):
        raise ValueError("Database path contains forbidden argument characters")
    if database_path.suffix.lower() not in {".i64", ".idb"}:
        raise ValueError("Database filename must end with .i64 or .idb")
    if database_path.exists() or database_path.is_symlink():
        raise ValueError("Owned database must not already exist")
    for extension in (".id0", ".id1", ".id2", ".nam", ".til"):
        sidecar = database_path.with_suffix(extension)
        if sidecar.exists() or sidecar.is_symlink():
            raise ValueError("Owned database sidecar must not already exist")
    if not database_path.parent.is_dir() or database_path.parent.is_symlink():
        raise ValueError("Database parent must be an existing non-symlink directory")
    database_path = database_path.parent.resolve(strict=True) / database_path.name
    if database_path == input_path:
        raise ValueError("Database must differ from input")
    if database_path.parent != input_path.parent:
        raise ValueError("Database must be beside this job's staged input")
    return database_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--database", required=True)
    options = parser.parse_args()
    input_path = checked_input(options.input)
    database_path = checked_database(options.database, input_path)
    # Base python avoids the Windows venv redirector process. -I keeps the CWD
    # and PYTHONPATH out; only this administrator-owned package directory enters.
    packages = Path(__file__).resolve().parents[2] / ".tools/ida-mcp/venv/Lib/site-packages"
    if not packages.is_dir():
        raise RuntimeError("Isolated IDA MCP packages have not been installed")
    sys.path.insert(0, str(packages))

    # Save the MCP pipe before redirecting fd 1, including native DLL writes.
    protocol_fd = os.dup(sys.stdout.fileno())
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    protocol_output = os.fdopen(protocol_fd, "wb", buffering=0)
    print("[wirefit-ida] initializing native IDALib", file=sys.stderr, flush=True)
    import idapro  # Must initialize native IDA before any IDAPython import.
    idapro.enable_console_messages(False)
    import idaapi
    import ida_auto
    import ida_kernwin
    import ida_nalt
    import idc
    from ida_pro_mcp.ida_mcp import MCP_SERVER, tool

    closed = False
    opened = False
    analysis_completed = False
    analysis_seconds = int(os.environ.get("IDA_MCP_ANALYSIS_TIMEOUT_SEC", "60"))
    if not 1 <= analysis_seconds <= 120:
        raise ValueError("IDA_MCP_ANALYSIS_TIMEOUT_SEC must be 1..120")

    def close_owned() -> bool:
        nonlocal closed, opened
        if opened and not closed:
            idapro.close_database(save=True)
            closed = True
            opened = False
        return closed

    @tool
    def wirefit_identity() -> dict:
        """Identity of the single database owned by this dedicated process."""
        if closed:
            raise RuntimeError("Owned database has already been closed")
        digest = hashlib.sha256()
        with input_path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return {
            "input_path": ida_nalt.get_input_file_path(),
            "sha256": digest.hexdigest(),
            "idb_path": idc.get_idb_path(),
            "imagebase": hex(idaapi.get_imagebase()),
            "version": idaapi.get_kernel_version(),
            "library_version": list(idapro.get_library_version() or ()),
            "revision": REVISION,
            "owned": True,
            "pid": os.getpid(),
            "analysis_completed": analysis_completed,
            "analysis_timeout_seconds": analysis_seconds,
        }

    @tool
    def ida_close() -> dict:
        """Close only this process-owned database. EOF then exits the process."""
        return {"idb_closed": close_owned(), "owned": True, "pid": os.getpid()}

    allowed = READ_ONLY_TOOLS | {"wirefit_identity", "ida_close"}
    for name in list(MCP_SERVER.tools.methods):
        if name not in allowed:
            del MCP_SERVER.tools.methods[name]
    # Resources are intentionally not exposed; some are unbounded snapshots.
    MCP_SERVER.resources.methods.clear()

    try:
        # -o is the supported IDA output location; all files stay in staging.
        output_argument = '-o"' + str(database_path) + '"'
        print("[wirefit-ida] opening owned database", file=sys.stderr, flush=True)
        if idapro.open_database(str(input_path), False, output_argument) != 0:
            raise RuntimeError("IDA failed to open the staged input")
        opened = True
        print("[wirefit-ida] database opened; waiting for bounded analysis", file=sys.stderr, flush=True)
        actual_database = Path(idc.get_idb_path()).resolve()
        if actual_database != database_path:
            raise RuntimeError(f"IDA database identity mismatch: {actual_database}")
        ida_kernwin.clr_cancelled()
        timer = threading.Timer(analysis_seconds, ida_kernwin.set_cancelled)
        timer.daemon = True
        timer.start()
        try:
            analysis_completed = bool(ida_auto.auto_wait())
        finally:
            timer.cancel()
            ida_kernwin.clr_cancelled()
        print(f"[wirefit-ida] serving MCP; analysis_completed={analysis_completed}", file=sys.stderr, flush=True)
        MCP_SERVER.stdio(stdin=sys.stdin.buffer, stdout=protocol_output)
    finally:
        close_owned()
        protocol_output.close()


if __name__ == "__main__":
    main()
