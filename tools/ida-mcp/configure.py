"""Record installed runtime identity and write local administrator configs."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "artifacts/ida-mcp/runtime"
REVISION = "c133c3853faa111a9b00ee615c013b720d0c4acd"


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    command = Path(sys._base_executable).resolve()
    wrapper = ROOT / "tools/ida-mcp/owned_stdio.py"
    report_path = RUNTIME / "fixture-verified/report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    identity = report["identity"]
    valid = not report.get("error") and report["exit_code"] == 0 and identity["pid"] == report["pid"] and report["source_unchanged"] and report["worker_exited"] and report["close"]["idb_closed"] and report.get("wrapper_sha256") == digest(wrapper) and identity.get("revision") == REVISION
    disassembly = bool(report.get("disasm", {}).get("instruction_count"))
    decompilation = bool(report.get("decompile", {}).get("code"))
    x86_report = json.loads((RUNTIME / "fixture-x86-verified/report.json").read_text(encoding="utf-8"))
    x86_decompilation = bool(x86_report.get("decompile", {}).get("code")) and x86_report.get("source_unchanged") and x86_report.get("worker_exited") and x86_report.get("exit_code") == 0 and x86_report.get("wrapper_sha256") == digest(wrapper)
    packages = ROOT / ".tools/ida-mcp/venv/Lib/site-packages"
    sys.path.insert(0, str(packages))
    from importlib.metadata import version
    receipt = {
        "status": "completed" if valid and disassembly and decompilation else "failed",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "revision": REVISION,
        "command_sha256": digest(command),
        "wrapper_sha256": digest(wrapper),
        "native_initialized": bool(identity.get("library_version")),
        "mcp_handshake": bool(report["initialize"].get("result")),
        "identity_verified": valid and identity["sha256"] == report["source_sha256"],
        "fixture": {"disassembly": disassembly, "decompilation": decompilation, "architecture": "x86_64", "source_sha256": report["source_sha256"], "report": str(report_path)},
        "ida": {"install_dir": "E:/IDA Professional 9.3", "version": identity["version"], "library_version": identity["library_version"]},
        "packages": {name: version(name) for name in ("ida-pro-mcp", "idapro", "tomli-w")},
        "capabilities": {"disassembly": True, "x64_decompilation": decompilation, "x86_decompilation": x86_decompilation, "native_execution": False},
        "x86_fixture_report": str(RUNTIME / "fixture-x86-verified/report.json"),
        "samples": [
            {"id": "owned-x64-fixture", "label": "源代码自有 x64 夹具", "file": report["source"], "sha256": report["source_sha256"], "address": "0x140001000", "scope_kind": "reference_fixture", "description": "WireFit 源代码自有 x64 夹具；已实测反汇编、Hex-Rays 反编译、CFG、交叉引用与字节。"},
            {"id": "owned-x86-fixture", "label": "源代码自有 x86 ABI 夹具", "file": x86_report["source"], "sha256": x86_report["source_sha256"], "address": "0x401000", "scope_kind": "reference_fixture", "description": "WireFit 源代码自有 32 位 x86 夹具；已实测 __thiscall 反编译和反汇编。"},
            {"id": "vmde-grid-derived-window", "label": "vmde grid 静态派生窗口", "file": str(RUNTIME / "vmde-window-00498000-source/vmde-window-00498000.exe"), "sha256": digest(RUNTIME / "vmde-window-00498000-source/vmde-window-00498000.exe"), "address": "0x498a50", "scope_kind": "derived_window", "provenance": {"file": str(RUNTIME / "vmde-window-00498000-source/provenance.json"), "sha256": digest(RUNTIME / "vmde-window-00498000-source/provenance.json")}, "description": "4096 字节 dump 派生 PE：代码字节与 VA 保持原 dump 映射，PE 加载头为合成；这不是完整 vmde，跨窗口引用与调用不完整，仅静态分析。"},
        ],
        "limitations": ["IDA analysis results describe this copied input; they do not prove original-target fidelity, runnable behavior, or whole-program equivalence.", "The native analysis wait uses a cancellation budget; database loading itself is bounded by the owning adapter's process timeout. Health and identity retain whether auto-analysis completed."],
    }
    write(RUNTIME / "probe-receipt.json", receipt)
    config = {
        "schema_version": 1,
        "command": str(command),
        "args": ["-I", "-X", "utf8", str(wrapper), "--input", "{input}", "--database", "{database}"],
        "env": {"IDADIR": "E:/IDA Professional 9.3", "PYTHONUTF8": "1", "IDA_MCP_TOOL_TIMEOUT_SEC": "60", "IDA_MCP_ANALYSIS_TIMEOUT_SEC": "60"},
        "provider": {"version": "9.3.251224", "server": "ida-pro-mcp@2.0.0", "revision": REVISION},
        "lifecycle": "owned-stdio",
        "probe_receipt": str(RUNTIME / "probe-receipt.json"),
    }
    write(ROOT / ".local/ida-mcp.json", config)
    receipt["configuration_sha256"] = digest(ROOT / ".local/ida-mcp.json")
    write(RUNTIME / "probe-receipt.json", receipt)
    external = {"command": config["command"], "args": ["-I", "-X", "utf8", str(ROOT / "tools/ida-mcp/external_stdio.py"), "--source", str(ROOT / "artifacts/native/fixture-build/wirefit-fixture.exe"), "--staging-root", str(ROOT / ".tools/ida-mcp/external-sessions")], "env": config["env"]}
    write(ROOT / ".local/ida-mcp-client.json", {"mcpServers": {"wirefit-ida-owned": external}})
    ida_directory = Path("E:/IDA Professional 9.3")
    files = [command, wrapper, ROOT / "tools/ida-mcp/external_stdio.py", RUNTIME / "upstream-source.zip", ROOT / ".local/ida-mcp.json", RUNTIME / "fixture-verified/tool-catalog.json", report_path, RUNTIME / "fixture-x86-verified/report.json", ida_directory / "idalib.dll", ida_directory / "ida.dll", ida_directory / "plugins/hexx64.dll", command.parent / "python314.dll"]
    for package in ("ida_pro_mcp", "idapro"):
        files.extend(path for path in (packages / package).rglob("*") if path.is_file() and path.suffix in {".py", ".pyc"} and "tests" not in path.parts)
    files.extend(path for path in (ida_directory / "python").glob("*.py") if path.name.startswith("ida") or path.name == "idc.py")
    files.extend((ida_directory / "python/lib-dynload").glob("*.pyd"))
    files.extend(Path(sample["file"]) for sample in receipt["samples"])
    files.extend(Path(sample["provenance"]["file"]) for sample in receipt["samples"] if sample.get("provenance"))
    files = sorted(set(files), key=str)
    if len(files) > 256 or sum(path.stat().st_size for path in files) > 512 * 1024 * 1024:
        raise RuntimeError("Runtime fingerprint exceeds the adapter's bounded manifest budget")
    manifest = {"revision": REVISION, "sha256": {str(path): digest(path) for path in files}}
    write(RUNTIME / "runtime-hashes.json", manifest)
    receipt["runtime_manifest"] = str(RUNTIME / "runtime-hashes.json")
    receipt["runtime_manifest_sha256"] = digest(RUNTIME / "runtime-hashes.json")
    write(RUNTIME / "probe-receipt.json", receipt)
    print(json.dumps({"config": str(ROOT / ".local/ida-mcp.json"), "receipt_status": receipt["status"]}))


if __name__ == "__main__":
    main()
