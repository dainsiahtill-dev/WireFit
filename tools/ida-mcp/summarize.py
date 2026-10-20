"""Summarize retained real probes without promoting partial or failed runs."""
from datetime import datetime, timezone
import json
from pathlib import Path

root = Path(__file__).resolve().parents[2]
runtime = root / "artifacts/ida-mcp/runtime"
records = []
for name in ("fixture-verified", "fixture-x86-verified", "fixture-eof", "fixture-terminate", "external-client", "vmde-dump", "vmde-bounded", "vmde-window", "vmde-grid-window"):
    path = runtime / name / "report.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    status = "completed" if not report.get("error") and report.get("exit_code") == 0 else "failed"
    if report.get("mode") == "terminate" and report.get("worker_exited"):
        status = "forced-cancellation-verified"
    records.append({
        "id": name, "report": str(path), "status": status,
        "mcp_handshake": bool(report.get("initialize", {}).get("result")),
        "identity": report.get("identity"),
        "disassembly_instructions": report.get("disasm", {}).get("instruction_count"),
        "decompilation": bool(report.get("decompile", {}).get("code")),
        "idb_closed": report.get("close", {}).get("idb_closed", False),
        "worker_exited": report.get("worker_exited"), "exit_code": report.get("exit_code"),
        "source_unchanged": report.get("source_unchanged"), "error": report.get("error"),
    })
payload = {
    "checked_at": datetime.now(timezone.utc).isoformat(),
    "revision": "c133c3853faa111a9b00ee615c013b720d0c4acd",
    "probes": records,
    "fixture_sources": ["fixtures/behavior_fixtures.c", "fixtures/fixture_probe.c", "tools/native-kernel/control.cpp"],
    "validation": {"target_execution": "not_run", "runnable_verified": False, "whole_program_equivalence": False, "installed_ida_modified": False},
    "limitations": ["Full vmde research dump startup did not finish within the bounded 180-second protocol deadline. The original Empty() diagnostic is Python queue.Empty from that deadline.", "The two vmde PE windows use declared synthetic loading headers around exact 4096-byte existing dump windows; external calls/references remain incomplete.", "Forced worker cancellation does not assert a gracefully saved database.", "Native analysis is isolated by ownership, not by an operating-system sandbox."],
    "wrapper_tests": {"total": 5, "passed": 4, "skipped": 1, "skip_reason": "Current Windows token cannot create symlinks", "log": str(runtime / "wrapper-tests.log")},
}
(runtime / "runtime-report.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"report": str(runtime / "runtime-report.json"), "probes": len(records)}))
