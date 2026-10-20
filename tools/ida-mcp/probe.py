"""Run bounded real MCP probes without ever executing the analyzed input."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import time


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def content(reply: dict):
    value = reply.get("result", {})
    if "structuredContent" in value:
        return value["structuredContent"]
    for entry in value.get("content", []):
        if entry.get("type") == "text":
            try:
                return json.loads(entry["text"])
            except (ValueError, KeyError):
                pass
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--address")
    parser.add_argument("--mode", choices=["complete", "eof", "terminate"], default="complete")
    parser.add_argument("--client-config", help="Optional standard external MCP client config to exercise")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = Path(args.out).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = Path(args.source).resolve(strict=True)
    staged = output / source.name
    shutil.copyfile(source, staged)
    database = output / "analysis.i64"
    environment = dict(os.environ, IDADIR="E:/IDA Professional 9.3", PYTHONUTF8="1", IDA_MCP_TOOL_TIMEOUT_SEC="60")
    command = [str(Path(sys._base_executable)), "-I", "-X", "utf8", str(root / "tools/ida-mcp/owned_stdio.py"), "--input", str(staged), "--database", str(database)]
    if args.client_config:
        client = json.loads(Path(args.client_config).read_text(encoding="utf-8"))["mcpServers"]["wirefit-ida-owned"]
        command = [client["command"], *client["args"]]
        environment.update(client.get("env", {}))
    report = {"source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "command": command, "mode": args.mode, "wrapper_sha256": hashlib.sha256((root / "tools/ida-mcp/owned_stdio.py").read_bytes()).hexdigest()}
    messages: queue.Queue = queue.Queue()
    with (output / "stderr.log").open("wb") as error_log:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_log, env=environment, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        report["pid"] = process.pid

        def read_output():
            try:
                while True:
                    line = process.stdout.readline(4 * 1024 * 1024 + 1)
                    if not line:
                        messages.put(RuntimeError("MCP stdout reached EOF"))
                        return
                    if len(line) > 4 * 1024 * 1024:
                        raise ValueError("MCP response exceeds 4 MiB")
                    messages.put(json.loads(line.decode("utf-8")))
            except Exception as error:
                messages.put(error)

        threading.Thread(target=read_output, daemon=True).start()
        request_id = 0

        def send(method, params=None, notification=False):
            nonlocal request_id
            request_id += 1
            packet = {"jsonrpc": "2.0", "method": method}
            if not notification:
                packet["id"] = request_id
            if params is not None:
                packet["params"] = params
            process.stdin.write((json.dumps(packet) + "\n").encode("utf-8"))
            process.stdin.flush()
            if notification:
                return None
            started = time.monotonic()
            while True:
                received = messages.get(timeout=max(.1, 180 - (time.monotonic() - started)))
                if isinstance(received, Exception):
                    raise received
                if received.get("id") == request_id:
                    write_json(output / f"{request_id:02d}-{method.replace('/', '-')}.json", {"request": packet, "response": received})
                    return received

        def call(name, arguments):
            return send("tools/call", {"name": name, "arguments": arguments})

        try:
            report["initialize"] = send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "wirefit-runtime-probe", "version": "1.0.0"}})
            send("notifications/initialized", notification=True)
            catalog = send("tools/list", {})
            write_json(output / "tool-catalog.json", catalog)
            report["identity"] = content(call("wirefit_identity", {}))
            if args.client_config:
                database = Path(report["identity"]["idb_path"])
            if args.mode == "complete":
                report["health"] = content(call("server_health", {}))
                report["survey"] = content(call("survey_binary", {"detail_level": "minimal"}))
                functions = content(call("list_funcs", {"queries": {"offset": 0, "count": 8, "filter": ""}}))
                report["functions"] = functions
                report["strings"] = content(call("entity_query", {"queries": {"kind": "strings", "offset": 0, "count": 8}}))
                report["types"] = content(call("type_query", {"queries": {"offset": 0, "count": 8}}))
                address = args.address
                if not address:
                    pages = functions.get("result", functions) if isinstance(functions, dict) else functions
                    address = pages[0]["data"][0]["addr"]
                report["address"] = address
                for name, arguments in [
                    ("disasm", {"addr": address, "max_instructions": 100, "offset": 0, "include_total": True}),
                    ("decompile", {"addr": address, "max_lines": 100, "offset": 0}),
                    ("basic_blocks", {"addrs": [address], "max_blocks": 100}),
                    ("xrefs_to", {"addrs": [address], "limit": 100}),
                    ("callees", {"addrs": [address], "limit": 100}),
                    ("func_profile", {"queries": {"addr": address, "count": 1, "include_lists": True, "max_items": 100}}),
                    ("get_bytes", {"regions": [{"addr": address, "size": 32}]}),
                ]:
                    report[name] = content(call(name, arguments))
                report["close"] = content(call("ida_close", {}))
            elif args.mode == "terminate":
                process.terminate()
            if not process.stdin.closed:
                process.stdin.close()
            report["exit_code"] = process.wait(timeout=20)
        except Exception as error:
            report["error"] = "MCP startup/tool response exceeded bounded 180-second deadline" if isinstance(error, queue.Empty) else repr(error)
            process.kill()
            report["exit_code"] = process.wait(timeout=10)
        finally:
            report["source_unchanged"] = hashlib.sha256(source.read_bytes()).hexdigest() == report["source_sha256"]
            report["worker_exited"] = process.poll() is not None
            report["database_exists"] = database.is_file()
            write_json(output / "report.json", report)
    print(json.dumps({"report": str(output / "report.json"), "error": report.get("error"), "exit_code": report.get("exit_code")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
