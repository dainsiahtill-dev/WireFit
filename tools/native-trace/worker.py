"""Bounded Frida collection worker. Only a newly spawned staged executable is owned.

The host supplies one UTF-8 JSON request on stdin and an isolated Frida package
directory in argv. All memory output uses exclusive creation in the worker cwd.
No target file is modified, and no existing PID can be supplied by the caller.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import sys
import threading
from typing import Any

FRIDA_VERSION = "17.2.17"
MAX_INPUT_BYTES = 65536
MAX_RANGE_BYTES = 1048576
MAX_TOTAL_BYTES = 4 * MAX_RANGE_BYTES
MAX_PROTOCOL_BYTES = 4 * 1024 * 1024
MAX_EVENT_TOTAL_BYTES = 3 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
HEX_RVA = re.compile(r"0x[0-9a-fA-F]{1,8}\Z")
HEX_POINTER = re.compile(r"0x[0-9a-fA-F]{1,16}\Z")
MODULE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
SYMBOL_NAME = re.compile(r"[A-Za-z0-9_?@$][A-Za-z0-9_?@.$-]{0,255}\Z")


class TraceFailure(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def bounded_message(value: Any) -> str:
    return str(value).replace("\x00", "?")[:2048].encode("utf-8", errors="replace").decode("utf-8")


def require(condition: bool, message: str, code: str = "INVALID_REQUEST") -> None:
    if not condition:
        raise TraceFailure(code, message)


def integer(value: Any, minimum: int, maximum: int, name: str) -> int:
    require(type(value) is int and minimum <= value <= maximum, f"Invalid {name}")
    return value


def object_keys(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == expected, f"Invalid fields in {name}")
    return value


def rva(value: Any) -> str:
    require(isinstance(value, str) and HEX_RVA.fullmatch(value) is not None, "RVA must be a 32-bit hexadecimal string")
    return hex(int(value, 16))


def module_name(value: Any) -> str:
    require(isinstance(value, str) and MODULE_NAME.fullmatch(value) is not None and value not in (".", ".."),
            "Invalid module basename")
    return value


def validate_request(value: Any) -> dict[str, Any]:
    object_keys(value, {"schema_version", "target", "duration_ms", "breakpoints_rva", "ranges", "api_hooks", "max_events"}, "request")
    integer(value["schema_version"], 1, 1, "schema_version")
    integer(value["duration_ms"], 1, 60000, "duration_ms")
    integer(value["max_events"], 1, 512, "max_events")
    target = value["target"]
    require(isinstance(target, str) and 0 < len(target) <= 32767 and "\x00" not in target, "Invalid target path")
    require(Path(target).is_absolute(), "Target must be an absolute staged path")
    require(Path(target).suffix.lower() == ".exe", "Target must be a staged .exe file", "INVALID_TARGET")
    try:
        target_path = Path(target).resolve(strict=True)
        require(target_path.is_file(), "Target must be a regular staged file", "INVALID_TARGET")
    except (OSError, ValueError) as exc:
        raise TraceFailure("INVALID_TARGET", "Staged target does not exist or is not accessible") from exc
    breakpoints = value["breakpoints_rva"]
    require(type(breakpoints) is list and len(breakpoints) <= 4, "At most four breakpoints are supported")
    breakpoints = [rva(address) for address in breakpoints]
    require(len(set(breakpoints)) == len(breakpoints), "Duplicate breakpoint RVA")
    ranges = value["ranges"]
    require(type(ranges) is list and len(ranges) <= 8, "At most eight ranges are supported")
    normalized_ranges = []
    range_keys = set()
    total = 0
    for entry in ranges:
        require(type(entry) is dict and set(entry) in ({"rva", "size_bytes"}, {"rva", "size_bytes", "module"}),
                "Invalid fields in range")
        start = rva(entry["rva"])
        size = integer(entry["size_bytes"], 1, MAX_RANGE_BYTES, "range size")
        require(int(start, 16) + size <= 0x100000000, "Range exceeds 32-bit RVA space")
        total += size
        normalized = {"rva": start, "size_bytes": size}
        if "module" in entry:
            normalized["module"] = module_name(entry["module"])
        key = (normalized.get("module", "").lower(), start, size)
        require(key not in range_keys, "Duplicate requested range")
        range_keys.add(key)
        normalized_ranges.append(normalized)
    require(total <= MAX_TOTAL_BYTES, "Total requested memory exceeds 4 MiB")
    hooks = value["api_hooks"]
    require(type(hooks) is list and len(hooks) <= 16, "At most sixteen API hooks are supported")
    normalized_hooks = []
    for entry in hooks:
        object_keys(entry, {"module", "symbol"}, "API hook")
        module, symbol = entry["module"], entry["symbol"]
        module_name(module)
        require(isinstance(symbol, str) and SYMBOL_NAME.fullmatch(symbol) is not None, "Invalid API symbol name")
        normalized_hooks.append({"module": module, "symbol": symbol})
    require(len({(entry["module"].lower(), entry["symbol"]) for entry in normalized_hooks}) == len(normalized_hooks), "Duplicate API hook")
    return {**value, "target": str(target_path), "breakpoints_rva": breakpoints, "ranges": normalized_ranges, "api_hooks": normalized_hooks}


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TraceFailure("PROTOCOL_ERROR", "Duplicate JSON object key")
        result[key] = value
    return result


def read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    require(len(raw) <= MAX_INPUT_BYTES, "Request exceeds 64 KiB", "PROTOCOL_ERROR")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_object,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("Nonfinite JSON number")))
        # Escaped lone UTF-16 surrogates and exponent overflow also violate the
        # finite UTF-8 protocol, although json.loads accepts them by default.
        json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8", errors="strict")
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise TraceFailure("PROTOCOL_ERROR", "Input must be one valid UTF-8 JSON object") from exc
    require(type(value) is dict, "Input must be a JSON object", "PROTOCOL_ERROR")
    return validate_request(value)


class ProtocolArguments(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise TraceFailure("INVALID_ARGUMENTS", bounded_message(message))


def load_frida(module_path: str) -> Any:
    try:
        directory = Path(module_path).resolve(strict=True)
        require(directory.is_dir(), "Frida module path must be a directory", "FRIDA_UNAVAILABLE")
        spec = importlib.machinery.PathFinder.find_spec("frida", [str(directory)])
        require(spec is not None, "Pinned Frida package is absent from the module directory", "FRIDA_UNAVAILABLE")
        sys.path.insert(0, str(directory))
        module = importlib.import_module("frida")
        require(Path(module.__file__).resolve().is_relative_to(directory), "Frida resolved outside the isolated module directory", "FRIDA_UNAVAILABLE")
        require(module.__version__ == FRIDA_VERSION, f"Frida {FRIDA_VERSION} is required", "FRIDA_VERSION_MISMATCH")
        return module
    except TraceFailure:
        raise
    except Exception as exc:
        raise TraceFailure("FRIDA_UNAVAILABLE", bounded_message(exc)) from exc


def initial_result() -> dict[str, Any]:
    return {"schema_version": 1, "status": "failed", "frida_version": None, "pid": None,
            "events": [], "snapshots": [], "omitted_events": 0, "omitted_events_complete": True,
            "hook_states": {"initial": [], "current": [], "final": []}, "hook_states_complete": False,
            "identities": {"worker": None, "agent": None, "frida": None},
            "cleanup": {"owned_pid_terminated": False, "session_detached": False, "windows_job_assigned": False}, "error": None}


def json_text(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
    require(len(text.encode("utf-8", errors="strict")) <= MAX_PROTOCOL_BYTES,
            "Trace protocol exceeds the four MiB envelope", "RESOURCE_LIMIT")
    return text


class Checkpoint:
    """One coherent, bounded receipt; callers share its lock for state changes.

    Atomic replacement protects the last complete receipt from worker death.
    This covers process interruption, not storage/power failure: fsync on each
    event would add unnecessary target perturbation. At most seven accepted
    events since the last batch and an in-flight capture can remain unrecorded.
    """

    def __init__(self, result: dict[str, Any]):
        self.result = result
        self.lock = threading.RLock()
        self.sequence = 0
        self.terminal = False
        self.path = Path("trace-checkpoint.json")
        self.temporary = Path("trace-checkpoint.tmp.json")
        require(not os.path.lexists(self.path) and not os.path.lexists(self.temporary),
                "Checkpoint files already exist in the evidence directory", "CHECKPOINT_COLLISION")
        self.flush()

    def flush(self, terminal: bool = False) -> None:
        with self.lock:
            if self.terminal:
                return
            row = {**self.result, "is_checkpoint": not terminal, "checkpoint_sequence": self.sequence + 1}
            if not terminal:
                row.update(status="failed", error={"code": "INTERRUPTED", "message": "Worker did not persist a terminal receipt; partial observations only"},
                           omitted_events_complete=False, hook_states_complete=False)
                if self.result["error"] is not None:
                    row["last_error"] = self.result["error"]
            text = json_text(row)
            created = False
            try:
                with self.temporary.open("x", encoding="utf-8", errors="strict", newline="") as output:
                    created = True
                    output.write(text)
                os.replace(self.temporary, self.path)
            except (OSError, UnicodeError) as exc:
                raise TraceFailure("CHECKPOINT_WRITE_FAILED", bounded_message(exc)) from exc
            finally:
                if created and os.path.lexists(self.temporary):
                    # Only an entry at our fixed owned basename is removed.
                    try:
                        self.temporary.unlink()
                    except OSError:
                        pass
            self.sequence += 1
            self.terminal = terminal


def source_copy(source: Path, name: str) -> tuple[str, dict[str, Any]]:
    try:
        with source.open("r", encoding="utf-8", errors="strict", newline="") as input_file:
            text = input_file.read(MAX_SOURCE_BYTES + 1)
        raw = text.encode("utf-8", errors="strict")
        require(0 < len(raw) <= MAX_SOURCE_BYTES, "Source snapshot exceeds one MiB", "RESOURCE_LIMIT")
        with Path(name).open("x", encoding="utf-8", errors="strict", newline="") as output:
            output.write(text)
        return text, {"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}
    except TraceFailure:
        raise
    except (OSError, UnicodeError) as exc:
        raise TraceFailure("SOURCE_SNAPSHOT_FAILED", bounded_message(exc)) from exc


def prepare_sources(result: dict[str, Any], checkpoint: Checkpoint) -> str:
    source = Path(__file__).resolve(strict=True)
    for key, path, name in (("worker", source, "trace-worker.py"), ("agent", source.with_name("agent.js"), "trace-agent.js")):
        text, identity = source_copy(path, name)
        with checkpoint.lock:
            result["identities"][key] = identity
            checkpoint.flush()
        if key == "agent":
            agent = text
    return agent


class WindowsJob:
    """Retain the actual process handle, avoiding PID reuse during cleanup."""

    def __init__(self) -> None:
        require(os.name == "nt", "Native trace execution currently requires Windows", "UNSUPPORTED_PLATFORM")
        from ctypes import wintypes

        class BasicLimit(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

        class IOCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class ExtendedLimit(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimit), ("IoInfo", IOCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            "SetInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
            "TerminateProcess": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
        }
        for name, (argtypes, restype) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = argtypes, restype
        self.handle = self.api.CreateJobObjectW(None, None)
        self.process_handle = None
        self.assigned = False
        require(bool(self.handle), f"CreateJobObjectW failed: {ctypes.get_last_error()}", "WINDOWS_JOB_FAILED")
        limits = ExtendedLimit()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.get_last_error()
            self.api.CloseHandle(self.handle)
            self.handle = None
            raise TraceFailure("WINDOWS_JOB_FAILED", f"SetInformationJobObject failed: {error}")

    def assign(self, pid: int) -> None:
        self.process_handle = self.api.OpenProcess(0x0001 | 0x0100 | 0x100000, False, pid)
        require(bool(self.process_handle), f"OpenProcess for owned PID failed: {ctypes.get_last_error()}", "WINDOWS_JOB_FAILED")
        require(bool(self.api.AssignProcessToJobObject(self.handle, self.process_handle)),
                f"AssignProcessToJobObject failed: {ctypes.get_last_error()}", "WINDOWS_JOB_FAILED")
        self.assigned = True

    def close(self) -> dict[str, Any]:
        closed = True
        if self.handle:
            closed = bool(self.api.CloseHandle(self.handle))
            if closed:
                self.handle = None
        terminated = False
        errors = []
        if self.process_handle:
            wait = self.api.WaitForSingleObject(self.process_handle, 5000 if self.assigned and closed else 0)
            if wait != 0:
                # The retained handle is for our own spawn even if job assignment failed.
                if not self.api.TerminateProcess(self.process_handle, 1):
                    errors.append(f"TerminateProcess failed: {ctypes.get_last_error()}")
                wait = self.api.WaitForSingleObject(self.process_handle, 5000)
            terminated = wait == 0
            if not self.api.CloseHandle(self.process_handle):
                errors.append(f"Process CloseHandle failed: {ctypes.get_last_error()}")
            self.process_handle = None
        if not closed:
            errors.append(f"Job CloseHandle failed: {ctypes.get_last_error()}")
        return {"owned_pid_terminated": terminated, "windows_job_assigned": self.assigned,
                "windows_job_closed": closed, "errors": errors}


class Collector:
    def __init__(self, config: dict[str, Any], result: dict[str, Any], checkpoint: Checkpoint | None = None):
        self.config, self.result = config, result
        self.checkpoint = checkpoint
        self.lock = checkpoint.lock if checkpoint is not None else threading.RLock()
        self.stopped = threading.Event()
        self.failure: TraceFailure | None = None
        self.seen_snapshots: set[tuple[str, int]] = set()
        self.omitted = 0
        self.agent_omitted = 0
        self.omitted_complete = False
        self.event_bytes = 0
        self.pending_events = 0
        self.closed = False

    def persist(self, required: bool = False) -> None:
        with self.lock:
            if self.closed:
                return
            self.result["omitted_events"] = self.omitted + self.agent_omitted
            self.result["omitted_events_complete"] = self.omitted_complete
            if self.checkpoint is not None:
                try:
                    self.checkpoint.flush()
                    self.pending_events = 0
                except TraceFailure as exc:
                    self.fail(exc.code, exc, persist=False)
                    if required:
                        raise self.failure

    def event(self, event: dict[str, Any]) -> None:
        with self.lock:
            if self.closed:
                return
            size = len(json.dumps(event, ensure_ascii=False, allow_nan=False).encode("utf-8", errors="strict"))
            require(size <= 32768, "Agent event exceeds 32 KiB", "AGENT_PROTOCOL_ERROR")
            if len(self.result["events"]) >= self.config["max_events"]:
                self.omitted += 1
            else:
                require(self.event_bytes + size <= MAX_EVENT_TOTAL_BYTES,
                        "Cumulative trace events exceed three MiB", "RESOURCE_LIMIT")
                self.result["events"].append(event)
                self.event_bytes += size
                self.pending_events += 1
                if self.pending_events >= 8:
                    self.persist(required=True)

    def fail(self, code: str, message: Any, persist: bool = True) -> None:
        with self.lock:
            if self.closed:
                return
            if self.failure is None:
                self.failure = TraceFailure(code, bounded_message(message))
                self.result["error"] = {"code": code, "message": bounded_message(message)}
            if persist and self.checkpoint is not None:
                try:
                    self.checkpoint.flush()
                except TraceFailure:
                    # Retain the original failure and previous valid receipt.
                    pass
        self.stopped.set()

    def hook_states(self, states: Any, phase: str) -> None:
        requests = self.config.get("api_hooks", [])
        require(phase in ("initial", "current", "final") and type(states) is list and len(states) == len(requests),
                "Agent did not account for each requested API hook", "AGENT_PROTOCOL_ERROR")
        normalized = []
        for request, state in zip(requests, states):
            require(type(state) is dict and set(state) == {"module", "symbol", "status", "observations", "address", "error"},
                    "Agent returned invalid API hook state fields", "AGENT_PROTOCOL_ERROR")
            require(state["module"] == request["module"] and state["symbol"] == request["symbol"] and
                    state["status"] in ("pending_module", "installed", "error", "unobserved") and
                    type(state["observations"]) is int and 0 <= state["observations"] <= 0x1fffffffffffff,
                    "Agent returned invalid API hook state", "AGENT_PROTOCOL_ERROR")
            require(state["address"] is None or isinstance(state["address"], str) and re.fullmatch(r"0x[0-9a-fA-F]{1,16}", state["address"]) is not None,
                    "Agent returned invalid API hook address", "AGENT_PROTOCOL_ERROR")
            require(state["error"] is None or isinstance(state["error"], str) and 0 < len(state["error"]) <= 2048,
                    "Agent returned invalid API hook error", "AGENT_PROTOCOL_ERROR")
            require(state["status"] != "installed" or state["address"] is not None, "Installed hook has no address", "AGENT_PROTOCOL_ERROR")
            require(state["status"] != "error" or state["error"] is not None, "Failed hook has no error", "AGENT_PROTOCOL_ERROR")
            require(phase != "final" or state["status"] != "pending_module", "Final hook state remains pending", "AGENT_PROTOCOL_ERROR")
            normalized.append(dict(state))
        with self.lock:
            table = self.result.setdefault("hook_states", {"initial": [], "current": [], "final": []})
            table[phase] = normalized
            if phase in ("initial", "final"):
                table["current"] = [dict(state) for state in normalized]
            if phase == "final":
                self.result["hook_states_complete"] = True
            if any(state["status"] == "error" for state in normalized):
                self.fail("API_HOOK_FAILED", "A requested API hook could not be installed")

    def snapshot(self, payload: dict[str, Any], data: bytes | None) -> None:
        phase, index = payload.get("phase"), payload.get("range_index")
        valid_phases = {"initial", "final", *("breakpoint-" + address[2:] for address in self.config["breakpoints_rva"])}
        require(phase in valid_phases and type(index) is int and 0 <= index < len(self.config["ranges"]), "Agent sent invalid snapshot metadata", "AGENT_PROTOCOL_ERROR")
        with self.lock:
            require((phase, index) not in self.seen_snapshots, "Agent duplicated a snapshot", "AGENT_PROTOCOL_ERROR")
            entry = self.config["ranges"][index]
            require(payload.get("rva") == entry["rva"] and payload.get("size_bytes") == entry["size_bytes"], "Agent snapshot differs from requested range", "AGENT_PROTOCOL_ERROR")
            allowed = {"kind", "phase", "range_index", "rva", "size_bytes", "error"}
            if "module" in entry:
                allowed.update(("module", "module_base", "module_size", "address"))
            require(set(payload) <= allowed and payload.get("kind", "snapshot") == "snapshot",
                    "Agent sent unexpected snapshot fields", "AGENT_PROTOCOL_ERROR")
            metadata = {**entry, "phase": phase, **self.scoped_snapshot_metadata(entry, payload)}
            if "error" in payload:
                require(data is None and isinstance(payload["error"], str) and 0 < len(payload["error"]) <= 2048,
                        "Failed snapshot must contain an error without bytes", "AGENT_PROTOCOL_ERROR")
                self.seen_snapshots.add((phase, index))
                self.result["snapshots"].append({**metadata, "error": bounded_message(payload["error"])})
                self.persist(required=True)
                return
            require(isinstance(data, bytes) and len(data) == entry["size_bytes"], "Agent sent invalid snapshot bytes", "AGENT_PROTOCOL_ERROR")
            self.seen_snapshots.add((phase, index))
            name = f"memory-{phase}-{index:02d}.bin"
            try:
                with Path(name).open("xb") as output:
                    output.write(data)
            except OSError as exc:
                self.result["snapshots"].append({**metadata, "error": bounded_message(exc)})
                self.persist(required=True)
                raise TraceFailure("SNAPSHOT_WRITE_FAILED", "Could not exclusively create a memory artifact") from exc
            self.result["snapshots"].append({**metadata, "file": name, "sha256": hashlib.sha256(data).hexdigest()})
            self.persist(required=True)

    def scoped_snapshot_metadata(self, entry: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        if "module" not in entry:
            return {}
        fields = {"module", "module_base", "module_size", "address"}
        require(fields <= set(payload) and isinstance(payload["module"], str) and
                payload["module"].lower() == entry["module"].lower(),
                "Agent snapshot differs from requested module scope", "AGENT_PROTOCOL_ERROR")
        base, size, address = payload["module_base"], payload["module_size"], payload["address"]
        metadata = {"module_base": base, "module_size": size, "address": address}
        if base is None:
            require(size is None and address is None and "error" in payload,
                    "Unresolved module snapshot has inconsistent metadata", "AGENT_PROTOCOL_ERROR")
            return metadata
        require(isinstance(base, str) and HEX_POINTER.fullmatch(base) is not None and int(base, 16) > 0 and
                type(size) is int and 1 <= size <= 0xffffffff and int(base, 16) + size <= 1 << 64,
                "Agent module interval is invalid or overflows 64 bits", "AGENT_PROTOCOL_ERROR")
        if address is None:
            require("error" in payload, "Successful scoped snapshot has no address", "AGENT_PROTOCOL_ERROR")
            return metadata
        start = int(entry["rva"], 16)
        require(isinstance(address, str) and HEX_POINTER.fullmatch(address) is not None and
                int(address, 16) == int(base, 16) + start and start + entry["size_bytes"] <= size and
                int(address, 16) + entry["size_bytes"] <= 1 << 64,
                "Agent scoped snapshot address is outside its module", "AGENT_PROTOCOL_ERROR")
        return metadata

    def missing_final_snapshots(self) -> None:
        with self.lock:
            for index, entry in enumerate(self.config["ranges"]):
                if ("final", index) not in self.seen_snapshots:
                    metadata = {"module_base": None, "module_size": None, "address": None} if "module" in entry else {}
                    self.snapshot({"phase": "final", "range_index": index, **entry, **metadata,
                                   "error": "Target exited before final memory capture"}, None)

    def on_message(self, message: dict[str, Any], data: bytes | None) -> None:
        with self.lock:
            if self.closed or self.failure is not None:
                return
            self._message(message, data)

    def _message(self, message: dict[str, Any], data: bytes | None) -> None:
        try:
            if message.get("type") == "error":
                self.fail("AGENT_ERROR", message.get("description", "Agent script failed"))
                return
            require(message.get("type") == "send" and type(message.get("payload")) is dict, "Unexpected agent message", "AGENT_PROTOCOL_ERROR")
            payload = message["payload"]
            kind = payload.get("kind")
            if kind == "event":
                event = payload.get("event")
                require(type(event) is dict and len(json.dumps(event, ensure_ascii=False).encode("utf-8")) <= 32768, "Invalid agent event", "AGENT_PROTOCOL_ERROR")
                self.event(event)
            elif kind == "snapshot":
                self.snapshot(payload, data)
            elif kind == "fatal":
                self.fail("AGENT_ERROR", payload.get("message", "Instrumentation failed"))
            elif kind == "stats":
                count = payload.get("omitted_events")
                require(type(count) is int and 0 <= count <= 0x7fffffffffffffff, "Invalid omitted event counter", "AGENT_PROTOCOL_ERROR")
                with self.lock:
                    self.agent_omitted = max(self.agent_omitted, count)
                    if "hook_states" in payload:
                        self.hook_states(payload["hook_states"], "current")
            elif kind == "hook_states":
                self.hook_states(payload.get("states"), payload.get("phase"))
                self.persist(required=True)
            else:
                raise TraceFailure("AGENT_PROTOCOL_ERROR", "Unknown agent message kind")
        except TraceFailure as exc:
            self.fail(exc.code, exc)
        except Exception as exc:
            self.fail("AGENT_PROTOCOL_ERROR", exc)

    def on_detached(self, reason: str, crash: Any = None) -> None:
        try:
            self.event({"type": "session_detached", "reason": bounded_message(reason), "crash": bounded_message(crash) if crash else None})
            self.persist()
        except TraceFailure as exc:
            self.fail(exc.code, exc)
        self.stopped.set()


def trace(config: dict[str, Any], frida: Any, result: dict[str, Any], agent: str, checkpoint: Checkpoint) -> None:
    job, session, script, device = None, None, None, None
    collector = Collector(config, result, checkpoint)
    operation = frida.Cancellable()
    deadline = threading.Timer(config["duration_ms"] / 1000 + 20, operation.cancel)
    deadline.daemon = True
    deadline.start()
    try:
        job = WindowsJob()
        with operation:
            device = frida.get_local_device()
            pid = device.spawn([config["target"]], cwd=str(Path(config["target"]).parent), stdio="pipe",
                               env={"__COMPAT_LAYER": "RUNASINVOKER"})
            require(type(pid) is int and pid > 0, "Frida returned an invalid owned PID", "SPAWN_FAILED")
            with collector.lock:
                result["pid"] = pid
            # Assign before checkpoint I/O to keep the suspended spawn's
            # pre-ownership window as short as possible.
            job.assign(pid)
            with collector.lock:
                result["cleanup"]["windows_job_assigned"] = True
                collector.persist(required=True)
            session = device.attach(pid)
            session.on("detached", collector.on_detached)
            # This is the exact decoded UTF-8 source that was hashed and copied
            # before spawn; the live source file is never read again here.
            script = session.create_script(agent, name="wirefit-native-trace", runtime="qjs")
            script.set_log_handler(lambda _level, _text: None)
            script.on("message", collector.on_message)
            script.load()
            agent_config = {key: config[key] for key in ("breakpoints_rva", "ranges", "api_hooks", "max_events")}
            agent_config["max_events"] = max(1, config["max_events"] - 2)
            setup = script.exports_sync.setup(agent_config)
            collector.event({"type": "agent_ready", **setup})
            collector.persist(required=True)
            if collector.failure:
                raise collector.failure
            device.resume(pid)
            collector.stopped.wait(config["duration_ms"] / 1000)
            if collector.failure:
                raise collector.failure
            if not session.is_detached:
                stats = script.exports_sync.finish()
                require(type(stats) is dict and type(stats.get("omitted_events")) is int and stats["omitted_events"] >= 0,
                        "Invalid agent finish statistics", "AGENT_PROTOCOL_ERROR")
                with collector.lock:
                    collector.agent_omitted = max(collector.agent_omitted, stats["omitted_events"])
                    collector.omitted_complete = True
                    collector.hook_states(stats.get("hook_states"), "final")
                    collector.persist(required=True)
            else:
                collector.missing_final_snapshots()
            if collector.failure:
                raise collector.failure
        with collector.lock:
            result["status"] = "completed"
    except (Exception, KeyboardInterrupt) as exc:
        code = exc.code if isinstance(exc, TraceFailure) else "NATIVE_TRACE_FAILED"
        if isinstance(exc, KeyboardInterrupt):
            code = "CANCELLED"
        if operation.is_cancelled:
            code = "TIMEOUT"
        with collector.lock:
            result["error"] = result["error"] or {"code": code, "message": bounded_message(exc)}
            collector.persist()
    finally:
        deadline.cancel()
        if job is not None:
            cleanup = job.close()
            with collector.lock:
                result["cleanup"].update(cleanup)
                collector.persist()
        # A failed OpenProcess can leave no retained handle; kill only our spawn.
        if result["pid"] is not None and not result["cleanup"]["owned_pid_terminated"] and device is not None:
            cleanup_operation = frida.Cancellable()
            cleanup_deadline = threading.Timer(3, cleanup_operation.cancel)
            cleanup_deadline.daemon = True
            cleanup_deadline.start()
            try:
                device.kill(result["pid"], cancellable=cleanup_operation)
                # Without a retained handle, successful kill is the available confirmation.
                with collector.lock:
                    result["cleanup"]["owned_pid_terminated"] = True
            except frida.ProcessNotFoundError:
                with collector.lock:
                    result["cleanup"]["owned_pid_terminated"] = True
            except Exception as exc:
                with collector.lock:
                    result["cleanup"].setdefault("errors", []).append(bounded_message(exc))
            finally:
                cleanup_deadline.cancel()
        if session is not None:
            cleanup_operation = frida.Cancellable()
            cleanup_deadline = threading.Timer(3, cleanup_operation.cancel)
            cleanup_deadline.daemon = True
            cleanup_deadline.start()
            try:
                if not session.is_detached:
                    session.detach(cancellable=cleanup_operation)
                with collector.lock:
                    result["cleanup"]["session_detached"] = bool(session.is_detached)
            except Exception as exc:
                with collector.lock:
                    result["cleanup"].setdefault("errors", []).append(bounded_message(exc))
            finally:
                cleanup_deadline.cancel()
        with collector.lock:
            result["omitted_events"] = collector.omitted + collector.agent_omitted
            result["omitted_events_complete"] = collector.omitted_complete
            if collector.failure is not None and result["error"] is None:
                result["error"] = {"code": collector.failure.code, "message": bounded_message(collector.failure)}
            collector.closed = True
        if result["pid"] is not None and (not result["cleanup"]["owned_pid_terminated"] or
                                           not result["cleanup"].get("windows_job_assigned") or
                                           not result["cleanup"].get("windows_job_closed") or
                                           (session is not None and not result["cleanup"]["session_detached"])):
            result["status"] = "failed"
            result["error"] = result["error"] or {"code": "CLEANUP_FAILED", "message": "Owned process or session cleanup could not be confirmed"}
        if result["error"] is not None:
            result["status"] = "failed"


def main() -> int:
    result = initial_result()
    checkpoint = None
    try:
        parser = ProtocolArguments(add_help=False)
        parser.add_argument("--module-path", required=True)
        args = parser.parse_args()
        config = read_request()
        require(Path(args.module_path).is_absolute(), "Frida module path must be absolute", "INVALID_ARGUMENTS")
        result["hook_states"]["current"] = [{**request, "status": "pending_module", "observations": 0,
                                             "address": None, "error": None} for request in config["api_hooks"]]
        checkpoint = Checkpoint(result)
        agent = prepare_sources(result, checkpoint)
        frida = load_frida(args.module_path)
        result["frida_version"] = frida.__version__
        result["identities"]["frida"] = {"version": frida.__version__, "module_path": str(Path(frida.__file__).resolve(strict=True))}
        checkpoint.flush()
        trace(config, frida, result, agent, checkpoint)
    except (Exception, KeyboardInterrupt) as exc:
        result["error"] = {"code": exc.code if isinstance(exc, TraceFailure) else "WORKER_ERROR", "message": bounded_message(exc)}
    if checkpoint is not None:
        try:
            checkpoint.flush(terminal=True)
        except TraceFailure as exc:
            result["status"] = "failed"
            result["error"] = result["error"] or {"code": exc.code, "message": bounded_message(exc)}
    encoded = json_text(result).encode("utf-8", errors="strict")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
