#!/usr/bin/env python3
"""Observe bounded remote PE exports of a host-validated owned CLI process.

Only read/query HANDLEs are used. No process is spawned, debug-attached, resumed,
suspended, modified or terminated. The owner remains responsible for its Job.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from types import ModuleType, SimpleNamespace
from typing import Any

MEMORY_SHA = "e2f062a4b2d72bc67de793a9afe6068336f5bd99ccf1b9d51b647320e719ec38"
REGIONS_SHA = "d55539bf335b55b848b53e4449f25f53c7443e0ff18cffaa5cc375ed0535e111"
MODEL_SHA = "f3d0e19585530335f6d77f92ba099262151719eedc1d56417864847fdf9e590a"
MAX_INDEX = 4 * 1024 * 1024
MAX_SAMPLE = 4 * 1024 * 1024
MAX_OUTPUT = 32 * 1024 * 1024
MAX_MODULES = 256
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
IDENTITY_ERRORS = {"PROCESS_IDENTITY_MISMATCH", "PROCESS_IDENTITY_FAILED", "CLOSED_HANDLE"}
STOP_ERRORS = IDENTITY_ERRORS | {"PROCESS_EXITED", "TIMEOUT"}
RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)
REQUEST_KEYS = {"schema_version", "pid", "expected_executable", "expected_creation_filetime",
                "source_sha256", "expected_module_file", "module_sha256", "symbols",
                "sample_offsets_ms", "timeout_ms"}


class ObserverError(Exception):
    def __init__(self, code: str, message: str, *, winerror: int | None = None):
        super().__init__(message)
        self.code, self.winerror = code, winerror


class StrictParser(argparse.ArgumentParser):
    def error(self, message):
        fail("INVALID_ARGUMENTS", message)


def fail(code: str, message: str) -> None:
    raise ObserverError(code, message)


def utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def error_row(error: BaseException, fallback: str = "OBSERVATION_FAILED") -> dict:
    row = {"code": getattr(error, "code", fallback), "message": str(error)[:2048]}
    winerror = getattr(error, "winerror", None)
    if type(winerror) is int:
        row["winerror"] = winerror
    return row


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_path(text: Any) -> Path:
    if not isinstance(text, str) or not text or len(text) > 32767 or "\0" in text or not os.path.isabs(text):
        fail("INVALID_PATH", "An absolute ordinary filesystem path is required")
    drive, tail = os.path.splitdrive(text)
    if os.name == "nt" and (len(drive) != 2 or drive[1] != ":" or ":" in tail):
        fail("INVALID_PATH", "Only local drive paths without alternate streams are accepted")
    if os.name != "nt" and ":" in text:
        fail("INVALID_PATH", "Alternate stream syntax is not accepted")
    for part in re.split(r"[\\/]", tail):
        if part in (".", "..") or (part and part[-1] in ". ") or RESERVED.match(part):
            fail("INVALID_PATH", "Ambiguous/reserved path component")
    return Path(os.path.abspath(text))


def check_ordinary_path(path: Path, *, must_exist: bool) -> Path:
    path = strict_path(str(path))
    for current in reversed((path, *path.parents)):
        try:
            info = current.lstat()
        except FileNotFoundError:
            if current == path and not must_exist:
                continue
            fail("INVALID_PATH", "Missing path ancestor")
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            fail("PATH_ALIAS", "Symlinks and reparse points are not accepted")
    if os.path.normcase(str(path.resolve(strict=must_exist))) != os.path.normcase(str(path)):
        fail("PATH_ALIAS", "The path is not canonical")
    return path


def stable_bytes(path: Path, expected_sha: str | None, maximum: int) -> bytes:
    path = check_ordinary_path(path, must_exist=True)
    before = path.stat()
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= maximum:
        fail("INVALID_SOURCE", "Source must be bounded, ordinary and single-link")
    with path.open("rb") as file:
        opened = os.fstat(file.fileno())
        if key(before)[:3] != key(opened)[:3] or opened.st_nlink != 1:
            fail("SOURCE_CHANGED", "Source path and HANDLE disagree")
        data = file.read(maximum + 1)
        if len(data) != before.st_size or key(opened) != key(os.fstat(file.fileno())):
            fail("SOURCE_CHANGED", "Source changed during retained HANDLE read")
    if key(before) != key(path.stat()):
        fail("SOURCE_CHANGED", "Source metadata changed")
    check_ordinary_path(path, must_exist=True)
    if expected_sha is not None and digest(data) != expected_sha:
        fail("SOURCE_IDENTITY_MISMATCH", "Source SHA-256 differs")
    return data


def compile_pinned(data: bytes, expected_sha: str, path: Path, name: str) -> ModuleType:
    if digest(data) != expected_sha:
        fail("TOOL_IDENTITY_MISMATCH", "Reviewed helper source SHA-256 differs before compile")
    module = ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(data.decode("utf-8", errors="strict"), str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load_frozen_support():
    native = Path(__file__).absolute().parent.parent / "native-trace"
    identities, modules = [], []
    for name, pin in (("memory-image.py", MEMORY_SHA), ("private-regions.py", REGIONS_SHA)):
        file = native / name
        data = stable_bytes(file, pin, 1024 * 1024)
        modules.append(compile_pinned(data, pin, file, "_runtime_export_" + name.replace("-", "_").replace(".", "_")))
        identities.append({"file": str(file), "size_bytes": len(data), "sha256": pin})
    return modules[0], modules[1], identities


def decode_request(data: bytes) -> dict:
    if not isinstance(data, bytes) or not 1 <= len(data) <= 65536:
        fail("INVALID_REQUEST", "Request must be at most 64 KiB")
    def pairs(values):
        output = {}
        for key, value in values:
            if key in output: fail("INVALID_REQUEST", "Duplicate JSON key")
            output[key] = value
        return output
    def constant(_): fail("INVALID_REQUEST", "Non-finite JSON numbers are not accepted")
    try:
        parsed = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=constant)
    except ObserverError:
        raise
    except (ValueError, UnicodeError) as error:
        raise ObserverError("INVALID_REQUEST", str(error)) from error
    return validate_request(parsed)


def validate_request(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != REQUEST_KEYS:
        fail("INVALID_REQUEST", "Request fields do not match the exact contract")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or type(value["pid"]) is not int or not 1 <= value["pid"] <= 0xffffffff:
        fail("INVALID_REQUEST", "Schema version/PID is invalid")
    token = value["expected_creation_filetime"]
    if not isinstance(token, str) or not re.fullmatch(r"[0-9]{1,20}", token, flags=re.ASCII) or not 0 < int(token) < 2**64 or str(int(token)) != token:
        fail("INVALID_REQUEST", "Creation FILETIME must be an exact positive decimal string")
    for field in ("source_sha256", "module_sha256"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{64}", value[field], flags=re.ASCII):
            fail("INVALID_REQUEST", "Source/module SHA-256 is invalid")
    for field in ("expected_executable", "expected_module_file"):
        strict_path(value[field])
    module_name = Path(value["expected_module_file"]).name
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,124}\.dll", module_name, flags=re.I | re.ASCII):
        fail("INVALID_REQUEST", "Expected module must have an ASCII DLL basename")
    symbols = value["symbols"]
    if not isinstance(symbols, list) or not 1 <= len(symbols) <= 8 or any(not isinstance(s, str) or not re.fullmatch(r"[!-~]{1,256}", s, flags=re.ASCII) for s in symbols) or len(set(symbols)) != len(symbols):
        fail("INVALID_REQUEST", "One through eight unique exact ASCII symbols are required")
    timeout, offsets = value["timeout_ms"], value["sample_offsets_ms"]
    if type(timeout) is not int or not 1 <= timeout <= 10000 or not isinstance(offsets, list) or not 1 <= len(offsets) <= 8:
        fail("INVALID_REQUEST", "Sampling deadline/count is invalid")
    if any(type(x) is not int or not 0 <= x <= 8000 or x >= timeout for x in offsets) or offsets[0] != 0 or offsets != sorted(set(offsets)):
        fail("INVALID_REQUEST", "Offsets must begin at zero and strictly increase before the deadline")
    return dict(value)


# Exact TlHelp32.h field order; native ctypes alignment, no manual target padding.
class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.POINTER(wintypes.BYTE)),
                ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
                ("szModule", wintypes.WCHAR * 256), ("szExePath", wintypes.WCHAR * 260)]


class Toolhelp:
    def __init__(self):
        if os.name != "nt":
            fail("UNSUPPORTED_PLATFORM", "Windows Toolhelp is required")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        k = self.kernel
        k.CreateToolhelp32Snapshot.argtypes, k.CreateToolhelp32Snapshot.restype = [wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE
        for name in ("Module32FirstW", "Module32NextW"):
            function = getattr(k, name)
            function.argtypes, function.restype = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)], wintypes.BOOL
        k.CloseHandle.argtypes, k.CloseHandle.restype = [wintypes.HANDLE], wintypes.BOOL

    def snapshot(self, pid):
        ctypes.set_last_error(0)
        handle = self.kernel.CreateToolhelp32Snapshot(0x08 | 0x10, pid)
        if not handle or handle == ctypes.c_void_p(-1).value:
            raise ObserverError("MODULE_SNAPSHOT_FAILED", "CreateToolhelp32Snapshot failed", winerror=ctypes.get_last_error())
        return handle

    def _entry(self, handle, first):
        value = MODULEENTRY32W()
        value.dwSize = ctypes.sizeof(value)
        ctypes.set_last_error(0)
        okay = (self.kernel.Module32FirstW if first else self.kernel.Module32NextW)(handle, ctypes.byref(value))
        if not okay:
            error = ctypes.get_last_error()
            if error == 18: return None
            raise ObserverError("MODULE_ENUM_FAILED", "Module32First/Next failed", winerror=error)
        if value.dwSize != ctypes.sizeof(value) or not value.szModule or not value.szExePath or len(value.szModule) >= 255 or len(value.szExePath) >= 259:
            fail("MODULE_ENUM_INVALID", "Module entry is truncated or structurally invalid")
        return {"pid": int(value.th32ProcessID), "name": value.szModule, "path": value.szExePath,
                "base": int(ctypes.cast(value.modBaseAddr, ctypes.c_void_p).value or 0),
                "size_bytes": int(value.modBaseSize)}

    def first(self, handle): return self._entry(handle, True)
    def next(self, handle): return self._entry(handle, False)

    def close(self, handle):
        if not self.kernel.CloseHandle(handle):
            raise ObserverError("SNAPSHOT_CLOSE_FAILED", "Snapshot CloseHandle failed", winerror=ctypes.get_last_error())


def snapshot_modules(api, pid, deadline, *, clock=time.monotonic, sleep=time.sleep):
    output = {"complete": False, "rows": [], "attempts": [], "snapshot_handle_closed": True, "error": None}
    handle = None
    try:
        for attempt in range(3):
            if clock() >= deadline: fail("TIMEOUT", "Observer deadline reached during Toolhelp")
            try:
                handle = api.snapshot(pid)
                output["snapshot_handle_closed"] = False
                output["attempts"].append({"attempt": attempt + 1, "success": True})
                break
            except Exception as error:
                output["attempts"].append({"attempt": attempt + 1, "success": False, "error": error_row(error)})
                if getattr(error, "winerror", None) != 24 or attempt == 2:
                    raise
                sleep(min(.010, max(0, deadline-clock())))
        current = api.first(handle)
        while current is not None:
            if clock() >= deadline: fail("TIMEOUT", "Observer deadline reached during module enumeration")
            if len(output["rows"]) >= MAX_MODULES:
                fail("MODULE_ENUM_TRUNCATED", "Module inventory exceeded 256 entries")
            if (not isinstance(current, dict) or set(current) != {"pid", "name", "path", "base", "size_bytes"}
                or type(current["pid"]) is not int or current["pid"] != pid
                or not isinstance(current["name"], str) or not 1 <= len(current["name"]) < 256
                or not isinstance(current["path"], str) or not 1 <= len(current["path"]) < 260
                or type(current["base"]) is not int or type(current["size_bytes"]) is not int
                or not 0 < current["base"] < 2**64 or not 0 < current["size_bytes"] <= 0xffffffff
                or current["base"]+current["size_bytes"] > 2**64):
                fail("MODULE_ENUM_INVALID", "Module entry is malformed or belongs to another PID")
            output["rows"].append(current)
            current = api.next(handle)
        output["complete"] = True
    except Exception as error:
        output["error"] = error_row(error)
    finally:
        if handle is not None:
            try:
                api.close(handle); output["snapshot_handle_closed"] = True
            except Exception as error:
                output["error"] = output["error"] or error_row(error)
                output["close_error"] = error_row(error)
                output["complete"] = False
    return output


def resolve_module(inventory, expected_path, pid):
    if inventory.get("complete") is not True:
        native = inventory.get("error")
        if isinstance(native, dict):
            raise ObserverError(native["code"], native["message"], winerror=native.get("winerror"))
        fail("MODULE_INVENTORY_INCOMPLETE", "Cannot prove module presence/absence from an incomplete inventory")
    expected_path = strict_path(str(expected_path))
    matches = [row for row in inventory["rows"] if isinstance(row, dict) and isinstance(row.get("name"), str) and row["name"].lower() == expected_path.name.lower()]
    if not matches:
        return {"status": "not_loaded", "name": expected_path.name, "base": None, "size_bytes": None, "path": None}
    if len(matches) != 1: fail("MODULE_AMBIGUOUS", "Expected DLL basename is not unique")
    row = matches[0]
    observed_path = strict_path(row.get("path"))
    base, size = row.get("base"), row.get("size_bytes")
    if row.get("pid") != pid or os.path.normcase(str(observed_path)) != os.path.normcase(str(expected_path)):
        fail("MODULE_IDENTITY_MISMATCH", "Module entry PID/path differs from expected fixed DLL")
    if type(base) is not int or type(size) is not int or not 0 < base < 2**32 or not 0 < size <= 64*1024*1024 or base % 4096 or size % 4096 or base+size > 2**32:
        fail("MODULE_RANGE_INVALID", "Module interval is not a bounded aligned PE32 image")
    return {**row, "status": "unique"}


class BoundReader:
    """All model reads/queries use the one retained, repeatedly verified HANDLE."""
    def __init__(self, reader, memory, regions, request, module, *, clock=time.monotonic, deadline):
        self.reader, self.memory, self.regions = reader, memory, regions
        self.request, self.module, self.clock, self.deadline = request, module, clock, deadline
        self.config = SimpleNamespace(pid=request["pid"], expected_exe=Path(request["expected_executable"]),
                                      expected_start_filetime=int(request["expected_creation_filetime"]))
        self.reads, self.policy_queries, self.target_queries = [], [], []
        self.fatal = None

    def check(self):
        if self.fatal:
            raise ObserverError(self.fatal["code"], self.fatal["message"])
        try:
            if self.clock() >= self.deadline: fail("TIMEOUT", "Observer cooperative deadline reached")
            value = self.reader.identity()
            self.memory.validate_identity(value, self.config, require_alive=True)
            return value
        except Exception as error:
            self.fatal = error_row(error)
            raise

    def _address(self, rva, length):
        size, base = self.module["size_bytes"], self.module["base"]
        if type(rva) is not int or type(length) is not int or not 0 <= rva < size or not 0 < length <= 4096 or rva+length > size or base+rva+length > 2**32:
            fail("INVALID_READ_RANGE", "Read exceeds this single PE32 module/page")
        return base+rva

    def _query(self, address, records):
        self.check()
        row = {"address": hex(address), "observed_utc": utc()}
        records.append(row)
        try:
            result = self.regions.validate_region(self.reader.query(address), address, 32)
            row["region"] = result
            return result
        except Exception as error:
            row["error"] = error_row(error)
            if getattr(error, "code", None) in IDENTITY_ERRORS:
                self.fatal = error_row(error)
            raise

    def query_va(self, address):
        if type(address) is not int or not self.module["base"] <= address < self.module["base"]+self.module["size_bytes"]:
            fail("INVALID_QUERY_RANGE", "Query exceeds this module")
        return self._query(address, self.target_queries)

    def read_rva(self, rva, length):
        address = self._address(rva, length)
        log = {"rva": hex(rva), "address": hex(address), "requested_bytes": length,
               "read_attempted": False, "read_not_attempted": True, "winerror": None}
        self.reads.append(log)
        try:
            region = self._query(address, self.policy_queries)
            if (region["state"] != 0x1000 or region["type"] != 0x1000000
                or region["allocation_base"] != self.module["base"] or region["protect"] & 0x100
                or region["protect"] & 0xff not in READABLE
                or address+length > region["base_address"]+region["region_size"]):
                fail("POLICY_READ_BLOCKED", "RPM not attempted: expected committed readable non-guard MEM_IMAGE region covering the whole request")
            self.check()
            log["read_attempted"], log["read_not_attempted"] = True, False
            result = self.memory.validated_read(self.reader, address, length)
            log.update(success=result["success"], winerror=result["winerror"],
                       transferred_bytes=result["transferred_bytes"], hex=result["data"].hex(),
                       sha256=digest(result["data"]) if result["data"] else None)
            return result
        except Exception as error:
            log["error"] = error_row(error)
            if getattr(error, "code", None) in STOP_ERRORS:
                self.fatal = self.fatal or error_row(error)
            raise


class Publisher:
    def __init__(self, out: Path):
        self.out = check_ordinary_path(out, must_exist=False)
        if self.out.exists(): fail("OUTPUT_EXISTS", "Output directory must be new")
        if not self.out.parent.is_dir(): fail("INVALID_PATH", "Output parent must be an ordinary directory")
        self.out.mkdir()
        self.total = 0
        self.files = {}

    def data(self, value, maximum):
        data = (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))+"\n").encode("utf-8", errors="strict")
        if len(data) > maximum: fail("OUTPUT_BUDGET", "JSON output exceeds its explicit byte bound")
        return data

    def write(self, name, value, *, atomic=False, maximum=MAX_INDEX):
        if not re.fullmatch(r"[a-z0-9-]+\.json", name): fail("INVALID_OUTPUT", "Output basename is not fixed-safe")
        check_ordinary_path(self.out, must_exist=True)
        data = self.data(value, maximum)
        if self.total+len(data) > MAX_OUTPUT: fail("OUTPUT_BUDGET", "Total output byte budget reached")
        destination = self.out/name
        target = self.out/(name+".tmp") if atomic else destination
        if atomic and destination.exists():
            check_ordinary_path(destination, must_exist=True)
            if destination.stat().st_nlink != 1: fail("PATH_ALIAS", "Progress output became a hardlink")
        with target.open("xb") as file:
            if file.write(data) != len(data): fail("OUTPUT_WRITE_FAILED", "Short JSON file write")
            file.flush()
        if atomic: os.replace(target, destination)
        self.total += len(data)
        record = {"file": name, "size_bytes": len(data), "sha256": digest(data)}
        self.files[name] = record
        return record

    def progress(self, result):
        return self.write("progress.json", result, atomic=True)


def initial_result(request):
    return {"schema_version": 1, "kind": "owned_runtime_export_observation",
            "status": "partial", "atomic": False, "frida_export_type": None,
            "started_utc": utc(), "ended_utc": None, "request": request,
            "identity": {"start": None, "end": None}, "time_anchor": "retained-HANDLE identity validation then observer monotonic t0",
            "samples": [{"index": i, "requested_offset_ms": offset, "status": "unattempted", "error": None}
                        for i, offset in enumerate(request["sample_offsets_ms"])],
            "cleanup": {"process_handle_closed": False, "all_snapshot_handles_closed": True, "errors": []},
            "error": None}


def compact_reads(reads, inspection):
    """Keep bytes once, with a reference only after exact transcript agreement."""
    output = [dict(row) for row in reads]
    observed = inspection.get("reads", []) if isinstance(inspection, dict) else []
    for row in output:
        if not row.get("hex"):
            continue
        for index, candidate in enumerate(observed):
            if (candidate.get("rva") == row.get("rva")
                and candidate.get("requested_size_bytes") == row.get("requested_bytes")
                and candidate.get("transferred_bytes") == row.get("transferred_bytes")
                and candidate.get("sha256") == row.get("sha256")
                and candidate.get("hex") == row["hex"]):
                del row["hex"]
                row["actual_bytes_reference"] = f"inspection.reads[{index}].hex"
                break
    return output


def collect_samples(request, out, reader, module_api, model, memory, regions, *,
                    clock=time.monotonic, sleep=time.sleep, publisher=None, finalize=None):
    request = validate_request(request)
    publisher = publisher or Publisher(out)
    result = initial_result(request)
    config = SimpleNamespace(pid=request["pid"], expected_exe=Path(request["expected_executable"]),
                             expected_start_filetime=int(request["expected_creation_filetime"]))
    def first(error):
        result["error"] = result["error"] or error_row(error)
    def identity(require_alive=True):
        value = reader.identity()
        memory.validate_identity(value, config, require_alive=require_alive)
        return value
    origin = clock()
    deadline = origin+request["timeout_ms"]/1000
    try:
        result["identity"]["start"] = identity()
        origin = clock(); deadline = origin+request["timeout_ms"]/1000
        publisher.progress(result)
        for row in result["samples"]:
            due = origin+row["requested_offset_ms"]/1000
            while clock() < due:
                identity()
                if clock() >= deadline: fail("TIMEOUT", "Observer deadline reached before scheduled sample")
                sleep(min(.020, due-clock(), max(0, deadline-clock())))
            if clock() >= deadline: fail("TIMEOUT", "Observer deadline reached before scheduled sample")
            before = identity()
            row["actual_offset_ms"] = (clock()-origin)*1000
            row["late_by_ms"] = max(0, (clock()-due)*1000)
            row["started_utc"] = utc()
            payload = {"schema_version": 1, "kind": "runtime_export_sample", "index": row["index"],
                       "requested_offset_ms": row["requested_offset_ms"], "actual_offset_ms": row["actual_offset_ms"],
                       "late_by_ms": row["late_by_ms"], "started_utc": row["started_utc"],
                       "identity": {"start": before, "end": None}, "module_inventory": None,
                       "module": None, "inspection": None, "policy_reads": [], "policy_queries": [],
                       "target_queries": [], "error": None, "atomic": False, "frida_export_type": None}
            bound = None
            stop = None
            try:
                inventory = snapshot_modules(module_api, request["pid"], deadline, clock=clock, sleep=sleep)
                payload["module_inventory"] = inventory
                if not inventory["snapshot_handle_closed"]:
                    result["cleanup"]["all_snapshot_handles_closed"] = False
                    result["cleanup"]["errors"].append(inventory.get("close_error", inventory["error"]))
                identity()
                module = resolve_module(inventory, request["expected_module_file"], request["pid"])
                payload["module"] = module
                if module["status"] == "unique":
                    bound = BoundReader(reader, memory, regions, request, module, clock=clock, deadline=deadline)
                    payload["inspection"] = model.inspect_exports(bound.read_rva, bound.query_va,
                        module["base"], module["size_bytes"], tuple(request["symbols"]),
                        query_struct_size=ctypes.sizeof(regions.MEMORY_BASIC_INFORMATION), target_prefix_bytes=16)
                    if bound.fatal: raise ObserverError(bound.fatal["code"], bound.fatal["message"])
                payload["identity"]["end"] = identity()
                if clock() >= deadline: fail("TIMEOUT", "Observer deadline reached during sample")
                row["status"] = "partial" if payload["inspection"] is not None and payload["inspection"].get("status") != "completed" else "completed"
                if row["status"] == "partial":
                    first(ObserverError("EXPORT_SAMPLE_PARTIAL", "Remote export metadata/bytes were incompletely observed"))
            except Exception as error:
                payload["error"] = error_row(error)
                row["status"], row["error"] = "failed", payload["error"]
                first(error)
                if getattr(error, "code", None) in IDENTITY_ERRORS | {"MODULE_IDENTITY_MISMATCH"}:
                    # Latch before sample publication, which can independently fail.
                    result["status"] = "failed"
                if getattr(error, "code", None) in STOP_ERRORS | {"MODULE_IDENTITY_MISMATCH"}:
                    stop = error
            finally:
                if bound:
                    payload["policy_reads"] = compact_reads(bound.reads, payload["inspection"])
                    payload["policy_queries"], payload["target_queries"] = bound.policy_queries, bound.target_queries
                payload["ended_utc"] = utc()
                sample_name = "sample-"+str(row["index"]).zfill(3)+".json"
                try:
                    metadata = publisher.write(sample_name, payload, maximum=MAX_SAMPLE)
                except Exception as error:
                    result.setdefault("publication_errors", []).append({"file": sample_name,
                        "error": error_row(error, "OUTPUT_PUBLICATION_FAILED")})
                    raise
                row.update(metadata, ended_utc=payload["ended_utc"])
                publisher.progress(result)
            if stop is not None: raise stop
        result["status"] = "completed" if result["error"] is None else "partial"
    except Exception as error:
        first(error)
        if result["status"] != "failed":
            result["status"] = "failed" if getattr(error, "code", None) in IDENTITY_ERRORS | {"MODULE_IDENTITY_MISMATCH"} else "partial"
    finally:
        try:
            result["identity"]["end"] = identity(require_alive=False)
        except Exception as error:
            first(error)
            if result["status"] != "failed":
                result["status"] = "failed" if getattr(error, "code", None) in IDENTITY_ERRORS else "partial"
        try:
            reader.close(); result["cleanup"]["process_handle_closed"] = True
        except Exception as error:
            result["cleanup"]["errors"].append(error_row(error, "CLOSE_FAILED"))
            first(error); result["status"] = "failed"
        if finalize is not None:
            try: finalize(result)
            except Exception as error:
                first(error); result["status"] = "failed"
                result["cleanup"]["errors"].append(error_row(error, "FINALIZE_FAILED"))
        if not result["cleanup"]["all_snapshot_handles_closed"]: result["status"] = "failed"
        result["ended_utc"] = utc()
        for name in ("progress.json", "result.json"):
            try:
                if name == "progress.json": publisher.progress(result)
                else: publisher.write(name, result)
            except Exception as error:
                publication_error = error_row(error, "OUTPUT_PUBLICATION_FAILED")
                result.setdefault("publication_errors", []).append({"file": name, "error": publication_error})
                result["error"] = result["error"] or publication_error
                result["status"] = "failed"
    return result


def summary(result, result_record=None):
    return {"schema_version": 1, "kind": result["kind"], "status": result["status"],
            "pid": result["request"]["pid"] if result.get("request") else None,
            "error": result["error"], "cleanup": result["cleanup"],
            "samples": result.get("samples", []), "result_file": "result.json" if result_record else None,
            "result_identity": result_record, "log_error": result.get("log_error"),
            "publication_errors": result.get("publication_errors", [])}


def finalize_sources(value, resources, provenance):
    """Verify/close every retained source, even after an earlier verification fails."""
    value["sources"] = []
    for snapshot in resources:
        record = snapshot.receipt()
        record["verified_stable"] = False
        try:
            snapshot.verify(); record["verified_stable"] = True
        except Exception as error:
            record["error"] = error_row(error)
            value["error"] = value["error"] or error_row(error)
            value["status"] = "failed"
        finally:
            try:
                snapshot.close(); record["handle_closed"] = True
            except Exception as error:
                record["handle_closed"] = False
                value["cleanup"]["errors"].append(error_row(error, "SOURCE_CLOSE_FAILED"))
                value["error"] = value["error"] or error_row(error, "SOURCE_CLOSE_FAILED")
                value["status"] = "failed"
        value["sources"].append(record)
    for row in provenance:
        try:
            stable_bytes(Path(row["file"]), row["sha256"], 1024*1024)
        except Exception as error:
            value["error"] = value["error"] or error_row(error)
            value["status"] = "failed"
            value.setdefault("tool_verification_errors", []).append(error_row(error))
    value["tools"] = provenance


def main(argv=None):
    result = {"schema_version": 1, "kind": "owned_runtime_export_observation", "status": "failed",
              "request": None, "samples": [], "error": None, "cleanup": {"errors": []}}
    publisher = None
    resources = []
    def finalize(value):
        finalize_sources(value, resources, provenance)
        value["request_input"] = {"file": str(request_path), "size_bytes": len(request_data),
                                  "sha256": digest(request_data), "verified_stable": False}
        try:
            stable_bytes(request_path, digest(request_data), 65536)
            value["request_input"]["verified_stable"] = True
        except Exception as error:
            value["request_input"]["error"] = error_row(error)
            value["error"] = value["error"] or error_row(error)
            value["status"] = "failed"
    try:
        values = list(sys.argv[1:] if argv is None else argv)
        parser = StrictParser(description=__doc__, allow_abbrev=False)
        parser.add_argument("--request", required=True)
        parser.add_argument("--out", required=True)
        names = [x.split("=", 1)[0] for x in values if x.startswith("--")]
        if len(names) != len(set(names)): fail("INVALID_ARGUMENTS", "Duplicate CLI options")
        args = parser.parse_args(values)
        request_path, out = strict_path(args.request), strict_path(args.out)
        request_data = stable_bytes(request_path, None, 65536)
        config = decode_request(request_data)
        check_ordinary_path(out, must_exist=False)
        if out.exists(): fail("OUTPUT_EXISTS", "Output directory must be new")
        for expected in (Path(config["expected_executable"]), Path(config["expected_module_file"])):
            check_ordinary_path(expected, must_exist=True)
        memory, regions, provenance = load_frozen_support()
        own = Path(__file__).absolute()
        own_data = stable_bytes(own, None, 1024*1024)
        model_path = own.with_name("model.py")
        model_data = stable_bytes(model_path, MODEL_SHA, 1024*1024)
        model = compile_pinned(model_data, MODEL_SHA, model_path, "_runtime_export_model")
        provenance += [{"file": str(own), "size_bytes": len(own_data), "sha256": digest(own_data)},
                       {"file": str(model_path), "size_bytes": len(model_data), "sha256": MODEL_SHA}]
        for field, pin in (("expected_executable", "source_sha256"), ("expected_module_file", "module_sha256")):
            snapshot = memory.SourceSnapshot(Path(config[field]))
            snapshot.__enter__(); resources.append(snapshot)
            if snapshot.sha256 != config[pin]: fail("SOURCE_IDENTITY_MISMATCH", "Staged executable or module file SHA differs")
        publisher = Publisher(out)
        publisher.write("request.json", config)
        module_api = Toolhelp()
        reader = regions.WindowsRegionReader(config["pid"], address_bits=32, support=memory)
        result = collect_samples(config, out, reader, module_api, model, memory, regions,
                                 publisher=publisher, finalize=finalize)
        resources.clear()
    except Exception as error:
        result["error"] = result.get("error") or error_row(error)
        result["status"] = "failed"
        for resource in resources:
            try: resource.close()
            except Exception as close_error: result["cleanup"]["errors"].append(error_row(close_error, "SOURCE_CLOSE_FAILED"))
        if publisher is not None and not (publisher.out/"result.json").exists():
            result["ended_utc"] = utc()
            try:
                publisher.progress(result); publisher.write("result.json", result)
            except Exception as output_error: result["log_error"] = error_row(output_error)
    output = (json.dumps(summary(result, publisher.files.get("result.json") if publisher else None), ensure_ascii=False, allow_nan=False)+"\n").encode("utf-8")
    if len(output) > 65536:
        output = (json.dumps({"schema_version": 1, "status": "failed", "error": {"code": "STDOUT_BUDGET", "message": "See saved result.json"}})+"\n").encode("utf-8")
    sys.stdout.buffer.write(output); sys.stdout.buffer.flush()
    return 0 if result["status"] == "completed" else (2 if result["status"] == "partial" else 1)


if __name__ == "__main__":
    raise SystemExit(main())
