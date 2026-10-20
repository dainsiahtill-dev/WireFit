#!/usr/bin/env python3
"""Capture bounded executable private regions derived from a bound main image.

No target is started, debug-attached, suspended, modified or terminated. Region
metadata and actual byte coverage are separate, cooperative non-atomic facts.
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
import struct
import sys
import time
from types import SimpleNamespace
from typing import Any


MAX_IMAGE = 64 * 1024 * 1024
MAX_CAPTURE = 16 * 1024 * 1024
MAX_JSON = 16 * 1024 * 1024
MAX_QUERIES = 4096
MAX_CALLERS = 16
MAX_REGIONS = 128
SUPPORT_SHA = "e2f062a4b2d72bc67de793a9afe6068336f5bd99ccf1b9d51b647320e719ec38"
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
EXECUTABLE_READABLE = {0x20, 0x40, 0x80}


class CaptureError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def fail(code: str, message: str) -> None:
    raise CaptureError(code, message)


def error_row(error: BaseException, fallback="CAPTURE_FAILED") -> dict[str, Any]:
    row = {"code": getattr(error, "code", fallback), "message": str(error)[:2048]}
    winerror = getattr(error, "winerror", None)
    if type(winerror) is int and 0 <= winerror <= 0xFFFFFFFF:
        row["winerror"] = winerror
    return row


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def integer(text: str, name: str, maximum: int, minimum=0, hexadecimal=False) -> int:
    if not isinstance(text, str) or len(text) > (18 if hexadecimal else 20) or not re.fullmatch(r"0x[0-9a-fA-F]+" if hexadecimal else r"[0-9]+", text, re.ASCII):
        fail("INVALID_ARGUMENTS", f"Invalid {name} {'hexadecimal' if hexadecimal else 'decimal'} value")
    value = int(text, 16 if hexadecimal else 10)
    if not minimum <= value <= maximum:
        fail("INVALID_ARGUMENTS", f"{name} exceeds its bounded range")
    return value


def absolute_path(text: str, name: str) -> Path:
    if not isinstance(text, str) or not text or len(text) > 32767 or "\x00" in text or not os.path.isabs(text):
        fail("INVALID_ARGUMENTS", f"{name} must be an absolute path")
    if os.name == "nt":
        drive, tail = os.path.splitdrive(text)
        if len(drive) != 2 or drive[1] != ":" or ":" in tail:
            fail("INVALID_ARGUMENTS", f"{name} must use a local drive without device paths/alternate streams")
    if any(part in (".", "..") or (part and part[-1] in (" ", ".")) for part in re.split(r"[\\/]", text)):
        fail("INVALID_ARGUMENTS", f"{name} has an ambiguous path component")
    return Path(os.path.abspath(text))


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        fail("INVALID_ARGUMENTS", message)


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    values = list(sys.argv[1:] if argv is None else argv)
    parser = Parser(description=__doc__, allow_abbrev=False)
    for name in ("receipt", "image", "out"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--caller-rva", action="append", required=True)
    parser.add_argument("--timeout-ms", default="30000")
    names = [value.split("=", 1)[0] for value in values if value.startswith("--") and not value.startswith("--caller-rva")]
    if len(names) != len(set(names)):
        fail("INVALID_ARGUMENTS", "Repeated singleton options are not accepted")
    config = parser.parse_args(values)
    config.receipt = absolute_path(config.receipt, "receipt")
    config.image = absolute_path(config.image, "image")
    config.out = absolute_path(config.out, "out")
    config.timeout_ms = integer(config.timeout_ms, "timeout-ms", 60000, minimum=1)
    config.caller_rva = [integer(value, "caller-rva", 0xFFFFFFFF, hexadecimal=True) for value in config.caller_rva]
    if not 1 <= len(config.caller_rva) <= MAX_CALLERS or len(set(config.caller_rva)) != len(config.caller_rva):
        fail("INVALID_ARGUMENTS", "Provide between one and sixteen unique caller RVAs")
    return config


def source_bytes(path: Path, maximum=1024 * 1024) -> bytes:
    with path.open("r", encoding="utf-8", errors="strict", newline="") as file:
        text = file.read(maximum + 1)
    data = text.encode("utf-8")
    if len(data) > maximum:
        fail("SOURCE_TOO_LARGE", "Tool/receipt text exceeds its explicit bound")
    return data


def load_support() -> Any:
    path = Path(__file__).resolve().with_name("memory-image.py")
    data = source_bytes(path)
    if sha(data) != SUPPORT_SHA:
        fail("SUPPORT_IDENTITY_MISMATCH", "The reviewed memory-image.py dependency has changed")
    namespace = {"__name__": "native_memory_image_support", "__file__": str(path)}
    exec(compile(data.decode("utf-8"), str(path), "exec"), namespace)
    return SimpleNamespace(**namespace, exact_source_bytes=data)


def observed_interval(start: int, length: int, intervals: list[tuple[int, int]]) -> bool:
    cursor = start
    for lo, hi in intervals:
        if lo <= cursor < hi:
            cursor = min(start + length, hi)
            if cursor == start + length:
                return True
        elif lo > cursor:
            return False
    return False


def derive_call_target(image: bytes, base: int, rva: int, intervals: list[tuple[int, int]]) -> dict[str, Any]:
    if type(rva) is not int or not 0 <= rva <= len(image) - 6:
        fail("INVALID_CALLER", "Caller must have a complete six-byte window inside the flat image")
    if not observed_interval(rva, 6, intervals):
        fail("UNOBSERVED_CALLER", "The caller window includes bytes not observed by the main capture")
    data = image[rva:rva + 6]
    if data[0] != 0xE8:
        fail("INVALID_CALLER", "Caller must begin with a captured x86 CALL rel32 instruction")
    caller = base + rva
    target = caller + 5 + struct.unpack_from("<i", data, 1)[0]
    if not 0 < caller < 1 << 32 or caller + 6 > 1 << 32 or not 0 < target < 1 << 32:
        fail("CALL_TARGET_OVERFLOW", "The caller or signed rel32 target exceeds the PE32 address range")
    return {"caller_rva": hex(rva), "caller_va": hex(caller), "expected_bytes": data.hex(), "target_va": hex(target),
            "status": "pending", "unknown_reason": None, "target_region_captured": False}


def validate_main_capture(receipt: Any, image: bytes, support: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 1 or receipt.get("status") not in ("completed", "partial"):
        fail("INVALID_MAIN_RECEIPT", "Expected a completed/partial main-image receipt schema 1")
    if receipt.get("layout") != "flat_rva_memory" or receipt.get("atomic") is not False or receipt.get("runnable_pe") is not False:
        fail("INVALID_MAIN_RECEIPT", "Expected an explicitly non-atomic flat-RVA observation")
    size = receipt.get("size_bytes")
    if type(size) is not int or not 1 <= size <= MAX_IMAGE or len(image) != size:
        fail("MAIN_IMAGE_MISMATCH", "Main image length does not match its bounded receipt")
    reference = receipt.get("image", {})
    if reference.get("size_bytes") != size or reference.get("sha256") != sha(image):
        fail("MAIN_IMAGE_MISMATCH", "Main image SHA/length does not match its receipt")
    base = integer(receipt.get("base"), "main base", 0xFFFFFFFF, minimum=1, hexadecimal=True)
    if base + size > 1 << 32:
        fail("INVALID_MAIN_RECEIPT", "Main PE32 range overflows")
    header = support.parse_pe_header(image[:support.MAX_HEADER_BYTES])
    if header["machine"] != 0x14C or header["size_of_image"] != size:
        fail("INVALID_MAIN_RECEIPT", "This caller-rel32 collector requires a matching PE32 main image")
    coverage = receipt.get("coverage", {})
    pages = coverage.get("pages")
    if not isinstance(pages, list) or not 1 <= len(pages) <= 16384 or coverage.get("unverified_output_bytes") != 0:
        fail("INVALID_MAIN_COVERAGE", "Main coverage is absent, excessive or includes unverified output")
    intervals, cursor, total_observed = [], 0, 0
    for page in pages:
        if not isinstance(page, dict):
            fail("INVALID_MAIN_COVERAGE", "Main coverage row must be an object")
        rva = integer(page.get("rva"), "coverage RVA", 0xFFFFFFFF, hexadecimal=True)
        length, observed = page.get("requested_bytes"), page.get("observed_bytes")
        if type(length) is not int or not 1 <= length <= MAX_IMAGE or type(observed) is not int or not 0 <= observed <= length or rva != cursor or rva + length > size:
            fail("INVALID_MAIN_COVERAGE", "Main coverage has inconsistent, overlapping or missing extents")
        if page.get("observed_prefix_bytes") != observed or page.get("coverage_complete") is not (observed == length):
            fail("INVALID_MAIN_COVERAGE", "Main coverage prefix/completion metadata is inconsistent")
        expected = sha(image[rva:rva + observed]) if observed else None
        if page.get("observed_sha256") != expected or any(image[rva + observed:rva + length]):
            fail("INVALID_MAIN_COVERAGE", "Main observed SHA or explicit unobserved zero placeholders differ")
        if observed:
            intervals.append((rva, rva + observed))
        cursor += length
        total_observed += observed
    if cursor != size or total_observed != coverage.get("observed_bytes") or size - total_observed != coverage.get("unobserved_bytes"):
        fail("INVALID_MAIN_COVERAGE", "Main coverage union/count mismatch")
    identity, source = receipt.get("identity", {}), receipt.get("source", {})
    pid = receipt.get("pid")
    if type(pid) is not int or not 1 <= pid <= 0xFFFFFFFF:
        fail("INVALID_MAIN_RECEIPT", "Main receipt PID is invalid")
    expected_exe = absolute_path(identity.get("expected_executable"), "expected executable")
    creation = identity.get("expected_creation_filetime")
    creation_value = integer(creation, "expected creation FILETIME", 0xFFFFFFFFFFFFFFFF, minimum=1)
    for endpoint in (identity.get("start"), identity.get("end")):
        if not isinstance(endpoint, dict) or endpoint.get("pid") != pid or endpoint.get("creation_filetime") != creation or endpoint.get("alive") is not True:
            fail("INVALID_MAIN_RECEIPT", "Main start/end PID, exact creation token or alive state is inconsistent")
        if os.path.normcase(str(absolute_path(endpoint.get("executable"), "observed executable"))) != os.path.normcase(str(expected_exe)):
            fail("INVALID_MAIN_RECEIPT", "Main start/end executable identity differs")
    if source.get("verified_stable") is not True or not isinstance(source.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"]):
        fail("INVALID_MAIN_RECEIPT", "Main source SHA/stability evidence is missing")
    if os.path.normcase(str(absolute_path(source.get("path"), "source executable"))) != os.path.normcase(str(expected_exe)):
        fail("INVALID_MAIN_RECEIPT", "Main source path differs from process identity")
    return {"pid": pid, "expected_exe": expected_exe, "expected_start_filetime": creation_value, "base": base,
            "size": size, "intervals": intervals, "source_sha256": source["sha256"], "source_size": source.get("size_bytes"), "header": header}


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    # VirtualQueryEx uses the collector's native ABI even for a PE32 target.
    _fields_ = ([ ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                  ("AllocationProtect", ctypes.c_uint32)]
                + ([("PartitionId", ctypes.c_uint16)] if ctypes.sizeof(ctypes.c_void_p) == 8 else [])
                + [("RegionSize", ctypes.c_size_t), ("State", ctypes.c_uint32),
                   ("Protect", ctypes.c_uint32), ("Type", ctypes.c_uint32)])


def validate_region(row: Any, queried: int, address_bits=32) -> dict[str, int]:
    names = ("base_address", "allocation_base", "allocation_protect", "region_size", "state", "protect", "type", "returned_size")
    if not isinstance(row, dict) or any(type(row.get(name)) is not int for name in names):
        fail("INVALID_QUERY_RESULT", "VirtualQueryEx did not return complete integer metadata")
    base, size, allocation = row["base_address"], row["region_size"], row["allocation_base"]
    if row["returned_size"] != ctypes.sizeof(MEMORY_BASIC_INFORMATION) or not 0 <= base <= queried < base + size <= 1 << address_bits or size <= 0:
        fail("INVALID_QUERY_RESULT", "VirtualQueryEx structure size, range or progress is invalid")
    if any(not 0 <= row[name] <= 0xFFFFFFFF for name in ("allocation_protect", "state", "protect", "type")):
        fail("INVALID_QUERY_RESULT", "VirtualQueryEx protection/state/type exceeds DWORD")
    if row["state"] not in (0x1000, 0x2000, 0x10000):
        fail("INVALID_QUERY_RESULT", "VirtualQueryEx returned an unknown page state")
    if row["state"] != 0x10000 and not 0 < allocation <= base:
        fail("INVALID_QUERY_RESULT", "VirtualQueryEx allocation base is invalid")
    return dict(row)


def region_rejection(row: dict[str, int]) -> str | None:
    if row["state"] != 0x1000:
        return "NOT_COMMITTED"
    if row["type"] != 0x20000:
        return "NOT_PRIVATE"
    if row["protect"] & 0x100:
        return "PAGE_GUARD"
    if row["protect"] & 0xFF not in READABLE:
        return "NOT_READABLE"
    if row["protect"] & 0xFF not in EXECUTABLE_READABLE:
        return "NOT_EXECUTABLE"
    return None


def public_region(row: dict[str, int]) -> dict[str, Any]:
    return {"base": hex(row["base_address"]), "allocation_base": hex(row["allocation_base"]),
            "size_bytes": row["region_size"], "allocation_protect": hex(row["allocation_protect"]),
            "state": hex(row["state"]), "protect": hex(row["protect"]), "type": hex(row["type"]),
            "returned_size": row["returned_size"], "allocation_fields_defined": row["state"] != 0x10000,
            "capture_reason": region_rejection(row)}


class WindowsRegionReader:
    """One read-only 0x410 HANDLE with shared reviewed identity/read/close logic.

    Binding declarations are initialized here because the frozen support's
    constructor opens QUERY_LIMITED. Its identity/read/close methods are reused
    unchanged on this retained QUERY_INFORMATION|VM_READ HANDLE.
    """
    def __init__(self, pid: int, *, address_bits=32, support=None):
        self.support = support or load_support()
        if os.name != "nt":
            fail("UNSUPPORTED_PLATFORM", "Windows VirtualQueryEx is required")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        k = self.kernel
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenProcess.restype = wintypes.HANDLE
        k.CloseHandle.argtypes, k.CloseHandle.restype = [wintypes.HANDLE], wintypes.BOOL
        k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        k.QueryFullProcessImageNameW.restype = wintypes.BOOL
        k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        k.GetProcessTimes.restype = wintypes.BOOL
        k.GetExitCodeProcess.argtypes, k.GetExitCodeProcess.restype = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL
        k.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        k.ReadProcessMemory.restype = wintypes.BOOL
        k.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
        k.VirtualQueryEx.restype = ctypes.c_size_t
        self.pid, self.address_bits = pid, address_bits
        self.handle = k.OpenProcess(0x0010 | 0x0400, False, pid)
        if not self.handle:
            fail("OPEN_PROCESS_FAILED", f"Read-only OpenProcess failed with Winerror {ctypes.get_last_error()}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def identity(self):
        return self.support.WindowsMemoryReader.identity(self)

    def read(self, address, length):
        return self.support.WindowsMemoryReader.read(self, address, length)

    def close(self):
        return self.support.WindowsMemoryReader.close(self)

    def query(self, address):
        if not self.handle or type(address) is not int or not 0 <= address < 1 << self.address_bits:
            fail("INVALID_QUERY_RESULT", "VirtualQueryEx requires an open HANDLE and bounded address")
        value = MEMORY_BASIC_INFORMATION()
        ctypes.set_last_error(0)
        returned = int(self.kernel.VirtualQueryEx(self.handle, ctypes.c_void_p(address), ctypes.byref(value), ctypes.sizeof(value)))
        if returned == 0:
            winerror = ctypes.get_last_error()
            error = CaptureError("QUERY_FAILED", f"VirtualQueryEx failed with Winerror {winerror}")
            error.winerror = winerror
            raise error
        return validate_region({"base_address": int(value.BaseAddress or 0), "allocation_base": int(value.AllocationBase or 0),
                                "allocation_protect": int(value.AllocationProtect), "region_size": int(value.RegionSize),
                                "state": int(value.State), "protect": int(value.Protect), "type": int(value.Type), "returned_size": returned}, address, self.address_bits)


class QueryContext:
    def __init__(self, reader, result, identity_config, support, deadline):
        self.reader, self.result, self.config, self.support, self.deadline = reader, result, identity_config, support, deadline

    def check(self):
        if time.monotonic() >= self.deadline:
            fail("TIMEOUT", "The cooperative capture deadline was reached")
        identity = self.reader.identity()
        self.support.validate_identity(identity, self.config, require_alive=False)
        if not identity["alive"]:
            fail("PROCESS_EXITED", "The retained identified process exited during capture")

    def query(self, address, purpose):
        self.check()
        if len(self.result["queries"]) >= MAX_QUERIES:
            fail("QUERY_BUDGET", "Global VirtualQueryEx query budget was reached")
        record = {"address": hex(address), "purpose": purpose, "observed_utc": utc_now()}
        self.result["queries"].append(record)
        try:
            row = validate_region(self.reader.query(address), address)
            record["region"] = public_region(row)
            return row
        except Exception as error:
            record["error"] = error_row(error)
            raise


def mark_unknown(caller, code, message):
    caller["status"], caller["target_region_captured"] = "unknown", False
    caller["unknown_reason"] = {"code": code, "message": message[:2048]}


def discover_allocations(context, callers):
    groups = {}
    for index, caller in enumerate(callers):
        if caller["status"] != "live_validated":
            continue
        try:
            row = context.query(int(caller["target_va"], 16), "target")
            reason = region_rejection(row)
            caller["target_initial_region"] = public_region(row)
            if reason:
                mark_unknown(caller, reason, "The target region does not satisfy committed private readable executable policy")
                continue
            allocation = row["allocation_base"]
            caller["allocation_base"] = hex(allocation)
            groups.setdefault(allocation, []).append(index)
        except CaptureError as error:
            if error.code == "INVALID_QUERY_RESULT":
                raise
            mark_unknown(caller, error.code, str(error))
    candidates = []
    for allocation, indices in groups.items():
        record = {"allocation_base": hex(allocation), "caller_indices": indices, "metadata_scan_complete": False,
                  "regions": [], "byte_scope": "readable_executable_private_regions_only", "all_allocation_bytes_captured": False}
        context.result["allocations"].append(record)
        cursor, boundary = allocation, min(1 << 32, allocation + MAX_CAPTURE)
        try:
            while cursor < boundary:
                row = context.query(cursor, "allocation_scan")
                if row["state"] == 0x10000 or row["allocation_base"] != allocation:
                    record["metadata_scan_complete"] = True
                    record["boundary_region"] = public_region(row)
                    break
                if row["base_address"] != cursor:
                    fail("REGION_CHANGED", "Allocation metadata merged or changed during its forward scan")
                public = public_region(row)
                record["regions"].append(public)
                end = row["base_address"] + row["region_size"]
                if end > boundary:
                    public["capture_reason"] = "ALLOCATION_SCAN_BOUND"
                    record["scan_error"] = {"code": "ALLOCATION_SCAN_BOUND", "message": "A region exceeds the bounded allocation metadata span"}
                    break
                if public["capture_reason"] is None:
                    seeds = [index for index in indices if row["base_address"] <= int(callers[index]["target_va"], 16) < end]
                    candidates.append({"native": row, "public": public, "allocation": record, "target_callers": seeds})
                cursor = end
            else:
                record["scan_error"] = {"code": "ALLOCATION_SCAN_BOUND", "message": "Allocation scan did not establish a boundary within its span budget"}
        except CaptureError as error:
            if error.code == "INVALID_QUERY_RESULT":
                raise
            record["scan_error"] = error_row(error)
    # Each allocation is scanned once. All target-covering extents precede
    # auxiliary executable extents, without cropping a region away from its seed.
    return sorted(candidates, key=lambda row: (not bool(row["target_callers"]), row["native"]["base_address"]))


def capture_region(context, candidate, config, index):
    native, support = candidate["native"], context.support
    path = Path(str(config.out) + f"-{index:03d}.bin")
    row = {"file": path.name, "base": hex(native["base_address"]), "allocation_base": hex(native["allocation_base"]),
           "size_bytes": native["region_size"], "status": "failed", "sha256": None, "coverage": None,
           "region_at_plan": public_region(native), "target_caller_indices": candidate["target_callers"],
           "unobserved_fill": "zero", "zero_fill_is_observed": False, "error": None}
    context.result["captures"].append(row)
    with path.open("xb+", buffering=0) as output:
        output.truncate(native["region_size"])
        row["coverage"] = support.finish_coverage([support.coverage_row(0, native["region_size"], b"", [], "not_attempted")], native["region_size"])

        class GatedReader:
            def read(self, address, length):
                try:
                    current = context.query(address, "pre_read")
                    # VQE at an interior page returns a suffix of the original
                    # homogeneous region. The suffix base/length normally vary;
                    # allocation, attributes, endpoint and request containment bind it.
                    planned_end = native["base_address"] + native["region_size"]
                    current_end = current["base_address"] + current["region_size"]
                    if region_rejection(current) is not None or any(current[name] != native[name] for name in ("allocation_base", "state", "protect", "type")) or current_end != planned_end or current["base_address"] < native["base_address"] or not native["base_address"] <= address < address + length <= current_end:
                        fail("REGION_CHANGED", "Region attributes/allocation/range changed before ReadProcessMemory; read refused")
                    return context.reader.read(address, length)
                except CaptureError as error:
                    raise support.MemoryImageError(error.code, str(error)) from error

        def write_at(offset, data):
            if not 0 <= offset <= native["region_size"] - len(data):
                raise support.MemoryImageError("OUTPUT_WRITE_FAILED", "Out-of-range region sink write")
            try:
                output.seek(offset)
            except Exception as error:
                wrapped = support.MemoryImageError("OUTPUT_WRITE_FAILED", str(error))
                wrapped.written_prefix_bytes = 0
                raise wrapped from error
            written = output.write(data)
            if written != len(data):
                error = support.MemoryImageError("OUTPUT_WRITE_FAILED", "Region output was short-written")
                error.written_prefix_bytes = written
                raise error

        try:
            row["coverage"] = support.read_segments(GatedReader(), native["base_address"], native["region_size"], write_at)
            row["status"] = "completed" if row["coverage"]["coverage_complete"] else "partial"
        except Exception as error:
            if getattr(error, "coverage", None) is not None:
                row["coverage"] = error.coverage
            row["error"] = error_row(error)
            row["status"] = "partial"
            if getattr(error, "code", None) in ("INVALID_READ_RESULT", "INVALID_QUERY_RESULT", "PROCESS_IDENTITY_MISMATCH", "PROCESS_IDENTITY_FAILED", "CLOSED_HANDLE") or getattr(error, "code", "").startswith("OUTPUT_"):
                row["status"] = "failed"
                raise
        except BaseException as error:
            # The shared reader cannot return its in-progress prefix ledger on
            # an asynchronous interruption. Keep the file, but do not invent
            # coverage over partially persisted bytes without that ledger.
            page = support.coverage_row(0, native["region_size"], b"", [], "interrupted_output_coverage_unavailable")
            page["output_bytes_unverified"] = True
            row["coverage"] = support.finish_coverage([page], native["region_size"], "interrupted")
            row["error"], row["status"] = error_row(error, "INTERRUPTED"), "failed"
            raise
        finally:
            if row["coverage"]["unverified_output_bytes"]:
                row["unobserved_fill"] = "zero_except_unverified_output_write_ranges"
            try:
                output.flush()
                row["sha256"] = support.file_hash(output)
            except Exception as error:
                failure = support.MemoryImageError("OUTPUT_FINALIZE_FAILED", str(error))
                if row["error"] is None:
                    row["error"] = error_row(failure)
                else:
                    row.setdefault("additional_errors", []).append(error_row(failure))
                row["status"] = "failed"
                raise failure from error
    return row


def read_receipt(path, support):
    support.check_path_aliases(path, must_exist=True)
    if path.stat().st_size > MAX_JSON or path.stat().st_nlink != 1:
        fail("INVALID_MAIN_RECEIPT", "Receipt is oversized or aliased by a hardlink")
    before = path.stat()
    data = source_bytes(path, MAX_JSON)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        fail("INPUT_CHANGED", "Main receipt changed while being read")
    return json.loads(data.decode("utf-8", errors="strict")), data


def capture_private_regions(config):
    result = {"schema_version": 1, "kind": "bound_private_executable_regions", "status": "failed", "atomic": False,
              "runnable_verified": False, "scope": "readable_executable_private_regions_of_captured_rel32_targets",
              "started_utc": utc_now(), "ended_utc": None, "inputs": {}, "tool": {},
              "identity": {"start": None, "end": None}, "callers": [], "allocations": [], "captures": [], "queries": [],
              "limits": {"total_capture_bytes": MAX_CAPTURE, "allocation_scan_span_bytes": MAX_CAPTURE, "query_count": MAX_QUERIES,
                         "callers": MAX_CALLERS, "capture_regions": MAX_REGIONS, "timeout_ms": config.timeout_ms},
              "cleanup": {"process_handle_closed": False, "source_handle_closed": False, "image_handle_closed": False}, "error": None}
    started = time.monotonic()
    reader = receipt_file = image_snapshot = source_snapshot = None
    source_open = image_open = False
    support = None
    original_receipt_bytes = None

    def record_failure(error):
        row = error_row(error, "INTERRUPTED" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "CAPTURE_FAILED")
        if result["error"] is None:
            result["error"] = row
        else:
            result.setdefault("additional_errors", []).append(row)
        result["status"] = "failed"

    try:
        support = load_support()
        receipt, original_receipt_bytes = read_receipt(config.receipt, support)
        support.check_path_aliases(config.image, must_exist=True)
        if config.image.stat().st_size > MAX_IMAGE:
            fail("MAIN_IMAGE_MISMATCH", "Main image exceeds 64 MiB")
        image_snapshot = support.SourceSnapshot(config.image)
        image_snapshot.__enter__()
        image_open = True
        image_snapshot.file.seek(0)
        image = image_snapshot.file.read(MAX_IMAGE + 1)
        main = validate_main_capture(receipt, image, support)
        if receipt["image"]["file"] != config.image.name:
            fail("MAIN_IMAGE_MISMATCH", "Main image basename differs from the receipt")
        result["callers"] = [derive_call_target(image, main["base"], rva, main["intervals"]) for rva in config.caller_rva]
        source_snapshot = support.SourceSnapshot(main["expected_exe"])
        source_snapshot.__enter__()
        source_open = True
        if source_snapshot.sha256 != main["source_sha256"] or source_snapshot.initial_stat[2] != main["source_size"]:
            fail("SOURCE_IDENTITY_MISMATCH", "Current staged source differs from the main-capture source SHA/length")
        support.validate_image_headers(source_snapshot.header, main["header"], main["base"], main["size"])
        parent = support.check_path_aliases(config.out.parent, must_exist=False)
        if not parent.is_dir():
            fail("INVALID_PATH", "Output parent must be an existing directory")
        paths = [Path(str(config.out) + ".json")] + [Path(str(config.out) + f"-{index:03d}.bin") for index in range(1, MAX_REGIONS + 1)]
        if any(os.path.lexists(path) for path in paths):
            fail("OUTPUT_EXISTS", "The output prefix is not new; existing evidence is never overwritten")
        helper_bytes = source_bytes(Path(__file__))
        result["tool"] = {"helper": {"file": Path(__file__).name, "sha256": sha(helper_bytes), "size_bytes": len(helper_bytes)},
                          "memory_image_support": {"file": "memory-image.py", "sha256": SUPPORT_SHA, "size_bytes": len(support.exact_source_bytes)}}
        result["inputs"] = {"main_receipt": {"path": str(config.receipt), "sha256": sha(original_receipt_bytes), "size_bytes": len(original_receipt_bytes)},
                            "main_image": {"path": str(config.image), "sha256": sha(image), "size_bytes": len(image)},
                            "source": {"path": str(main["expected_exe"]), "sha256": source_snapshot.sha256, "size_bytes": source_snapshot.initial_stat[2], "verified_stable": False}}
        result["identity"].update({"pid": main["pid"], "expected_executable": str(main["expected_exe"]), "expected_creation_filetime": str(main["expected_start_filetime"])})
        receipt_file = paths[0].open("x", encoding="utf-8", errors="strict", newline="\n")
        identity_config = SimpleNamespace(pid=main["pid"], expected_exe=main["expected_exe"], expected_start_filetime=main["expected_start_filetime"])
        reader = WindowsRegionReader(main["pid"], address_bits=32, support=support)
        result["identity"]["start"] = reader.identity()
        support.validate_identity(result["identity"]["start"], identity_config, require_alive=True)
        context = QueryContext(reader, result, identity_config, support, started + config.timeout_ms / 1000)
        for caller in result["callers"]:
            try:
                address = int(caller["caller_va"], 16)
                region = context.query(address, "caller_pre_read")
                if region["state"] != 0x1000 or region["protect"] & 0x100 or region["protect"] & 0xFF not in READABLE or address + 6 > region["base_address"] + region["region_size"]:
                    mark_unknown(caller, "CALLER_UNREADABLE", "Caller window is not wholly committed readable non-guard memory")
                    continue
                live = support.validated_read(reader, address, 6)
                caller["live_read"] = {"hex": live["data"].hex(), "transferred_bytes": live["transferred_bytes"], "success": live["success"], "winerror": live["winerror"]}
                if not live["success"] or live["transferred_bytes"] != 6:
                    mark_unknown(caller, "CALLER_UNREADABLE", "The same-HANDLE caller reread was incomplete")
                elif live["data"].hex() != caller["expected_bytes"]:
                    mark_unknown(caller, "CALLER_CHANGED", "Live caller bytes differ from the observed main image; no target is queried from them")
                else:
                    caller["status"] = "live_validated"
            except CaptureError as error:
                if error.code == "INVALID_QUERY_RESULT":
                    raise
                mark_unknown(caller, error.code, str(error))
        candidates = discover_allocations(context, result["callers"])
        reserved = 0
        for candidate in candidates:
            size = candidate["native"]["region_size"]
            if len(result["captures"]) >= MAX_REGIONS or reserved + size > MAX_CAPTURE:
                candidate["public"]["capture_reason"] = "CAPTURE_BUDGET"
                continue
            reserved += size
            captured = capture_region(context, candidate, config, len(result["captures"]) + 1)
            candidate["public"]["capture_file"] = captured["file"]
            candidate["public"]["byte_capture_status"] = captured["status"]
            for index in candidate["target_callers"]:
                caller = result["callers"][index]
                caller["capture_file"] = captured["file"]
                caller["allocation_metadata_scan_complete"] = candidate["allocation"]["metadata_scan_complete"]
                if captured["status"] == "completed":
                    caller["status"], caller["target_region_captured"] = "captured", True
                else:
                    mark_unknown(caller, "TARGET_REGION_PARTIAL", "The target region was only partially observed; retained coverage identifies exact known bytes")
        for caller in result["callers"]:
            if caller["status"] == "live_validated":
                mark_unknown(caller, "TARGET_REGION_NOT_CAPTURED", "No complete target-covering executable extent was captured within the policy/budgets")
        complete = all(caller["status"] == "captured" for caller in result["callers"])
        complete = complete and all(allocation["metadata_scan_complete"] for allocation in result["allocations"])
        complete = complete and all(capture["status"] == "completed" for capture in result["captures"])
        complete = complete and all(candidate["public"].get("byte_capture_status") == "completed" for candidate in candidates)
        result["status"] = "completed" if complete else "partial"
        if not complete:
            result["error"] = {"code": "PARTIAL_CAPTURE", "message": "Some callers, metadata scan scope or executable byte coverage remain unknown; see per-item evidence"}
    except BaseException as error:
        if result["captures"] and result["captures"][-1]["sha256"] is None:
            current = result["captures"][-1]
            current["status"] = "failed"
            if current["error"] is None:
                current["error"] = error_row(error)
        record_failure(error)
    finally:
        if reader is not None:
            try:
                result["identity"]["end"] = reader.identity()
                support.validate_identity(result["identity"]["end"], identity_config, require_alive=False)
            except Exception as error:
                result["identity"]["end_error"] = error_row(error)
                record_failure(error)
            try:
                reader.close()
                result["cleanup"]["process_handle_closed"] = True
            except Exception as error:
                record_failure(error)
        for snapshot, opened, key in ((source_snapshot, source_open, "source_handle_closed"), (image_snapshot, image_open, "image_handle_closed")):
            if opened:
                try:
                    snapshot.verify()
                    if key == "source_handle_closed" and result["inputs"].get("source"):
                        result["inputs"]["source"]["verified_stable"] = True
                except Exception as error:
                    record_failure(error)
                try:
                    snapshot.close()
                    result["cleanup"][key] = True
                except Exception as error:
                    record_failure(error)
        if original_receipt_bytes is not None and support is not None:
            try:
                _, current = read_receipt(config.receipt, support)
                if current != original_receipt_bytes:
                    fail("INPUT_CHANGED", "Main receipt changed during private capture")
            except Exception as error:
                record_failure(error)
        result["ended_utc"] = utc_now()
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        result["totals"] = {"capture_file_bytes": sum(item["size_bytes"] for item in result["captures"]),
                            "observed_bytes": sum((item.get("coverage") or {}).get("observed_bytes", 0) for item in result["captures"]),
                            "unobserved_bytes": sum((item.get("coverage") or {}).get("unobserved_bytes", item["size_bytes"]) for item in result["captures"]),
                            "query_count": len(result["queries"])}
        if receipt_file is not None:
            try:
                payload = json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n"
                if len(payload.encode("utf-8")) > MAX_JSON:
                    fail("RECEIPT_TOO_LARGE", "Private receipt exceeded 16 MiB")
                receipt_file.write(payload)
                receipt_file.flush()
            except Exception as error:
                record_failure(error)
            finally:
                try:
                    receipt_file.close()
                except Exception as error:
                    record_failure(error)
    return result


def main(argv=None):
    try:
        result = capture_private_regions(parse_arguments(argv))
    except Exception as error:
        result = {"schema_version": 1, "status": "failed", "error": error_row(error)}
    sys.stdout.buffer.write((json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0 if result["status"] in ("completed", "partial") else 1


if __name__ == "__main__":
    raise SystemExit(main())
