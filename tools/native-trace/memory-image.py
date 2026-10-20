#!/usr/bin/env python3
"""Read an explicitly identified Windows process image as non-atomic analysis data.

The output is flat RVA memory, including explicitly unobserved zero placeholders.
It is neither a reconstructed PE file nor an executable. No target is started,
attached with a debugger, suspended, modified, or terminated by this program.
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
import struct
import sys
import time
from typing import Any, Callable


MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_HEADER_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
PAGE_BYTES = 4096
REPARSE_POINT = 0x400


class MemoryImageError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.coverage: dict[str, Any] | None = None


def fail(code: str, message: str) -> None:
    raise MemoryImageError(code, message)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def error_row(error: Exception, fallback: str = "CAPTURE_FAILED") -> dict[str, str]:
    return {"code": getattr(error, "code", fallback), "message": str(error)[:2048]}


class StrictParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        fail("INVALID_ARGUMENTS", message)


def integer(text: str, name: str, minimum: int, maximum: int, *, hexadecimal: bool = False) -> int:
    pattern = r"0x[0-9a-fA-F]+" if hexadecimal else r"[0-9]+"
    if len(text) > (18 if hexadecimal else 20) or not re.fullmatch(pattern, text, flags=re.ASCII):
        fail("INVALID_ARGUMENTS", f"{name} must be {'0x-prefixed hexadecimal' if hexadecimal else 'decimal'}")
    value = int(text, 16 if hexadecimal else 10)
    if not minimum <= value <= maximum:
        fail("INVALID_ARGUMENTS", f"{name} must be between {minimum} and {maximum}")
    return value


def absolute_path(text: str, name: str) -> Path:
    if not text or len(text) > 32767 or "\x00" in text or not os.path.isabs(text):
        fail("INVALID_ARGUMENTS", f"{name} must be an absolute filesystem path")
    # Reject device paths, alternate data streams, dot segments and Windows aliases.
    if os.name == "nt":
        drive, tail = os.path.splitdrive(text)
        if len(drive) != 2 or drive[1] != ":" or ":" in tail:
            fail("INVALID_ARGUMENTS", f"{name} must use a local drive path without an alternate stream")
    pieces = re.split(r"[\\/]", text)
    if any(piece in (".", "..") or (piece and piece[-1] in (" ", ".")) for piece in pieces):
        fail("INVALID_ARGUMENTS", f"{name} contains an ambiguous path component")
    return Path(os.path.abspath(text))


def check_path_aliases(path: Path, *, must_exist: bool) -> Path:
    """Reject reparse/symlink components instead of silently resolving aliases."""
    for item in reversed((path, *path.parents)):
        try:
            metadata = item.lstat()
        except FileNotFoundError:
            if item == path and not must_exist:
                continue
            fail("INVALID_PATH", f"Path does not exist: {item}")
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT:
            fail("PATH_ALIAS", f"Reparse points and symbolic links are not accepted: {item}")
    if must_exist and not path.is_file():
        fail("INVALID_PATH", f"Expected a regular file: {path}")
    resolved = path.resolve(strict=must_exist)
    if os.path.normcase(str(resolved)) != os.path.normcase(str(path)):
        fail("PATH_ALIAS", f"Path does not name its canonical location: {path}")
    return resolved


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    values = list(sys.argv[1:] if argv is None else argv)
    parser = StrictParser(description=__doc__, allow_abbrev=False)
    for name in ("pid", "expected-exe", "expected-start-filetime", "base", "size", "out"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--timeout-ms", default="30000")
    # argparse otherwise silently lets a repeated identity argument replace an earlier one.
    names = [value.split("=", 1)[0] for value in values if value.startswith("--")]
    if len(names) != len(set(names)):
        fail("INVALID_ARGUMENTS", "Repeated options are not accepted")
    config = parser.parse_args(values)
    config.pid = integer(config.pid, "pid", 1, 0xFFFFFFFF)
    config.expected_start_filetime = integer(config.expected_start_filetime, "expected-start-filetime", 1, 0xFFFFFFFFFFFFFFFF)
    config.base = integer(config.base, "base", 1, 0xFFFFFFFFFFFFFFFF, hexadecimal=True)
    config.size = integer(config.size, "size", 1, MAX_IMAGE_BYTES)
    config.timeout_ms = integer(config.timeout_ms, "timeout-ms", 1, 60000)
    if config.base + config.size > 0x10000000000000000:
        fail("INVALID_ARGUMENTS", "The requested address range overflows a 64-bit address")
    if config.base + config.size > 1 << (ctypes.sizeof(ctypes.c_void_p) * 8):
        fail("INVALID_ARGUMENTS", "The requested range cannot be represented by this Python process")
    config.expected_exe = absolute_path(config.expected_exe, "expected-exe")
    config.out = absolute_path(config.out, "out")
    # No filesystem/process access until every scalar argument has been validated.
    return config


def parse_pe_header(data: bytes) -> dict[str, int]:
    if len(data) < 64 or data[:2] != b"MZ":
        fail("INVALID_PE_HEADER", "The image has no complete DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if not 64 <= pe_offset <= MAX_HEADER_BYTES - 24 or len(data) < pe_offset + 24:
        fail("INVALID_PE_HEADER", "The PE header offset is invalid or unavailable")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        fail("INVALID_PE_HEADER", "The image has no PE signature")
    machine, sections, timestamp = struct.unpack_from("<HHI", data, pe_offset + 4)
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    header_extent = optional_offset + optional_size + sections * 40
    if machine not in (0x14C, 0x8664) or not 1 <= sections <= 96:
        fail("INVALID_PE_HEADER", "Only structurally valid x86 or x64 PE images are supported")
    if header_extent > MAX_HEADER_BYTES or len(data) < header_extent or optional_size < 96:
        fail("INVALID_PE_HEADER", "The optional or section headers are incomplete or oversized")
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if (machine, magic) not in ((0x14C, 0x10B), (0x8664, 0x20B)) or (magic == 0x20B and optional_size < 112):
        fail("INVALID_PE_HEADER", "The PE machine and optional header format disagree")
    preferred_base = struct.unpack_from("<I" if magic == 0x10B else "<Q", data, optional_offset + (28 if magic == 0x10B else 24))[0]
    image_size, headers_size = struct.unpack_from("<II", data, optional_offset + 56)
    entry_point = struct.unpack_from("<I", data, optional_offset + 16)[0]
    if not header_extent <= headers_size <= image_size <= MAX_IMAGE_BYTES or entry_point >= image_size:
        fail("INVALID_PE_HEADER", "PE image/header sizes or entry point are out of bounds")
    return {"machine": machine, "optional_magic": magic, "number_of_sections": sections,
            "time_date_stamp": timestamp, "pe_offset": pe_offset, "header_extent": header_extent,
            "size_of_headers": headers_size, "size_of_image": image_size,
            "entry_point_rva": entry_point, "preferred_image_base": preferred_base}


def validate_image_headers(source: dict[str, int], live: dict[str, int], actual_base: int, size: int) -> list[dict[str, Any]]:
    machine = source.get("machine")
    if machine not in (0x14C, 0x8664) or live.get("machine") != machine:
        fail("IMAGE_MISMATCH", "The source and live PE machines disagree")
    if source.get("size_of_image") != size or live.get("size_of_image") != size:
        fail("IMAGE_MISMATCH", "Source/live SizeOfImage must both equal the declared size")
    limit = 1 << (32 if machine == 0x14C else 64)
    if type(actual_base) is not int or type(size) is not int or not 0 < size <= MAX_IMAGE_BYTES or not 0 < actual_base < limit or actual_base + size > limit:
        fail("INVALID_IMAGE_RANGE", "The actual image range overflows the PE address width")
    for name in ("optional_magic", "number_of_sections", "time_date_stamp", "pe_offset", "size_of_headers"):
        if name in source and source.get(name) != live.get(name):
            fail("IMAGE_MISMATCH", f"Source and live PE header field differs: {name}")
    if "entry_point_rva" in source or "entry_point_rva" in live:
        for header in (source, live):
            entry = header.get("entry_point_rva")
            if type(entry) is not int or not 0 <= entry < size:
                fail("INVALID_PE_HEADER", "Source/live entry point must be a valid in-image RVA")
    # A runtime may rewrite EntryPoint or ImageBase. Their observed differences
    # are evidence, without identifying an original entry point or executable PE.
    return [{"field": name, "source_value": source[name], "live_value": live[name]}
            for name in ("entry_point_rva", "preferred_image_base")
            if name in source and name in live and source[name] != live[name]]


def validated_read(reader: Any, address: int, length: int) -> dict[str, Any]:
    row = reader.read(address, length)
    if not isinstance(row, dict):
        fail("INVALID_READ_RESULT", "Reader did not return a result object")
    data, count, success, winerror = (row.get(name) for name in ("data", "transferred_bytes", "success", "winerror"))
    if not isinstance(data, bytes) or type(count) is not int or not 0 <= count <= length or len(data) != count or type(success) is not bool or type(winerror) is not int or not 0 <= winerror <= 0xFFFFFFFF:
        fail("INVALID_READ_RESULT", "ReadProcessMemory returned an inconsistent transfer count or result")
    return {"data": data, "transferred_bytes": count, "success": success, "winerror": winerror}


def attempt_row(row: dict[str, Any], rva: int, requested: int, source: str) -> dict[str, Any]:
    return {"rva": hex(rva), "requested_bytes": requested, "transferred_bytes": row["transferred_bytes"],
            "success": row["success"], "winerror": row["winerror"], "source": source,
            "transferred_sha256": hashlib.sha256(row["data"]).hexdigest() if row["data"] else None}


def coverage_row(rva: int, length: int, data: bytes, attempts: list[dict[str, Any]], reason: str | None = None) -> dict[str, Any]:
    row = {"rva": hex(rva), "requested_bytes": length, "observed_bytes": len(data),
           "coverage_complete": len(data) == length, "observed_prefix_bytes": len(data),
           "observed_sha256": hashlib.sha256(data).hexdigest() if data else None, "attempts": attempts}
    if reason is not None:
        row["unobserved_reason"] = reason
    return row


def finish_coverage(pages: list[dict[str, Any]], size: int, stopped: str | None = None) -> dict[str, Any]:
    observed = sum(page["observed_bytes"] for page in pages)
    result = {"pages": pages, "observed_bytes": observed, "unobserved_bytes": size - observed,
              "unverified_output_bytes": sum(page["requested_bytes"] for page in pages if page.get("output_bytes_unverified")),
              "coverage_complete": observed == size, "counting": "union_of_observed_prefix_bytes_per_disjoint_rva_extent"}
    if stopped:
        result["stopped_reason"] = stopped
    return result


def persist_prefix(write_at: Callable[[int, bytes], None], rva: int, length: int, previous: bytes,
                   data: bytes, attempts: list[dict[str, Any]]) -> tuple[dict[str, Any], Exception | None]:
    """Bind coverage to successfully persisted bytes, including short writes.

    A sink may report a trustworthy written_prefix_bytes on its exception.
    Without that count the affected output extent is explicitly unverified;
    retaining an earlier hash would falsely describe overwritten file bytes.
    """
    failure: Exception | None = None
    try:
        if data:
            write_at(rva, data)
        written: int | None = len(data)
    except Exception as error:
        failure = error
        written = getattr(error, "written_prefix_bytes", None)
        if type(written) is not int or not 0 <= written <= len(data):
            written = None
    attempts[-1]["output_write"] = {"success": failure is None, "written_prefix_bytes": written}
    if written is None:
        row = coverage_row(rva, length, b"", attempts, "output_write_count_unknown")
        row["output_bytes_unverified"] = True
    else:
        combined = bytearray(previous)
        copied = data[:written]
        if len(copied) > len(combined):
            combined.extend(copied[len(combined):])
        combined[:len(copied)] = copied
        row = coverage_row(rva, length, bytes(combined), attempts)
    if failure is not None:
        row["output_write_error"] = error_row(failure, "OUTPUT_WRITE_FAILED")
    return row, failure


def read_segments(reader: Any, base: int, size: int, write_at: Callable[[int, bytes], None],
                  stop: Callable[[], str | None] | None = None) -> dict[str, Any]:
    """Read 64KiB extents; retry partial extents once per 4KiB page.

    Both RPM results describe prefixes. Combining them uses the longer observed
    prefix, replacing only bytes actually returned by the page retry. A failed
    retry therefore never erases a successfully copied initial prefix.
    """
    if type(base) is not int or type(size) is not int or not 0 < size <= MAX_IMAGE_BYTES or not 0 < base or base + size > 1 << (ctypes.sizeof(ctypes.c_void_p) * 8):
        fail("INVALID_IMAGE_RANGE", "The read range is invalid")
    pages: list[dict[str, Any]] = []
    committed = 0
    try:
        for offset in range(0, size, CHUNK_BYTES):
            length = min(CHUNK_BYTES, size - offset)
            reason = stop() if stop else None
            if reason:
                for remaining in range(offset, size, CHUNK_BYTES):
                    pages.append(coverage_row(remaining, min(CHUNK_BYTES, size - remaining), b"", [], reason))
                return finish_coverage(pages, size, reason)
            initial = validated_read(reader, base + offset, length)
            initial_attempt = attempt_row(initial, offset, length, "initial_chunk")
            initial_row, write_error = persist_prefix(write_at, offset, length, b"", initial["data"], [initial_attempt])
            if write_error is not None:
                pages.append(initial_row)
                committed = offset + length
                raise write_error
            if initial["transferred_bytes"] == length:
                pages.append(initial_row)
                committed = offset + length
                continue
            first_page = len(pages)
            for page_offset in range(0, length, PAGE_BYTES):
                page_size = min(PAGE_BYTES, length - page_offset)
                initial_prefix = initial["data"][page_offset:page_offset + page_size]
                pages.append(coverage_row(offset + page_offset, page_size, initial_prefix,
                                          [initial_attempt], "page_retry_not_attempted"))
            # The entire initial prefix has already been written. Register all
            # of it before any retry can raise, including later pages.
            committed = offset + length
            for page_index, page_offset in enumerate(range(0, length, PAGE_BYTES)):
                page_size = min(PAGE_BYTES, length - page_offset)
                initial_prefix = initial["data"][page_offset:page_offset + page_size]
                attempts = [initial_attempt]
                try:
                    retry = validated_read(reader, base + offset + page_offset, page_size)
                except Exception as error:
                    # Initial copied bytes are evidence even when a retry API fails.
                    pages[first_page + page_index]["unobserved_reason"] = "retry_error"
                    pages[first_page + page_index]["retry_error"] = error_row(error, "MEMORY_READ_FAILED")
                    raise
                attempts.append(attempt_row(retry, offset + page_offset, page_size, "page_retry"))
                pages[first_page + page_index], write_error = persist_prefix(write_at, offset + page_offset, page_size,
                                                                            initial_prefix, retry["data"], attempts)
                if write_error is not None:
                    raise write_error
    except Exception as error:
        for remaining in range(committed, size, CHUNK_BYTES):
            pages.append(coverage_row(remaining, min(CHUNK_BYTES, size - remaining), b"", [], "capture_aborted"))
        coverage = finish_coverage(pages, size, "capture_aborted")
        if isinstance(error, MemoryImageError):
            error.coverage = coverage
            raise
        wrapped = MemoryImageError("MEMORY_READ_FAILED", str(error))
        wrapped.coverage = coverage
        raise wrapped from error
    return finish_coverage(pages, size)


class WindowsMemoryReader:
    """One retained read-only HANDLE; no PID re-open occurs during capture."""
    def __init__(self, pid: int):
        if os.name != "nt":
            fail("UNSUPPORTED_PLATFORM", "Windows process memory APIs are required")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        k = self.kernel
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenProcess.restype = wintypes.HANDLE
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        k.QueryFullProcessImageNameW.restype = wintypes.BOOL
        k.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]
        k.GetProcessTimes.restype = wintypes.BOOL
        k.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k.GetExitCodeProcess.restype = wintypes.BOOL
        k.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        k.ReadProcessMemory.restype = wintypes.BOOL
        self.pid = pid
        self.handle = k.OpenProcess(0x0010 | 0x1000, False, pid)
        if not self.handle:
            fail("OPEN_PROCESS_FAILED", f"OpenProcess failed with Winerror {ctypes.get_last_error()}")

    def __enter__(self) -> WindowsMemoryReader:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        if self.handle:
            handle, self.handle = self.handle, None
            if not self.kernel.CloseHandle(handle):
                fail("CLOSE_HANDLE_FAILED", f"CloseHandle failed with Winerror {ctypes.get_last_error()}")

    def identity(self) -> dict[str, Any]:
        if not self.handle:
            fail("CLOSED_HANDLE", "The process HANDLE is already closed")
        name, length = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
        if not self.kernel.QueryFullProcessImageNameW(self.handle, 0, name, ctypes.byref(length)):
            fail("PROCESS_IDENTITY_FAILED", f"QueryFullProcessImageNameW failed with Winerror {ctypes.get_last_error()}")
        creation, exit_time, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
        if not self.kernel.GetProcessTimes(self.handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel_time), ctypes.byref(user_time)):
            fail("PROCESS_IDENTITY_FAILED", f"GetProcessTimes failed with Winerror {ctypes.get_last_error()}")
        exit_code = wintypes.DWORD()
        if not self.kernel.GetExitCodeProcess(self.handle, ctypes.byref(exit_code)):
            fail("PROCESS_IDENTITY_FAILED", f"GetExitCodeProcess failed with Winerror {ctypes.get_last_error()}")
        filetime = lambda value: (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)
        exited = filetime(exit_time)
        return {"pid": self.pid, "executable": name.value, "creation_filetime": str(filetime(creation)),
                "exit_filetime": str(exited), "exit_code": int(exit_code.value),
                "alive": exited == 0 and exit_code.value == 259, "observed_utc": utc_now()}

    def read(self, address: int, length: int) -> dict[str, Any]:
        if not self.handle:
            fail("CLOSED_HANDLE", "The process HANDLE is already closed")
        if type(address) is not int or type(length) is not int or not 0 < length <= MAX_HEADER_BYTES or not 0 < address or address + length > 1 << (ctypes.sizeof(ctypes.c_void_p) * 8):
            fail("INVALID_IMAGE_RANGE", "ReadProcessMemory range is outside the bounded pointer/read limit")
        data, count = ctypes.create_string_buffer(length), ctypes.c_size_t()
        ctypes.set_last_error(0)
        success = bool(self.kernel.ReadProcessMemory(self.handle, ctypes.c_void_p(address), data, length, ctypes.byref(count)))
        error = 0 if success else ctypes.get_last_error()
        if count.value > length:
            fail("INVALID_READ_RESULT", "ReadProcessMemory reported more bytes than requested")
        return {"data": data.raw[:count.value], "transferred_bytes": int(count.value), "success": success, "winerror": error}


def live_pe_header(reader: Any, base: int) -> dict[str, int]:
    def exact(address: int, length: int) -> bytes:
        result = validated_read(reader, address, length)
        if result["transferred_bytes"] != length:
            fail("INVALID_PE_HEADER", f"Live PE header was not fully readable: requested={length}, transferred={result['transferred_bytes']}, Winerror={result['winerror']}")
        return result["data"]
    dos = exact(base, 64)
    if dos[:2] != b"MZ":
        fail("INVALID_PE_HEADER", "Live memory has no DOS signature")
    offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if not 64 <= offset <= MAX_HEADER_BYTES - 24:
        fail("INVALID_PE_HEADER", "Live PE header offset exceeds the bounded header limit")
    coff = exact(base + offset, 24)
    sections, optional_size = struct.unpack_from("<H", coff, 6)[0], struct.unpack_from("<H", coff, 20)[0]
    extent = offset + 24 + optional_size + sections * 40
    if coff[:4] != b"PE\0\0" or not 1 <= sections <= 96 or not 96 <= optional_size <= 4096 or extent > MAX_HEADER_BYTES:
        fail("INVALID_PE_HEADER", "Live PE header structure exceeds the bounded header limit")
    return parse_pe_header(exact(base, extent))


class SourceSnapshot:
    """Keep the disk source open without write/delete sharing on Windows."""
    def __init__(self, path: Path):
        self.path = check_path_aliases(path, must_exist=True)
        self.file: Any = None

    def __enter__(self) -> SourceSnapshot:
        if os.name == "nt":
            import msvcrt
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle.restype = wintypes.BOOL
            handle = kernel.CreateFileW(str(self.path), 0x80000000, 1, None, 3, 0x80, None)
            if handle == ctypes.c_void_p(-1).value:
                fail("SOURCE_OPEN_FAILED", f"CreateFileW(source, read-only share) failed with Winerror {ctypes.get_last_error()}")
            try:
                descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
            except Exception:
                kernel.CloseHandle(handle)
                raise
            self.file = os.fdopen(descriptor, "rb")
            # Validate the opened HANDLE itself, closing the path/handle race.
            kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
            kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            count = kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
            final_path = buffer.value[4:] if buffer.value.startswith("\\\\?\\") else buffer.value
            if not 0 < count < len(buffer) or os.path.normcase(final_path) != os.path.normcase(str(self.path)):
                self.file.close()
                fail("PATH_ALIAS", "Opened source HANDLE differs from the expected canonical path")
        else:
            self.file = self.path.open("rb")
        try:
            metadata = os.fstat(self.file.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or not 1 <= metadata.st_size <= MAX_SOURCE_BYTES:
                fail("INVALID_SOURCE", "Source must be a regular, unaliased file no larger than 256 MiB")
            self.initial_stat = self.stat_key(metadata)
            self.initial_path_stat = self.stat_key(self.path.stat())
            # Windows Python versions may give stat() and fstat() different
            # ctime semantics. Compare each API to its own baseline; compare
            # file IDs/length across APIs, without conflating those clocks.
            if self.initial_stat[:3] != self.initial_path_stat[:3]:
                fail("SOURCE_CHANGED", "The source path and opened HANDLE refer to different files")
            self.sha256 = self.hash()
            self.file.seek(0)
            self.header = parse_pe_header(self.file.read(min(MAX_HEADER_BYTES, metadata.st_size)))
            self.verify()
            return self
        except BaseException:
            self.file.close()
            raise

    @staticmethod
    def stat_key(value: os.stat_result) -> tuple[int, ...]:
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)

    def hash(self) -> str:
        self.file.seek(0)
        digest, total = hashlib.sha256(), 0
        while block := self.file.read(CHUNK_BYTES):
            total += len(block)
            if total > MAX_SOURCE_BYTES:
                fail("SOURCE_CHANGED", "Source exceeded its size bound during hashing")
            digest.update(block)
        return digest.hexdigest()

    def verify(self) -> None:
        check_path_aliases(self.path, must_exist=True)
        if self.initial_stat != self.stat_key(os.fstat(self.file.fileno())) or self.initial_path_stat != self.stat_key(self.path.stat()) or self.hash() != self.sha256:
            fail("SOURCE_CHANGED", "Source path, identity, metadata or SHA-256 changed during capture")

    def receipt(self) -> dict[str, Any]:
        return {"path": str(self.path), "size_bytes": self.initial_stat[2], "sha256": self.sha256,
                "header": self.header, "write_delete_sharing_denied": os.name == "nt", "verified_stable": True}

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        if self.file is not None:
            self.file.close()


def validate_identity(identity: dict[str, Any], config: argparse.Namespace, *, require_alive: bool) -> None:
    path = absolute_path(identity["executable"], "observed executable")
    if os.path.normcase(str(path)) != os.path.normcase(str(config.expected_exe)) or int(identity["creation_filetime"]) != config.expected_start_filetime or identity["pid"] != config.pid:
        fail("PROCESS_IDENTITY_MISMATCH", "Retained process HANDLE does not match expected executable, PID and creation FILETIME")
    if require_alive and not identity["alive"]:
        fail("PROCESS_EXITED", "The identified process is no longer alive")


def file_hash(file: Any) -> str:
    file.seek(0)
    digest = hashlib.sha256()
    while block := file.read(CHUNK_BYTES):
        digest.update(block)
    return digest.hexdigest()


def tool_identity() -> dict[str, Any]:
    path = Path(__file__)
    with path.open("r", encoding="utf-8", newline="") as source:
        text = source.read(MAX_HEADER_BYTES + 1)
    data = text.encode("utf-8")
    if len(data) > MAX_HEADER_BYTES:
        fail("INVALID_TOOL_SOURCE", "Memory image collector source exceeds 1 MiB")
    return {"file": path.name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def capture_memory_image(config: argparse.Namespace) -> dict[str, Any]:
    config.expected_exe = check_path_aliases(config.expected_exe, must_exist=True)
    output_parent = check_path_aliases(config.out.parent, must_exist=False)
    if not output_parent.is_dir():
        fail("INVALID_PATH", "Output prefix parent must be an existing directory")
    binary_path, receipt_path = Path(str(config.out) + ".bin"), Path(str(config.out) + ".json")
    if any(os.path.lexists(path) for path in (binary_path, receipt_path)):
        fail("OUTPUT_EXISTS", "Both output names must be new; existing evidence is never overwritten")
    result: dict[str, Any] = {"schema_version": 1, "status": "failed", "pid": config.pid,
        "base": hex(config.base), "size_bytes": config.size, "atomic": False, "runnable_pe": False,
        "layout": "flat_rva_memory", "observation": "cooperative_non_atomic_external_read",
        "unobserved_fill": "zero", "zero_fill_is_observed": False,
        "started_utc": utc_now(), "ended_utc": None,
        "limits": {"image_bytes": MAX_IMAGE_BYTES, "chunk_bytes": CHUNK_BYTES, "retry_page_bytes": PAGE_BYTES, "timeout_ms": config.timeout_ms},
        "identity": {"expected_executable": str(config.expected_exe), "expected_creation_filetime": str(config.expected_start_filetime), "start": None, "end": None},
        "tool": tool_identity(),
        "coverage": None, "image": None, "error": None,
        "live_header": None, "mutable_header_differences": None,
        "cleanup": {"process_handle_closed": False, "source_handle_closed": False}}
    started = time.monotonic()
    source, reader, image, receipt = SourceSnapshot(config.expected_exe), None, None, None
    source_open = False

    def record_failure(error: Exception, fallback: str = "CAPTURE_FAILED") -> None:
        row = error_row(error, fallback)
        if result["error"] is None:
            result["error"] = row
        else:
            result.setdefault("additional_errors", []).append(row)
        result["status"] = "failed"

    try:
        source.__enter__()
        source_open = True
        result["source"] = source.receipt()
        result["source"]["verified_stable"] = False
        reader = WindowsMemoryReader(config.pid)
        result["identity"]["start"] = reader.identity()
        validate_identity(result["identity"]["start"], config, require_alive=True)
        live = live_pe_header(reader, config.base)
        result["live_header"] = live
        result["mutable_header_differences"] = validate_image_headers(source.header, live, config.base, config.size)
        # Keep the exclusively created JSON HANDLE until final metadata commit.
        # A failure after reservation retains a receipt alongside any read bytes.
        receipt = receipt_path.open("x", encoding="utf-8", newline="\n")
        image = binary_path.open("xb+", buffering=0)
        image.truncate(config.size)  # Explicitly unobserved zero placeholders.
        result["coverage"] = finish_coverage([coverage_row(0, config.size, b"", [], "not_attempted")], config.size)

        def write_at(offset: int, data: bytes) -> None:
            if not 0 <= offset <= config.size - len(data):
                fail("INVALID_READ_RESULT", "Reader attempted an out-of-range output write")
            try:
                image.seek(offset)
            except Exception as error:
                wrapped = MemoryImageError("OUTPUT_WRITE_FAILED", f"Cannot seek the memory image: {error}")
                wrapped.written_prefix_bytes = 0
                raise wrapped from error
            written = image.write(data)
            if written != len(data):
                error = MemoryImageError("OUTPUT_WRITE_FAILED", "The memory image write was incomplete")
                error.written_prefix_bytes = written
                raise error

        def stop() -> str | None:
            if (time.monotonic() - started) * 1000 >= config.timeout_ms:
                return "timeout"
            identity = reader.identity()
            validate_identity(identity, config, require_alive=False)
            return None if identity["alive"] else "process_exited"

        result["coverage"] = read_segments(reader, config.base, config.size, write_at, stop)
        result["status"] = "completed" if result["coverage"]["coverage_complete"] else "partial"
        if result["coverage"].get("stopped_reason"):
            reason = result["coverage"]["stopped_reason"]
            result["error"] = {"code": "TIMEOUT" if reason == "timeout" else "PROCESS_EXITED", "message": f"Capture stopped: {reason}; unread bytes remain explicitly unobserved"}
    except Exception as error:
        record_failure(error)
        if getattr(error, "coverage", None) is not None:
            result["coverage"] = error.coverage
    finally:
        if result["coverage"] and result["coverage"].get("unverified_output_bytes"):
            result["unobserved_fill"] = "zero_except_unverified_output_write_ranges"
            result["unobserved_fill_note"] = "Ordinary unread gaps remain zero placeholders; extents marked output_bytes_unverified may contain partially overwritten data and have no accepted observed hash"
        if reader is not None:
            try:
                result["identity"]["end"] = reader.identity()
                validate_identity(result["identity"]["end"], config, require_alive=False)
            except Exception as error:
                result["identity"]["end_error"] = error_row(error)
                record_failure(error)
            try:
                reader.close()
                result["cleanup"]["process_handle_closed"] = True
            except Exception as error:
                record_failure(error, "CLOSE_HANDLE_FAILED")
        if source_open:
            try:
                source.verify()
                result["source"]["verified_stable"] = True
            except Exception as error:
                record_failure(error)
            try:
                source.close()
                result["cleanup"]["source_handle_closed"] = True
            except Exception as error:
                record_failure(error, "SOURCE_CLOSE_FAILED")
        if image is not None:
            try:
                image.flush()
                actual_size = os.fstat(image.fileno()).st_size
                result["image"] = {"file": binary_path.name, "size_bytes": actual_size,
                                   "sha256": file_hash(image), "hash_includes_unobserved_zero_fill": True}
                if actual_size != config.size:
                    fail("OUTPUT_SIZE_MISMATCH", "The output memory image length differs from its declared size")
            except Exception as error:
                record_failure(error, "OUTPUT_FINALIZE_FAILED")
            finally:
                try:
                    image.close()
                except Exception as error:
                    record_failure(error, "OUTPUT_CLOSE_FAILED")
        result["ended_utc"] = utc_now()
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        if receipt is not None:
            try:
                payload = json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n"
                if len(payload.encode("utf-8")) > MAX_RECEIPT_BYTES:
                    fail("RECEIPT_TOO_LARGE", "Receipt exceeded the 16 MiB evidence bound")
                receipt.write(payload)
                receipt.flush()
            except Exception as error:
                record_failure(error, "RECEIPT_WRITE_FAILED")
            finally:
                try:
                    receipt.close()
                except Exception as error:
                    record_failure(error, "RECEIPT_CLOSE_FAILED")
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        result = capture_memory_image(parse_arguments(argv))
    except Exception as error:
        result = {"schema_version": 1, "status": "failed", "error": error_row(error)}
    # Explicit UTF-8 even when the launching console has a legacy code page.
    sys.stdout.buffer.write((json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0 if result["status"] in ("completed", "partial") else 1


if __name__ == "__main__":
    raise SystemExit(main())
