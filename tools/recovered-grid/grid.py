"""Strict UTF-8 single-case CLI for the independent recovered grid model."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from model import number_grid

MAX_INPUT_BYTES = 65536
CASE_FIELDS = {"id", "width", "height", "node_stride", "source_stride", "labels"}
BAD_COMPONENT = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
RESERVED = re.compile(r"(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)")


def checked_path(value: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise ValueError("Expected a bounded local path")
    selected = Path(value)
    if os.name == "nt" and (selected.anchor and not selected.is_absolute() or selected.is_absolute() and re.match(r"^[A-Za-z]:[\\/]", value) is None):
        raise ValueError("Drive-relative, root-relative and network paths are not accepted")
    for part in selected.parts:
        if part == selected.anchor:
            continue
        if part in (".", "..") or part.endswith((".", " ")) or BAD_COMPONENT.search(part) or RESERVED.match(part):
            raise ValueError("Aliased or special path component")
    return selected.absolute()


def check_chain(selected: Path) -> None:
    for current in (selected, *selected.parents):
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Symlinks, junctions and reparse aliases are not accepted")
    if os.path.normcase(str(selected.resolve(strict=True))) != os.path.normcase(str(selected)):
        raise ValueError("Path resolves through an alias")


def read_input(selected: Path) -> bytes:
    check_chain(selected)
    entry = selected.stat()
    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or not 0 < entry.st_size <= MAX_INPUT_BYTES:
        raise ValueError("Input must be one ordinary single-link file of 1..65536 bytes")
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_nlink)
    state = lambda value: (*identity(value), value.st_ctime_ns)
    with selected.open("rb") as handle:
        first = os.fstat(handle.fileno())
        if identity(first) != identity(entry):
            raise ValueError("Input changed before opening")
        data = handle.read(MAX_INPUT_BYTES + 1)
        last = os.fstat(handle.fileno())
    check_chain(selected)
    final = selected.stat()
    # stat and fstat have distinct Windows ctime semantics; compare each API
    # against itself while retaining common identity/mtime across both APIs.
    if state(first) != state(last) or state(entry) != state(final) or identity(last) != identity(final) or len(data) != entry.st_size:
        raise ValueError("Input changed during the retained-handle read")
    return data


def parse_case(data: bytes) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON field: " + key)
            value[key] = item
        return value

    def nonfinite(_):
        raise ValueError("NaN and infinity are not JSON inputs")

    value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=unique, parse_constant=nonfinite)
    if type(value) is not dict or set(value) != CASE_FIELDS:
        raise ValueError("A case must contain exactly id,width,height,node_stride,source_stride,labels")
    if not isinstance(value["id"], str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value["id"]) is None:
        raise ValueError("Invalid case id")
    width, source_stride = value["width"], value["source_stride"]
    if type(width) is not int or type(source_stride) is not int or not 2 <= width <= 16 or not width <= source_stride <= width + 8:
        raise ValueError("source_stride must be an integer from width through width+8")
    return value


def write_output(selected: Path, value: dict) -> dict:
    check_chain(selected.parent)
    data = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n"
    with selected.open("x", encoding="utf-8", errors="strict", newline="\n") as output:
        if output.write(data) != len(data):
            raise OSError("Short output write")
        output.flush()
        os.fsync(output.fileno())
    check_chain(selected)
    saved = read_input(selected)
    expected = data.encode("utf-8", errors="strict")
    if saved != expected:
        raise OSError("New output changed after writing")
    return {"path": str(selected), "size_bytes": len(saved), "sha256": hashlib.sha256(saved).hexdigest()}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


class Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            raise ValueError("Repeated option: " + str(option_string))
        setattr(namespace, self.dest, values)


def main(argv=None) -> int:
    try:
        parser = Parser(description="Number one dense-label grid under the bounded 2..16 local contract", allow_abbrev=False)
        parser.add_argument("--input", required=True, action=Once)
        parser.add_argument("--out", required=True, action=Once)
        args = parser.parse_args(argv)
        source, destination = checked_path(args.input), checked_path(args.out)
        if os.path.normcase(str(source)) == os.path.normcase(str(destination)):
            raise ValueError("Input and output must be different paths")
        check_chain(destination.parent)
        if os.path.lexists(destination):
            raise ValueError("Output already exists")
        case = parse_case(read_input(source))
        result = number_grid(case["labels"], case["width"], case["height"], case["node_stride"])
        value = {"schema_version": 1, "kind": "recovered_grid_numbering", "case_id": case["id"], "width": case["width"],
                 "height": case["height"], "node_stride": case["node_stride"], "nodes": result.nodes,
                 "node_count": result.node_count, "target_rva": "0x98a50"}
        receipt = {"schema_version": 1, "status": "completed", "output": write_output(destination, value), "target_execution": "not_run"}
        code = 0
    except (Exception, KeyboardInterrupt) as error:
        receipt = {"schema_version": 1, "status": "failed", "error": {"code": "GRID_INPUT_OR_OUTPUT_INVALID", "message": str(error).replace("\x00", "?")[:2048]}, "target_execution": "not_run"}
        code = 1
    sys.stdout.buffer.write((json.dumps(receipt, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8", errors="strict"))
    sys.stdout.buffer.flush()
    return code


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    sys.stderr.reconfigure(encoding="utf-8", errors="strict")
    raise SystemExit(main())
