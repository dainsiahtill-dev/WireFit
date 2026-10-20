"""Create a declared PE loading envelope around exact existing dump bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--start", default="0x42b000")
parser.add_argument("--entry", default="0x42b560")
arguments = parser.parse_args()
start = int(arguments.start, 16)
entry = int(arguments.entry, 16)
if start % 0x1000 or not start <= entry < start + 0x1000:
    raise ValueError("Start must be page aligned and contain entry")
source = root / "artifacts/research/vmde/grid-kernel-analysis/run-ayl3ui/analysis-input.exe"
output = root / f"artifacts/ida-mcp/runtime/vmde-window-{start:08x}-source"
output.mkdir(exist_ok=True)
data = source.read_bytes()
pe = struct.unpack_from("<I", data, 0x3c)[0]
if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\x00\x00":
    raise ValueError("Source is not a PE dump")
machine, sections = struct.unpack_from("<HH", data, pe + 4)
optional_size = struct.unpack_from("<H", data, pe + 20)[0]
optional = bytearray(data[pe + 24:pe + 24 + optional_size])
if machine != 0x14c or struct.unpack_from("<H", optional, 0)[0] != 0x10b:
    raise ValueError("Expected existing x86 PE32 research dump")
imagebase = struct.unpack_from("<I", optional, 28)[0]
length = 0x1000
rva = start - imagebase
raw_offset = None
for index in range(sections):
    position = pe + 24 + optional_size + index * 40
    virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, position + 8)
    if virtual_address <= rva and rva + length <= virtual_address + raw_size:
        raw_offset = raw_pointer + rva - virtual_address
        break
if raw_offset is None or raw_offset + length > len(data):
    raise ValueError("Selected window is not completely file-backed")
window = data[raw_offset:raw_offset + length]
header = bytearray(0x200)
header[:2] = b"MZ"
struct.pack_into("<I", header, 0x3c, 0x80)
header[0x80:0x84] = b"PE\x00\x00"
struct.pack_into("<HHIIIHH", header, 0x84, 0x14c, 1, 0, 0, 0, 0xe0, 0x102)
optional = optional[:0xe0]
struct.pack_into("<III", optional, 4, length, 0, 0)
struct.pack_into("<III", optional, 16, entry - imagebase, rva, 0)
struct.pack_into("<II", optional, 32, 0x1000, 0x200)
struct.pack_into("<III", optional, 56, rva + length, 0x200, 0)
struct.pack_into("<I", optional, 92, 16)
optional[96:224] = bytes(128)
header[0x98:0x178] = optional
header[0x178:0x180] = b".text\x00\x00\x00"
struct.pack_into("<IIIIIIHHI", header, 0x180, length, rva, length, 0x200, 0, 0, 0, 0, 0x60000020)
target = output / f"vmde-window-{start:08x}.exe"
target.write_bytes(header + window)
receipt = {
    "kind": "declared-bounded-dump-derivative",
    "source": str(source), "source_sha256": hashlib.sha256(data).hexdigest(),
    "source_file_offset": raw_offset, "source_va": hex(start), "source_rva": hex(rva), "size_bytes": length,
    "window_sha256": hashlib.sha256(window).hexdigest(),
    "derivative": str(target), "derivative_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    "imagebase": hex(imagebase), "entrypoint": hex(entry),
    "limitations": ["PE loading headers are synthetic; code window bytes and virtual addresses match the existing dump.", "Only this 4 KiB window is present. External xrefs/calls/types and original-target fidelity cannot be recovered from this derivative.", "This file is analyzed statically and must never be executed."],
}
(output / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
print(json.dumps(receipt))
