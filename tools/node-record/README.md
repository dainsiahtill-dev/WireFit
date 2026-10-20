# Bounded node record writer

`model.py` implements only the observed 40-byte record write at VA `0x480230`.
It accepts an existing byte buffer of 1..289 records, dimensions 2..16, an
existing record ID and inclusive coordinates `0..width`, `0..height`.
Integers exclude Python booleans. Input bytes remain unchanged.

```python
from model import patch_node_record
patched = patch_node_record(bytes(80), 1, 2, 0, 2, 2)
```

The writer stores little-endian double x/y at offsets 0/8, float x/y at 16/20,
and byte 3 at offset 28 for a corner, otherwise 0. All remaining bytes,
including the 15 unknown bytes in the selected record, are preserved. This
does not reconstruct a C++ class, allocator, constructor or ownership model.

The independent static inventory is
`artifacts/research/vmde/node-records/static-abi.json`. It records 38 complete
instructions / 104 contiguous bytes, SHA256
`d7daa514e39357d058792f132bfbc084f1b03d8f67a17668af8839eb8da6aa38`.
There are no calls or unknown exits in this body. ECX supplies a synthetic
context; fields +8/+0x34/+0x38 hold the record pointer / width / height.
The stack holds node ID, x, y after the return address; `RET 12` restores
ESP to entry ESP +16. The fixed raw PE dump and a fully observed owned flat
main image contain identical body bytes at their respective file/RVA offsets.

Run the pure model and runner boundary tests, without importing Unicorn:

```powershell
python -X utf8 -B -I -S tools/node-record/test_model.py
python -X utf8 -B -I -S tools/node-record/test_replay.py
```

After independent runner review, a bounded CPU replay can be requested with:

```powershell
python -X utf8 -B -I -S tools/node-record/replay.py `
  --module-path E:/wirefit/.tools/analysis/unicorn-python `
  --image E:/wirefit/exports/vmde-20261020/unpacked_vmde.exe `
  --out E:/wirefit/artifacts/research/vmde/node-records/NEW-RUN
```

The caller must enforce a 30-second process deadline and retain stdout/stderr
and exit status. The output directory must not exist. Neither the source PE
nor any original process is loaded or executed. Only the pinned 104 body
bytes run inside the Unicorn CPU emulator. The pinned source SHA is
`50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992`;
the raw file offset is `0x7f630`, distinct from RVA `0x80230`.

The runner freezes its local model before constructing 31 deterministic
cases: 2x2, 3x2 and 16x16 corners, edges and interiors, plus four maximum-ID
cases at ID 288 / capacity 289. They are regression samples selected after
static recovery, not unseen-input validation. The runner admits only the
38 pinned instruction addresses and lengths, at most 128 instructions and
100000 **microseconds** per case. It rejects unknown instruction fetches,
memory faults and writes outside the five observed fields or the one stack
slot used to preserve ESI. No imports, system calls or external functions
are emulated. Synthetic context, records and stack have unmapped guard
pages; surrounding mapped bytes and permissions are checked afterwards.

`unicorn-pins.json` fixes version 2.1.4, all 21 installed Python source files,
the exact Windows DLL and the API header, including a legitimate empty package
initializer. All 23 files are read, hash-checked and cached before creating
`NEW-RUN/runtime`. Only those exact bytes are copied there with exclusive
creation; the original installation is never added to the import path.
The staged inventory is checked before import, so an extra extension module
in the original installation cannot shadow the pinned Python initializer.
The receipt distinguishes original source identities, staged identities and
actual loaded origins; both source and staged files are rehashed afterwards.
A fresh cache prefix prevents loading the installation's old bytecode cache.
Only this fixed approximately 10 MB runtime subset is staged, not an SDK,
system DLL tree or original executable.
The API header specifies the timeout unit as microseconds; the installed
Python binding forwards the value unchanged even though its docstring says
milliseconds. The runner explicitly writes and reads x87 CW `0x037f`,
status `0` (TOP 0), and tag `0xffff`, and fails if the roundtrip differs.
Before/after actual x87 state is recorded. These are synthetic settings;
the natural caller's FPU state and constructor initialization remain unknown.
Coordinates 0..16 are exactly representable in binary32 and binary64.

`result.json` and stdout contain the final bounded JSON receipt. Each attempted
case retains actual storage bytes, register observations, write addresses,
PC sequence, steps, model comparison and wrong-flag/wrong-coordinate negative
controls. Comparison covers the entire storage, including neighbors and
unknown fields. Missing CPU output stays null; failure stops subsequent
cases, whose rows remain explicitly unattempted. `progress.json` is replaced
atomically before/after cases, while fixed source copies and `body.bin` use
exclusive creation. A forced kill can leave a started case without its final
observation; the progress receipt must not be promoted to a complete run.

Successful CPU replay would substantiate this local writer under these
synthetic conditions. It would not prove native execution, a natural image
processing path, full object initialization, or a runnable restored program.
