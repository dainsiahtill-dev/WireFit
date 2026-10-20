# Bounded label forest state

This component recovers three local state transitions from saved x86 listings:

| API | Entry | Listed bytes / instructions | Return used |
| --- | --- | --- | --- |
| `lookup(state, index)` | `0x47e8e0` | 56 / 26 | EAX representative |
| `merge_roots(state, keep, drop)` | `0x47e1b0` | 27 / 9 | incidental EAX only |
| `normalize(state)` | `0x47fcb0` | 101 / 42 | incidental EAX only |

None of the three listed bodies calls another function. Normalization has a
three-byte gap at `0x47fcbd..0x47fcbf`; its 101 listed bytes occupy a 104-byte
span. The runner preserves original instruction addresses and fills the gap
with `0xcc`. It never concatenates the two ranges into executable code.

`model.py` is pure Python standard library code. Frozen `LabelState` contains
`width`, `height`, tuple `labels`, tuple `parents`, signed-int32 `components`
and unsigned-byte `dirty`. Dimensions are 1..16, dense labels have exactly
width*height elements and parents have 1..256 entries. Labels select parent
indices. Each parent is a negative int32 root marker or an existing index;
the complete graph, including unused entries, must be acyclic. Booleans are
rejected as integers. `components` is the requested API name for a stored
metadata field; the listings alone do not establish its natural meaning.

```python
from model import LabelState, lookup, merge_roots, normalize
initial = LabelState(2, 1, (0, 2), (-1, -7, 1), 3, 0)
merged = merge_roots(initial, 0, 1)
resolved = lookup(merged, 1)
assert resolved.representative == 0
assert normalize(resolved.state).labels == (0, 0)
```

Lookup compresses only the selected pixel's **initial** label parent entry
and that one pixel; intermediate parents and other pixels remain unchanged.
An initial root causes no state write. Merge requires two different roots,
sets `parents[drop]=keep`, forces dirty to 1 and decrements components with
signed-int32 wrapping; labels remain unchanged. Normalization with dirty 0
returns the identical state, including all existing parent chains. Otherwise
it replaces every pixel with its root's original index, sets dirty to 0 and
resets **all** parents to -1. It does not compact or renumber root indices.

Run only the scoped pure tests:

```powershell
python -X utf8 -B -I -S -m unittest discover -s tools/label-state -p 'test_*.py' -v
```

The model was frozen before constructing CPU scenarios. Tests include fixed
partial-compression expectations, arbitrary negative root markers, unused
cycles, metadata neighbors, count wrap, dirty-zero no-op and capacity 256.
Runner tests do not import Unicorn or execute body instructions; their real
Python children exercise only invalid-input paths. `test-log.json` preserves
the actual RED/GREEN output.

After independent review, the root operator can run the CPU verifier with
an external 30-second process deadline and retained stdout/stderr/exit status:

```powershell
python -X utf8 -B -I -S tools/label-state/replay.py `
  --module-path E:/wirefit/.tools/analysis/unicorn-python `
  --image E:/wirefit/exports/vmde-20261020/unpacked_vmde.exe `
  --out E:/wirefit/artifacts/research/vmde/segmentation-results/NEW-LABEL-CPU-RUN
```

The PE is read only as data. Its exact SHA256 must be
`50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992`
and size 14,454,272 bytes. Every listed instruction is checked through a
unique full raw PE section mapping; flat-RVA offsets are not raw file offsets.
The three saved JSON listings also have fixed identities. Only the 184 listed
bytes are installed at their original VAs in two RX code pages; all other
bytes there are `0xcc`. No whole executable image is mapped into the guest.

The runner reuses only pure bootstrap/IO/runtime helpers from frozen
`tools/node-record/replay.py`, SHA256
`440ccbd82f3056bfe6b08fb16b63be860bea1f66d53f4c6ec68b995b53b15629`.
It verifies retained source bytes before compiling those trusted definitions
with their original `__file__`; the old model, cases and main routine do not
execute. The existing 23-file Unicorn 2.1.4 pins remain unchanged. The helper
validates/cache-reads them, copies exactly those bytes into a new owned runtime
tree, rejects extra staged files before import and checks loaded origins.
The receipt retains original/staged identities and rehashes both afterwards.
This does not claim closure over Python, the host OS or all SDK dependencies.

There are 12 deterministic scenarios and 26 method calls, limited to at most
64 scenarios / 96 calls. They cover root and multi-level lookups, forward and
reverse links, merge/lookup/normalize sequences, dirty 0/1/19/255, signed-count
wrap, a 256-parent chain and unused entries. Scenarios are synthetic regression
inputs selected after static recovery, not unseen or natural image inputs.
Each call allows at most 65,536 instructions, 8,192 writes and 200,000
microseconds. PC and instruction length must belong to the selected method;
the full permitted inventory is exactly 77 instructions. Write permission is
also tied to the actual writer PC and exact context/array field or saved
register stack slot. There are no syscall, external-call or unknown-callee
emulators and no x87 instructions or natural FPU-state claim.

Context, labels, parents and stack occupy separate guarded mappings. Context
unknown bytes and array canaries are compared through full-page hashes against
the independently expected pages. Arguments and preserved-register pushes
are checked explicitly; return ESP must match `RET 4`, `RET 8` or plain `RET`.
Each call resets only synthetic invocation registers/stack. Context/labels/
parents carry the actual preceding CPU result across scenario calls. Actual
input must match the independently advanced declared model trajectory before
the next call; a wrong observation cannot become a new expected starting state.

`result.json` and stdout retain actual full context/label/parent bytes, GP
registers before/after, memory/permission checks, writes, steps and a complete
PC-frequency map plus SHA256 of the ordered `(pc,size)` trace. Only lookup EAX
is compared semantically. Every successful call must reject a wrong-state
mutant; lookups must also reject a wrong-return mutant. Missing CPU bytes or
registers remain absent/null, never filled from the model. A failed call stops
all subsequent calls and leaves their declared rows unattempted. The first
error survives later input/persistence errors. Fixed outputs use exclusive
creation; `progress.json` is atomically replaced before and after calls.

Even a successful replay establishes only these bounded local transitions
under synthetic memory, forest and calling assumptions. It does not validate
natural image labels, object construction, `0x484100` flood fill, the complete
segmentation algorithm, native execution, or a runnable restored program.
