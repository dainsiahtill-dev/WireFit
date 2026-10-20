# Recovered small-grid numbering

This independent Python standard-library component implements the local dense
int32 label-grid contract associated with target RVA `0x98a50`. It does not load
or execute the original program. It does not decode image files, recover classes,
perform vectorization, or establish whole-program equivalence or a runnable PE.
Natural image-to-label dataflow remains unresolved.

Python 3.11 or later is required. No package installation is needed.

```powershell
python -X utf8 -B -I -S tools/recovered-grid/grid.py `
  --input C:/work/case.json --out C:/work/new-grid.json
```

The input is exactly one six-field case:

```json
{"id":"small-2","width":2,"height":2,"node_stride":3,"source_stride":2,"labels":[0,0,0,0]}
```

`width` and `height` must be integers from 2 through 16. `node_stride` must be
between `width+1` and `width+8`; `source_stride` must be between `width` and
`width+8`. Labels are a dense `width*height` list of signed int32 integers, even
when `source_stride` is larger than `width`. Source padding is not supplied in
this CLI format. Booleans and floats are rejected. Case IDs contain at most 64
ASCII letters, digits, `_`, `.`, or `-`, starting with a letter or digit.

The output contains `schema_version:1`, `kind:"recovered_grid_numbering"`,
`case_id`, `width`, `height`, `node_stride`, `nodes`, `node_count`, and
`target_rva:"0x98a50"`. `nodes` has `height+1` rows of `node_stride` elements.
IDs begin at zero and follow the left column, right column, top non-corner edge,
bottom non-corner edge, then nonuniform interior junctions in row order. Uniform
interior junctions are `-1`; output padding is zero. `node_count` counts assigned
IDs and excludes padding and `-1` entries. It is a model result, not a recovered
source-level return-type declaration.

For the uniform example above the result is:

```json
{"schema_version":1,"kind":"recovered_grid_numbering","case_id":"small-2","width":2,"height":2,"node_stride":3,"nodes":[0,6,3,1,-1,4,2,7,5],"node_count":8,"target_rva":"0x98a50"}
```

The pure API is `number_grid(labels, width, height, node_stride)` in `model.py`.
It returns a frozen `GridNumbering` dataclass with immutable `nodes:tuple[int,...]`
and `node_count:int`. It does not modify the labels. The implementation constructs
an ordered coordinate sequence and classifies four-label junctions independently;
it does not import or copy the earlier candidate/replay implementation.

Input JSON is strict UTF-8, at most 64 KiB, with no duplicate keys, NaN, or
infinity. Input reads retain one handle and compare metadata before and after.
Input and output must differ. Symlinks, junctions, reparse aliases, hardlinked
inputs, streams, and special or ambiguous path components are rejected. Output
is created exclusively and existing files are preserved. Stdout is one UTF-8 JSON
receipt; errors exit nonzero. A storage failure may leave a new partial output;
the failed receipt does not certify that output and no existing file is deleted.

Run the scoped tests without any target execution:

```powershell
python -X utf8 -B -I -S tools/recovered-grid/test_grid.py
```

Tests use fixed small-grid expectations and owned temporary files. They cover
number/count order, non-square layouts, zero padding, signed extremes, immutability,
invalid inputs, strict JSON, and real CLI filesystem behavior. `test-log.json`
retains the actual RED/GREEN runs. Independent comparison with the immutable
904-case native receipt is a separate validation step; this module does not
replace missing observations or contain an observation-comparison API.
