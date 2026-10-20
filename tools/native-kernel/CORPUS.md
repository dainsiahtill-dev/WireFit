# Native-kernel input corpus and output comparison

These Python tools construct declared inputs and compare provided output values.
They do not load or execute a PE, emulate instructions, attach to a process or
start the original application. The host owns those actions and their evidence.

The historical candidate remains unchanged, SHA-256
`00d212c77b5d4a62566820306ebbb0828d95cafe8301ee6ae77e0e94aabc95e5`.
`build_corpus` checks that source identity before constructing samples and again
afterwards. `compare_observations` compiles only that exact candidate source and
rechecks it after comparison. No historical replay module is imported, and no
bytecode is written beside the frozen candidate.

```text
python -X utf8 -I -S tools/native-kernel/corpus.py --profile edges8 --out ABS_NEW_JSON
python -X utf8 -I -S tools/native-kernel/corpus.py --profile legacy896 --out ABS_NEW_JSON
python -X utf8 -I -S tools/native-kernel/compare.py --corpus ABS_JSON \
  --observations ABS_BASIC_ROWS_JSON --out ABS_NEW_JSON
```

`all904` concatenates the eight edges with the historical 896 inputs. Output
files use exclusive create and explicit UTF-8. Inputs are bounded stable file
reads with strict JSON, rejecting duplicate keys and nonfinite numbers.

Each case has exactly `id`, `width`, `height`, `node_stride`, `source_stride` and
`labels`. W/H are integers 2..16, node stride W+1..W+8, source stride W..W+8, and
labels a dense W*H list of signed-int32 values. Booleans are rejected as integers.
IDs are ASCII identifiers of 1..64 characters, start with an alphanumeric character,
and are unique within a corpus. The agent's own validator admits up to 128
characters and permits a leading dot, underscore or hyphen; the supported host
workflow uses this corpus's stricter intersection before any RPC and does not
broaden accepted inputs to the agent's larger set. The envelope records
candidate/body identities and a canonical sorted-key SHA-256 of the case list.
Envelope validation checks declared shape/digest/domain; generation separately
verifies the fixed legacy source identity. Merely supplying metadata does not
prove which workflow generated a case list.

The eight fresh cases cover uniform 2x2, int32-extreme checkerboard with maximum
padding, an isolated bottom-right difference, 16x2 and 2x16 strips, 16x16 uniform
with maximum padding, a 16x16 extreme checkerboard, and an isolated 3x3 center.
The historical 896 inputs are extracted solely from the six input fields of the
frozen JSONL, SHA-256
`98d0609048c7898575241918935670e3333233a70e9b6dc0d96dc8e814efac24`.
Its machine and candidate outputs are never used to build the corpus.

The comparison function consumes a list of basic observations; the CLI also
accepts an exact `{ "rows": [...] }` envelope. Each row has only `id`, `status`,
optional `output`, optional `error`. Completed rows require the entire actual
signed-int32 node buffer and no error. Failed rows require `{code,message}`;
unattempted rows cannot have output. A missing row counts as unattempted.
The host projects these fields only after separately validating the full native
receipt. Body hashes, canaries, process ownership and guard metadata cannot be
injected as a comparison verdict. Failed partial bytes remain in the host's raw
receipt; optional provided partial values are retained without comparing them.

The summary counts declared/attempted/completed/matched/mismatched/failed/
unattempted separately. Missing or failed outputs are never populated from the
candidate. Up to eight concrete counterexamples retain both observed and
candidate arrays; the total mismatch count and truncation count remain explicit.
The all-zero candidate is a negative control against completed observed arrays.
With no completed observations that control stays unattempted. Success requires
all declared cases completed, equal outputs and rejection of that control.

CLI exit 0 means `sampled_contract_matched`. Other valid result states are saved
in full and return exit 2. Invalid input/source identity returns exit 1 without a
result file. The comparator explicitly reports `native_origin_verified:false`
and `comparison_executes_native_code:false`; the host must validate native origin,
positive control, immutable inputs, body identity, canaries and cleanup separately.
It does not claim natural application calls or whole-program equivalence.

Tests were written first: 15 initially failed for missing implementation, then
passed. A later candidate-size metadata regression was observed RED and fixed.
The final 18 tests compare the frozen historical **machine observations as data**
(896 matches/896 zero-mutant rejections), exercise a concrete changed output,
missing/failed/unattempted calls, unknown IDs/verdict injection, invalid int32
values and shapes, candidate/legacy pin changes, bounded counterexamples and
immutable UTF-8 CLI output. This is not a new native call or a new emulation run.

```text
python -X utf8 -I -S -m unittest discover -s tools/native-kernel -p test_*.py -v
```