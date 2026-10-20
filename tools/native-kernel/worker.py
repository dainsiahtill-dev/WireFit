"""Fixed source/body native-kernel profile under a newly spawned owned Job.

The public trace job supplies the staged target. No PID, address or code payload
is accepted. Full native evidence is a bounded data receipt, never an executable.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys
import threading
import time

PROFILES = {
    "vmde-grid": {"source_sha256": "9a0fa724e4a2f189da4cafdd700842d5b6c7aa6c571269500e5eb56cc3fa9a5d", "rva": "0x98a50", "size_bytes": 637,
                  "body_sha256": "65d46a13deb731ea75b91fd29baf96dc614da6ad8bfcf48805aba748a139f70c"},
    "positive-control": {"source_sha256": "09cfe13ed66a35bf87144bfa9792857ce722cf0b6a9547bcc3c51d2767efd46b", "rva": "0x1030", "size_bytes": 64,
                         "body_sha256": "5dbf852fb27678e543a24e63a9c988ad53ee530b3f84b242a7e2482e51ba2a0e"},
}
SUPPORT_SHA = "7e71b0624fb6a3331e98cc42487d13e83301b5fbad3a18e4d029ef76283772dc"
AGENT_SHA = "6c628d6d74ce44138e635c478b6896cfbee6cb5ff69e25932f276f3093b53581"
CANDIDATE_SHA = "00d212c77b5d4a62566820306ebbb0828d95cafe8301ee6ae77e0e94aabc95e5"
LEGACY_SHA = "98d0609048c7898575241918935670e3333233a70e9b6dc0d96dc8e814efac24"
EDGES_HASH = "7084ca37e211164d008e660328df624704ec29d8c08564d73597c52cd4f980a4"
CASES_HASHES = {"edges8": EDGES_HASH, "legacy896": "21c7c0846ddadf5b5f7f7f8d9a46e8ad83f168f961cd897ce04442881c2407a5", "all904": "68d404fb2efa0666ddd9bb5192a1ffb295c90b6627233725bfd9a493bd5c3c19"}
WRAPPER_HEX = "5589e55356578b551089e0894204895a0c897210897a14896a18fc9c5889028b4d0cff55088b551089423089e0894208895a1c897220897a24896a289c5889422c8d65f45f5e5b5dc3"
HASH = re.compile(r"[a-f0-9]{64}\Z")
HEX = re.compile(r"0x[0-9a-fA-F]{1,8}\Z")
COMPONENTS = ("context", "header", "source", "nodes")
BASE_CHECKS = {"direction_flag_clear", "return_direction_flag_clear", "stack_balanced", "callee_saved_unchanged", "body_unchanged", "wrapper_unchanged"}
CHECKS = BASE_CHECKS | {name + suffix for name in COMPONENTS for suffix in ("_prefix_canary", "_guards", "_protection")} | {name + "_immutable" for name in COMPONENTS if name != "nodes"}
MAX_NATIVE = 16 * 1024 * 1024


class KernelFailure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def require(ok, message, code="INVALID_CORPUS"):
    if not ok:
        raise KernelFailure(code, message)


def integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8", errors="strict")


def error_row(error, fallback="NATIVE_KERNEL_FAILED"):
    return {"code": getattr(error, "code", fallback), "message": str(error).replace("\x00", "?")[:2048]}


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON object key", "PROTOCOL_ERROR")
        result[key] = value
    return result


def decode_json(data):
    try:
        require(len(data) <= MAX_NATIVE, "JSON input exceeds bound", "PROTOCOL_ERROR")
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
        pending, count = [value], 0
        while pending:
            item = pending.pop()
            count += 1
            require(count <= 500000, "JSON structure exceeds bound", "PROTOCOL_ERROR")
            if isinstance(item, dict):
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
            elif isinstance(item, float):
                require(math.isfinite(item), "Nonfinite JSON number", "PROTOCOL_ERROR")
        return value
    except KernelFailure:
        raise
    except Exception as error:
        raise KernelFailure("PROTOCOL_ERROR", "Input is not bounded strict UTF-8 JSON") from error


def stable_bytes(path, limit, nonempty=True):
    path = Path(path)
    require(path.is_absolute() and "\x00" not in str(path), "Input path must be absolute", "INVALID_PATH")
    if os.name == "nt":
        require(re.match(r"^[A-Za-z]:[\\/]", str(path)) is not None and ":" not in str(path)[2:], "Input contains a stream or non-drive alias", "INVALID_PATH")
        for part in path.parts[1:]:
            require(not part.endswith((".", " ")) and re.search(r'[<>:"|?*\x00-\x1f]', part) is None and re.match(r"(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", part) is None,
                    "Input contains an aliased Windows component", "INVALID_PATH")
    def check_chain():
        for current in (path, *path.parents):
            require(not current.is_symlink() and not current.is_junction(), "Input path contains a symlink or junction", "INVALID_PATH")
        require(os.path.normcase(str(path.resolve(strict=True))) == os.path.normcase(str(path)), "Input has a path alias", "INVALID_PATH")
    check_chain()
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and (0 < before.st_size if nonempty else 0 <= before.st_size) and before.st_size <= limit,
            "Input is linked, empty or oversized", "INVALID_PATH")
    identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_nlink)
    state = lambda st: (*identity(st), st.st_ctime_ns)
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        data = source.read(limit + 1)
        last = os.fstat(source.fileno())
    current = path.stat()
    # Windows stat() and fstat() expose different ctime clocks on Python 3.14.
    # Compare each API's clock only against that same API; identity crosses APIs.
    require(state(before) == state(current) and state(opened) == state(last) and identity(before) == identity(opened) == identity(current) and len(data) == before.st_size,
            "Input changed during retained-HANDLE read", "INPUT_CHANGED")
    check_chain()
    return data


def validate_case(value):
    require(type(value) is dict and set(value) == {"id", "width", "height", "node_stride", "source_stride", "labels"}, "Unexpected case fields")
    require(isinstance(value["id"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value["id"]) is not None, "Invalid case ID")
    w, h = value["width"], value["height"]
    require(integer(w, 2, 16) and integer(h, 2, 16), "Invalid dimensions")
    require(integer(value["node_stride"], w + 1, w + 8) and integer(value["source_stride"], w, w + 8), "Invalid strides")
    require(type(value["labels"]) is list and len(value["labels"]) == w * h and all(integer(label, -(1 << 31), (1 << 31) - 1) for label in value["labels"]), "Invalid int32 labels")
    return value


def cases_hash(cases):
    return digest(json.dumps(cases, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))


def validate_corpus(value):
    require(type(value) is dict and set(value) <= {"schema_version", "kind", "profile", "candidate", "kernel", "cases_sha256", "cases", "legacy_inputs"}, "Unexpected corpus fields")
    require(type(value.get("schema_version")) is int and value["schema_version"] == 1 and value.get("kind") == "native_kernel_corpus" and value.get("profile") in ("edges8", "legacy896", "all904"), "Invalid corpus profile")
    require(value.get("kernel") == {"rva": "0x98a50", "size_bytes": 637, "sha256": PROFILES["vmde-grid"]["body_sha256"]}, "Corpus does not identify the fixed kernel")
    candidate = value.get("candidate")
    require(type(candidate) is dict and set(candidate) == {"path", "size_bytes", "sha256", "frozen_before_cases"} and candidate["sha256"] == CANDIDATE_SHA and candidate["frozen_before_cases"] is True and integer(candidate["size_bytes"], 1, 1048576) and isinstance(candidate["path"], str) and Path(candidate["path"]).is_absolute() and "\x00" not in candidate["path"], "Candidate was not frozen before samples")
    cases = value.get("cases")
    require(type(cases) is list and len(cases) == {"edges8": 8, "legacy896": 896, "all904": 904}[value["profile"]], "Corpus count differs from profile")
    for case in cases:
        validate_case(case)
    require(len({case["id"] for case in cases}) == len(cases) and value.get("cases_sha256") == cases_hash(cases), "Duplicate cases or mismatched canonical case hash")
    require(value["cases_sha256"] == CASES_HASHES[value["profile"]], "Inputs differ from the fixed declared corpus")
    require(("legacy_inputs" in value) == (value["profile"] != "edges8"), "Legacy input accounting differs")
    if "legacy_inputs" in value:
        legacy = value["legacy_inputs"]
        require(type(legacy) is dict and set(legacy) == {"path", "size_bytes", "sha256", "cases"} and type(legacy["cases"]) is int and legacy["cases"] == 896 and integer(legacy["size_bytes"], 1, MAX_NATIVE) and legacy["sha256"] == LEGACY_SHA and isinstance(legacy["path"], str) and Path(legacy["path"]).is_absolute() and "\x00" not in legacy["path"], "Invalid legacy input identity")
    require(sum(case["node_stride"] * (case["height"] + 1) * 12 + 1800 for case in cases) < 2800000, "Corpus cannot retain required output events within the trace budget")
    return value


def pointer(value):
    require(isinstance(value, str) and HEX.fullmatch(value) is not None and 0 < int(value, 16) < 1 << 32, "Invalid x86 pointer", "AGENT_PROTOCOL_ERROR")
    return int(value, 16)


def validate_identity(value, profile, pid, target, anchor=None, ready=True):
    fixed = PROFILES[profile]
    require(type(value) is dict and value.get("pid") == pid and value.get("arch") == "ia32" and value.get("pointer_size") == 4, "Agent identity PID/architecture differs", "AGENT_PROTOCOL_ERROR")
    main = value.get("main")
    require(type(main) is dict and set(main) == {"base", "size", "path"} and integer(main["size"], 1, 64 * 1024 * 1024), "Invalid main module", "AGENT_PROTOCOL_ERROR")
    base = pointer(main["base"])
    require(base + main["size"] <= 1 << 32 and os.path.normcase(main["path"]) == os.path.normcase(target), "Main identity differs from owned staged target", "AGENT_PROTOCOL_ERROR")
    require(pointer(value.get("entry")) == base + int(fixed["rva"], 16) and int(fixed["rva"], 16) + fixed["size_bytes"] <= main["size"] and value.get("body_size_bytes") == fixed["size_bytes"], "Entry/body interval differs", "AGENT_PROTOCOL_ERROR")
    body_hex = value.get("body_hex")
    require(isinstance(body_hex, str) and re.fullmatch(r"[a-f0-9]{" + str(fixed["size_bytes"] * 2) + r"}", body_hex) is not None, "Incomplete original body bytes", "AGENT_PROTOCOL_ERROR")
    require(digest(bytes.fromhex(body_hex)) == value.get("body_sha256"), "Body byte hash disagrees", "AGENT_PROTOCOL_ERROR")
    if ready:
        require(value.get("ready") is True and value["body_sha256"] == fixed["body_sha256"], "Fixed body is not ready", "BODY_IDENTITY_MISMATCH")
    if anchor is not None:
        require(main == anchor, "Main base/size/path changed", "BODY_IDENTITY_MISMATCH")
    return value


def validate_setup(value, profile):
    require(type(value) is dict and value.get("profile") == profile and value.get("arch") == "ia32" and value.get("pointer_size") == 4 and value.get("wrapper_hex") == WRAPPER_HEX and value.get("wrapper_sha256") == digest(bytes.fromhex(WRAPPER_HEX)), "Setup/wrapper identity differs", "AGENT_PROTOCOL_ERROR")
    if profile == "positive-control":
        probe = value.get("abi_probe")
        expected = 0x8F31D2A5 ^ 0x5A17C3E9
        require(type(probe) is dict and set(probe) == {"context", "observed_context", "tag", "result", "expected"} and pointer(probe["context"]) == pointer(probe["observed_context"]) and probe["tag"] == 0x8F31D2A5 and probe["result"] == probe["expected"] == expected, "Compiled thiscall ABI probe failed", "ABI_CONTROL_FAILED")
    else:
        require(value.get("abi_probe") is None, "Unexpected ABI probe", "AGENT_PROTOCOL_ERROR")
    return value


def validate_row(row, case, profile, main):
    require(type(row) is dict and set(row) <= {"id", "status", "output", "error", "evidence"} and row.get("id") == case["id"] and row.get("status") in ("completed", "failed"), "Unexpected native case result", "AGENT_PROTOCOL_ERROR")
    require(len(encoded(row)) <= 32768, "Case evidence exceeds bound", "AGENT_PROTOCOL_ERROR")
    if "output" in row:
        require(type(row["output"]) is list and len(row["output"]) == case["node_stride"] * (case["height"] + 1) and all(integer(v, -(1 << 31), (1 << 31) - 1) for v in row["output"]), "Native output shape is invalid", "AGENT_PROTOCOL_ERROR")
    if row["status"] == "failed":
        require(type(row.get("error")) is dict and set(row["error"]) == {"code", "message"} and all(isinstance(row["error"][k], str) and 0 < len(row["error"][k]) <= 2048 for k in ("code", "message")), "Failed native result lacks error", "AGENT_PROTOCOL_ERROR")
        return row
    require("error" not in row, "Completed native result cannot also declare an error", "AGENT_PROTOCOL_ERROR")
    evidence = row.get("evidence")
    require(type(evidence) is dict and evidence.get("invocation_started") is True and evidence.get("invocation_returned") is True and evidence.get("capture_errors") == [] and evidence.get("register_observation") == "captured_by_wrapper", "Native call did not return with complete evidence", "AGENT_PROTOCOL_ERROR")
    expected_identity = {"main_base": main["base"], "entry": hex(pointer(main["base"]) + int(PROFILES[profile]["rva"], 16)), "body_sha256": PROFILES[profile]["body_sha256"]}
    require(evidence.get("before") == expected_identity and evidence.get("after") == expected_identity, "Per-call body identity differs", "BODY_IDENTITY_MISMATCH")
    registers = evidence.get("registers")
    names = ["eflags_before", "esp_before", "esp_after", "ebx_before", "esi_before", "edi_before", "ebp_before", "ebx_after", "esi_after", "edi_after", "ebp_after", "eflags_after", "eax_incidental"]
    require(type(registers) is dict and set(registers) == set(names) and all(integer(registers[k], 0, 0xffffffff) for k in names), "Incomplete native register observations", "AGENT_PROTOCOL_ERROR")
    require(evidence.get("raw_register_state_hex") == struct.pack("<13I", *(registers[k] for k in names)).hex(), "Raw register bytes disagree", "AGENT_PROTOCOL_ERROR")
    require(registers["esp_before"] == registers["esp_after"] and registers["esp_before"] > 0 and all(registers[k + "_before"] == registers[k + "_after"] for k in ("ebx", "esi", "edi", "ebp")) and (registers["eflags_before"] | registers["eflags_after"]) & 0x400 == 0, "Native register/DF contract violated", "NATIVE_INVARIANT_FAILED")
    checks = evidence.get("checks")
    require(type(checks) is dict and set(checks) == CHECKS and all(v is True for v in checks.values()), "A declared native invariant failed", "NATIVE_INVARIANT_FAILED")
    require("output" in row, "Completed call has no actual output", "AGENT_PROTOCOL_ERROR")
    output_bytes = struct.pack("<" + "i" * len(row["output"]), *row["output"])
    require(evidence.get("output_hex") == output_bytes.hex() and evidence.get("output_sha256") == digest(output_bytes), "Output bytes disagree with actual int32 output", "AGENT_PROTOCOL_ERROR")
    buffers = evidence.get("buffers")
    require(type(buffers) is list and len(buffers) == 4 and {b.get("name") for b in buffers if type(b) is dict} == set(COMPONENTS), "Missing synthetic buffers", "AGENT_PROTOCOL_ERROR")
    by, intervals = {}, []
    sizes = {"context": 156, "header": 12, "source": case["source_stride"] * case["height"] * 4, "nodes": len(output_bytes)}
    for b in buffers:
        name = b["name"]
        require(set(b) == {"name", "allocation", "data", "size_bytes", "data_page", "page_size", "protection"}, "Unexpected buffer fields", "AGENT_PROTOCOL_ERROR")
        page = b["page_size"]
        require(integer(page, 4096, 65536) and page & (page - 1) == 0 and b["size_bytes"] == sizes[name] and sizes[name] + 64 <= page, "Invalid buffer extent", "AGENT_PROTOCOL_ERROR")
        allocation, data, middle = pointer(b["allocation"]), pointer(b["data"]), pointer(b["data_page"])
        require(allocation % page == 0 and allocation + page * 3 <= 1 << 32 and middle == allocation + page and data == middle + page - sizes[name] and data % 4 == 0 and b["protection"] == ("rw-" if name == "nodes" else "r--"), "Synthetic buffer address/protection mismatch", "AGENT_PROTOCOL_ERROR")
        require(all(allocation + page * 3 <= start or end <= allocation for start, end in intervals), "Synthetic allocations overlap", "AGENT_PROTOCOL_ERROR")
        intervals.append((allocation, allocation + page * 3))
        by[name] = b
    context = bytearray(b"\xa5" * 156)
    for offset, value in ((0, pointer(by["nodes"]["data"])), (4, case["node_stride"]), (8, case["height"] + 1), (12, pointer(by["header"]["data"])), (0x94, case["width"]), (0x98, case["height"])):
        struct.pack_into("<I", context, offset, value)
    source = bytearray(b"\xa5" * sizes["source"])
    for index, label in enumerate(case["labels"]):
        struct.pack_into("<i", source, (index // case["width"] * case["source_stride"] + index % case["width"]) * 4, label)
    expected = {"context": bytes(context), "header": struct.pack("<III", pointer(by["source"]["data"]), case["source_stride"], case["height"]), "source": bytes(source), "nodes": b"\xa5" * sizes["nodes"]}
    before, after = evidence.get("buffer_before_sha256"), evidence.get("buffer_after_sha256")
    require(type(before) is dict and type(after) is dict and set(before) == set(after) == set(COMPONENTS), "Incomplete immutable/canary byte hashes", "AGENT_PROTOCOL_ERROR")
    for name in COMPONENTS:
        prefix = b"\xa5" * (by[name]["page_size"] - sizes[name])
        require(before[name] == digest(prefix + expected[name]) and after[name] == digest(prefix + (output_bytes if name == "nodes" else expected[name])), "Actual input/output/canary page bytes differ", "NATIVE_INVARIANT_FAILED")
    return row


def load_support():
    path = Path(__file__).resolve().parent.parent / "native-trace" / "worker.py"
    data = stable_bytes(path, 1048576)
    require(digest(data) == SUPPORT_SHA, "Frozen trace lifecycle dependency changed", "SUPPORT_IDENTITY_MISMATCH")
    spec = importlib.util.spec_from_file_location("wirefit_fixed_trace_support", path)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    exec(compile(data.decode("utf-8", errors="strict"), str(path), "exec"), module.__dict__)
    return module, path


class NativeReceipt:
    def __init__(self, result, profile, corpus, corpus_identity, identities):
        self.result, self.lock = result, threading.RLock()
        self.path, self.tmp = Path("native-result.json"), Path("native-result.tmp.json")
        self.progress_path, self.progress_tmp = Path("native-progress.json"), Path("native-progress.tmp.json")
        self.journal_path = Path("native-calls.jsonl")
        require(not any(os.path.lexists(p) for p in (self.path, self.tmp, self.progress_path, self.progress_tmp, self.journal_path)), "Native receipt already exists", "OUTPUT_COLLISION")
        self.journal = self.journal_path.open("xb")
        self.journal_hash, self.journal_size, self.sequence = hashlib.sha256(), 0, 0
        self.doc = {"schema_version": 1, "kind": "native_inprocess_kernel", "profile": profile, "status": "failed", "is_checkpoint": True,
                    "source_sha256": PROFILES[profile]["source_sha256"], "corpus": corpus_identity, "candidate": corpus["candidate"], "corpus_input": corpus,
                    "identities": identities, "setup": None, "identity_initial": None, "identity_final": None,
                    "in_flight_id": None, "rows": [{"id": c["id"], "status": "unattempted"} for c in corpus["cases"]],
                    "cleanup": result["cleanup"], "error": None, "source_unchanged": None,
                    "scope": "native_inprocess_kernel_under_explicit_synthetic_objects_not_natural_application_call", "runnable_verified": False}

    def atomic(self, path, temporary, data):
        created = False
        try:
            with temporary.open("xb") as output:
                created = True
                require(output.write(data) == len(data), "Short receipt write", "RECEIPT_WRITE_FAILED")
            os.replace(temporary, path)
        finally:
            if created and os.path.lexists(temporary):
                temporary.unlink()

    def record(self, phase, index, row=None):
        """Durable small records avoid quadratic full-receipt rewrites per call.

        A killed worker can leave the current call unresolved. The journal records
        its start and every actually returned row; it never supplies missing bytes.
        Full native/trace checkpoints are refreshed every sixteen returns.
        """
        with self.lock:
            event = {"sequence": self.sequence + 1, "phase": phase, "index": index,
                     "id": self.doc["rows"][index]["id"]}
            if row is not None:
                event["row"] = row
            data = encoded(event)
            require(len(data) <= 35000 and self.journal_size + len(data) <= MAX_NATIVE, "Call journal exceeds bound", "RESOURCE_LIMIT")
            require(self.journal.write(data) == len(data), "Short journal write", "RECEIPT_WRITE_FAILED")
            self.journal.flush()
            os.fsync(self.journal.fileno())
            self.journal_hash.update(data)
            self.journal_size += len(data)
            self.sequence += 1
            progress = {"schema_version": 1, "status": "failed", "is_checkpoint": True,
                        "error": self.result["error"] or {"code": "INTERRUPTED", "message": "Only a terminal receipt completes the observation"},
                        "profile": self.doc["profile"], "in_flight_id": self.doc["in_flight_id"],
                        "journal": self.journal_identity(), "counts": self.counts()}
            self.atomic(self.progress_path, self.progress_tmp, encoded(progress))

    def journal_identity(self):
        return {"file": self.journal_path.name, "size_bytes": self.journal_size, "sha256": self.journal_hash.hexdigest(), "records": self.sequence}

    def counts(self):
        return {key: sum(r["status"] == key for r in self.doc["rows"]) for key in ("completed", "failed", "unattempted")}

    def flush(self, terminal=False):
        with self.lock:
            row = {**self.doc, "cleanup": dict(self.result["cleanup"]), "is_checkpoint": not terminal,
                   "journal": self.journal_identity(),
                   "status": self.result["status"] if terminal else "failed",
                   "error": self.result["error"] or (None if terminal else {"code": "INTERRUPTED", "message": "Native observation has no terminal receipt"})}
            data = encoded(row)
            require(len(data) <= MAX_NATIVE, "Native receipt exceeds 16 MiB", "RESOURCE_LIMIT")
            self.atomic(self.path, self.tmp, data)
            self.result["native_kernel"] = {"profile": self.doc["profile"], "file": self.path.name, "sha256": digest(data), "size_bytes": len(data), "counts": self.counts(), "in_flight_id": self.doc["in_flight_id"], "source_sha256": self.doc["source_sha256"], "corpus": self.doc["corpus"], "identities": self.doc["identities"], "journal": self.journal_identity(), "attachment_status": "pending_managed_artifact_registration"}
            if terminal and not self.journal.closed:
                self.journal.close()


def validate_control(data, worker_sha, agent_sha):
    value = decode_json(data)
    require(type(value) is dict and type(value.get("schema_version")) is int and value["schema_version"] == 1 and value.get("kind") == "native_inprocess_kernel" and value.get("profile") == "positive-control" and value.get("status") == "completed" and value.get("is_checkpoint") is False and value.get("source_sha256") == PROFILES["positive-control"]["source_sha256"] and value.get("source_unchanged") is True and value.get("inputs_unchanged") is True and value.get("error") is None, "A terminal compiled positive-control receipt is required", "POSITIVE_CONTROL_REQUIRED")
    require(all(value.get("cleanup", {}).get(k) is True for k in ("owned_pid_terminated", "session_detached", "windows_job_assigned", "windows_job_closed")) and not value["cleanup"].get("errors"), "Positive control cleanup is incomplete", "POSITIVE_CONTROL_REQUIRED")
    require(value.get("identities", {}).get("worker", {}).get("sha256") == worker_sha and value["identities"].get("agent", {}).get("sha256") == agent_sha, "Positive control used different worker/agent bytes", "POSITIVE_CONTROL_REQUIRED")
    validate_setup(value.get("setup"), "positive-control")
    corpus = validate_corpus(value.get("corpus_input"))
    require(corpus["profile"] == "edges8", "Positive control did not use the fixed eight cases", "POSITIVE_CONTROL_REQUIRED")
    identity = value.get("corpus")
    require(type(identity) is dict and set(identity) == {"path", "size_bytes", "sha256", "cases_sha256", "case_count"} and identity["cases_sha256"] == EDGES_HASH and identity["case_count"] == 8, "Control corpus identity is incomplete", "POSITIVE_CONTROL_REQUIRED")
    corpus_bytes = stable_bytes(identity["path"], MAX_NATIVE)
    require(len(corpus_bytes) == identity["size_bytes"] and digest(corpus_bytes) == identity["sha256"] and decode_json(corpus_bytes) == corpus, "Control corpus input changed", "POSITIVE_CONTROL_REQUIRED")
    first, last = value.get("identity_initial"), value.get("identity_final")
    require(type(first) is dict and integer(first.get("pid"), 1, 0xffffffff) and type(first.get("main")) is dict and isinstance(first["main"].get("path"), str), "Control initial identity is incomplete", "POSITIVE_CONTROL_REQUIRED")
    target, pid = first["main"]["path"], first["pid"]
    require(digest(stable_bytes(target, 64 * 1024 * 1024)) == PROFILES["positive-control"]["source_sha256"], "Compiled control source changed", "POSITIVE_CONTROL_REQUIRED")
    validate_identity(first, "positive-control", pid, target)
    validate_identity(last, "positive-control", pid, target, first["main"])
    require(value["setup"].get("main") == first["main"] and value.get("finish") == {"completed_calls": 8, "halted": False} and value.get("in_flight_id") is None, "Control lifecycle proof is incomplete", "POSITIVE_CONTROL_REQUIRED")
    require(type(value.get("rows")) is list and len(value["rows"]) == 8 and all(r.get("status") == "completed" for r in value["rows"]), "The eight compiled positive calls did not all complete", "POSITIVE_CONTROL_REQUIRED")
    for row, case in zip(value["rows"], corpus["cases"]):
        validate_row(row, case, "positive-control", first["main"])
    compare_control_outputs(corpus, value["rows"])
    return value


def compare_control_outputs(corpus, rows):
    """Execute only the pre-frozen Python candidate, never a user code payload."""
    candidate = corpus["candidate"]
    data = stable_bytes(candidate["path"], 1048576)
    require(digest(data) == CANDIDATE_SHA and len(data) == candidate["size_bytes"], "Frozen comparison source differs", "POSITIVE_CONTROL_REQUIRED")
    namespace = {"__name__": "wirefit_frozen_candidate", "__file__": candidate["path"]}
    exec(compile(data.decode("utf-8", errors="strict"), candidate["path"], "exec"), namespace)
    function = namespace.get("recover_grid")
    require(callable(function), "Frozen comparison entry missing", "POSITIVE_CONTROL_REQUIRED")
    for case, row in zip(corpus["cases"], rows):
        expected = function(case["labels"], case["width"], case["height"], case["node_stride"])
        require(row["output"] == expected and row["output"] != [0] * len(expected), "Positive control did not match candidate and reject zero mutant", "POSITIVE_CONTROL_REQUIRED")
    require(stable_bytes(candidate["path"], 1048576) == data, "Frozen comparison source changed", "POSITIVE_CONTROL_REQUIRED")


def run_experiment(config, corpus, profile, frida, support, result, agent, checkpoint, receipt, job_factory=None):
    class KernelCollector(support.Collector):
        def fail(self, code, message, persist=True):
            with self.lock:
                if result["error"] is not None:
                    if self.failure is None:
                        self.failure = support.TraceFailure(result["error"]["code"], result["error"]["message"])
                    self.stopped.set()
                    return
                super().fail(code, message, persist)

    collector = KernelCollector(config, result, checkpoint)
    operation, expired = frida.Cancellable(), threading.Event()
    job, device, session = None, None, None
    job_lock, job_cleanup = threading.Lock(), None
    lifecycle_lock, completion_committed = collector.lock, False
    fallback_attempted = False
    deadline_at = time.monotonic() + config["duration_ms"] / 1000
    batch = []

    def close_job():
        nonlocal job_cleanup, fallback_attempted
        with job_lock:
            if job is not None and job_cleanup is None:
                try:
                    job_cleanup = job.close()
                except Exception as error:
                    job_cleanup = {"owned_pid_terminated": False, "windows_job_assigned": bool(job.assigned), "windows_job_closed": False, "errors": ["Owned Job close: " + str(error)[:1900]]}
            if job is not None and not job.assigned and result["pid"] is not None and device is not None and not fallback_attempted:
                # This PID is the suspended spawn returned above, never caller input.
                # No target execution is allowed until assignment succeeds. Frida's
                # own spawn bookkeeping is the only fallback when OpenProcess failed.
                fallback_attempted = True
                cleanup_operation = frida.Cancellable()
                cleanup_timer = threading.Timer(3, cleanup_operation.cancel)
                cleanup_timer.daemon = True
                cleanup_timer.start()
                try:
                    device.kill(result["pid"], cancellable=cleanup_operation)
                    job_cleanup["owned_spawn_kill_requested"] = True
                except Exception as error:
                    job_cleanup.setdefault("errors", []).append("Owned suspended-spawn fallback: " + str(error)[:1800])
                finally:
                    cleanup_timer.cancel()
            if job_cleanup:
                with collector.lock:
                    result["cleanup"].update(job_cleanup)

    def timeout():
        with lifecycle_lock:
            if completion_committed:
                return
            expired.set()
            if result["error"] is None:
                result["error"] = {"code": "TIMEOUT", "message": "Host native-call deadline exceeded"}
        operation.cancel()
        # Cancellable releases Python's RPC wait, not the native call. Closing
        # the confirmed owned Job independently is the native-call deadline.
        if job is not None and job.assigned:
            close_job()

    deadline = threading.Timer(config["duration_ms"] / 1000, timeout)
    deadline.daemon = True

    def persist():
        with collector.lock, receipt.lock:
            receipt.flush()
            checkpoint.flush()

    def flush_batch():
        if batch:
            collector.event({"type": "native_kernel_cases", "rows": list(batch)})
            batch.clear()

    def snapshot(identity, phase):
        entry = config["ranges"][0]
        collector.snapshot({"phase": phase, "range_index": 0, **entry}, bytes.fromhex(identity["body_hex"]))

    try:
        job = (job_factory or support.WindowsJob)()
        deadline.start()
        with operation:
            device = frida.get_local_device()
            pid = device.spawn([config["target"]], cwd=str(Path(config["target"]).parent), stdio="pipe", env={"__COMPAT_LAYER": "RUNASINVOKER"})
            require(integer(pid, 1, 0xffffffff), "Invalid owned spawn PID", "SPAWN_FAILED")
            result["pid"] = pid
            job.assign(pid)  # No checkpoint I/O before suspended-spawn assignment.
            result["cleanup"]["windows_job_assigned"] = True
            persist()
            session = device.attach(pid)
            session.on("detached", collector.on_detached)
            script = session.create_script(agent, name="wirefit-fixed-native-kernel", runtime="qjs")
            script.set_log_handler(lambda _level, _text: None)
            script.on("message", collector.on_message)
            script.load()
            setup = validate_setup(script.exports_sync.setup({"profile": profile}), profile)
            receipt.doc["setup"] = setup
            device.resume(pid)
            warmup = min(time.monotonic() + 20, time.monotonic() + config["duration_ms"] / 1000)
            identity = None
            while True:
                if collector.failure:
                    raise collector.failure
                current = validate_identity(script.exports_sync.identity(), profile, pid, config["target"], ready=False)
                if current["body_sha256"] == PROFILES[profile]["body_sha256"] and current.get("ready") is True:
                    identity = validate_identity(current, profile, pid, config["target"])
                    break
                require(time.monotonic() < warmup, "Fixed body was not ready within warmup", "BODY_WARMUP_TIMEOUT")
                operation.raise_if_cancelled()
                time.sleep(0.1)
            anchor = identity["main"]
            require(setup.get("main") == anchor, "Setup main identity differs from ready identity", "BODY_IDENTITY_MISMATCH")
            receipt.doc["identity_initial"] = identity
            collector.event({"type": "agent_ready", "arch": "ia32", "pointer_size": 4, "image_base": anchor["base"], "image_size": anchor["size"], "hardware_breakpoints": 0, "installed_api_hooks": 0})
            collector.event({"type": "native_kernel_setup", "profile": profile, "setup": setup})
            collector.hook_states([], "initial")
            snapshot(identity, "initial")
            persist()
            for index, case in enumerate(corpus["cases"]):
                if collector.failure:
                    raise collector.failure
                operation.raise_if_cancelled()
                receipt.doc["in_flight_id"] = case["id"]
                receipt.record("started", index)
                actual = script.exports_sync.run(case)
                # Reject non-JSON/oversized agent returns before recording arbitrary
                # objects. A JSON-shaped invalid proof is retained under agent_return.
                require(len(encoded(actual)) <= 32768, "Agent row exceeds 32 KiB", "AGENT_PROTOCOL_ERROR")
                try:
                    validate_row(actual, case, profile, anchor)
                except Exception as error:
                    actual = {"id": case["id"], "status": "failed", "error": error_row(error), "evidence": {"host_validation_failed": True, "agent_return": actual}}
                receipt.doc["rows"][index] = actual
                receipt.doc["in_flight_id"] = None
                receipt.record("returned", index, actual)
                compact = {k: actual[k] for k in ("id", "status", "output", "error") if k in actual}
                if len(encoded({"type": "native_kernel_cases", "rows": batch + [compact]})) > 30000:
                    flush_batch()
                batch.append(compact)
                if len(batch) >= 16:
                    flush_batch()
                    persist()
                require(actual["status"] == "completed", actual.get("error", {}).get("message", "Native call failed"), actual.get("error", {}).get("code", "NATIVE_KERNEL_CALL_FAILED"))
            flush_batch()
            final = validate_identity(script.exports_sync.identity(), profile, pid, config["target"], anchor)
            receipt.doc["identity_final"] = final
            snapshot(final, "final")
            stats = script.exports_sync.finish()
            require(type(stats) is dict and stats.get("completed_calls") == len(corpus["cases"]) and stats.get("halted") is False, "Final native call statistics differ", "AGENT_PROTOCOL_ERROR")
            receipt.doc["finish"] = stats
            require(collector.omitted == 0 and collector.failure is None, "Native evidence was omitted", "RESOURCE_LIMIT")
            collector.hook_states([], "final")
            collector.omitted_complete = True
            with lifecycle_lock:
                require(not expired.is_set() and time.monotonic() < deadline_at and result["error"] is None, "Host native-call deadline exceeded", "TIMEOUT")
                completion_committed = True
                result["status"] = "completed"
    except (Exception, KeyboardInterrupt) as error:
        with lifecycle_lock:
            if result["error"] is None:
                result["error"] = error_row(KernelFailure("TIMEOUT", "Host native-call deadline exceeded") if expired.is_set() else KernelFailure("CANCELLED", "Worker interrupted") if isinstance(error, KeyboardInterrupt) else error)
        if receipt.doc["in_flight_id"] is not None:
            for row in receipt.doc["rows"]:
                if row["id"] == receipt.doc["in_flight_id"] and row["status"] == "unattempted":
                    row.update(status="failed", error=result["error"])
        try:
            flush_batch()
            persist()
        except Exception:
            pass
    finally:
        deadline.cancel()
        with collector.lock:
            collector.closed = True
        close_job()  # Owned Job closes before any detach/unload RPC.
        if session is not None:
            cleanup = frida.Cancellable()
            timer = threading.Timer(3, cleanup.cancel)
            timer.daemon = True
            timer.start()
            try:
                if not session.is_detached:
                    session.detach(cancellable=cleanup)
                result["cleanup"]["session_detached"] = bool(session.is_detached)
            except Exception as error:
                result["cleanup"].setdefault("errors", []).append(str(error)[:2048])
            finally:
                timer.cancel()
        result["omitted_events"] = collector.omitted + collector.agent_omitted
        result["omitted_events_complete"] = collector.omitted_complete
        if result["pid"] is not None and (not all(result["cleanup"].get(k) is True for k in ("owned_pid_terminated", "session_detached", "windows_job_assigned", "windows_job_closed")) or result["cleanup"].get("errors")):
            result["error"] = result["error"] or {"code": "CLEANUP_FAILED", "message": "Owned target/session cleanup was not confirmed"}
        if result["error"] is not None:
            result["status"] = "failed"


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise KernelFailure("INVALID_ARGUMENTS", message)


class Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        require(getattr(namespace, self.dest, None) is None, "Repeated option: " + self.dest, "INVALID_ARGUMENTS")
        setattr(namespace, self.dest, values)


def main():
    support, checkpoint, receipt, config, target_data, corpus_data = None, None, None, None, None, None
    frozen_inputs = {}
    result = {"schema_version": 1, "status": "failed", "frida_version": None, "pid": None, "events": [], "snapshots": [], "omitted_events": 0, "omitted_events_complete": False,
              "hook_states": {"initial": [], "current": [], "final": []}, "hook_states_complete": False, "identities": {"worker": None, "agent": None, "frida": None},
              "cleanup": {"owned_pid_terminated": False, "session_detached": False, "windows_job_assigned": False, "windows_job_closed": False}, "error": None}
    try:
        parser = Arguments(add_help=False, allow_abbrev=False)
        for name in ("module-path", "profile", "corpus", "corpus-sha256"):
            parser.add_argument("--" + name, required=True, action=Once)
        parser.add_argument("--control-receipt", action=Once)
        parser.add_argument("--control-receipt-sha256", action=Once)
        args = parser.parse_args()
        require(args.profile in PROFILES and HASH.fullmatch(args.corpus_sha256) is not None, "Invalid fixed profile or corpus pin", "INVALID_ARGUMENTS")
        support, support_path = load_support()
        request_bytes = sys.stdin.buffer.read(65537)
        require(len(request_bytes) <= 65536, "Trace request exceeds 64 KiB", "INVALID_REQUEST")
        config = support.validate_request(decode_json(request_bytes))
        fixed = PROFILES[args.profile]
        require(config["duration_ms"] >= 1 and config["breakpoints_rva"] == [] and config["api_hooks"] == [] and config["ranges"] == [{"rva": fixed["rva"], "size_bytes": fixed["size_bytes"]}] and config["max_events"] >= 8, "Kernel profile requires its exact main-body range and no hooks/breakpoints", "INVALID_REQUEST")
        require(Path(config["target"]).parent == Path.cwd().resolve(), "Only the job's cwd-staged target may be spawned", "INVALID_TARGET")
        target_data = stable_bytes(Path(config["target"]), 64 * 1024 * 1024)
        require(digest(target_data) == fixed["source_sha256"], "Target is not the fixed profile executable", "SOURCE_IDENTITY_MISMATCH")
        corpus_data = stable_bytes(Path(args.corpus), MAX_NATIVE)
        frozen_inputs[Path(args.corpus)] = corpus_data
        require(digest(corpus_data) == args.corpus_sha256, "Corpus bytes differ from explicit pin", "CORPUS_IDENTITY_MISMATCH")
        corpus = validate_corpus(decode_json(corpus_data))
        for declared in (corpus["candidate"], *([corpus["legacy_inputs"]] if "legacy_inputs" in corpus else [])):
            path = Path(declared["path"])
            original = stable_bytes(path, MAX_NATIVE)
            require(len(original) == declared["size_bytes"] and digest(original) == declared["sha256"], "Corpus declared input is not the fixed byte identity", "CORPUS_IDENTITY_MISMATCH")
            frozen_inputs[path] = original
        require(args.profile != "positive-control" or corpus["profile"] == "edges8", "Compiled control is restricted to the initial eight cases", "INVALID_CORPUS")
        identities = {}
        for role, path, name in (("worker", Path(__file__).resolve(), "trace-worker.py"), ("agent", Path(__file__).resolve().with_name("agent.js"), "trace-agent.js"), ("support", support_path, "native-trace-support.py")):
            original = stable_bytes(path, 1048576)
            text, identity = support.source_copy(path, name)
            require(text.encode("utf-8", errors="strict") == original, "Source changed while creating its exact snapshot", "INPUT_CHANGED")
            require(role != "agent" or digest(original) == AGENT_SHA, "Fixed agent source changed", "AGENT_IDENTITY_MISMATCH")
            frozen_inputs[path] = original
            identities[role] = identity
            if role in result["identities"]:
                result["identities"][role] = identity
            if role == "agent":
                agent = text
        if args.profile == "vmde-grid":
            require(args.control_receipt is not None and args.control_receipt_sha256 is not None and HASH.fullmatch(args.control_receipt_sha256) is not None, "Pinned compiled control receipt is required", "POSITIVE_CONTROL_REQUIRED")
            control_data = stable_bytes(Path(args.control_receipt), MAX_NATIVE)
            frozen_inputs[Path(args.control_receipt)] = control_data
            require(digest(control_data) == args.control_receipt_sha256, "Control receipt pin differs", "POSITIVE_CONTROL_REQUIRED")
            validate_control(control_data, identities["worker"]["sha256"], identities["agent"]["sha256"])
        else:
            require(args.control_receipt is None and args.control_receipt_sha256 is None, "Unexpected control receipt", "INVALID_ARGUMENTS")
        checkpoint = support.Checkpoint(result)
        receipt = NativeReceipt(result, args.profile, corpus, {"path": str(Path(args.corpus)), "sha256": args.corpus_sha256, "size_bytes": len(corpus_data), "cases_sha256": corpus["cases_sha256"], "case_count": len(corpus["cases"])}, identities)
        receipt.flush()
        checkpoint.flush()
        frida = support.load_frida(args.module_path)
        result["frida_version"] = frida.__version__
        result["identities"]["frida"] = {"version": frida.__version__, "module_path": str(Path(frida.__file__).resolve(strict=True))}
        identities["frida"] = result["identities"]["frida"]
        run_experiment(config, corpus, args.profile, frida, support, result, agent, checkpoint, receipt)
    except (Exception, KeyboardInterrupt) as error:
        result["error"] = result["error"] or error_row(error)
    finally:
        if receipt:
            receipt.doc["inputs_unchanged"] = True
        for path, initial in frozen_inputs.items():
            try:
                require(stable_bytes(path, max(len(initial), 1)) == initial, "Pinned input changed after the experiment: " + str(path), "INPUT_CHANGED")
            except Exception as error:
                result["error"] = result["error"] or error_row(error)
                if receipt:
                    receipt.doc["inputs_unchanged"] = False
        if config is not None and target_data is not None:
            try:
                unchanged = stable_bytes(Path(config["target"]), 64 * 1024 * 1024) == target_data
                require(unchanged, "Staged source changed after the experiment", "SOURCE_CHANGED")
                if receipt:
                    receipt.doc["source_unchanged"] = True
            except Exception as error:
                result["error"] = result["error"] or error_row(error)
                if receipt:
                    receipt.doc["source_unchanged"] = False
        if result["error"] is not None:
            result["status"] = "failed"
        if receipt is not None:
            try:
                receipt.doc["in_flight_id"] = None
                receipt.flush(terminal=True)
            except Exception as error:
                result["status"] = "failed"
                result["error"] = result["error"] or error_row(error)
        if checkpoint is not None:
            try:
                checkpoint.flush(terminal=True)
            except Exception as error:
                result["status"] = "failed"
                result["error"] = result["error"] or error_row(error)
        if receipt is not None and not receipt.journal.closed:
            receipt.journal.close()
    sys.stdout.buffer.write(encoded(result))
    sys.stdout.buffer.flush()
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
