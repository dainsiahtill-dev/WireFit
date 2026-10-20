#!/usr/bin/env python3
"""Bounded, standard-library QA for this handoff package, not WireFix.

Default: read package files, execute the explicitly identified self-authored
FP32 fixture in fresh processes, and print a summary. Only --write-report writes
docs/HANDOFF_VALIDATION.md. No installed JSON Schema validator, solver, REA,
Ghidra, Handwired, product implementation, or product verdict is used here.

The schema checker below supports this package's limited keyword set. It is
NOT a conforming JSON Schema 2020-12 implementation or meta-schema compiler.
Unknown schema keywords fail this check instead of being silently ignored.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import platform
import re
import struct
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urldefrag, urljoin


class CheckError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CheckError(message)


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(text):
    def invalid_constant(value):
        raise CheckError(f"Nonstandard JSON constant: {value}")
    return json.loads(text, object_pairs_hook=no_duplicates,
                      parse_constant=invalid_constant)


def json_equal(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if type(a) in (int, float) and type(b) in (int, float):
        return a == b
    if type(a) is not type(b):
        return False
    if isinstance(a, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    return a == b


def pattern_matches(pattern, value):
    # Current patterns are anchored ASCII-compatible expressions. Python's $
    # permits a final newline; fullmatch avoids that difference for this subset.
    if pattern.startswith("^") and pattern.endswith("$"):
        return re.fullmatch(pattern, value) is not None
    return re.search(pattern, value) is not None


class SubsetSchemaChecker:
    """Small fixture checker; does not claim 2020-12 conformance."""

    KEYWORDS = {
        "$schema", "$id", "$ref", "$defs", "title", "description", "$comment",
        "type", "const", "enum", "oneOf", "anyOf", "allOf", "not", "if", "then", "else",
        "properties", "patternProperties", "additionalProperties", "required",
        "minProperties", "maxProperties", "items", "minItems", "maxItems", "uniqueItems",
        "minLength", "maxLength", "pattern", "minimum", "maximum", "format",
    }

    def __init__(self, schemas):
        self.schemas = schemas
        self.ref_count = 0
        self.keywords = Counter()

    def resolve(self, reference, base):
        uri, pointer = urldefrag(urljoin(base, reference))
        require(uri in self.schemas, f"Unregistered/local schema reference: {uri}")
        target = self.schemas[uri]
        if pointer:
            require(pointer.startswith("/"), f"Unsupported non-pointer fragment: {pointer}")
            try:
                for part in pointer[1:].split("/"):
                    key = part.replace("~1", "/").replace("~0", "~")
                    target = target[int(key)] if isinstance(target, list) else target[key]
            except (KeyError, IndexError, ValueError, TypeError) as exc:
                raise CheckError(f"Missing JSON Pointer: {reference}") from exc
        return target, uri

    def inspect(self, schema, base):
        if isinstance(schema, bool):
            return
        require(isinstance(schema, dict), "Schema node is neither object nor boolean")
        unknown = set(schema) - self.KEYWORDS
        require(not unknown, f"Unsupported checker keywords: {sorted(unknown)}")
        self.keywords.update(schema.keys())
        if "$id" in schema:
            base = urljoin(base, schema["$id"])
        if "$ref" in schema:
            self.resolve(schema["$ref"], base)
            self.ref_count += 1
        if "pattern" in schema:
            re.compile(schema["pattern"])
        for keyword in ("$defs", "properties", "patternProperties"):
            for name, child in schema.get(keyword, {}).items():
                if keyword == "patternProperties":
                    re.compile(name)
                self.inspect(child, base)
        for keyword in ("items", "additionalProperties", "not", "if", "then", "else"):
            if keyword in schema:
                self.inspect(schema[keyword], base)
        for keyword in ("oneOf", "anyOf", "allOf"):
            for child in schema.get(keyword, []):
                self.inspect(child, base)

    def validate(self, instance, schema, base, path="$"):
        if isinstance(schema, bool):
            require(schema, f"{path}: false schema")
            return
        if "$id" in schema:
            base = urljoin(base, schema["$id"])
        if "$ref" in schema:
            target, uri = self.resolve(schema["$ref"], base)
            self.validate(instance, target, uri, path)
        for keyword in ("oneOf", "anyOf", "allOf"):
            if keyword in schema:
                passed = 0
                for child in schema[keyword]:
                    try:
                        self.validate(instance, child, base, path)
                        passed += 1
                    except CheckError:
                        pass
                expected = (passed == 1 if keyword == "oneOf" else
                            passed > 0 if keyword == "anyOf" else passed == len(schema[keyword]))
                require(expected, f"{path}: {keyword} matched {passed} branches")
        if "not" in schema:
            try:
                self.validate(instance, schema["not"], base, path)
            except CheckError:
                pass
            else:
                raise CheckError(f"{path}: forbidden schema matched")
        if "if" in schema:
            try:
                self.validate(instance, schema["if"], base, path)
                branch = "then"
            except CheckError:
                branch = "else"
            if branch in schema:
                self.validate(instance, schema[branch], base, path)
        if "type" in schema:
            checks = {
                "object": isinstance(instance, dict), "array": isinstance(instance, list),
                "string": isinstance(instance, str), "boolean": type(instance) is bool,
                "null": instance is None,
                "number": type(instance) in (int, float) and math.isfinite(instance),
                "integer": type(instance) in (int, float) and math.isfinite(instance) and int(instance) == instance,
            }
            requested = schema["type"]
            requested = requested if isinstance(requested, list) else [requested]
            require(all(t in checks for t in requested), "Unsupported schema type")
            require(any(checks[t] for t in requested), f"{path}: wrong type")
        if "const" in schema:
            require(json_equal(instance, schema["const"]), f"{path}: wrong const")
        if "enum" in schema:
            require(any(json_equal(instance, v) for v in schema["enum"]), f"{path}: outside enum")
        if isinstance(instance, dict):
            require(set(schema.get("required", [])) <= set(instance), f"{path}: missing required field")
            require(len(instance) >= schema.get("minProperties", 0), f"{path}: too few properties")
            require(len(instance) <= schema.get("maxProperties", math.inf), f"{path}: too many properties")
            properties = schema.get("properties", {})
            patterns = schema.get("patternProperties", {})
            for key, value in instance.items():
                matched = False
                if key in properties:
                    self.validate(value, properties[key], base, f"{path}.{key}")
                    matched = True
                for pattern, child in patterns.items():
                    if pattern_matches(pattern, key):
                        self.validate(value, child, base, f"{path}.{key}")
                        matched = True
                if not matched and "additionalProperties" in schema:
                    self.validate(value, schema["additionalProperties"], base, f"{path}.{key}")
        if isinstance(instance, list):
            require(len(instance) >= schema.get("minItems", 0), f"{path}: too few items")
            require(len(instance) <= schema.get("maxItems", math.inf), f"{path}: too many items")
            if schema.get("uniqueItems"):
                for i, value in enumerate(instance):
                    require(not any(json_equal(value, x) for x in instance[:i]), f"{path}: duplicate items")
            if "items" in schema:
                for i, value in enumerate(instance):
                    self.validate(value, schema["items"], base, f"{path}[{i}]")
        if isinstance(instance, str):
            require(len(instance) >= schema.get("minLength", 0), f"{path}: too short")
            require(len(instance) <= schema.get("maxLength", math.inf), f"{path}: too long")
            if "pattern" in schema:
                require(pattern_matches(schema["pattern"], instance), f"{path}: pattern mismatch")
        if type(instance) in (int, float):
            require(math.isfinite(instance), f"{path}: nonfinite JSON number")
            require(instance >= schema.get("minimum", -math.inf), f"{path}: below minimum")
            require(instance <= schema.get("maximum", math.inf), f"{path}: above maximum")
        # format is an annotation here. No RFC3339/format-assertion claim is made.


def value_type(value):
    return {k: value[k] for k in ("kind", "width") if k in value}


def fp32(value):
    require(value["kind"] == "fp32", "Expected FP32 typed value")
    return struct.unpack("!f", bytes.fromhex(value["bits"][2:]))[0]


def signature(model):
    return {side: [{"id": x["id"], "type": x["type"]} for x in model[side]]
            for side in ("inputs", "outputs")}


def check_values(values, entries):
    expected = {x["id"]: x["type"] for x in entries}
    require(len(expected) == len(entries), "Duplicate signature ID")
    require(set(values) == set(expected), "Typed value keys differ from signature")
    for key, value in values.items():
        require(value_type(value) == expected[key], f"Typed value type differs: {key}")
        if value["kind"] == "fp32":
            require(math.isfinite(fp32(value)), f"Nonfinite fixture value: {key}")


def check_mapping(mapping, left, right):
    for side in ("inputs", "outputs"):
        ltypes = {x["id"]: x["type"] for x in left[side]}
        rtypes = {x["id"]: x["type"] for x in right[side]}
        pairs = mapping[side]
        lkeys, rkeys = [p["left"] for p in pairs], [p["right"] for p in pairs]
        require(pairs and len(set(lkeys)) == len(lkeys) and len(set(rkeys)) == len(rkeys),
                f"Empty or noninjective {side} mapping")
        require(set(lkeys) <= set(ltypes) and set(rkeys) <= set(rtypes), "Unbound mapping ID")
        if side == "inputs":
            require(set(lkeys) == set(ltypes) and set(rkeys) == set(rtypes), "Incomplete input bijection")
        for pair in pairs:
            require(ltypes[pair["left"]] == rtypes[pair["right"]], "Mapping type mismatch")


def check_domain(domain, inputs, values=None):
    types = {x["id"]: x["type"] for x in inputs}
    for constraint in domain["constraints"]:
        key, op, bound = constraint["input"], constraint["op"], constraint["value"]
        require(key in types and value_type(bound) == types[key], "Domain name/type mismatch")
        kind = bound["kind"]
        allowed = {"bool": {"eq", "ne"}, "bv": {"eq", "ne", "ule", "uge", "sle", "sge"},
                   "fp32": {"eq", "ne", "le", "ge"}}[kind]
        require(op in allowed, "Domain operation/type mismatch")
        if kind == "fp32":
            require(math.isfinite(fp32(bound)), "Nonfinite domain bound")
        if values is None:
            continue
        value = values[key]
        if kind == "fp32":
            a, b = fp32(value), fp32(bound)
        elif kind == "bool":
            a, b = value["value"], bound["value"]
        else:
            a, b = int(value["bits"], 16), int(bound["bits"], 16)
            if op.startswith("s"):
                width = bound["width"]
                a = a - (1 << width) if a >> (width - 1) else a
                b = b - (1 << width) if b >> (width - 1) else b
        passed = (a == b if op == "eq" else a != b if op == "ne" else
                  a <= b if op in {"le", "ule", "sle"} else a >= b)
        require(passed, f"Fixture input outside declared domain: {key} {op}")


def check_example_model(model):
    sig = signature(model)
    for entries in sig.values():
        require(len({x["id"] for x in entries}) == len(entries), "Duplicate signature ID")
    check_domain(model["domain"], sig["inputs"])
    if model["kind"] == "numeric_template":
        definition = model["definition"]
        params, bounds = definition["parameters"], definition["parameter_bounds"]
        template = definition["template"]
        count = len(definition["fixed"].get("knots", [])) + 1
        keys = {"a", "b"} if template != "piecewise_affine" else {
            f"{letter}{i}" for i in range(count) for letter in "ab"}
        require(set(params) == set(bounds) == keys, "Numeric parameter/bound keys differ")
        for key in keys:
            lo, p, hi = fp32(bounds[key]["lower"]), fp32(params[key]), fp32(bounds[key]["upper"])
            require(all(math.isfinite(x) for x in (lo, p, hi)) and lo <= p <= hi, "Invalid parameter bounds")
        fixed = definition["fixed"]
        if template == "affine_clamp":
            lo, hi = fp32(fixed["lo"]), fp32(fixed["hi"])
            require(math.isfinite(lo) and math.isfinite(hi) and lo <= hi, "Invalid clamp bounds")
        if template == "piecewise_affine":
            knots = [fp32(v) for v in fixed["knots"]]
            require(all(math.isfinite(x) for x in knots) and all(a < b for a, b in zip(knots, knots[1:])),
                    "Invalid piecewise knots")
        return
    types = {x["id"]: x["type"] for x in model["inputs"]}
    fixture_ops = {"const", "bv_add", "bv_mul", "bv_xor", "bv_and", "bv_shl"}
    for node in model["nodes"]:
        require(node["id"] not in types, "Duplicate or shadowed SSA ID")
        require(all(arg in types for arg in node["args"]), "Forward/missing SSA reference")
        require(node["op"] in fixture_ops, "This handoff QA only evaluates the supplied BV fixture operations")
        require(node["type"]["kind"] == "bv", "Fixture BV node must return BV")
        if node["op"] == "const":
            require(value_type(node["attrs"]["value"]) == node["type"], "Constant type mismatch")
        elif node["op"] == "bv_shl":
            require(types[node["args"][0]] == node["type"] and
                    types[node["args"][1]]["kind"] == "bv", "Shift type mismatch")
        else:
            require(all(types[arg] == node["type"] for arg in node["args"]), "Arithmetic type mismatch")
        types[node["id"]] = node["type"]
    for output in model["outputs"]:
        require(types.get(output["ref"]) == output["type"], "Output reference/type mismatch")
    guard = model["scope"]["execution_guard"]
    if guard["kind"] == "model_bool":
        require(types.get(guard["node_id"]) == {"kind": "bool"}, "Invalid Bool guard")


def eval_bv_fixture(model, inputs):
    """Only the six operations used by the supplied self-authored BV models."""
    values = dict(inputs)
    for node in model["nodes"]:
        op, width = node["op"], node["type"]["width"]
        args = [values[key] for key in node["args"]]
        if op == "const":
            result = int(node["attrs"]["value"]["bits"], 16)
        elif op == "bv_add": result = args[0] + args[1]
        elif op == "bv_mul": result = args[0] * args[1]
        elif op == "bv_xor": result = args[0] ^ args[1]
        elif op == "bv_and": result = args[0] & args[1]
        elif op == "bv_shl": result = 0 if args[1] >= width else args[0] << args[1]
        else: raise CheckError(f"Unsupported fixture evaluation operation: {op}")
        values[node["id"]] = result & ((1 << width) - 1)
    return {x["id"]: values[x["ref"]] for x in model["outputs"]}


class HandoffQA:
    def __init__(self, root, skip_oracle):
        self.root = root.resolve()
        self.skip_oracle = skip_oracle
        self.results = []
        self.watched = {}
        self.schemas = {}
        self.objects = {}
        self.entries = []
        self.models, self.datasets, self.oracles = {}, {}, {}
        self.started_at = datetime.now(timezone.utc).isoformat()

    def read_bytes(self, path):
        path = Path(path).resolve()
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        previous = self.watched.setdefault(str(path), digest)
        require(previous == digest, f"File changed during QA: {path}")
        return data

    def load(self, relative):
        return parse_json(self.read_bytes(self.root / relative).decode("utf-8"))

    def lines(self, relative):
        text = self.read_bytes(self.root / relative).decode("utf-8")
        require(text.endswith("\n"), f"JSONL file has no final newline: {relative}")
        rows = []
        for number, line in enumerate(text.splitlines(), 1):
            require(line.strip(), f"Blank JSONL record: {relative}:{number}")
            rows.append(parse_json(line))
        return rows

    def run(self, label, action):
        try:
            details = action()
            self.results.append({"check": label, "status": "PASS", "details": details})
        except Exception as exc:
            self.results.append({"check": label, "status": "FAIL", "details": f"{type(exc).__name__}: {exc}"})

    def schema_checks(self):
        paths = sorted((self.root / "contracts").glob("*.schema.json"))
        require(len(paths) == 11, "Expected the 11 handoff schemas")
        for path in paths:
            schema = parse_json(self.read_bytes(path).decode("utf-8"))
            require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "Unexpected schema dialect label")
            require(schema["$id"] not in self.schemas, "Duplicate schema $id")
            self.schemas[schema["$id"]] = schema
        self.checker = SubsetSchemaChecker(self.schemas)
        for uri, schema in self.schemas.items():
            self.checker.inspect(schema, uri)
        return {"json_files": len(paths), "local_refs": self.checker.ref_count,
                "checker": "package-specific subset; NOT standard 2020-12 validation",
                "keywords_seen": sorted(self.checker.keywords), "format_assertions": "NOT_RUN"}

    def validate(self, instance, schema_reference):
        file, fragment = urldefrag(schema_reference)
        document = self.load(file)
        target, base = self.checker.resolve("#" + fragment if fragment else "", document["$id"])
        self.checker.validate(instance, target, base)

    def positive_checks(self):
        index = self.load("examples/contract-fixture-index.json")
        self.entries = index["positive_examples"]
        require(len({e["file"] for e in self.entries}) == len(self.entries), "Duplicate fixture-index file")
        records, json_count, jsonl_count = 0, 0, 0
        for entry in self.entries:
            require(entry["format"] in {"json", "jsonl"}, "Unknown index format")
            rows = self.lines(entry["file"]) if entry["format"] == "jsonl" else [self.load(entry["file"])]
            self.objects[entry["file"]] = rows
            for row in rows:
                self.validate(row, entry["schema"])
            records += len(rows)
            json_count += entry["format"] == "json"
            jsonl_count += entry["format"] == "jsonl"
        return {"indexed_files": len(self.entries), "json_files": json_count,
                "jsonl_files": jsonl_count, "jsonl_rows": records-json_count,
                "records_checked": records}

    def negative_checks(self):
        attempts = []
        model = self.load("examples/model.mba-u8.json")
        bad = copy.deepcopy(model); bad["fidelity"] = "sampled_match"
        attempts.append((bad, "contracts/model.schema.json", "imported fidelity field"))
        bad = self.load("examples/model.increment-u64.json")
        bad["nodes"][0]["attrs"]["value"]["bits"] = "0x01"
        attempts.append((bad, "contracts/model.schema.json", "short BV64 bit string"))
        numeric = self.load("examples/request.compare-numeric-samples.json")
        bad = copy.deepcopy(numeric); del bad["sample_source"]
        attempts.append((bad, "contracts/experiment-request.schema.json", "sampled FP32 without inputs"))
        bad = copy.deepcopy(numeric); bad["comparison_policy"] = {"kind": "exact-bv"}
        attempts.append((bad, "contracts/experiment-request.schema.json", "FP32 with BV policy"))
        bad = self.load("examples/request.compare-equivalent.json"); bad["mapping"]["outputs"] = []
        attempts.append((bad, "contracts/experiment-request.schema.json", "empty compared outputs"))
        for instance, schema, name in attempts:
            try:
                self.validate(instance, schema)
            except CheckError:
                continue
            raise CheckError(f"Known-invalid mutation was accepted: {name}")
        bad_mapping = {"inputs": [{"left": "a", "right": "a"}, {"left": "b", "right": "a"}],
                       "outputs": [{"left": "result", "right": "result"}]}
        try:
            check_mapping(bad_mapping, signature(model), signature(model))
        except CheckError:
            pass
        else:
            raise CheckError("Noninjective input mapping was accepted")
        return {"rejected_mutations": len(attempts)+1, "scope": "smoke checks, not checker conformance tests"}

    def artifact_checks(self):
        found = set()
        def walk(value):
            if isinstance(value, dict):
                keys = {"sha256", "relative_path", "media_type", "size_bytes"}
                if keys <= set(value) and isinstance(value["sha256"], str) and isinstance(value["relative_path"], str):
                    self.validate(value, "contracts/common.schema.json#/$defs/artifact_ref")
                    relative = value["relative_path"]
                    path = self.root / relative
                    require(path.resolve().is_relative_to(self.root), f"Artifact escapes package: {relative}")
                    require(not any(p.is_symlink() for p in [path, *path.parents] if p != self.root.parent),
                            f"Symlink artifact path: {relative}")
                    data = self.read_bytes(path)
                    require(len(data) == value["size_bytes"], f"Artifact length mismatch: {relative}")
                    require(hashlib.sha256(data).hexdigest() == value["sha256"], f"Artifact hash mismatch: {relative}")
                    found.add((relative, value["sha256"], value["size_bytes"]))
                for child in value.values(): walk(child)
            elif isinstance(value, list):
                for child in value: walk(child)
        for path in sorted(self.root.rglob("*.json")):
            walk(parse_json(self.read_bytes(path).decode("utf-8")))
        for path in sorted(self.root.rglob("*.jsonl")):
            for row in self.lines(path.relative_to(self.root)): walk(row)
        oracle = self.load("examples/oracle.reference-fp32.json")
        for item in oracle["target_files"]:
            path = self.root / "examples" / item["path"]
            data = self.read_bytes(path)
            require(hashlib.sha256(data).hexdigest() == item["sha256"], "Oracle target-file hash mismatch")
        return {"unique_artifact_refs": len(found), "oracle_target_files": len(oracle["target_files"])}

    def reference_checks(self):
        requests = []
        for rows in self.objects.values():
            for obj in rows:
                for key, registry in (("model_id", self.models), ("dataset_id", self.datasets), ("oracle_id", self.oracles)):
                    if key in obj and ((key == "model_id" and "kind" in obj) or
                                       (key == "dataset_id" and isinstance(obj.get("splits"), dict) and "signature" in obj) or
                                       (key == "oracle_id" and obj.get("kind") == "process_jsonl")):
                        require(obj[key] not in registry, f"Duplicate object ID: {obj[key]}")
                        registry[obj[key]] = obj
                if "experiment_id" in obj: requests.append(obj)
        require(len({r["experiment_id"] for r in requests}) == len(requests), "Duplicate experiment ID")
        for model in self.models.values(): check_example_model(model)
        for request in requests:
            budget = request["budget"]
            require(budget["solver_soft_time_ms"] <= budget["solver_hard_time_ms"] <= budget["wall_time_ms"], "Inconsistent deadlines")
            op = request["operation"]
            if op == "compare_models":
                left, right = self.models[request["left_model_id"]], self.models[request["right_model_id"]]
                check_mapping(request["mapping"], signature(left), signature(right))
                kind = "bv_dag" if request["mode"] == "exact_bv" else "numeric_template"
                require(left["kind"] == right["kind"] == kind, "Comparison mode/model mismatch")
                # The provided examples use identical domains; this is not a general implication solver.
                require(request["domain"] == left["domain"] == right["domain"], "QA domain equality case changed")
            elif op == "verify_candidate":
                model, dataset = self.models[request["candidate_model_id"]], self.datasets[request["dataset_id"]]
                check_mapping(request["mapping"], signature(model), dataset["signature"])
                if request["source_mode"] == "live":
                    oracle = self.oracles[request["oracle_id"]]
                    require(oracle["signature"] == dataset["signature"] and oracle["domain"] == dataset["domain"], "Live binding mismatch")
            elif op == "fit_numeric":
                model, dataset = self.models[request["template_model_id"]], self.datasets[request["dataset_id"]]
                require(model["kind"] == "numeric_template" and signature(model) == dataset["signature"], "Fit signature mismatch")
                require(model["domain"] == dataset["domain"], "Fit fixture domains differ")
                require(all(dataset["splits"][s]["sample_ids"] for s in ("train", "validation", "holdout")), "Empty fit split")
            elif op == "simplify":
                model = self.models[request["reference_model_id"]]
                require(model["kind"] == "bv_dag" and request["domain"] == model["domain"], "Simplify fixture mismatch")
            elif op == "suggest_inputs":
                selected = [self.models[key] for key in request["model_ids"]]
                require(all(signature(x) == signature(selected[0]) and x["domain"] == request["domain"] for x in selected), "Suggestion signatures/domains differ")
            else:
                raise CheckError(f"No supplied-request QA handler: {op}")
        return {"models": len(self.models), "datasets": len(self.datasets), "oracles": len(self.oracles),
                "requests": len(requests), "domain_check_scope": "the supplied identical-domain examples only"}

    def dataset_checks(self):
        dataset = self.load("examples/dataset.numeric-expected.json")
        plan = self.lines(dataset["sampling_plan"]["inputs_artifact"]["relative_path"])
        require(len(plan) == dataset["sampling_plan"]["planned"] == 32, "Expected 32 planned fixture inputs")
        planned = {row["sample_id"]: row for row in plan}
        require(len(planned) == len(plan), "Duplicate planned sample ID")
        definition_data = self.read_bytes(self.root / "examples/numeric-reference-definition.json")
        source_hash = hashlib.sha256(definition_data).hexdigest()
        require(dataset["source"]["source_identity_sha256"] == source_hash, "Fixture definition identity mismatch")
        ids, observation_ids, request_ids, input_splits = set(), set(), set(), {}
        sizes, observations = {}, []
        for split in ("train", "validation", "holdout"):
            part = dataset["splits"][split]
            rows = self.lines(part["artifact"]["relative_path"])
            require([row["sample_id"] for row in rows] == part["sample_ids"], f"Split membership differs: {split}")
            sizes[split] = len(rows)
            for row in rows:
                require(row["sample_id"] not in ids and row["observation_id"] not in observation_ids and
                        row["request_id"] not in request_ids, "Duplicate observation/sample/request identity")
                ids.add(row["sample_id"]); observation_ids.add(row["observation_id"]); request_ids.add(row["request_id"])
                require(row["split"] == split == planned[row["sample_id"]]["split"], "Split label mismatch")
                require(row["inputs"] == planned[row["sample_id"]]["inputs"], "Observed/planned input mismatch")
                require(row["record_kind"] == "expected_fixture" and row["source_kind"] == "reference_fixture", "Expected data must remain self-authored fixture material")
                require(row["source_id"] == dataset["source"]["source_id"] and row["source_identity_sha256"] == source_hash, "Observation source differs")
                require(row["observed_at"] is None and row["duration_ms"] is None, "Expected fixture falsely carries run metadata")
                require(row["status"] == "ok" and row["error"] is None, "Expected supplied fixture is not ok")
                check_values(row["inputs"], dataset["signature"]["inputs"])
                check_values(row["outputs"], dataset["signature"]["outputs"])
                check_domain(dataset["domain"], dataset["signature"]["inputs"], row["inputs"])
                key = json.dumps(row["inputs"], sort_keys=True, separators=(",", ":"))
                require(key not in input_splits or input_splits[key] == split, "Typed input leaks across splits")
                input_splits[key] = split
                observations.append(row)
        require(ids == set(planned), "Input plan and observations differ")
        require(sizes == {"train": 16, "validation": 8, "holdout": 8}, "Expected 16/8/8 fixture partition")
        self.observations = observations
        return {"planned": 32, "split_sizes": sizes, "distinct_typed_inputs": len(input_splits),
                "source_records": "expected_fixture only; zero historical original-target observations"}

    def bv_material_checks(self):
        mba = self.models["mba_u8"]; add = self.models["add_u8"]; wrong = self.models["add_u8_wrong"]
        differing = 0
        for a in range(256):
            for b in range(256):
                values = {"a": a, "b": b}; expected = (a + b) & 255
                require(eval_bv_fixture(mba, values)["result"] == expected, "MBA fixture differs from modular addition")
                require(eval_bv_fixture(add, values)["result"] == expected, "Add fixture differs")
                differing += eval_bv_fixture(wrong, values)["result"] != expected
        require(differing == 65536, "Intentional wrong candidate did not differ everywhere")
        wide_values = [0, (1 << 53)+1, 1 << 63, (1 << 64)-1]
        for value in wide_values:
            require(eval_bv_fixture(self.models["increment_u64"], {"x": value})["result"] == (value+1) % (1 << 64), "BV64 increment differs")
        counts = [0, 7, 8, 9, 255, 256, (1 << 64)-1]
        for value in [1, 128, 255]:
            for count in counts:
                expected = 0 if count >= 8 else (value << count) & 255
                require(eval_bv_fixture(self.models["wide_shift_u8"], {"x": value, "count": count})["result"] == expected, "Wide-count shift differs")
        return {"bv8_input_pairs": 65536, "wrong_candidate_differences": differing,
                "first_wrong_counterexample": {"a": "0x00", "b": "0x00", "reference": "0x00", "wrong": "0x01"},
                "bv64_boundary_inputs": len(wide_values), "wide_count_shift_inputs": 21,
                "scope": "self-authored Python fixture mathematics; no Z3 or TS product execution"}

    def vector_checks(self):
        rows = self.lines("fixtures/reference_vectors.jsonl")
        require(len({r["sample_id"] for r in rows}) == len(rows), "Duplicate reference vector ID")
        checked = 0
        for row in rows:
            require(row["origin"] == "self_authored_reference" and row["is_upstream_observation"] is False, "Vector origin overclaims")
            op = row["probe_operation"]
            if op not in {"mba_original", "mba_simplified", "add64", "mul64", "shl8", "lshr8", "ashr8", "shl64", "lshr64", "ashr64"}:
                continue
            a, b = [int(v, 16) for v in row["probe_arguments"]]
            width = 8 if op.endswith("8") or op.startswith("mba") else 64
            mask = (1 << width)-1
            if op in {"mba_original", "mba_simplified", "add64"}: value = (a+b) & mask
            elif op == "mul64": value = (a*b) & mask
            elif op.startswith("shl"): value = 0 if b >= width else (a << b) & mask
            elif op.startswith("lshr"): value = 0 if b >= width else a >> b
            else:
                signed = a - (1 << width) if a >> (width-1) else a
                value = (mask if signed < 0 else 0) if b >= width else (signed >> b) & mask
            expected = row["expected"]
            require(expected["status"] == "ok" and expected["outputs"]["result"] ==
                    {"kind": "bv", "width": width, "bits": f"0x{value:0{width//4}x}"}, f"Integer vector mismatch: {row['sample_id']}")
            checked += 1
        require(checked == 76, "Expected 76 supplied integer/MBA/shift reference vectors")
        return {"all_vector_rows_read": len(rows), "integer_vectors_checked": checked,
                "other_vector_computations": "outside this script's bounded scope"}

    def oracle_checks(self):
        require(hasattr(self, "observations"), "Dataset check must succeed before fixture replay")
        manifest = self.load("examples/oracle.reference-fp32.json")
        fixture = self.root / "fixtures/oracle_fp32.py"
        require(manifest["argv"] == ["python3", "fixtures/oracle_fp32.py"] and
                (self.root / "examples" / manifest["cwd"]).resolve() == self.root and
                manifest["reset_strategy"] == "fresh_process", "QA only runs the explicitly known self-authored fixture")
        before = hashlib.sha256(self.read_bytes(fixture)).hexdigest()
        require(any((self.root / "examples" / x["path"]).resolve() == fixture.resolve() and x["sha256"] == before
                    for x in manifest["target_files"]), "Fresh fixture identity is not bound by manifest")
        replies = []
        for row in self.observations:
            request = {"protocol_version": 1, "request_id": row["request_id"], "inputs": row["inputs"]}
            self.validate(request, "contracts/oracle-request.schema.json")
            process = subprocess.run([sys.executable, str(fixture)],
                                     input=json.dumps(request, separators=(",", ":"))+"\n",
                                     cwd=self.root, capture_output=True, text=True,
                                     timeout=manifest["request_timeout_ms"]/1000,
                                     env={k: os.environ[k] for k in manifest["allowed_env_keys"] if k in os.environ})
            require(process.returncode == 0 and not process.stderr, f"Fixture process failed for {row['sample_id']}")
            lines = process.stdout.splitlines()
            require(len(lines) == 1, "Fixture response is not exactly one JSONL line")
            reply = parse_json(lines[0])
            self.validate(reply, "contracts/oracle-response.schema.json")
            require(reply["request_id"] == request["request_id"] and reply["status"] == "ok", "Fixture response correlation/status differs")
            require(reply["outputs"] == row["outputs"], f"Fixture FP32 bits differ: {row['sample_id']}")
            replies.append(reply)
        require(hashlib.sha256(self.read_bytes(fixture)).hexdigest() == before, "Fixture changed during replay")
        return {"fresh_processes": len(replies), "bitwise_matches": len(replies), "fixture_sha256": before,
                "responses_sha256": hashlib.sha256(json.dumps(replies, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "python_executable": sys.executable,
                "scope": "self-authored exact-integer/rational FP32 fixture; not WireFix Oracle integration"}

    def stability_checks(self):
        for filename, before in self.watched.items():
            require(hashlib.sha256(Path(filename).read_bytes()).hexdigest() == before, f"QA input changed: {filename}")
        inventory = {str(Path(path).relative_to(self.root)): sha for path, sha in self.watched.items()}
        return {"watched_files": len(inventory), "input_inventory_sha256": hashlib.sha256(
            json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}

    def execute(self):
        for label, action in [
            ("Schema JSON / local references / keyword inventory", self.schema_checks),
            ("Indexed positive examples and JSONL rows", self.positive_checks),
            ("Known-invalid in-memory mutations", self.negative_checks),
            ("Artifact and fixture target hash/length checks", self.artifact_checks),
            ("Example model/request IDs and key cross-field checks", self.reference_checks),
            ("32 expected rows and 16/8/8 leakage checks", self.dataset_checks),
            ("BV8 exhaustive identity and wide-integer models", self.bv_material_checks),
            ("Self-authored integer reference-vector checks", self.vector_checks),
        ]:
            self.run(label, action)
        if self.skip_oracle:
            self.results.append({"check": "Self-authored FP32 fixture fresh-process replay", "status": "NOT_RUN", "details": "Explicit --skip-oracle"})
        else:
            self.run("Self-authored FP32 fixture fresh-process replay", self.oracle_checks)
        self.run("Input files stable during QA", self.stability_checks)
        for label in ["Standard JSON Schema 2020-12 validator compilation/conformance",
                      "REA/Ghidra product integration", "Z3 product solver execution",
                      "Handwired build/evaluation/backprop product integration",
                      "WireFix CLI/MCP/product implementation"]:
            self.results.append({"check": label, "status": "NOT_RUN", "details": "Outside this handoff QA; no success is claimed"})
        return {"scope": "handoff_package_qa_only", "started_at": self.started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "python_version": platform.python_version(), "platform": platform.platform(),
                "overall": "FAIL" if any(x["status"] == "FAIL" for x in self.results) else "PASS_BOUNDED_CHECKS",
                "checks": self.results}


def report_markdown(summary):
    lines = ["# 交付包离线校验记录", "",
             "本记录仅验证本实施包和自写夹具。它不是 WireFix 产品验收报告，也不证明外部工具已经接入。", "",
             f"- 开始：`{summary['started_at']}`", f"- 完成：`{summary['finished_at']}`",
             f"- 环境：Python `{summary['python_version']}`；`{summary['platform']}`",
             f"- 本轮结论：`{summary['overall']}`", "",
             "## 重跑", "", "```bash", "python3 tools/check_handoff.py",
             "# 显式更新本记录；重新打包前还需重建最终 MANIFEST：",
             "python3 tools/check_handoff.py --write-report", "```", "",
             "默认不写文件；会对本包已明确绑定的自写 FP32 fixture 发起 32 次 fresh-process 调用。"
             "`--skip-oracle` 可跳过该调用，届时该项记录为 NOT_RUN。", "",
             "## 本轮检查", "", "| 检查 | 状态 |", "| --- | --- |"]
    for row in summary["checks"]:
        lines.append(f"| {row['check']} | {row['status']} |")
    lines += ["", "## 方法与限制", "",
              "- 使用 Python 标准库解析 JSON、拒绝重复键和非标准数值，并核对本地 `$ref`。",
              "- 自定义结构检查器仅覆盖本包出现的有限关键词；未知关键词报错。它不是标准 JSON Schema 2020-12 validator，未运行 meta-schema/conformance 编译。",
              "- `format` 只作注解；正则按本包的有限 ASCII 表达式检查，不宣称实现完整 ECMAScript 正则语义。",
              "- 跨字段检查只针对所附样例的 ID、签名、拓扑、六种 BV 夹具算子、数值参数和域、映射、文件身份及数据划分；它不是产品完整语义 validator，也不是域包含关系求解器。",
              "- 32 行历史数据仍是 expected_fixture。重跑自写 Python fixture 只增加本包夹具回放证据，不把这些文件重标为原目标观测。",
              "- BV8 全枚举和整数向量一致性是自写材料的数学核对，没有运行 Z3、产品 TypeScript 执行器或外部二进制逆向链。",
              "- 其余 C/浮点/状态夹具的独立检查若有记录，见 fixtures/validation；本脚本不把它们冒充本轮执行。",
              "- 最终文件 MANIFEST 由打包步骤另行生成；默认重跑本脚本不会改写本记录或使清单过期。", "",
              "## 详细记录", "", "```json", json.dumps(summary, ensure_ascii=False, indent=2), "```", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--write-report", action="store_true", help="Explicitly update docs/HANDOFF_VALIDATION.md")
    parser.add_argument("--skip-oracle", action="store_true", help="Do not launch the self-authored fixture")
    args = parser.parse_args()
    qa = HandoffQA(args.root, args.skip_oracle)
    summary = qa.execute()
    if args.write_report:
        destination = qa.root / "docs/HANDOFF_VALIDATION.md"
        destination.write_text(report_markdown(summary), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 1 if summary["overall"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
