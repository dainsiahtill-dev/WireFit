#!/usr/bin/env python3
"""Generate owned reference vectors and compare real compiled C observations.

This development-only verifier is not a WireFix product implementation.
No solver, REA, Ghidra, Handwired or fitting run is performed here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
from oracle_fp32 import (  # noqa: E402; local public ground-truth reference only
    Fp32DomainError, affine_bits, clamp_bits, f32_add_bits, f32_mul_bits,
    finite_fraction, reference_target_bits,
)

ROOT = Path(__file__).resolve().parent
MASK64 = (1 << 64) - 1
SEED = 0xB1AB2026


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def hex_bits(value: int, width: int) -> str:
    return f"0x{value:0{width // 4}x}"


@dataclass(frozen=True)
class Case:
    group: str
    operation: str
    arguments: tuple[str, ...]
    expected: str

    def command(self) -> str:
        return " ".join((self.operation, *self.arguments))


def bv_case(group: str, op: str, args: list[tuple[int, int]], width: int, expected: int) -> Case:
    return Case(group, op, tuple(hex_bits(value, bits) for value, bits in args),
                f"OK bv{width} {hex_bits(expected, width)}")


def numeric_result(op: str, args: tuple[int, ...]) -> int:
    if op == "f32_add": return f32_add_bits(*args)
    if op == "f32_mul": return f32_mul_bits(*args)
    if op == "f32_affine": return affine_bits(*args)
    if op == "f32_clamp": return clamp_bits(*args)
    x = args[0]
    if op == "affine_target": return affine_bits(x, 0x3FC00000, 0xBE800000)
    if op == "clamp_target": return reference_target_bits(x)
    if op == "piecewise_target":
        value = finite_fraction(x)
        a, b = (0x3F000000, 0xBE800000) if value < -1 else \
               (0xBFC00000, 0x3F000000) if value < 1 else (0x40000000, 0xBF800000)
        return affine_bits(x, a, b)
    raise ValueError(f"Unknown numeric operation {op}")


def fp_case(group: str, op: str, *args: int, golden: int | str | None = None) -> Case:
    try:
        expected = f"OK fp32 {numeric_result(op, args):#010x}"
    except Fp32DomainError as exc:
        expected = f"ERROR {exc.code}"
    if golden is not None:
        literal = f"ERROR {golden}" if isinstance(golden, str) else f"OK fp32 {golden:#010x}"
        if expected != literal:
            raise AssertionError(f"Independent literal expectation failed: {op} {args}: {expected} != {literal}")
    return Case(group, op, tuple(hex_bits(value, 32) for value in args), expected)


def golden_numeric_cases() -> list[Case]:
    cases = [
        fp_case("fp32_goldens", "f32_add", 0, 0x80000000, golden=0),
        fp_case("fp32_goldens", "f32_add", 0x80000000, 0x80000000, golden=0x80000000),
        fp_case("fp32_goldens", "f32_add", 0x3F800000, 0xBF800000, golden=0),
        fp_case("fp32_goldens", "f32_add", 0x3F800000, 0x33800000, golden=0x3F800000),
        fp_case("fp32_goldens", "f32_add", 0x3F800001, 0x33800000, golden=0x3F800002),
        fp_case("fp32_goldens", "f32_mul", 1, 0x3F800000, golden=1),
        fp_case("fp32_goldens", "f32_mul", 0x00800000, 0x3F000000, golden=0x00400000),
        fp_case("fp32_goldens", "f32_mul", 1, 0x3F000000, golden=0),
        fp_case("fp32_goldens", "f32_mul", 0x80000001, 0x3F000000, golden=0x80000000),
        fp_case("fp32_goldens", "f32_mul", 3, 0x3F000000, golden=2),
        fp_case("fp32_goldens", "f32_mul", 0x80000000, 0x3F800000, golden=0x80000000),
        fp_case("fp32_goldens", "f32_affine", 0x3F7FFFFE, 0x3F800001, 0xBF800000, golden=0),
        fp_case("fp32_goldens", "f32_clamp", 0x80000000, 0, 0, golden=0x80000000),
        fp_case("fp32_goldens", "f32_clamp", 0, 0x80000000, 0x80000000, golden=0),
        fp_case("fp32_goldens", "f32_clamp", 0xC0000001, 0xC0000000, 0x40000000, golden=0xC0000000),
        fp_case("fp32_goldens", "f32_clamp", 0x40000001, 0xC0000000, 0x40000000, golden=0x40000000),
        fp_case("fp32_goldens", "f32_clamp", 0xC0000000, 0xC0000000, 0x40000000, golden=0xC0000000),
        fp_case("fp32_goldens", "f32_clamp", 0x40000000, 0xC0000000, 0x40000000, golden=0x40000000),
        fp_case("fp32_rejections", "f32_mul", 0x7F7FFFFF, 0x40000000, golden="NONFINITE_INTERMEDIATE"),
        fp_case("fp32_rejections", "f32_add", 0x7F7FFFFF, 0x7F7FFFFF, golden="NONFINITE_INTERMEDIATE"),
        fp_case("fp32_rejections", "clamp_target", 0x7F7FFFFF, golden="NONFINITE_INTERMEDIATE"),
        fp_case("fp32_rejections", "clamp_target", 0x7F800000, golden="NONFINITE_INPUT"),
        fp_case("fp32_rejections", "clamp_target", 0x7FC00000, golden="NONFINITE_INPUT"),
        fp_case("fp32_rejections", "f32_clamp", 0, 0x3F800000, 0xBF800000, golden="INVALID_BOUNDS"),
    ]
    for bits in (0xBF800001, 0xBF800000, 0xBF7FFFFF, 0x3F7FFFFF, 0x3F800000, 0x3F800001):
        cases.append(fp_case("fp32_piecewise_boundaries", "piecewise_target", bits))
    return cases


def shift_reference(value: int, count: int, width: int, kind: str) -> int:
    mask = (1 << width) - 1
    if kind == "ashr":
        signed = value - (1 << width) if value & (1 << (width - 1)) else value
        return (mask if signed < 0 else 0) if count >= width else (signed >> count) & mask
    if count >= width: return 0
    return (value << count) & mask if kind == "shl" else value >> count


def all_cases(*, smoke: bool = False) -> list[Case]:
    rng = random.Random(SEED)
    cases: list[Case] = []
    pairs = [(0, 0), (255, 1), (127, 1), (170, 85), (255, 255)] if smoke else \
        ((x, y) for x in range(256) for y in range(256))
    for x, y in pairs:
        for op in ("mba_original", "mba_simplified"):
            cases.append(bv_case("bv8_mba", op, [(x, 8), (y, 8)], 8, (x + y) & 255))
    edges = [0, 1, 2, (1 << 32) - 1, 1 << 32, (1 << 53) - 1, (1 << 53) + 1,
             (1 << 63) - 1, 1 << 63, MASK64 - 1, MASK64]
    pairs64 = [(MASK64, 1), (1 << 63, 2), ((1 << 53) + 1, 0)] if smoke else \
        [(x, y) for x in edges for y in edges] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(256)]
    for x, y in pairs64:
        cases.append(bv_case("bv64_wrap", "add64", [(x, 64), (y, 64)], 64, (x + y) & MASK64))
        cases.append(bv_case("bv64_wrap", "mul64", [(x, 64), (y, 64)], 64, (x * y) & MASK64))
    counts = [0, 1, 7, 8, 9, 31, 32, 62, 63, 64, 65, 255, 256, 257, 1 << 32, (1 << 53) + 1, MASK64]
    for width, values in ((8, [1, 128] if smoke else range(256)),
                          (64, [1, 1 << 63] if smoke else edges + [rng.getrandbits(64) for _ in range(64)])):
        selected_counts = [width - 1, width, width + 1, 256, MASK64] if smoke else counts
        for value in values:
            for count in selected_counts:
                for kind in ("shl", "lshr", "ashr"):
                    cases.append(bv_case(f"wide_shifts_bv{width}", f"{kind}{width}",
                                         [(value, width), (count, 64)], width,
                                         shift_reference(value, count, width, kind)))
    for x in ([99, 100, 101] if smoke else list(range(256)) + [0x7FFFFFFF, 0xFFFFFFFF]):
        cases.append(bv_case("boundary_versions", "boundary_v1", [(x, 32)], 8, int(x < 100)))
        cases.append(bv_case("boundary_versions", "boundary_v2", [(x, 32)], 8, int(x <= 100)))
    for op, arg, expected in (("side_reset", 0, 0), ("side_effect", 5, 6), ("side_effect", 5, 7),
                              ("side_reset", 0xFFFFFFFF, 0xFFFFFFFF), ("side_effect", 0, 0), ("side_effect", 0, 1)):
        cases.append(bv_case("side_effect_sequence", op, [(arg, 32)], 32, expected))
    cases.extend(golden_numeric_cases())
    numeric_edges = [0, 0x80000000, 1, 0x80000001, 0x007FFFFF, 0x00800000,
                     0xBF800001, 0xBF800000, 0xBF7FFFFF, 0x3F7FFFFF, 0x3F800000,
                     0x3F800001, 0xBFA00000, 0x3FC00000, 0x40000000, 0xC0000000]
    for x in numeric_edges:
        for op in ("affine_target", "clamp_target", "piecewise_target"):
            cases.append(fp_case("fp32_targets", op, x))
    if not smoke:
        def random_finite() -> int:
            while True:
                bits = rng.getrandbits(32)
                if (bits & 0x7F800000) != 0x7F800000: return bits
        for _ in range(512):
            a, b = random_finite(), random_finite()
            cases.append(fp_case("fp32_random", "f32_add", a, b))
            cases.append(fp_case("fp32_random", "f32_mul", a, b))
        for _ in range(128):
            x, a, b = random_finite(), random_finite(), random_finite()
            cases.append(fp_case("fp32_random", "f32_affine", x, a, b))
            lo, hi = sorted((a, b), key=finite_fraction)
            cases.append(fp_case("fp32_random", "f32_clamp", x, lo, hi))
        for _ in range(256):
            x = random_finite()
            for op in ("affine_target", "clamp_target", "piecewise_target"):
                cases.append(fp_case("fp32_random_targets", op, x))
    return cases


def vector_record(case: Case, index: int) -> dict[str, object]:
    fields = case.expected.split()
    if fields[0] == "ERROR":
        expected: dict[str, object] = {"status": "error", "outputs": {}, "error": {"code": fields[1]}}
    else:
        value = {"kind": "fp32", "bits": fields[2]} if fields[1] == "fp32" else \
            {"kind": "bv", "width": int(fields[1][2:]), "bits": fields[2]}
        expected = {"status": "ok", "outputs": {"result": value}}
    return {"schema_version": "wirefix.fixture-vector.v1", "sample_id": f"fixture_{index:04d}",
            "origin": "self_authored_reference", "reference_method": "exact_python_integer_or_rational",
            "group": case.group, "probe_operation": case.operation, "probe_arguments": list(case.arguments),
            "expected": expected, "is_upstream_observation": False}


def run_compiled(compiler: str, tag: str, extra_flags: list[str], build_dir: Path, cases: list[Case]) -> dict[str, object]:
    binary = build_dir / f"fixture_probe_{tag}"
    argv = [compiler, "-std=c11", "-g", "-Wall", "-Wextra", "-Werror", "-pedantic",
            "-fno-fast-math", "-ffp-contract=off", "-frounding-math", "-fno-lto", *extra_flags,
            str(ROOT / "behavior_fixtures.c"), str(ROOT / "fixture_probe.c"), "-lm", "-o", str(binary)]
    started = utc_now()
    compiled = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
    result: dict[str, object] = {"configuration": tag, "started_at": started, "compile_argv": argv,
                                 "compile_exit_code": compiled.returncode, "compile_stdout": compiled.stdout,
                                 "compile_stderr": compiled.stderr}
    if compiled.returncode != 0:
        result.update(status="FAIL", reason="compiler_failed", finished_at=utc_now())
        return result
    env_run = subprocess.run([str(binary), "f32_env"], capture_output=True, text=True, timeout=10, check=False)
    result["fp32_environment"] = {"exit_code": env_run.returncode, "stdout": env_run.stdout, "stderr": env_run.stderr}
    payload = ("\n".join(case.command() for case in cases) + "\n").encode()
    run_argv = [str(binary), "--batch"]
    observed = subprocess.run(run_argv, input=payload, capture_output=True, timeout=120, check=False)
    lines = observed.stdout.decode("utf-8", errors="replace").splitlines()
    groups: dict[str, dict[str, int]] = defaultdict(lambda: {"planned": 0, "observed": 0, "matched": 0,
                                                           "mismatched": 0, "expected_rejections": 0})
    failures = []
    for index, case in enumerate(cases):
        counts = groups[case.group]
        counts["planned"] += 1
        counts["expected_rejections"] += int(case.expected.startswith("ERROR "))
        actual = lines[index] if index < len(lines) else None
        counts["observed"] += int(actual is not None)
        counts["matched"] += int(actual == case.expected)
        counts["mismatched"] += int(actual != case.expected)
        if actual != case.expected and len(failures) < 20:
            failures.append({"index": index, "command": case.command(), "expected": case.expected, "actual": actual})
    ok = observed.returncode == 0 and len(lines) == len(cases) and not failures and \
        env_run.returncode == 0 and env_run.stdout.strip() == "OK environment binary32-rne-gradual"
    result.update(status="PASS" if ok else "FAIL", finished_at=utc_now(), run_argv=run_argv,
                  executable_sha256=sha256_bytes(binary.read_bytes()), stdin_sha256=sha256_bytes(payload),
                  stdout_sha256=sha256_bytes(observed.stdout), exit_code=observed.returncode,
                  stderr=observed.stderr.decode("utf-8", errors="replace")[:1_048_576],
                  planned=len(cases), response_lines=len(lines), groups=dict(groups), failures=failures)
    return result


def wrapper_checks() -> dict[str, object]:
    valid_bits = [0, 0x80000000, 1, 0x80000001, 0x007FFFFF, 0x00800000, 0xBF800000,
                  0x3F800000, 0x3FC00000, 0x40000000, 0xC0000000, 0x7F7FFFFF,
                  0xFF7FFFFF, 0x7F800000, 0xFF800000, 0x7FC00000]
    checks: list[tuple[bytes, object, str, str | None]] = []
    for index, bits in enumerate(valid_bits):
        request_id = f"fresh_{index:03d}"
        request = {"protocol_version": 1, "request_id": request_id,
                   "inputs": {"x": {"kind": "fp32", "bits": hex_bits(bits, 32)}}}
        try:
            expected, code = hex_bits(reference_target_bits(bits), 32), None
        except Fp32DomainError as exc:
            expected, code = "error", exc.code
        checks.append(((json.dumps(request) + "\n").encode(), request_id, expected, code))
    malformed = [
        (b'{bad}\n', None, "MALFORMED_JSON"),
        (b'[]\n', None, "INVALID_REQUEST"),
        (b'{"protocol_version":1,"inputs":{}}\n', None, "INVALID_REQUEST_ID"),
        (b'{"protocol_version":1,"request_id":"has space","inputs":{}}\n', None, "INVALID_REQUEST_ID"),
        (b'{"protocol_version":true,"request_id":"bad","inputs":{}}\n', "bad", "INVALID_REQUEST"),
        (b'{"protocol_version":1,"request_id":"bad","inputs":{},"extra":1}\n', "bad", "INVALID_REQUEST"),
        (b'{"protocol_version":1,"request_id":"bad","inputs":{}}\n', "bad", "INVALID_INPUTS"),
        (b'{"protocol_version":1,"request_id":"bad","inputs":{"x":{"kind":"fp32","bits":"0xABCDEF00"}}}\n', "bad", "INVALID_BITS"),
        (b'{"protocol_version":1,"request_id":"bad","request_id":"dup","inputs":{}}\n', None, "MALFORMED_JSON"),
        (b'\xff\n', None, "MALFORMED_JSON"),
        (b'x' * 1_048_577, None, "LINE_TOO_LONG"),
    ]
    checks.extend((raw, request_id, "error", code) for raw, request_id, code in malformed)
    records = []
    for raw, request_id, expected, code in checks:
        response_id = request_id if request_id is not None else "unbound_request"
        started = time.monotonic()
        run = subprocess.run([sys.executable, str(ROOT / "oracle_fp32.py")], input=raw,
                             capture_output=True, timeout=10, check=False)
        try:
            response = json.loads(run.stdout)
            framed = run.returncode == 0 and not run.stderr and len(run.stdout.splitlines()) == 1 and \
                response.get("protocol_version") == 1 and response.get("request_id") == response_id
            ok = framed and (response.get("status") == "error" and response.get("outputs") == {} and
                             response.get("error", {}).get("code") == code if expected == "error" else
                             response.get("status") == "ok" and response.get("outputs") ==
                             {"result": {"kind": "fp32", "bits": expected}})
        except (ValueError, AttributeError):
            response, ok = None, False
        records.append({"status": "PASS" if ok else "FAIL", "request_id": request_id,
                        "expected_response_id": response_id,
                        "request_sha256": sha256_bytes(raw), "request_bytes": len(raw),
                        "expected": expected, "expected_error_code": code, "response": response,
                        "exit_code": run.returncode, "stderr": run.stderr.decode("utf-8", errors="replace"),
                        "elapsed_ms": round((time.monotonic() - started) * 1000, 3)})
    return {"status": "PASS" if all(row["status"] == "PASS" for row in records) else "FAIL",
            "execution_mode": "fresh_process", "actual_process_invocations": len(records), "records": records,
            "independence_note": "Wrapper and reference use the same exact arithmetic; compiled-C comparisons and literal goldens supply the independent cross-check."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--out", type=Path, default=ROOT / "reference_vectors.jsonl")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--cc", default="cc")
    verify.add_argument("--build-dir", type=Path, default=ROOT / "build")
    verify.add_argument("--report", type=Path, default=ROOT / "validation" / "local-validation.json")
    verify.add_argument("--ubsan", action="store_true", help="Also compile and execute an UndefinedBehaviorSanitizer configuration")
    args = parser.parse_args()
    if args.command == "generate":
        cases = all_cases(smoke=True)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text("".join(json.dumps(vector_record(case, i), separators=(",", ":")) + "\n"
                                    for i, case in enumerate(cases)), encoding="utf-8")
        print(json.dumps({"status": "GENERATED_REFERENCE", "records": len(cases), "path": str(args.out),
                          "is_upstream_observation": False}))
        return 0
    compiler = shutil.which(args.cc)
    if compiler is None:
        parser.error(f"Compiler unavailable: {args.cc}")
    args.build_dir = args.build_dir.resolve()
    args.build_dir.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, object] = {"schema_version": "wirefix.fixture-validation.v1", "started_at": utc_now(),
        "scope": "self_authored_reference_fixtures_only", "host": platform.platform(),
        "machine": platform.machine(), "python": sys.version, "python_executable": sys.executable,
        "compiler": compiler, "compiler_version": subprocess.run([compiler, "--version"],
            capture_output=True, text=True, timeout=10, check=True).stdout,
        "seed": hex(SEED), "source_sha256": {name: sha256_bytes((ROOT / name).read_bytes()) for name in
            ("behavior_fixtures.h", "behavior_fixtures.c", "fixture_probe.c", "oracle_fp32.py", "reference_verify.py")},
        "upstream_integration": {name: {"status": "NOT_RUN", "reason": "This verifier does not invoke this integration"}
                                  for name in ("REA", "Ghidra", "Handwired", "Z3", "WireFix", "Codex_MCP")}}
    try:
        cases = all_cases()
        configurations = [("O0", ["-O0"]), ("O2", ["-O2"])]
        if args.ubsan:
            configurations.append(("O1_ubsan", ["-O1", "-fsanitize=undefined", "-fno-sanitize-recover=all"]))
        report["compiled_checks"] = [run_compiled(compiler, tag, flags, args.build_dir, cases)
                                      for tag, flags in configurations]
        report["fresh_process_wrapper"] = wrapper_checks()
        report["status"] = "PASS" if all(row["status"] == "PASS" for row in report["compiled_checks"]) and \
            report["fresh_process_wrapper"]["status"] == "PASS" else "FAIL"
    except Exception as exc:
        report["status"] = "FAIL"
        report["exception"] = {"type": type(exc).__name__, "message": str(exc)}
    report["finished_at"] = utc_now()
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "report": str(args.report),
                      "compiled_configurations": [{"name": row["configuration"], "status": row["status"],
                                                   "planned": row.get("planned")} for row in report.get("compiled_checks", [])],
                      "fresh_process_wrapper": report.get("fresh_process_wrapper", {}).get("status"),
                      "exception": report.get("exception")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
