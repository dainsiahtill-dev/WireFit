#!/usr/bin/env python3
"""Self-authored reference_fixture, not a recovered third-party target.

One request per fresh process. No WireFix, REA, Handwired, NumPy or external
package dependency. Exact integer/rational arithmetic implements binary32 RNE;
the source is public ground truth and must not be given to a fitting worker.
"""

from __future__ import annotations

import json
import re
import sys
from fractions import Fraction

MAX_LINE_BYTES = 1_048_576
SIGN = 0x80000000
EXPONENT = 0x7F800000
REQUEST_ID_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}")


class Fp32DomainError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def finite_fraction(bits: int) -> Fraction:
    """Decode one finite IEEE binary32 bit pattern exactly; zero sign is separate."""
    if type(bits) is not int or not 0 <= bits <= 0xFFFFFFFF:
        raise Fp32DomainError("INVALID_BITS", "Expected an unsigned 32-bit pattern")
    exponent = (bits >> 23) & 0xFF
    fraction = bits & 0x7FFFFF
    if exponent == 0xFF:
        raise Fp32DomainError("NONFINITE_INPUT", "NaN and infinity are outside this fixture")
    if exponent == 0:
        significand, power = fraction, -149
    else:
        significand, power = (1 << 23) | fraction, exponent - 150
    value = Fraction(significand << power, 1) if power >= 0 else Fraction(significand, 1 << -power)
    return -value if bits & SIGN else value


def _round_even_ratio(numerator: int, denominator: int) -> int:
    quotient, remainder = divmod(numerator, denominator)
    twice = remainder << 1
    return quotient + int(twice > denominator or (twice == denominator and (quotient & 1) != 0))


def round_binary32(value: Fraction, *, negative_zero: bool = False) -> int:
    """Round an exact value once, ties to even, retaining gradual underflow."""
    if value == 0:
        return SIGN if negative_zero else 0
    sign = SIGN if value < 0 else 0
    value = abs(value)
    numerator, denominator = value.numerator, value.denominator
    exponent = numerator.bit_length() - denominator.bit_length()
    below = numerator < (denominator << exponent) if exponent >= 0 else (numerator << -exponent) < denominator
    if below:
        exponent -= 1
    if exponent < -126:
        significand = _round_even_ratio(numerator << 149, denominator)
        # 0 is signed underflow; 0x00800000 is the rounded smallest normal.
        return sign | significand
    scale = 23 - exponent
    significand = _round_even_ratio(numerator << scale, denominator) if scale >= 0 else \
        _round_even_ratio(numerator, denominator << -scale)
    if significand == (1 << 24):
        significand >>= 1
        exponent += 1
    if exponent > 127:
        raise Fp32DomainError("NONFINITE_INTERMEDIATE", "A declared binary32 rounding site overflows")
    return sign | ((exponent + 127) << 23) | (significand - (1 << 23))


def f32_mul_bits(a: int, b: int) -> int:
    value = finite_fraction(a) * finite_fraction(b)
    return round_binary32(value, negative_zero=bool((a ^ b) & SIGN))


def f32_add_bits(a: int, b: int) -> int:
    left, right = finite_fraction(a), finite_fraction(b)
    # Under roundTiesToEven, exact cancellation is +0; -0 + -0 is -0.
    negative_zero = left == 0 and right == 0 and bool(a & b & SIGN)
    return round_binary32(left + right, negative_zero=negative_zero)


def affine_bits(x: int, a: int, b: int) -> int:
    return f32_add_bits(f32_mul_bits(a, x), b)


def clamp_bits(t: int, lo: int, hi: int) -> int:
    """Exactly: t < lo ? lo : t > hi ? hi : t; equality retains t's bits."""
    tv, lv, hv = finite_fraction(t), finite_fraction(lo), finite_fraction(hi)
    if lv > hv:
        raise Fp32DomainError("INVALID_BOUNDS", "Clamp requires lo <= hi")
    return lo if tv < lv else hi if tv > hv else t


def reference_target_bits(x: int) -> int:
    """f32(f32(1.5*x) + (-0.25)), then strict clamp[-2,+2]."""
    return clamp_bits(affine_bits(x, 0x3FC00000, 0xBE800000), 0xC0000000, 0x40000000)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def _no_json_constant(value: str) -> object:
    raise ValueError(f"Nonstandard JSON constant: {value}")


def _error(request_id: object, code: str, message: str) -> dict[str, object]:
    # A malformed request may contain no recoverable correlation ID. The fixed
    # sentinel is schema-valid, but a supervisor must reject its correlation.
    if not isinstance(request_id, str) or REQUEST_ID_PATTERN.fullmatch(request_id) is None:
        request_id = "unbound_request"
    return {"protocol_version": 1, "request_id": request_id, "status": "error", "outputs": {},
            "error": {"code": code, "message": message, "scope": "reference_fixture",
                      "retryable": False, "artifacts": []}}


def process_line(raw: bytes) -> dict[str, object]:
    request_id: object = None
    if len(raw) > MAX_LINE_BYTES:
        return _error(None, "LINE_TOO_LONG", "Request exceeds the fixture line limit")
    try:
        request = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
                             parse_constant=_no_json_constant)
    except (ValueError, UnicodeError):
        return _error(None, "MALFORMED_JSON", "Expected one UTF-8 JSON object")
    if not isinstance(request, dict):
        return _error(None, "INVALID_REQUEST", "Top-level request must be an object")
    raw_id = request.get("request_id")
    if isinstance(raw_id, str) and REQUEST_ID_PATTERN.fullmatch(raw_id) is not None:
        request_id = raw_id
    else:
        return _error(None, "INVALID_REQUEST_ID", "request_id must match [A-Za-z][A-Za-z0-9_.:-]{0,127}")
    if set(request) != {"protocol_version", "request_id", "inputs"} or \
            type(request["protocol_version"]) is not int or request["protocol_version"] != 1:
        return _error(request_id, "INVALID_REQUEST", "Expected the exact protocol_version=1 request fields")
    inputs = request["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {"x"}:
        return _error(request_id, "INVALID_INPUTS", "Expected exactly one input named x")
    x = inputs["x"]
    if not isinstance(x, dict) or set(x) != {"kind", "bits"} or x["kind"] != "fp32" or \
            not isinstance(x["bits"], str) or re.fullmatch(r"0x[0-9a-f]{8}", x["bits"]) is None:
        return _error(request_id, "INVALID_BITS", "x must contain kind=fp32 and eight lowercase hexadecimal digits")
    try:
        result = reference_target_bits(int(x["bits"], 16))
    except Fp32DomainError as exc:
        return _error(request_id, exc.code, str(exc))
    return {"protocol_version": 1, "request_id": request_id, "status": "ok",
            "outputs": {"result": {"kind": "fp32", "bits": f"0x{result:08x}"}}}


def main() -> int:
    # The supervisor owns timeouts and supplies one request per fresh process.
    raw = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
    response = process_line(raw)
    sys.stdout.write(json.dumps(response, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
