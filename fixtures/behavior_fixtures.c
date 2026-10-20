#include "behavior_fixtures.h"

#include <float.h>
#include <limits.h>

_Static_assert(CHAR_BIT == 8, "fixtures require 8-bit bytes");
_Static_assert(sizeof(uint8_t) == 1 && sizeof(uint64_t) == 8,
               "fixtures require exact-width integer types");
_Static_assert(sizeof(float) == 4 && FLT_RADIX == 2 && FLT_MANT_DIG == 24 &&
                   FLT_MIN_EXP == -125 && FLT_MAX_EXP == 128,
               "numeric fixtures require binary32 float");

uint8_t fixture_bv8_mba_original(uint8_t x, uint8_t y) {
    /* Widen first: neither the shift nor the sum can overflow signed int. */
    const uint32_t a = (uint32_t)x;
    const uint32_t b = (uint32_t)y;
    return (uint8_t)((a ^ b) + ((a & b) << 1u));
}

uint8_t fixture_bv8_mba_simplified(uint8_t x, uint8_t y) {
    return (uint8_t)((uint32_t)x + (uint32_t)y);
}

uint64_t fixture_bv64_add(uint64_t x, uint64_t y) {
    return x + y; /* Unsigned wraparound is intentional and defined. */
}

uint64_t fixture_bv64_mul(uint64_t x, uint64_t y) {
    return x * y;
}

uint8_t fixture_bv8_shl_wide(uint8_t value, uint64_t count) {
    if (count >= UINT64_C(8)) return UINT8_C(0);
    return (uint8_t)((uint32_t)value << (unsigned)count);
}

uint8_t fixture_bv8_lshr_wide(uint8_t value, uint64_t count) {
    if (count >= UINT64_C(8)) return UINT8_C(0);
    return (uint8_t)((uint32_t)value >> (unsigned)count);
}

uint8_t fixture_bv8_ashr_wide(uint8_t value, uint64_t count) {
    const uint32_t sign = (uint32_t)value & UINT32_C(0x80);
    if (count >= UINT64_C(8)) return sign ? UINT8_C(0xff) : UINT8_C(0);
    if (count == 0) return value;
    const unsigned shift = (unsigned)count;
    const uint32_t logical = (uint32_t)value >> shift;
    const uint32_t fill = sign ? (UINT32_C(0xff) ^ (UINT32_C(0xff) >> shift)) : 0;
    return (uint8_t)(logical | fill);
}

uint64_t fixture_bv64_shl_wide(uint64_t value, uint64_t count) {
    if (count >= UINT64_C(64)) return UINT64_C(0);
    return value << (unsigned)count;
}

uint64_t fixture_bv64_lshr_wide(uint64_t value, uint64_t count) {
    if (count >= UINT64_C(64)) return UINT64_C(0);
    return value >> (unsigned)count;
}

uint64_t fixture_bv64_ashr_wide(uint64_t value, uint64_t count) {
    const uint64_t sign = value & (UINT64_C(1) << 63u);
    if (count >= UINT64_C(64)) return sign ? UINT64_MAX : UINT64_C(0);
    if (count == 0) return value;
    const unsigned shift = (unsigned)count;
    const uint64_t logical = value >> shift;
    const uint64_t fill = sign ? (UINT64_MAX << (64u - shift)) : UINT64_C(0);
    return logical | fill;
}

uint8_t fixture_boundary_v1(uint32_t x) {
    return x < UINT32_C(100) ? UINT8_C(1) : UINT8_C(0);
}

uint8_t fixture_boundary_v2(uint32_t x) {
    return x <= UINT32_C(100) ? UINT8_C(1) : UINT8_C(0);
}

static volatile uint32_t side_effect_counter = 0;

void fixture_side_effect_reset(uint32_t seed) {
    side_effect_counter = seed;
}

uint32_t fixture_side_effect(uint32_t x) {
    const uint32_t next = (uint32_t)((uint64_t)side_effect_counter + UINT64_C(1));
    side_effect_counter = next;
    return (uint32_t)((uint64_t)x + (uint64_t)next);
}

float fixture_f32_mul(float a, float b) {
    volatile float result = a * b;
    return result;
}

float fixture_f32_add(float a, float b) {
    volatile float result = a + b;
    return result;
}

float fixture_f32_affine(float x, float a, float b) {
    /* Separate calls and volatile stores preserve both declared rounding sites. */
    const float product = fixture_f32_mul(a, x);
    return fixture_f32_add(product, b);
}

float fixture_f32_clamp(float t, float lo, float hi) {
    /* Equality returns t, including its zero sign. This is not fminf/fmaxf. */
    return t < lo ? lo : t > hi ? hi : t;
}

float fixture_f32_affine_target(float x) {
    return fixture_f32_affine(x, 0x1.8p0f, -0x1p-2f);
}

float fixture_f32_clamp_target(float x) {
    const float t = fixture_f32_affine_target(x);
    return fixture_f32_clamp(t, -0x1p1f, 0x1p1f);
}

float fixture_f32_piecewise_target(float x) {
    /* Knots -1 and +1; intervals are left-closed/right-open. */
    if (x < -0x1p0f) return fixture_f32_affine(x, 0x1p-1f, -0x1p-2f);
    if (x < 0x1p0f) return fixture_f32_affine(x, -0x1.8p0f, 0x1p-1f);
    return fixture_f32_affine(x, 0x1p1f, -0x1p0f);
}
