#ifndef wirefix_REFERENCE_FIXTURES_H
#define wirefix_REFERENCE_FIXTURES_H

#include <stdint.h>

/* Self-authored reference fixtures; not output from REA, Ghidra or Handwired. */
#if defined(_MSC_VER)
#define FIXTURE_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define FIXTURE_NOINLINE __attribute__((noinline))
#else
#define FIXTURE_NOINLINE
#endif

FIXTURE_NOINLINE uint8_t fixture_bv8_mba_original(uint8_t x, uint8_t y);
FIXTURE_NOINLINE uint8_t fixture_bv8_mba_simplified(uint8_t x, uint8_t y);
FIXTURE_NOINLINE uint64_t fixture_bv64_add(uint64_t x, uint64_t y);
FIXTURE_NOINLINE uint64_t fixture_bv64_mul(uint64_t x, uint64_t y);

FIXTURE_NOINLINE uint8_t fixture_bv8_shl_wide(uint8_t value, uint64_t count);
FIXTURE_NOINLINE uint8_t fixture_bv8_lshr_wide(uint8_t value, uint64_t count);
FIXTURE_NOINLINE uint8_t fixture_bv8_ashr_wide(uint8_t value, uint64_t count);
FIXTURE_NOINLINE uint64_t fixture_bv64_shl_wide(uint64_t value, uint64_t count);
FIXTURE_NOINLINE uint64_t fixture_bv64_lshr_wide(uint64_t value, uint64_t count);
FIXTURE_NOINLINE uint64_t fixture_bv64_ashr_wide(uint64_t value, uint64_t count);

FIXTURE_NOINLINE uint8_t fixture_boundary_v1(uint32_t x);
FIXTURE_NOINLINE uint8_t fixture_boundary_v2(uint32_t x);

/* Deliberately stateful negative fixture. Repeated calls must share a process. */
FIXTURE_NOINLINE void fixture_side_effect_reset(uint32_t seed);
FIXTURE_NOINLINE uint32_t fixture_side_effect(uint32_t x);

/* finite binary32, roundTiesToEven, separate rounding, gradual underflow. */
FIXTURE_NOINLINE float fixture_f32_mul(float a, float b);
FIXTURE_NOINLINE float fixture_f32_add(float a, float b);
FIXTURE_NOINLINE float fixture_f32_affine(float x, float a, float b);
FIXTURE_NOINLINE float fixture_f32_clamp(float t, float lo, float hi);
FIXTURE_NOINLINE float fixture_f32_affine_target(float x);
FIXTURE_NOINLINE float fixture_f32_clamp_target(float x);
FIXTURE_NOINLINE float fixture_f32_piecewise_target(float x);

#endif
