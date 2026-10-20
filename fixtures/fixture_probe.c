/*
 * Small owned target driver. Its input is whitespace-delimited probe commands,
 * NOT the future WireFix JSONL Oracle protocol. See README.md.
 */
#include "behavior_fixtures.h"

#include <errno.h>
#include <fenv.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t f32_bits(float value) {
    uint32_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

static float f32_value(uint32_t bits) {
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static int is_finite_bits(uint32_t bits) {
    return (bits & UINT32_C(0x7f800000)) != UINT32_C(0x7f800000);
}

static int parse_hex(const char *text, unsigned width, uint64_t *result) {
    if (text == NULL || text[0] != '0' || text[1] != 'x') return 0;
    const size_t digits = strlen(text + 2);
    if (digits == 0 || digits > width / 4u) return 0;
    for (size_t i = 2; text[i] != '\0'; ++i) {
        const char c = text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    char *end = NULL;
    errno = 0;
    const uintmax_t value = strtoumax(text + 2, &end, 16);
    if (errno != 0 || end == NULL || *end != '\0' || value > UINT64_MAX) return 0;
    if (width < 64u && value >= (UINT64_C(1) << width)) return 0;
    *result = (uint64_t)value;
    return 1;
}

static void error_line(const char *code) {
    printf("ERROR %s\n", code);
}

static void bv_line(unsigned width, uint64_t value) {
    printf("OK bv%u 0x%0*" PRIx64 "\n", width, (int)(width / 4u), value);
}

static void f32_line(float value) {
    const uint32_t bits = f32_bits(value);
    if (!is_finite_bits(bits)) {
        error_line("NONFINITE_INTERMEDIATE");
        return;
    }
    printf("OK fp32 0x%08" PRIx32 "\n", bits);
}

static int f32_environment_ready(void) {
    if (fesetround(FE_TONEAREST) != 0 || fegetround() != FE_TONEAREST) return 0;
    if (f32_bits(1.0f) != UINT32_C(0x3f800000)) return 0;
    if (f32_bits(-0.0f) != UINT32_C(0x80000000)) return 0;
    /* Reject FTZ/DAZ environments; never claim gradual underflow from metadata. */
    if (f32_bits(fixture_f32_mul(f32_value(1), 1.0f)) != UINT32_C(1)) return 0;
    if (f32_bits(fixture_f32_mul(f32_value(0x00800000), 0.5f)) != UINT32_C(0x00400000)) return 0;
    if (f32_bits(fixture_f32_mul(f32_value(1), 0.5f)) != UINT32_C(0)) return 0;
    if (f32_bits(fixture_f32_mul(f32_value(0x80000001), 0.5f)) != UINT32_C(0x80000000)) return 0;
    if (f32_bits(fixture_f32_add(1.0f, 0x1p-24f)) != UINT32_C(0x3f800000)) return 0;
    if (f32_bits(fixture_f32_add(f32_value(0x3f800001), 0x1p-24f)) != UINT32_C(0x3f800002)) return 0;
    return 1;
}

static void dispatch(int argc, char **argv) {
    uint64_t a = 0, b = 0, c = 0;
    if (argc == 1 && strcmp(argv[0], "f32_env") == 0) {
        puts(f32_environment_ready() ? "OK environment binary32-rne-gradual" :
                                     "ERROR UNSUPPORTED_FP_ENVIRONMENT");
        return;
    }
    if (argc < 2 || argc > 4) {
        error_line("ARGUMENTS");
        return;
    }
    const char *op = argv[0];
    if (strcmp(op, "mba_original") == 0 || strcmp(op, "mba_simplified") == 0) {
        if (argc != 3 || !parse_hex(argv[1], 8, &a) || !parse_hex(argv[2], 8, &b)) {
            error_line("ARGUMENTS"); return;
        }
        bv_line(8, strcmp(op, "mba_original") == 0 ?
                fixture_bv8_mba_original((uint8_t)a, (uint8_t)b) :
                fixture_bv8_mba_simplified((uint8_t)a, (uint8_t)b));
        return;
    }
    if (strcmp(op, "add64") == 0 || strcmp(op, "mul64") == 0) {
        if (argc != 3 || !parse_hex(argv[1], 64, &a) || !parse_hex(argv[2], 64, &b)) {
            error_line("ARGUMENTS"); return;
        }
        bv_line(64, strcmp(op, "add64") == 0 ? fixture_bv64_add(a, b) : fixture_bv64_mul(a, b));
        return;
    }
    if (strcmp(op, "shl8") == 0 || strcmp(op, "lshr8") == 0 || strcmp(op, "ashr8") == 0 ||
        strcmp(op, "shl64") == 0 || strcmp(op, "lshr64") == 0 || strcmp(op, "ashr64") == 0) {
        const unsigned width = strstr(op, "64") != NULL ? 64u : 8u;
        if (argc != 3 || !parse_hex(argv[1], width, &a) || !parse_hex(argv[2], 64, &b)) {
            error_line("ARGUMENTS"); return;
        }
        uint64_t result;
        if (width == 8u) {
            result = strcmp(op, "shl8") == 0 ? fixture_bv8_shl_wide((uint8_t)a, b) :
                     strcmp(op, "lshr8") == 0 ? fixture_bv8_lshr_wide((uint8_t)a, b) :
                                               fixture_bv8_ashr_wide((uint8_t)a, b);
        } else {
            result = strcmp(op, "shl64") == 0 ? fixture_bv64_shl_wide(a, b) :
                     strcmp(op, "lshr64") == 0 ? fixture_bv64_lshr_wide(a, b) :
                                                fixture_bv64_ashr_wide(a, b);
        }
        bv_line(width, result);
        return;
    }
    if (strcmp(op, "boundary_v1") == 0 || strcmp(op, "boundary_v2") == 0 ||
        strcmp(op, "side_effect") == 0 || strcmp(op, "side_reset") == 0) {
        if (argc != 2 || !parse_hex(argv[1], 32, &a)) { error_line("ARGUMENTS"); return; }
        if (strcmp(op, "side_reset") == 0) {
            fixture_side_effect_reset((uint32_t)a); bv_line(32, a);
        } else if (strcmp(op, "side_effect") == 0) {
            bv_line(32, fixture_side_effect((uint32_t)a));
        } else {
            bv_line(8, strcmp(op, "boundary_v1") == 0 ? fixture_boundary_v1((uint32_t)a) :
                                                      fixture_boundary_v2((uint32_t)a));
        }
        return;
    }
    const int is_f32_binary = strcmp(op, "f32_add") == 0 || strcmp(op, "f32_mul") == 0;
    const int is_f32_ternary = strcmp(op, "f32_affine") == 0 || strcmp(op, "f32_clamp") == 0;
    const int is_f32_target = strcmp(op, "affine_target") == 0 || strcmp(op, "clamp_target") == 0 ||
                             strcmp(op, "piecewise_target") == 0;
    if (!is_f32_binary && !is_f32_ternary && !is_f32_target) { error_line("UNKNOWN_OPERATION"); return; }
    const int expected_argc = is_f32_binary ? 3 : is_f32_ternary ? 4 : 2;
    if (argc != expected_argc || !parse_hex(argv[1], 32, &a) ||
        (argc > 2 && !parse_hex(argv[2], 32, &b)) ||
        (argc > 3 && !parse_hex(argv[3], 32, &c))) { error_line("ARGUMENTS"); return; }
    if (!is_finite_bits((uint32_t)a) || (argc > 2 && !is_finite_bits((uint32_t)b)) ||
        (argc > 3 && !is_finite_bits((uint32_t)c))) { error_line("NONFINITE_INPUT"); return; }
    if (!f32_environment_ready()) { error_line("UNSUPPORTED_FP_ENVIRONMENT"); return; }
    const float x = f32_value((uint32_t)a), y = f32_value((uint32_t)b), z = f32_value((uint32_t)c);
    if (strcmp(op, "f32_add") == 0) { f32_line(fixture_f32_add(x, y)); return; }
    if (strcmp(op, "f32_mul") == 0) { f32_line(fixture_f32_mul(x, y)); return; }
    if (strcmp(op, "f32_clamp") == 0) {
        if (y > z) { error_line("INVALID_BOUNDS"); return; }
        f32_line(fixture_f32_clamp(x, y, z)); return;
    }
    /* Observe the product before clamp: saturation must not hide overflow. */
    float product;
    if (strcmp(op, "f32_affine") == 0) product = fixture_f32_mul(y, x);
    else if (strcmp(op, "piecewise_target") == 0) product = fixture_f32_mul(x, x < -1.0f ? 0.5f : x < 1.0f ? -1.5f : 2.0f);
    else product = fixture_f32_mul(x, 1.5f);
    if (!is_finite_bits(f32_bits(product))) { error_line("NONFINITE_INTERMEDIATE"); return; }
    if (strcmp(op, "f32_affine") == 0) { f32_line(fixture_f32_affine(x, y, z)); return; }
    if (strcmp(op, "affine_target") == 0) { f32_line(fixture_f32_affine_target(x)); return; }
    if (strcmp(op, "piecewise_target") == 0) { f32_line(fixture_f32_piecewise_target(x)); return; }
    const float t = fixture_f32_affine_target(x);
    if (!is_finite_bits(f32_bits(t))) { error_line("NONFINITE_INTERMEDIATE"); return; }
    f32_line(fixture_f32_clamp_target(x));
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--batch") == 0) {
        char line[512];
        while (fgets(line, sizeof(line), stdin) != NULL) {
            if (strchr(line, '\n') == NULL && !feof(stdin)) {
                int ch;
                while ((ch = getchar()) != '\n' && ch != EOF) {}
                error_line("LINE_TOO_LONG");
                continue;
            }
            char *items[5];
            int count = 0;
            char *part = strtok(line, " \t\r\n");
            while (part != NULL && count < 5) {
                items[count++] = part;
                part = strtok(NULL, " \t\r\n");
            }
            dispatch(count, items);
        }
        return ferror(stdin) ? 2 : 0;
    }
    if (argc < 2) {
        fputs("usage: fixture_probe OP 0xBITS ... | fixture_probe --batch\n", stderr);
        return 2;
    }
    dispatch(argc - 1, argv + 1);
    return 0;
}
