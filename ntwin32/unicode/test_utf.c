/* SPDX-License-Identifier: GPL-2.0-only
 * Original host checks and exhaustive scalar conversion oracle.
 */
#include "utf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long checks, scalars;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); \
} } while (0)

/* Independent arithmetic oracle: radix-64 digits, not the core encoder. */
static size_t oracle_utf8(uint32_t scalar, uint8_t output[4])
{
    static const uint8_t prefixes[] = { 0, 0, 0xc0, 0xe0, 0xf0 };
    size_t width = scalar < 128 ? 1u : scalar < 2048 ? 2u : scalar < 65536 ? 3u : 4u;
    size_t i = width;
    while (i > 1) {
        output[--i] = (uint8_t)(128 + scalar % 64);
        scalar /= 64;
    }
    output[0] = (uint8_t)(prefixes[width] + scalar);
    return width;
}

static size_t oracle_utf16(uint32_t scalar, uint16_t output[2])
{
    if (scalar < 65536) {
        output[0] = (uint16_t)scalar;
        return 1;
    }
    scalar -= 65536;
    output[0] = (uint16_t)(55296 + scalar / 1024);
    output[1] = (uint16_t)(56320 + scalar % 1024);
    return 2;
}

static void exhaustive_scalars(void)
{
    uint32_t scalar;
    for (scalar = 0; scalar <= UINT32_C(0x10ffff); ++scalar) {
        uint8_t expected_bytes[4], encoded[6] = { 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
        uint16_t expected_wide[2], decoded[4] = { 0x5a5a, 0x5a5a, 0x5a5a, 0x5a5a };
        size_t bytes, units, required = SIZE_MAX;
        if (scalar >= 0xd800 && scalar <= 0xdfff) continue;
        bytes = oracle_utf8(scalar, expected_bytes);
        units = oracle_utf16(scalar, expected_wide);
        CHECK(ntwu_utf16_to_utf8(expected_wide, units, NULL, 0, NTWU_STRICT, &required) == NTWU_OK);
        CHECK(required == bytes);
        CHECK(ntwu_utf16_to_utf8(expected_wide, units, encoded + 1, bytes, NTWU_STRICT, &required) == NTWU_OK);
        CHECK(required == bytes && memcmp(encoded + 1, expected_bytes, bytes) == 0);
        CHECK(encoded[0] == 0x5a && encoded[bytes + 1] == 0x5a);
        CHECK(ntwu_utf8_to_utf16(encoded + 1, bytes, NULL, 0, NTWU_STRICT, &required) == NTWU_OK);
        CHECK(required == units);
        CHECK(ntwu_utf8_to_utf16(encoded + 1, bytes, decoded + 1, units, NTWU_STRICT, &required) == NTWU_OK);
        CHECK(required == units && memcmp(decoded + 1, expected_wide, units * sizeof(uint16_t)) == 0);
        CHECK(decoded[0] == 0x5a5a && decoded[units + 1] == 0x5a5a);
        if (bytes > 1) {
            required = SIZE_MAX;
            CHECK(ntwu_utf8_to_utf16(encoded + 1, bytes - 1, NULL, 0, NTWU_STRICT, &required) == NTWU_MALFORMED);
            CHECK(required == SIZE_MAX);
            CHECK(ntwu_utf8_to_utf16(encoded + 1, bytes - 1, decoded, 4, 0, &required) == NTWU_OK);
            CHECK(required == 1 && decoded[0] == 0xfffd);
        }
        ++scalars;
    }
    CHECK(scalars == 1112064ul);
}

typedef struct malformed_case {
    uint8_t bytes[12];
    size_t count;
    uint16_t wide[12];
    size_t units;
} malformed_case;

static void malformed_utf8(void)
{
    /* Each row has a distinct semantic boundary: invalid leaders, overlongs,
     * surrogate encodings, >10FFFF, truncated prefixes, or valid successors. */
    static const malformed_case cases[] = {
        {{0x80}, 1, {0xfffd}, 1},
        {{0xbf}, 1, {0xfffd}, 1},
        {{0xc0,0xaf}, 2, {0xfffd,0xfffd}, 2},
        {{0xc1,0xbf}, 2, {0xfffd,0xfffd}, 2},
        {{0xc2}, 1, {0xfffd}, 1},
        {{0xc2,0x41,0x42}, 3, {0xfffd,0x41,0x42}, 3},
        {{0xc2,0xc3,0xb1}, 3, {0xfffd,0xf1}, 2},
        {{0xe0,0x80,0xbf}, 3, {0xfffd,0xfffd,0xfffd}, 3},
        {{0xe0,0x9f,0x80}, 3, {0xfffd,0xfffd,0xfffd}, 3},
        {{0xe0,0xa0}, 2, {0xfffd}, 1},
        {{0xe1,0x80,0x41}, 3, {0xfffd,0x41}, 2},
        {{0xe1,0x80,0xe2,0xf0,0x91,0x92,0xf1,0xbf,0x41}, 9,
         {0xfffd,0xfffd,0xfffd,0xfffd,0x41}, 5},
        {{0xed,0xa0,0x80}, 3, {0xfffd,0xfffd,0xfffd}, 3},
        {{0xed,0xbf,0xbf}, 3, {0xfffd,0xfffd,0xfffd}, 3},
        {{0xf0,0x80,0x80,0x41}, 4, {0xfffd,0xfffd,0xfffd,0x41}, 4},
        {{0xf0,0x90}, 2, {0xfffd}, 1},
        {{0xf0,0x90,0x80}, 3, {0xfffd}, 1},
        {{0xf0,0x90,0x80,0x00}, 4, {0xfffd,0}, 2},
        {{0xf4,0x90,0x80,0x80}, 4, {0xfffd,0xfffd,0xfffd,0xfffd}, 4},
        {{0xf5,0x80,0x80,0x80}, 4, {0xfffd,0xfffd,0xfffd,0xfffd}, 4},
        {{0xf8,0x88,0x80,0x80,0x80}, 5, {0xfffd,0xfffd,0xfffd,0xfffd,0xfffd}, 5},
        {{0xff,0xfe,0x41}, 3, {0xfffd,0xfffd,0x41}, 3},
        {{0x41,0xc2,0xa2,0xf4,0x8f,0xbf,0xbf,0xe1,0x80}, 9,
         {0x41,0xa2,0xdbff,0xdfff,0xfffd}, 5},
    };
    size_t i, j;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint16_t output[16], original[16];
        size_t required = 777;
        for (j = 0; j < 16; ++j) output[j] = original[j] = 0x5678;
        CHECK(ntwu_utf8_to_utf16(cases[i].bytes, cases[i].count, output, 16,
                                 NTWU_STRICT, &required) == NTWU_MALFORMED);
        CHECK(required == 777 && memcmp(output, original, sizeof(output)) == 0);
        CHECK(ntwu_utf8_to_utf16(cases[i].bytes, cases[i].count, NULL, 0,
                                 NTWU_STRICT, &required) == NTWU_MALFORMED);
        CHECK(required == 777);
        CHECK(ntwu_utf8_to_utf16(cases[i].bytes, cases[i].count, NULL, 0, 0, &required) == NTWU_OK);
        CHECK(required == cases[i].units);
        CHECK(ntwu_utf8_to_utf16(cases[i].bytes, cases[i].count, output, cases[i].units,
                                 0, &required) == NTWU_OK);
        CHECK(required == cases[i].units);
        CHECK(memcmp(output, cases[i].wide, required * sizeof(uint16_t)) == 0);
        CHECK(output[required] == 0x5678);
        if (cases[i].units > 1) {
            memcpy(output, original, sizeof(output));
            CHECK(ntwu_utf8_to_utf16(cases[i].bytes, cases[i].count, output,
                                     cases[i].units - 1, 0, &required) == NTWU_INSUFFICIENT);
            CHECK(required == cases[i].units && memcmp(output, original, sizeof(output)) == 0);
        }
    }
}

static void malformed_utf16(void)
{
    uint32_t unit;
    uint16_t pair[3];
    uint8_t output[16];
    size_t required;
    static const uint16_t chain[] = { 0xd800, 0xd801, 0xdc00, 0xdc01, 0x41, 0xdfff, 0xdbff };
    static const uint8_t expected[] = {
        0xef,0xbf,0xbd, 0xf0,0x90,0x90,0x80, 0xef,0xbf,0xbd, 0x41,
        0xef,0xbf,0xbd, 0xef,0xbf,0xbd
    };
    uint8_t longer[32];
    for (unit = 0xd800; unit <= 0xdfff; ++unit) {
        pair[0] = 0x41;
        pair[1] = (uint16_t)unit;
        memset(output, 0x57, sizeof(output));
        required = 777;
        CHECK(ntwu_utf16_to_utf8(pair, 2, output, sizeof(output), NTWU_STRICT, &required) == NTWU_MALFORMED);
        CHECK(required == 777);
        CHECK(output[0] == 0x57 && output[3] == 0x57 && output[15] == 0x57);
        CHECK(ntwu_utf16_to_utf8(pair, 2, output, sizeof(output), 0, &required) == NTWU_OK);
        CHECK(required == 4 && output[0] == 0x41 && output[1] == 0xef &&
              output[2] == 0xbf && output[3] == 0xbd && output[4] == 0x57);
    }
    CHECK(ntwu_utf16_to_utf8(chain, sizeof(chain)/sizeof(chain[0]), longer,
                             sizeof(longer), 0, &required) == NTWU_OK);
    CHECK(required == sizeof(expected) && memcmp(longer, expected, required) == 0);
    memset(output, 0x57, sizeof(output));
    pair[0] = 0xdbff; pair[1] = 0xdfff; pair[2] = 0x41;
    CHECK(ntwu_utf16_to_utf8(pair, 3, output, 4, NTWU_STRICT, &required) == NTWU_INSUFFICIENT);
    CHECK(required == 5 && output[0] == 0x57 && output[3] == 0x57);
    CHECK(ntwu_utf16_to_utf8(pair, 3, output, 5, NTWU_STRICT, &required) == NTWU_OK);
    CHECK(required == 5 && output[0] == 0xf4 && output[1] == 0x8f &&
          output[2] == 0xbf && output[3] == 0xbf && output[4] == 0x41 && output[5] == 0x57);
}

static void exact_lengths_and_text(void)
{
    static const uint8_t source[] = { 'A',0,0xed,0x95,0x9c,0xea,0xb8,0x80,
                                     0xf0,0x9f,0x8c,0x8a,0xef,0xbb,0xbf };
    static const uint16_t expected[] = { 0x41,0,0xd55c,0xae00,0xd83c,0xdf0a,0xfeff };
    uint8_t bytes[32];
    uint16_t wide[16];
    size_t required;
    memset(wide, 0x5a, sizeof(wide));
    CHECK(ntwu_utf8_to_utf16(source, sizeof(source), wide, 16, NTWU_STRICT, &required) == NTWU_OK);
    CHECK(required == sizeof(expected)/sizeof(expected[0]));
    CHECK(memcmp(wide, expected, sizeof(expected)) == 0 && wide[required] == 0x5a5a);
    memset(bytes, 0x5a, sizeof(bytes));
    CHECK(ntwu_utf16_to_utf8(wide, required, bytes, sizeof(bytes), NTWU_STRICT, &required) == NTWU_OK);
    CHECK(required == sizeof(source) && memcmp(bytes, source, sizeof(source)) == 0);
    CHECK(bytes[required] == 0x5a);
    CHECK(ntwu_utf8_to_utf16(source, 1, wide, 16, 0, &required) == NTWU_OK && required == 1);
    CHECK(ntwu_utf8_to_utf16(source, 2, wide, 16, 0, &required) == NTWU_OK && required == 2 && wide[1] == 0);
    CHECK(ntwu_utf8_to_utf16(NULL, 0, NULL, 0, NTWU_STRICT, &required) == NTWU_OK && required == 0);
    CHECK(ntwu_utf16_to_utf8(NULL, 0, bytes, sizeof(bytes), 0, &required) == NTWU_OK && required == 0);
    CHECK(bytes[0] == 'A');
    /* Size queries must not use even an intentionally unaligned output value. */
    CHECK(ntwu_utf8_to_utf16(source, 1, (uint16_t *)(uintptr_t)1, 0, 0, &required) == NTWU_OK);
    CHECK(required == 1);
    CHECK(ntwu_utf16_to_utf8(expected, 1, (uint8_t *)(uintptr_t)1, 0, 0, &required) == NTWU_OK);
    CHECK(required == 1);
}

static void errors_and_overlap(void)
{
    uint8_t bytes[32] = { 0x41, 0x42 };
    uint16_t wide[16] = { 0x41, 0x42 };
    size_t required = 777;
    _Alignas(size_t) uint8_t storage[128] = { 0x41, 0x42 };
    const uint8_t *wrapping8 = (const uint8_t *)(uintptr_t)(UINTPTR_MAX - 1);
    const uint16_t *wrapping16 = (const uint16_t *)(uintptr_t)(UINTPTR_MAX - 1);
    CHECK(ntwu_utf8_to_utf16(bytes, 2, wide, 16, 2, &required) == NTWU_INVALID_FLAGS);
    CHECK(ntwu_utf16_to_utf8(wide, 2, bytes, 32, UINT32_MAX, &required) == NTWU_INVALID_FLAGS);
    CHECK(ntwu_utf8_to_utf16(bytes, 2, wide, 16, 0, NULL) == NTWU_INVALID);
    CHECK(ntwu_utf16_to_utf8(NULL, 1, bytes, 32, 0, &required) == NTWU_INVALID);
    CHECK(ntwu_utf8_to_utf16(NULL, 1, wide, 16, 0, &required) == NTWU_INVALID);
    CHECK(ntwu_utf8_to_utf16(bytes, 2, NULL, 16, 0, &required) == NTWU_INVALID);
    CHECK(ntwu_utf16_to_utf8(wide, 2, NULL, 32, 0, &required) == NTWU_INVALID);
    CHECK(ntwu_utf8_to_utf16(bytes, 2, (uint16_t *)(void *)(storage + 1), 1, 0, &required) == NTWU_INVALID);
    CHECK(ntwu_utf16_to_utf8((const uint16_t *)(const void *)(storage + 1), 1,
                             bytes, 32, 0, &required) == NTWU_INVALID);
    CHECK(ntwu_utf8_to_utf16(bytes, 2, wide, 16, 0,
                             (size_t *)(void *)(storage + 1)) == NTWU_INVALID);
    CHECK(ntwu_utf8_to_utf16(wrapping8, 4, wide, 16, 0, &required) == NTWU_OVERFLOW);
    CHECK(ntwu_utf16_to_utf8(wrapping16, 2, bytes, 32, 0, &required) == NTWU_OVERFLOW);
    CHECK(ntwu_utf16_to_utf8(wide, SIZE_MAX, bytes, 32, 0, &required) == NTWU_OVERFLOW);
    CHECK(ntwu_utf8_to_utf16(bytes, 2, wide, SIZE_MAX, 0, &required) == NTWU_OVERFLOW);
    CHECK(ntwu_utf16_to_utf8(wide, 2, (uint8_t *)(uintptr_t)(UINTPTR_MAX - 1),
                             4, 0, &required) == NTWU_OVERFLOW);
    CHECK(ntwu_utf8_to_utf16(storage, 8, (uint16_t *)(void *)(storage + 2), 4,
                             0, &required) == NTWU_OVERLAP);
    CHECK(ntwu_utf8_to_utf16(storage + 2, 8, (uint16_t *)(void *)storage, 4,
                             0, &required) == NTWU_OVERLAP);
    CHECK(ntwu_utf16_to_utf8(wide, 2, (uint8_t *)(void *)wide, sizeof(wide),
                             0, &required) == NTWU_OVERLAP);
    CHECK(ntwu_utf8_to_utf16(storage, 8, wide, 16, 0,
                             (size_t *)(void *)storage) == NTWU_OVERLAP);
    CHECK(ntwu_utf16_to_utf8(wide, 2, storage, sizeof(storage), 0,
                             (size_t *)(void *)storage) == NTWU_OVERLAP);
    CHECK(ntwu_utf8_to_utf16(storage, 8, NULL, 0, 0,
                             (size_t *)(void *)storage) == NTWU_OVERLAP);
    CHECK(required == 777 && bytes[0] == 0x41 && wide[0] == 0x41 && storage[0] == 0x41);
    CHECK(ntwu_utf8_to_utf16(bytes, 2, wide, 1, 0, &required) == NTWU_INSUFFICIENT);
    CHECK(required == 2 && wide[0] == 0x41 && wide[1] == 0x42);
    CHECK(ntwu_utf16_to_utf8(wide, 2, bytes, 1, 0, &required) == NTWU_INSUFFICIENT);
    CHECK(required == 2 && bytes[0] == 0x41 && bytes[1] == 0x42);
    {
        struct adjacent { uint8_t input[4]; uint16_t output[4]; size_t length; } adjacent = { { 1,2,3,4 }, { 0 }, 0 };
        CHECK(ntwu_utf8_to_utf16(adjacent.input, 4, adjacent.output, 4, 0,
                                 &adjacent.length) == NTWU_OK);
        CHECK(adjacent.length == 4 && adjacent.output[3] == 4);
    }
}

int main(void)
{
    malformed_utf8();
    malformed_utf16();
    exact_lengths_and_text();
    errors_and_overlap();
    exhaustive_scalars();
    printf("UTF core: %lu checks passed; %lu Unicode scalars exhaustively roundtripped; host only.\n",
            checks, scalars);
    return 0;
}
