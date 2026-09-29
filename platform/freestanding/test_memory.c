/* SPDX-License-Identifier: GPL-2.0-only
 * Host libc remains the oracle and sanitizer runtime provider. Only the new
 * source object and these declarations use test-prefixed function symbols.
 */
#define memset ntwm_test_memset
#define memcpy ntwm_test_memcpy
#define memmove ntwm_test_memmove
#define memcmp ntwm_test_memcmp
#include "memory.h"
#undef memset
#undef memcpy
#undef memmove
#undef memcmp
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { REGION = 48, GUARD = 8, BYTES = REGION + 2 * GUARD };
static uint64_t checks, moves, copies, fills, comparisons;
#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { fprintf(stderr, "failure line %d: %s\n", __LINE__, #condition); exit(1); } \
} while (0)

static int sign_of(int value) { return (value > 0) - (value < 0); }
static void seed(unsigned char *data, size_t bytes, unsigned pattern)
{
    size_t i;
    for (i = 0; i < bytes; ++i)
        data[i] = (unsigned char)(i * 37u + pattern * 113u + (i >> 2));
}

static void exhaustive_moves(void)
{
    unsigned char original[BYTES], actual[BYTES], reference[BYTES], oracle[BYTES];
    size_t source, destination, count, i;
    unsigned pattern;
    for (pattern = 0; pattern < 4; ++pattern) {
        seed(original, sizeof(original), pattern);
        for (source = 0; source <= REGION; ++source)
            for (destination = 0; destination <= REGION; ++destination)
                for (count = 0; count <= REGION - source && count <= REGION - destination; ++count) {
                    memcpy(actual, original, sizeof(actual));
                    memcpy(reference, original, sizeof(reference));
                    memcpy(oracle, original, sizeof(oracle));
                    for (i = 0; i < count; ++i)
                        oracle[GUARD + destination + i] = original[GUARD + source + i];
                    memmove(reference + GUARD + destination, reference + GUARD + source, count);
                    CHECK(ntwm_test_memmove(actual + GUARD + destination, actual + GUARD + source, count) == actual + GUARD + destination);
                    CHECK(memcmp(actual, oracle, sizeof(actual)) == 0);
                    CHECK(memcmp(actual, reference, sizeof(actual)) == 0);
                    ++moves;
                }
    }
}

static void exhaustive_copies(void)
{
    unsigned char source[BYTES], actual[BYTES], reference[BYTES], original[BYTES];
    size_t input, output, count;
    unsigned pattern;
    for (pattern = 0; pattern < 4; ++pattern) {
        seed(source, sizeof(source), pattern);
        seed(original, sizeof(original), pattern + 7u);
        for (input = 0; input <= REGION; ++input)
            for (output = 0; output <= REGION; ++output)
                for (count = 0; count <= REGION - input && count <= REGION - output; ++count) {
                    memcpy(actual, original, sizeof(actual));
                    memcpy(reference, original, sizeof(reference));
                    memcpy(reference + GUARD + output, source + GUARD + input, count);
                    CHECK(ntwm_test_memcpy(actual + GUARD + output, source + GUARD + input, count) == actual + GUARD + output);
                    CHECK(memcmp(actual, reference, sizeof(actual)) == 0);
                    ++copies;
                }
    }
}

static void exhaustive_fills(void)
{
    static const int values[] = {INT_MIN, -1025, -257, -256, -1, 0, 1, 127,
                                128, 255, 256, 257, 0x12345, INT_MAX};
    unsigned char actual[BYTES], reference[BYTES];
    size_t value, offset, count;
    for (value = 0; value < sizeof(values) / sizeof(values[0]); ++value)
        for (offset = 0; offset <= REGION; ++offset)
            for (count = 0; count <= REGION - offset; ++count) {
                seed(actual, sizeof(actual), 5);
                memcpy(reference, actual, sizeof(reference));
                memset(reference + GUARD + offset, values[value], count);
                CHECK(ntwm_test_memset(actual + GUARD + offset, values[value], count) == actual + GUARD + offset);
                CHECK(memcmp(actual, reference, sizeof(actual)) == 0);
                ++fills;
            }
}

static void exhaustive_comparisons(void)
{
    static const unsigned char values[][2] = {{0,255},{255,0},{127,128},
                                              {128,127},{255,127},{127,255}};
    unsigned char a[BYTES], b[BYTES];
    size_t left, right, count, mismatch, pair;
    unsigned x, y;
    for (x = 0; x < 256; ++x)
        for (y = 0; y < 256; ++y) {
            a[0] = (unsigned char)x; b[0] = (unsigned char)y;
            CHECK(sign_of(ntwm_test_memcmp(a, b, 1)) == sign_of(memcmp(a, b, 1)));
            ++comparisons;
        }
    for (left = 0; left < 4; ++left)
        for (right = 0; right < 4; ++right)
            for (count = 0; count <= REGION; ++count) {
                memset(a, 0x80, sizeof(a)); memset(b, 0x80, sizeof(b));
                CHECK(ntwm_test_memcmp(a + left, b + right, count) == 0);
                ++comparisons;
                for (mismatch = 0; mismatch < count; ++mismatch)
                    for (pair = 0; pair < sizeof(values) / sizeof(values[0]); ++pair) {
                        memset(a, 0x80, sizeof(a)); memset(b, 0x80, sizeof(b));
                        a[left + mismatch] = values[pair][0];
                        b[right + mismatch] = values[pair][1];
                        CHECK(sign_of(ntwm_test_memcmp(a + left, b + right, count)) ==
                              sign_of(memcmp(a + left, b + right, count)));
                        ++comparisons;
                    }
            }
}

static void larger_buffers(void)
{
    unsigned char actual[8192], reference[8192], original[8192];
    const size_t sizes[] = {0,1,15,16,17,255,256,257,4095,4096};
    size_t i, shift;
    seed(original, sizeof(original), 19);
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
        for (shift = 0; shift <= 33; ++shift) {
            memcpy(actual, original, sizeof(actual)); memcpy(reference, original, sizeof(reference));
            memmove(reference + 128 + shift, reference + 128, sizes[i]);
            CHECK(ntwm_test_memmove(actual + 128 + shift, actual + 128, sizes[i]) == actual + 128 + shift);
            CHECK(memcmp(actual, reference, sizeof(actual)) == 0); ++moves;
            memcpy(actual, original, sizeof(actual)); memcpy(reference, original, sizeof(reference));
            memmove(reference + 128, reference + 128 + shift, sizes[i]);
            CHECK(ntwm_test_memmove(actual + 128, actual + 128 + shift, sizes[i]) == actual + 128);
            CHECK(memcmp(actual, reference, sizeof(actual)) == 0); ++moves;
            memcpy(actual, original, sizeof(actual)); memcpy(reference, original, sizeof(reference));
            memcpy(reference + shift, original + 128, sizes[i]);
            CHECK(ntwm_test_memcpy(actual + shift, original + 128, sizes[i]) == actual + shift);
            CHECK(memcmp(actual, reference, sizeof(actual)) == 0); ++copies;
            memset(reference + shift, -257, sizes[i]);
            CHECK(ntwm_test_memset(actual + shift, -257, sizes[i]) == actual + shift);
            CHECK(memcmp(actual, reference, sizeof(actual)) == 0); ++fills;
        }
}

int main(void)
{
    exhaustive_moves(); exhaustive_copies(); exhaustive_fills();
    exhaustive_comparisons(); larger_buffers();
    printf("{\"checks\":%" PRIu64 ",\"memmove_cases\":%" PRIu64
           ",\"memcpy_cases\":%" PRIu64 ",\"memset_cases\":%" PRIu64
           ",\"memcmp_cases\":%" PRIu64 "}\n", checks, moves, copies, fills, comparisons);
    return 0;
}
