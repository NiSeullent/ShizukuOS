/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the actual static production helper, rather than a copied version.
 * Link with --gc-sections: unrelated allocator entry points are not test mocks.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef SFS_ALLOC_SOURCE
#define SFS_ALLOC_SOURCE "../libsfs/sfs_alloc.c"
#endif
#include SFS_ALLOC_SOURCE

static uint64_t cases, checked_bits, digest;
static uint32_t random_state = 0x4d383053u;

static uint32_t next_random(void)
{
    uint32_t v = random_state;
    v ^= v << 13;
    v ^= v >> 17;
    v ^= v << 5;
    random_state = v;
    return v;
}

static uint32_t oracle(uint8_t *map, uint32_t from, uint32_t n)
{
    uint32_t already_clear = 0;
    for (uint32_t j = 0; j < n; j++) {
        uint32_t bit = from + j;
        uint8_t mask = (uint8_t)(1u << (bit % 8u));
        if ((map[bit / 8u] & mask) == 0) already_clear++;
        map[bit / 8u] = (uint8_t)(map[bit / 8u] & (uint8_t)~mask);
    }
    return already_clear;
}

static void check_case(uint32_t from, uint32_t n, unsigned alignment, int pattern)
{
    /* The last bitmap byte meets the allocation's ASan right redzone. Prefix
     * bytes check underruns and give each offset modulo 16. Compare every byte,
     * including preserved prefix, first/last partial bytes and unused bits.
     */
    size_t prefix = 16u + alignment;
    size_t bitmap_bytes = ((size_t)from + n + 7u) / 8u;
    if (!bitmap_bytes) bitmap_bytes = 1;
    size_t bytes = prefix + bitmap_bytes;
    uint8_t *actual = malloc(bytes), *expected = malloc(bytes);
    if (!actual || !expected) {
        fprintf(stderr, "allocation failed\n");
        free(actual);
        free(expected);
        exit(2);
    }
    for (size_t i = 0; i < bytes; i++)
        actual[i] = pattern < 0 ? (uint8_t)next_random() : (uint8_t)pattern;
    memcpy(expected, actual, bytes);
    uint32_t want = oracle(expected + prefix, from, n);
    uint32_t got = clear_bits(actual + prefix, from, n);
    if (want != got || memcmp(actual, expected, bytes) != 0) {
        fprintf(stderr, "FAIL from=%u n=%u alignment=%u pattern=%d want=%u got=%u\n",
                from, n, alignment, pattern, want, got);
        exit(1);
    }
    /* Every freed range is already clear on a repeated call. */
    if (clear_bits(actual + prefix, from, n) != n ||
        memcmp(actual, expected, bytes) != 0) {
        fprintf(stderr, "FAIL repeated clear from=%u n=%u\n", from, n);
        exit(1);
    }
    digest = (digest * 33u) ^ got ^ ((uint64_t)from << 32) ^ n;
    cases++;
    checked_bits += n;
    free(actual);
    free(expected);
}

static int correctness(void)
{
    static const unsigned offsets[] = {0, 1, 7, 15};
    static const uint32_t starts[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 31, 32, 63, 64, 65, 127};
    static const uint32_t lengths[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17,
                                    55, 56, 57, 63, 64, 65, 127, 128, 129,
                                    255, 256, 257, 4095, 4096, 4097, 32767, 32768, 32769};
    static const int patterns[] = {0, 255, 85, 170, -1};
    if (clear_bits(NULL, UINT32_MAX, 0) != 0) return 1;
    /* Exhaust every byte state and every interval within it. */
    for (unsigned pattern = 0; pattern < 256; pattern++)
        for (uint32_t from = 0; from <= 8; from++)
            for (uint32_t n = 0; n <= 8 - from; n++)
                for (unsigned a = 0; a < sizeof offsets / sizeof offsets[0]; a++)
                    check_case(from, n, offsets[a], (int)pattern);
    for (unsigned s = 0; s < sizeof starts / sizeof starts[0]; s++)
        for (unsigned n = 0; n < sizeof lengths / sizeof lengths[0]; n++)
            for (unsigned a = 0; a < 16; a++)
                for (unsigned p = 0; p < sizeof patterns / sizeof patterns[0]; p++)
                    check_case(starts[s], lengths[n], a, patterns[p]);
    for (unsigned i = 0; i < 10000; i++) {
        uint32_t from = next_random() % 521u;
        uint32_t n = next_random() % 32770u;
        unsigned a = next_random() % 16u;
        check_case(from, n, a, -1);
    }
    printf("PASS cases=%llu checked_bits=%llu digest=%016llx\n",
           (unsigned long long)cases, (unsigned long long)checked_bits,
           (unsigned long long)digest);
    return 0;
}

/* Keep the measured call boundary identical for the old and new actual helper.
 * Neither buffer preparation nor wall-clock scheduling enters CPU duration.
 */
__attribute__((noinline))
static uint32_t measured_clear(uint8_t *map, uint32_t from, uint32_t n)
{
    return clear_bits(map, from, n);
}

static uint64_t cpu_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

static int compare_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int benchmark(void)
{
    static const uint32_t lengths[] = {1, 7, 8, 16, 63, 64, 65, 512, 4096, 32768};
    static const uint32_t starts[] = {0, 3};
    static const int patterns[] = {0, 255, 85};
    const unsigned samples = 7;
    volatile uint64_t checksum = 0;
    struct timespec resolution;
    if (clock_getres(CLOCK_PROCESS_CPUTIME_ID, &resolution) != 0) {
        perror("clock_getres");
        return 2;
    }
    uint64_t timer_pairs[64];
    for (unsigned i = 0; i < 64; i++) {
        uint64_t before = cpu_ns();
        timer_pairs[i] = cpu_ns() - before;
    }
    qsort(timer_pairs, 64, sizeof timer_pairs[0], compare_u64);
    printf("{\"clock\":\"CLOCK_PROCESS_CPUTIME_ID\",\"samples\":%u,\"timer_resolution_ns\":%llu,\"timer_pair_median_cpu_ns\":%llu,\"rows\":[\n",
           samples, (unsigned long long)((uint64_t)resolution.tv_sec * 1000000000u + (uint64_t)resolution.tv_nsec),
           (unsigned long long)timer_pairs[32]);
    unsigned row = 0;
    for (unsigned l = 0; l < sizeof lengths / sizeof lengths[0]; l++)
        for (unsigned s = 0; s < sizeof starts / sizeof starts[0]; s++)
            for (unsigned p = 0; p < sizeof patterns / sizeof patterns[0]; p++) {
                uint32_t from = starts[s], n = lengths[l];
                size_t stride = ((size_t)from + n + 7u) / 8u + 1;
                /* Raise fast full-word sample duration while bounding all maps
                 * (including deliberate misalignment) to at most one MiB.
                 */
                unsigned calls = (unsigned)((1024u * 1024u - 1u) / stride);
                if (calls > 8192) calls = 8192;
                uint8_t *maps = malloc(stride * calls + 1);
                if (!maps) { fprintf(stderr, "benchmark allocation failed\n"); return 2; }
                uint64_t durations[7];
                uint64_t row_checksum = 0;
                uint32_t expected_bad = 0;
                for (uint32_t i = 0; i < n; i++)
                    if (((uint8_t)patterns[p] & (uint8_t)(1u << ((from + i) % 8u))) == 0)
                        expected_bad++;
                uint64_t expected_row_checksum = (uint64_t)expected_bad * calls * samples;
                /* +1 deliberately misaligns all otherwise aligned full-word runs. */
                for (unsigned sample = 0; sample < samples; sample++) {
                    memset(maps, patterns[p], stride * calls + 1);
                    uint64_t begin = cpu_ns();
                    uint64_t sum = 0;
                    for (unsigned c = 0; c < calls; c++)
                        sum += measured_clear(maps + 1 + stride * c, from, n);
                    durations[sample] = cpu_ns() - begin;
                    checksum += sum;
                    row_checksum += sum;
                }
                if (row_checksum != expected_row_checksum) {
                    fprintf(stderr, "benchmark count differs from independent expected pattern\n");
                    free(maps);
                    return 1;
                }
                qsort(durations, samples, sizeof durations[0], compare_u64);
                printf("%s{\"from\":%u,\"bits\":%u,\"pattern\":%d,\"calls_per_sample\":%u,\"row_checksum\":%llu,\"expected_row_checksum\":%llu,\"median_cpu_ns\":%llu,\"min_cpu_ns\":%llu,\"max_cpu_ns\":%llu}",
                       row++ ? ",\n" : "", from, n, patterns[p], calls,
                       (unsigned long long)row_checksum, (unsigned long long)expected_row_checksum,
                       (unsigned long long)durations[samples / 2],
                       (unsigned long long)durations[0],
                       (unsigned long long)durations[samples - 1]);
                free(maps);
            }
    printf("\n],\"checksum\":%llu}\n", (unsigned long long)checksum);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--benchmark") == 0) return benchmark();
    if (argc != 1) { fprintf(stderr, "usage: test_alloc_bitmap [--benchmark]\n"); return 2; }
    return correctness();
}
