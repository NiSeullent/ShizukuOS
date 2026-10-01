/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded observations of existing pixels for opt-in bring-up diagnostics.
 * This never changes pixels and its hash describes at most 64 samples, not a
 * complete frame or an application rendering success claim. */
#ifndef SHZ_PIXEL_SAMPLE_H
#define SHZ_PIXEL_SAMPLE_H
#include <stdint.h>
#include <stddef.h>
typedef struct {
    uint32_t count, first, last, hash, differing, nonface, alpha;
} shz_pixel_samples_t;

static inline shz_pixel_samples_t shz_pixel_samples(const uint32_t *bits,
    int32_t width, int32_t height, uint32_t stride, int topdown,
    int32_t left, int32_t top, int32_t right, int32_t bottom)
{
    shz_pixel_samples_t out = {0,0,0,0,0,0,0};
    uint64_t total, span, step, rem;
    uint32_t n, i;
    if (!bits || width <= 0 || height <= 0 || stride < (uint32_t)width ||
        stride > SIZE_MAX / sizeof(uint32_t) / (uint32_t)height) return out;
    if (left < 0) left = 0;
    if (top < 0) top = 0;
    if (right > width) right = width;
    if (bottom > height) bottom = height;
    if (left >= right || top >= bottom) return out;
    span = (uint32_t)(right - left);
    total = span * (uint32_t)(bottom - top);
    n = total < 64 ? (uint32_t)total : 64;
    step = n > 1 ? (total - 1) / (n - 1) : 0;
    rem = n > 1 ? (total - 1) % (n - 1) : 0;
    out.hash = 2166136261u;
    for (i = 0; i < n; ++i) {
        const uint64_t at = step * i + (n > 1 ? rem * i / (n - 1) : 0);
        const uint32_t x = (uint32_t)left + (uint32_t)(at % span);
        const uint32_t y = (uint32_t)top + (uint32_t)(at / span);
        const uint32_t row = topdown ? y : (uint32_t)height - 1 - y;
        const uint32_t p = bits[(size_t)row * stride + x];
        if (!i) out.first = p;
        out.last = p;
        out.hash = (out.hash ^ p) * 16777619u;
        out.differing += p != out.first;
        out.nonface += (p & 0xffffffu) != 0xc0c0c0u;
        out.alpha += (p >> 24) != 0;
    }
    out.count = n;
    return out;
}
#endif
