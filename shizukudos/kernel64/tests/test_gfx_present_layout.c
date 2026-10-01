/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "../gfx_present_layout.h"

#define LO UINT64_C(0x10000)
#define HI UINT64_C(0x7ffffffef000)
#define LIMIT UINT64_C(16777216)
static int checks;
#define CHECK(x) do { ++checks; assert(x); } while (0)
static shz_present_t normal(void)
{
    shz_present_t p;
    memset(&p, 0, sizeof p);
    p.bits = LO; p.w = p.surf_w = 32; p.h = p.surf_h = 24;
    p.stride = 128;
    return p;
}
static int layout(shz_present_t p, shz_present_layout_t *out)
{
    return shz_present_layout(&p, p.surf_w, p.surf_h, LIMIT, LO, HI, out);
}
int main(void)
{
    shz_present_t p = normal();
    shz_present_layout_t out;
    CHECK(layout(p, &out) == SHZ_PRESENT_OK && out.source_offset == 0 &&
          out.row_bytes == 128 && out.packed_bytes == 3072);
    p.x = -2; p.y = -3; p.w = 5; p.h = 7;
    CHECK(layout(p, &out) == SHZ_PRESENT_OK && out.rect.left == 0 &&
          out.rect.top == 0 && out.rect.right == 3 && out.rect.bottom == 4 &&
          out.row_bytes == 12 && out.packed_bytes == 48);
    p = normal(); p.x = 30; p.y = 22; p.w = 4; p.h = 4;
    CHECK(layout(p, &out) == SHZ_PRESENT_OK && out.rect.right == 32 &&
          out.rect.bottom == 24 && out.source_offset == 2936 &&
          out.row_bytes == 8 && out.packed_bytes == 16);
    p = normal(); p.w = 0; p.bits = 0;
    CHECK(layout(p, &out) == SHZ_PRESENT_EMPTY);
    p = normal(); p.h = 0;
    CHECK(layout(p, &out) == SHZ_PRESENT_EMPTY);
    p = normal(); p.w = -1;
    CHECK(layout(p, &out) == SHZ_PRESENT_BAD_LAYOUT);
    p = normal(); p.h = INT_MIN;
    CHECK(layout(p, &out) == SHZ_PRESENT_BAD_LAYOUT);
    p = normal(); p.stride = 127;
    CHECK(layout(p, &out) == SHZ_PRESENT_BAD_LAYOUT);
    p = normal(); p.surf_w = INT_MAX; p.stride = UINT_MAX;
    CHECK(layout(p, &out) == SHZ_PRESENT_BAD_LAYOUT);
    p = normal(); p.surf_w = 2049; p.surf_h = 2048; p.stride = 8196;
    CHECK(layout(p, &out) == SHZ_PRESENT_BAD_LAYOUT);
    p = normal(); p.x = INT_MAX; p.w = INT_MAX;
    CHECK(layout(p, &out) == SHZ_PRESENT_EMPTY);
    p = normal(); p.x = 1; p.w = INT_MAX;
    CHECK(layout(p, &out) == SHZ_PRESENT_OK && out.rect.left == 1 && out.rect.right == 32 && out.row_bytes == 124);
    p = normal(); p.x = INT_MIN; p.w = INT_MAX;
    CHECK(layout(p, &out) == SHZ_PRESENT_EMPTY);
    p = normal(); p.bits = LO - 1;
    CHECK(layout(p, &out) == SHZ_PRESENT_BAD_ADDRESS);
    p.bits = HI;
    CHECK(layout(p, &out) == SHZ_PRESENT_BAD_ADDRESS);
    p.bits = UINT64_MAX - 4;
    CHECK(layout(p, &out) == SHZ_PRESENT_BAD_ADDRESS);
    p = normal(); p.bits = HI - 3072;
    CHECK(layout(p, &out) == SHZ_PRESENT_OK);
    ++p.bits;
    CHECK(layout(p, &out) == SHZ_PRESENT_BAD_ADDRESS);
    p = normal(); p.stride = UINT_MAX;
    CHECK(layout(p, &out) == SHZ_PRESENT_OK && out.source_offset == 0 && out.packed_bytes == 3072);
    p.bits = HI - (uint64_t)23 * UINT_MAX - 128;
    CHECK(layout(p, &out) == SHZ_PRESENT_OK);
    ++p.bits;
    CHECK(layout(p, &out) == SHZ_PRESENT_BAD_ADDRESS);
    p = normal(); p.x = 31; p.y = 23; p.w = p.h = 1;
    p.bits = HI - 3072;
    CHECK(layout(p, &out) == SHZ_PRESENT_OK && out.source_offset == 3068 && out.packed_bytes == 4);
    p = normal(); p.surf_w = 0; p.w = 0;
    CHECK(layout(p, &out) == SHZ_PRESENT_EMPTY);
    p = normal();
    CHECK(shz_present_layout(&p, 31, 24, LIMIT, LO, HI, &out) == SHZ_PRESENT_BAD_LAYOUT);
    CHECK(shz_present_layout(&p, 32, 23, LIMIT, LO, HI, &out) == SHZ_PRESENT_BAD_LAYOUT);
    CHECK(shz_present_layout(&p, -1, 24, LIMIT, LO, HI, &out) == SHZ_PRESENT_BAD_LAYOUT);
    CHECK(shz_present_layout(&p, 32, 24, LIMIT, HI, LO, &out) == SHZ_PRESENT_BAD_ADDRESS);
    printf("present layout: %d checks passed\n", checks);
    return 0;
}
