/* SPDX-License-Identifier: GPL-2.0-only */
#include "../gdi_dib_layout.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
    shz_dib_layout_t layout;
    unsigned checks = 0;
#define VERIFY(condition) do { assert(condition); ++checks; } while (0)
    VERIFY(shz_dib_layout(4, -3, 1, 4, &layout));
    VERIFY(layout.width == 4 && layout.height == 3 && layout.topdown);
    VERIFY(layout.pixel_bytes == 48 && layout.view_bytes == 52 && !layout.map_offset && layout.delta == 4);
    VERIFY(shz_dib_layout(4, 3, 1, 65540, &layout));
    VERIFY(layout.pixel_bytes == 48 && layout.view_bytes == 52 && layout.map_offset == 65536 && layout.delta == 4 && !layout.topdown);
    VERIFY(shz_dib_layout(4, 3, 1, UINT32_MAX - 3, &layout));
    VERIFY((uint64_t)layout.map_offset + layout.view_bytes == (uint64_t)UINT32_MAX - 3 + 48);
    VERIFY(!shz_dib_layout(4, 3, 1, 2, &layout));
    VERIFY(shz_dib_layout(4, 3, 0, UINT32_MAX, &layout) && !layout.map_offset && !layout.delta && layout.view_bytes == 48);
    VERIFY(!shz_dib_layout(0, 3, 1, 0, &layout));
    VERIFY(!shz_dib_layout(-1, 3, 1, 0, &layout));
    VERIFY(!shz_dib_layout(4, 0, 1, 0, &layout));
    VERIFY(!shz_dib_layout(4, INT32_MIN, 1, 0, &layout));
    VERIFY(!shz_dib_layout(INT32_MAX, INT32_MAX, 1, 0, &layout));
    VERIFY(shz_dib_layout(8192, 8192, 1, 0, &layout) && layout.pixel_bytes == (256u << 20));
    VERIFY(!shz_dib_layout(8192, 8193, 1, 0, &layout));
    VERIFY(!shz_dib_layout(4, 3, 1, 0, NULL));
    printf("DIB layout host: %u checks passed\n", checks);
    return 0;
}
