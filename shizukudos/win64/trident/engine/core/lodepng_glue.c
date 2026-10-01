/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - allocator hooks for the vendored LodePNG (src/vendor/lodepng, zlib licence), which the build
 * compiles with LODEPNG_NO_COMPILE_ALLOCATORS / _DISK / _CPP / _ENCODER / _ERROR_TEXT. The PNG decoder glue itself is
 * L2's (image_png.c).
 */
#include "base.h"

void *lodepng_malloc(size_t size);
void *lodepng_realloc(void *ptr, size_t new_size);
void lodepng_free(void *ptr);

void *lodepng_malloc(size_t size)
{
    return shz_realloc(NULL, size);
}

void *lodepng_realloc(void *ptr, size_t new_size)
{
    return shz_realloc(ptr, new_size);
}

void lodepng_free(void *ptr)
{
    shz_free(ptr);
}
