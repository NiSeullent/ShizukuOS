/* SPDX-License-Identifier: GPL-2.0-only
 * Builds the vendored, unmodified LodePNG (src/vendor/lodepng/lodepng.c, zlib licence, (c) Lode Vandevenne) into the
 * Sapphire image with the same configuration the Trident engine uses (decoder only, no disk/C++/error text), routing its
 * allocations through the Win64 CRT. build_sys_apps compiles every .c file of an apps directory, so no build.py change is needed. */
#include "shzcrt.h"
#define LODEPNG_NO_COMPILE_ALLOCATORS
#define LODEPNG_NO_COMPILE_DISK
#define LODEPNG_NO_COMPILE_CPP
#define LODEPNG_NO_COMPILE_ENCODER
#define LODEPNG_NO_COMPILE_ERROR_TEXT
void *lodepng_malloc(size_t size) { return shz_malloc(size); }
void *lodepng_realloc(void *ptr, size_t new_size) { return shz_realloc(ptr, new_size); }
void lodepng_free(void *ptr) { shz_free(ptr); }
#include "../../../../src/vendor/lodepng/lodepng.c"
