/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_MAIN_IMAGE_H
#define NTW_MAIN_IMAGE_H
#include <stddef.h>
#include <stdint.h>
enum { PX_SECTIONS=32 };
typedef struct px_section {uint32_t start,bytes,flags;} px_section;
typedef struct px_image {uintptr_t base;uint32_t bytes,count;px_section sections[PX_SECTIONS];} px_image;
/* Parse ONLY readable native-image headers; no file mapping or executable load.
 * available is the verified readable memory range beginning at native EXE base.
 */
int px_main_image(px_image *,const void *,size_t,uintptr_t);
int px_main_callback(const px_image *,uintptr_t,uintptr_t,size_t);
#endif
