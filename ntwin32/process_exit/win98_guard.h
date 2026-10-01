/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PX_WIN98_GUARD_H
#define PX_WIN98_GUARD_H
#include "main_image.h"
typedef struct px_page {
 uintptr_t allocation,base;size_t bytes;uint32_t state,protection;
} px_page;
int px_kernel_image(px_image *,const void *,size_t,uintptr_t);
int px_guard_code(const px_image *,uintptr_t,const px_page *,int);
int px_guard_data(const px_image *,uintptr_t,size_t,const px_page *);
#endif
