/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PX_WIN98_EXPORT_H
#define PX_WIN98_EXPORT_H
#include "main_image.h"
typedef const unsigned char *(*px_read_image)(void *,uintptr_t,size_t);
int px_named_export(const px_image *,const void *,size_t,const char *,
                    px_read_image,void *,uintptr_t *);
#endif
