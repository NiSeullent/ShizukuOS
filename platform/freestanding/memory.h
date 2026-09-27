/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWM_FREESTANDING_MEMORY_H
#define NTWM_FREESTANDING_MEMORY_H
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *memset(void *destination, int value, size_t count);
void *memcpy(void *destination, const void *source, size_t count);
void *memmove(void *destination, const void *source, size_t count);
int memcmp(const void *left, const void *right, size_t count);

#ifdef __cplusplus
}
#endif
#endif
