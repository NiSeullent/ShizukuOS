/* SPDX-License-Identifier: GPL-2.0-only
 * ASCII ordinal compare. Bytes above 127 are not folded. NULL is less than
 * any string, and two NULL pointers compare equal. Wine kernel32/string.c
 * was not copied.
 */
#ifndef NTW_STRCMP_H
#define NTW_STRCMP_H
#include <stdint.h>
int32_t ntw_lstrcmpi_a(const uint8_t *left, const uint8_t *right);
#endif
