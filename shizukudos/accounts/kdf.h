/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_KDF_H
#define SHZ_KDF_H
#include <stddef.h>
#include <stdint.h>
void shz_secret_clear(void *, size_t);
int shz_pbkdf2(const void *,size_t,const void *,size_t,uint32_t,uint8_t[32]);
#endif
