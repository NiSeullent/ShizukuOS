/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SECRET_H
#define SHZ_SECRET_H
#include <stdint.h>
typedef struct {uint16_t chars[129];unsigned length;} shz_secret;
void shz_secret_reset(shz_secret *);
int shz_secret_key(shz_secret *,uint16_t);
void shz_secret_mask(const shz_secret *,uint16_t[129]);
#endif
