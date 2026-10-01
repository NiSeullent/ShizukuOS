/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_DELAY_FIXTURE_H
#define NTW_DELAY_FIXTURE_H
#include "delay_runtime.h"
#define DF_FILE_BYTES 2048u
#define DF_IMAGE_BYTES 12288u
#define DF_BASE 0x00400000u
#define DF_DESCRIPTOR 0x2000u
#define DF_IAT 0x2100u
#define DF_HANDLE 0x2140u
void df_build(uint8_t *,uint8_t *,uint32_t);
void df_put32(uint8_t *,uint32_t);
#endif
