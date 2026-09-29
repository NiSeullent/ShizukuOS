/* SPDX-License-Identifier: GPL-2.0-only
 * Read a PE VERSION resource and answer VerQueryValue.
 * The layout is the public VS_VERSIONINFO / VS_FIXEDFILEINFO contract.
 * A file with no RT_VERSION resource fails with error 1812.
 */
#ifndef NTW_VERINFO_H
#define NTW_VERINFO_H
#include <stdint.h>
#define NTW_VER_NOT_FOUND 1812u
#define NTW_VER_INVALID 87u
#define NTW_VER_SMALL 122u
int ntw_ver_find(const uint8_t *image, uint32_t length, uint32_t *offset, uint32_t *size, uint32_t *error);
int ntw_ver_query(const uint8_t *block, uint32_t block_size, const uint16_t *path,
                  const void **data, uint32_t *data_bytes, uint32_t *error);
#endif
