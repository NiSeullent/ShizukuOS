/* SPDX-License-Identifier: GPL-2.0-only
 * Checksums used by the ext4 format: CRC-32C (Castagnoli polynomial 0x1EDC6F41, reflected 0x82F63B78) exactly as
 * the kernel's crc32c() is applied to ext4 metadata (no final inversion), and the classic CRC-16 (0x8005 reflected,
 * 0xA001) used by the older group-descriptor checksum. Tables are generated on first use.
 */
#include "sfs_internal.h"

static uint32_t crc32c_table[256];
static uint16_t crc16_table[256];
static int tables_ready;

static void make_tables(void)
{
    uint32_t i, j;
    for (i = 0; i < 256; ++i) {
        uint32_t c = i;
        uint16_t s = (uint16_t)i;
        for (j = 0; j < 8; ++j) {
            c = (c & 1) ? (c >> 1) ^ 0x82F63B78u : c >> 1;
            s = (uint16_t)((s & 1) ? (s >> 1) ^ 0xA001u : s >> 1);
        }
        crc32c_table[i] = c;
        crc16_table[i] = s;
    }
    tables_ready = 1;
}

uint32_t sfs_crc32c(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *p = data;
    if (!tables_ready) make_tables();
    while (len--) crc = crc32c_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return crc;
}

uint16_t sfs_crc16(uint16_t crc, const void *data, size_t len)
{
    const uint8_t *p = data;
    if (!tables_ready) make_tables();
    while (len--) crc = (uint16_t)(crc16_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8));
    return crc;
}
