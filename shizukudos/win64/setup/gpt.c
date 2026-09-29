/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: GPT + protective MBR builder and checker. See gpt.h. Layout per UEFI 2.10 section 5.2/5.3:
 * LBA 0 protective MBR (one 0xEE entry covering the disk), LBA 1 primary header, LBA 2.. the 128-entry array,
 * the backup array just before the last LBA, the backup header in the last LBA.
 */
#include "gpt.h"
#include <string.h>

const uint8_t GPT_TYPE_ESP[16] = {0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11,
                                  0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b};
const uint8_t GPT_TYPE_LINUX_FS[16] = {0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47,
                                       0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4};
const uint8_t GPT_TYPE_MS_BASIC_DATA[16] = {0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44,
                                            0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7};

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, v); put16(p + 2, v >> 16); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t get64(const uint8_t *p) { return get32(p) | (uint64_t)get32(p + 4) << 32; }

uint32_t gpt_crc32(const void *data, size_t n)
{
    const uint8_t *p = data;
    uint32_t crc = 0xffffffffu;
    while (n--) {
        int b;
        crc ^= *p++;
        for (b = 0; b < 8; ++b) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

static uint64_t array_sectors(uint32_t ss) { return (GPT_ARRAY_BYTES + ss - 1) / ss; }
uint64_t gpt_first_usable(uint32_t ss) { return 2 + array_sectors(ss); }
uint64_t gpt_last_usable(uint32_t ss, uint64_t sectors) { return sectors - 2 - array_sectors(ss); }

static void header(const gpt_layout_t *l, uint8_t *h, uint64_t my, uint64_t alt, uint64_t array_lba, uint32_t array_crc)
{
    memset(h, 0, l->sector_size);
    memcpy(h, "EFI PART", 8);
    put32(h + 8, 0x00010000u);
    put32(h + 12, 92);
    put64(h + 24, my);
    put64(h + 32, alt);
    put64(h + 40, gpt_first_usable(l->sector_size));
    put64(h + 48, gpt_last_usable(l->sector_size, l->sectors));
    memcpy(h + 56, l->disk_guid, 16);
    put64(h + 72, array_lba);
    put32(h + 80, GPT_ENTRIES);
    put32(h + 84, GPT_ENTRY_SIZE);
    put32(h + 88, array_crc);
    put32(h + 16, gpt_crc32(h, 92));
}

static void mbr_entry(uint8_t *e, uint8_t type, uint64_t first, uint64_t count)
{
    e[0] = 0x00;                                    /* not active (UEFI 2.10 table 5.4) */
    e[1] = 0x00; e[2] = 0x02; e[3] = 0x00;          /* CHS 0/0/2 for LBA 1; other starts use the LBA-only marker */
    if (first != 1) { e[1] = 0xfe; e[2] = 0xff; e[3] = 0xff; }
    e[4] = type;
    e[5] = 0xfe; e[6] = 0xff; e[7] = 0xff;          /* CHS end: not representable, use LBA */
    put32(e + 8, first > 0xffffffffull ? 0xffffffffu : (uint32_t)first);
    put32(e + 12, count > 0xffffffffull ? 0xffffffffu : (uint32_t)count);
}

int gpt_build(const gpt_layout_t *l, uint8_t *mbr, uint8_t *primary, uint8_t *array, uint8_t *backup)
{
    const uint64_t first = gpt_first_usable(l->sector_size), last = gpt_last_usable(l->sector_size, l->sectors);
    unsigned i, j, slot = 1;
    uint32_t crc;
    if ((l->sector_size != 512 && l->sector_size != 4096) || l->count > GPT_MAX_PARTS || l->sectors < 2 * first + 2)
        return -1;
    memset(array, 0, GPT_ARRAY_BYTES);
    for (i = 0; i < l->count; ++i) {
        const gpt_part_t *p = &l->part[i];
        uint8_t *e = array + i * GPT_ENTRY_SIZE;
        if (p->first_lba < first || p->last_lba > last || p->last_lba < p->first_lba) return -2;
        for (j = 0; j < i; ++j)
            if (p->first_lba <= l->part[j].last_lba && l->part[j].first_lba <= p->last_lba) return -3;
        memcpy(e, p->type, 16);
        memcpy(e + 16, p->guid, 16);
        put64(e + 32, p->first_lba);
        put64(e + 40, p->last_lba);
        put64(e + 48, p->attrs);
        for (j = 0; j < 36 && p->name[j]; ++j) put16(e + 56 + 2 * j, (uint8_t)p->name[j]);
    }
    crc = gpt_crc32(array, GPT_ARRAY_BYTES);
    header(l, primary, 1, l->sectors - 1, 2, crc);
    header(l, backup, l->sectors - 1, 1, l->sectors - 1 - array_sectors(l->sector_size), crc);
    memset(mbr, 0, l->sector_size);
    if (l->boot_code) memcpy(mbr, l->boot_code, 440);
    put32(mbr + 440, l->mbr_signature);
    mbr_entry(mbr + 446, 0xee, 1, l->sectors - 1);
    for (i = 0; i < l->count && slot < 4; ++i) {                   /* optional hybrid entries (legacy OS view) */
        const gpt_part_t *p = &l->part[i];
        if (!p->mbr_type) continue;
        if (p->last_lba > 0xffffffffull) return -4;
        mbr_entry(mbr + 446 + 16 * slot++, p->mbr_type, p->first_lba, p->last_lba - p->first_lba + 1);
    }
    if (slot > 1)                                                   /* hybrid: the 0xEE entry covers only the GPT area */
        mbr_entry(mbr + 446, 0xee, 1, first - 1);
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    return 0;
}

int gpt_check(const uint8_t *h, const uint8_t *array, uint32_t ss, uint64_t my_lba, uint64_t sectors)
{
    uint8_t tmp[92];
    if (memcmp(h, "EFI PART", 8) || get32(h + 8) != 0x00010000u || get32(h + 12) != 92) return -1;
    memcpy(tmp, h, 92);
    put32(tmp + 16, 0);
    if (gpt_crc32(tmp, 92) != get32(h + 16)) return -2;
    if (get64(h + 24) != my_lba || get64(h + 32) != (my_lba == 1 ? sectors - 1 : 1)) return -3;
    if (get32(h + 80) != GPT_ENTRIES || get32(h + 84) != GPT_ENTRY_SIZE) return -4;
    if (gpt_crc32(array, GPT_ARRAY_BYTES) != get32(h + 88)) return -5;
    if (get64(h + 40) != gpt_first_usable(ss) || get64(h + 48) != gpt_last_usable(ss, sectors)) return -6;
    return 0;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int gpt_guid_parse(const char *t, uint8_t out[16])
{
    static const int order[16] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t raw[16];
    int i = 0, k = 0;
    while (t[k] && i < 16) {
        int hi, lo;
        if (t[k] == '-') { ++k; continue; }
        hi = hexval(t[k]);
        lo = hexval(t[k + 1]);
        if (hi < 0 || lo < 0) return -1;
        raw[i++] = (uint8_t)(hi << 4 | lo);
        k += 2;
    }
    if (i != 16 || t[k]) return -1;
    for (i = 0; i < 16; ++i) out[i] = raw[order[i]];
    return 0;
}

void gpt_guid_format(const uint8_t g[16], char out[37])
{
    static const int order[16] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    static const char hex[] = "0123456789abcdef";
    int i, o = 0;
    for (i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[o++] = '-';
        out[o++] = hex[g[order[i]] >> 4];
        out[o++] = hex[g[order[i]] & 15];
    }
    out[o] = 0;
}
