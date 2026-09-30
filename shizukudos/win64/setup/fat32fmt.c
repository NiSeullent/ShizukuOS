/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: empty FAT32 volume formatter. See fat32fmt.h.
 */
#include "fat32fmt.h"
#include <string.h>

#define SS 512u
#define RSVD 32u
#define CHUNK 32u                                   /* sectors per write when zeroing */

static uint8_t zero_chunk[SS * CHUNK];

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, v); put16(p + 2, v >> 16); }

static uint32_t cluster_sectors(uint64_t sectors)
{
    if (sectors < 66600) return 0;                   /* too small for FAT32 */
    if (sectors <= 532480) return 1;
    if (sectors <= 16777216) return 8;
    if (sectors <= 33554432) return 16;
    if (sectors <= 67108864) return 32;
    return 64;
}

static int wr(const fat32_io *io, uint64_t s, uint32_t n, const void *buf) { return io->write(io->ctx, s, n, buf) ? -2 : 0; }

static int zero(const fat32_io *io, uint64_t s, uint64_t n)
{
    while (n) {
        const uint32_t k = n < CHUNK ? (uint32_t)n : CHUNK;
        if (wr(io, s, k, zero_chunk)) return -2;
        s += k;
        n -= k;
    }
    return 0;
}

int fat32_format(const fat32_io *io, const fat32_params *p, uint32_t *clusters_out)
{
    uint8_t bs[SS], fsinfo[SS], sec[SS];
    const uint32_t spc = cluster_sectors(p->sectors);
    uint64_t tmp1, tmp2, fatsz, clusters, data;
    int st;
    if (!spc || p->sectors > 0xffffffffull) return -1;
    tmp1 = p->sectors - RSVD;
    tmp2 = (256u * spc + 2u) / 2u;
    fatsz = (tmp1 + tmp2 - 1) / tmp2;
    data = RSVD + 2 * fatsz;
    clusters = (p->sectors - data) / spc;
    if (clusters < 65525 || clusters >= 0x0ffffff5u || (clusters + 2) * 4 > fatsz * SS) return -1;
    memset(bs, 0, sizeof bs);
    bs[0] = 0xeb; bs[1] = 0x58; bs[2] = 0x90;
    memcpy(bs + 3, "MSWIN4.1", 8);                  /* OEM id legacy drivers expect; not Microsoft code */
    put16(bs + 0x0b, SS);
    bs[0x0d] = (uint8_t)spc;
    put16(bs + 0x0e, RSVD);
    bs[0x10] = 2;
    bs[0x15] = 0xf8;
    put16(bs + 0x18, 63);
    put16(bs + 0x1a, 255);
    put32(bs + 0x1c, p->hidden);
    put32(bs + 0x20, (uint32_t)p->sectors);
    put32(bs + 0x24, (uint32_t)fatsz);
    put32(bs + 0x2c, 2);                            /* root directory cluster */
    put16(bs + 0x30, 1);                            /* FSInfo sector */
    put16(bs + 0x32, 6);                            /* backup boot sector */
    bs[0x40] = 0x80;
    bs[0x42] = 0x29;
    put32(bs + 0x43, p->volume_id);
    memcpy(bs + 0x47, p->label, 11);
    memcpy(bs + 0x52, "FAT32   ", 8);
    bs[0x5a] = 0xcd; bs[0x5b] = 0x18;               /* not bootable until the user installs a system: INT 18h */
    bs[0x5c] = 0xf4; bs[0x5d] = 0xeb; bs[0x5e] = 0xfd;
    bs[510] = 0x55; bs[511] = 0xaa;
    memset(fsinfo, 0, sizeof fsinfo);
    put32(fsinfo + 0, 0x41615252u);
    put32(fsinfo + 484, 0x61417272u);
    put32(fsinfo + 488, (uint32_t)clusters - 1);    /* the root directory uses cluster 2 */
    put32(fsinfo + 492, 3);
    put32(fsinfo + 508, 0xaa550000u);
    if ((st = zero(io, 0, RSVD))) return st;
    if ((st = zero(io, RSVD, 2 * fatsz))) return st;
    if ((st = zero(io, data, spc))) return st;
    memset(sec, 0, sizeof sec);
    put32(sec + 0, 0x0ffffff8u);                    /* media descriptor */
    put32(sec + 4, 0x0fffffffu);                    /* clean shutdown, no hard error */
    put32(sec + 8, 0x0fffffffu);                    /* root directory: one cluster, end of chain */
    if ((st = wr(io, RSVD, 1, sec)) || (st = wr(io, RSVD + fatsz, 1, sec))) return st;
    memset(sec, 0, sizeof sec);
    memcpy(sec, p->label, 11);
    sec[11] = 0x08;                                 /* volume label entry */
    if ((st = wr(io, data, 1, sec))) return st;
    if ((st = wr(io, 6, 1, bs)) || (st = wr(io, 7, 1, fsinfo))) return st;
    if ((st = wr(io, 1, 1, fsinfo)) || (st = wr(io, 0, 1, bs))) return st;       /* primary boot sector last */
    if (clusters_out) *clusters_out = (uint32_t)clusters;
    return 0;
}
