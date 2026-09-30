/* SPDX-License-Identifier: GPL-2.0-only
 * MBR / GPT partition scanner (see blk_part.h). Host-testable: -DBLK_HOST_TEST uses <string.h>, the kernel build uses
 * lib.c's memcpy/memcmp/memset through the prototypes below.
 *
 * GPT rules applied (UEFI 2.x, section 5.3): signature "EFI PART", revision 1.0, header size 92..sector, header CRC32
 * with the CRC field zeroed, MyLBA equal to the LBA the header was read from, sane entry geometry (entry size a multiple
 * of 8 and >= 128, array inside the device), entry-array CRC32 over NumberOfEntries * SizeOfEntry bytes. A primary that
 * fails any of these is replaced by the backup header at the last LBA (AlternateLBA of the primary is not trusted when
 * the primary is corrupt, so the last sector is used, which is where the spec puts it). MBR rules: 0x55AA at 510, four
 * 16-byte entries at 446, type 0xEE = protective, types 0x05/0x0F/0x85 = extended -> EBR chain (entry 0 relative to the
 * EBR, entry 1 relative to the extended partition start).
 */
#include "blk_part.h"
#ifdef BLK_HOST_TEST
#include <string.h>
#else
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
#endif

static uint32_t crc_table[256];
static int crc_ready;

uint32_t blk_crc32(uint32_t crc, const void *data, size_t n)
{
    const uint8_t *p = data;
    if (!crc_ready) {
        uint32_t i, j;
        for (i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (j = 0; j < 8; ++j) c = (c & 1) ? 0xedb88320u ^ (c >> 1) : c >> 1;
            crc_table[i] = c;
        }
        crc_ready = 1;
    }
    crc = ~crc;
    while (n--) crc = crc_table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    return ~crc;
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

typedef struct {
    blk_part_read_fn read;
    void *ctx;
    uint32_t ss;                        /* sector size */
    uint64_t sectors;
    uint8_t *buf0, *buf1;               /* two sector buffers inside scratch */
    blk_part_t *out;
    unsigned max, n;
    uint32_t notes;
} scan_t;

static int add(scan_t *s, const blk_part_t *p)
{
    if (p->start >= s->sectors || p->sectors == 0 || p->sectors > s->sectors - p->start) {
        s->notes |= PSCAN_OUT_OF_RANGE;
        return 0;
    }
    if (s->n >= s->max) {
        s->notes |= PSCAN_TRUNCATED;
        return -1;
    }
    s->out[s->n] = *p;
    s->out[s->n].index = s->n + 1;
    ++s->n;
    return 0;
}

/* ---------------------------------------------------------------- GPT */
struct gpt_hdr {
    uint32_t header_size, header_crc, entries_crc, num_entries, entry_size;
    uint64_t my_lba, alt_lba, first_usable, last_usable, entries_lba;
};

/* Reads and validates the GPT header at `lba`; 0 = ok. */
static int gpt_header(scan_t *s, uint64_t lba, struct gpt_hdr *h)
{
    uint8_t *b = s->buf0;
    uint8_t tmp[92];
    uint32_t crc;
    if (lba >= s->sectors) return -1;
    if (s->read(s->ctx, lba, 1, b)) { s->notes |= PSCAN_READ_ERROR; return -1; }
    if (memcmp(b, "EFI PART", 8)) return -1;
    if (rd32(b + 8) != 0x00010000u) return -1;
    h->header_size = rd32(b + 12);
    if (h->header_size < 92 || h->header_size > s->ss) return -1;
    h->header_crc = rd32(b + 16);
    if (h->header_size > sizeof tmp) {          /* CRC covers header_size bytes: use the sector buffer in place */
        uint8_t saved[4];
        memcpy(saved, b + 16, 4);
        memset(b + 16, 0, 4);
        crc = blk_crc32(0, b, h->header_size);
        memcpy(b + 16, saved, 4);
    } else {
        memcpy(tmp, b, 92);
        memset(tmp + 16, 0, 4);
        crc = blk_crc32(0, tmp, h->header_size);
    }
    if (crc != h->header_crc) return -1;
    h->my_lba = rd64(b + 24);
    h->alt_lba = rd64(b + 32);
    h->first_usable = rd64(b + 40);
    h->last_usable = rd64(b + 48);
    h->entries_lba = rd64(b + 72);
    h->num_entries = rd32(b + 80);
    h->entry_size = rd32(b + 84);
    h->entries_crc = rd32(b + 88);
    if (h->my_lba != lba) return -1;
    if (h->entry_size < 128 || (h->entry_size & 7) || h->entry_size > s->ss) return -1;
    if (h->num_entries == 0 || h->num_entries > 4096) return -1;
    {
        const uint64_t bytes = (uint64_t)h->num_entries * h->entry_size;
        const uint64_t nsec = (bytes + s->ss - 1) / s->ss;
        if (h->entries_lba == 0 || h->entries_lba >= s->sectors || nsec > s->sectors - h->entries_lba) return -1;
        if (h->entries_lba <= lba && lba < h->entries_lba + nsec) return -1;   /* array overlaps its own header */
    }
    if (h->first_usable > h->last_usable || h->last_usable >= s->sectors) return -1;
    return 0;
}

static void fold_name(const uint8_t *u16, char *out)
{
    unsigned i;
    for (i = 0; i < 36; ++i) {
        const uint16_t c = rd16(u16 + 2 * i);
        if (!c) break;
        out[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    out[i] = 0;
}

/* Walks the entry array of a validated header, checking its CRC while parsing. Returns 0 = ok, -1 = CRC mismatch
 * (the partitions already stored are discarded by the caller). */
static int gpt_entries(scan_t *s, const struct gpt_hdr *h, uint8_t flags)
{
    const uint64_t bytes = (uint64_t)h->num_entries * h->entry_size;
    uint64_t done = 0, lba = h->entries_lba;
    uint32_t crc = 0, per_sector = s->ss / h->entry_size, e;
    static const uint8_t zero_guid[16] = {0};
    const unsigned first = s->n;
    unsigned truncated = 0;
    while (done < bytes) {
        const uint32_t chunk = (uint32_t)((bytes - done) < s->ss ? (bytes - done) : s->ss);
        if (s->read(s->ctx, lba, 1, s->buf1)) { s->notes |= PSCAN_READ_ERROR; s->n = first; return -1; }
        crc = blk_crc32(crc, s->buf1, chunk);
        for (e = 0; e < per_sector && (done + (uint64_t)e * h->entry_size) < bytes; ++e) {
            const uint8_t *ent = s->buf1 + e * h->entry_size;
            blk_part_t p;
            if (!memcmp(ent, zero_guid, 16)) continue;
            memset(&p, 0, sizeof p);
            memcpy(p.type_guid, ent, 16);
            memcpy(p.part_guid, ent + 16, 16);
            p.start = rd64(ent + 32);
            p.sectors = rd64(ent + 40) >= p.start ? rd64(ent + 40) - p.start + 1 : 0;
            p.scheme = PART_SCHEME_GPT;
            p.flags = flags;
            fold_name(ent + 56, p.name);
            if (!truncated && add(s, &p) < 0) truncated = 1;
        }
        done += chunk;
        ++lba;
    }
    if (crc != h->entries_crc) {
        s->notes |= PSCAN_GPT_ENTRIES_CRC_BAD;
        s->n = first;
        return -1;
    }
    return 0;
}

static int scan_gpt(scan_t *s)
{
    struct gpt_hdr h;
    if (gpt_header(s, 1, &h) == 0) {
        s->notes |= PSCAN_GPT_PRIMARY_OK;
        if (gpt_entries(s, &h, 0) == 0) return 1;
        /* primary array corrupt: try the backup header before giving up */
    } else {
        s->notes |= PSCAN_GPT_PRIMARY_BAD;
    }
    if (gpt_header(s, s->sectors - 1, &h) == 0) {
        s->notes |= PSCAN_GPT_BACKUP_OK;
        if (gpt_entries(s, &h, PARTF_FROM_BACKUP_GPT) == 0) {
            s->notes |= PSCAN_GPT_USED_BACKUP;
            return 1;
        }
    } else {
        s->notes |= PSCAN_GPT_BACKUP_BAD;
    }
    return 0;
}

/* ---------------------------------------------------------------- MBR */
static int is_extended(uint8_t t) { return t == 0x05 || t == 0x0f || t == 0x85; }

static void scan_ebr(scan_t *s, uint64_t ext_start, uint64_t ext_sectors)
{
    uint64_t ebr = ext_start, seen[32];
    unsigned depth = 0, i;
    s->notes |= PSCAN_EBR_CHAIN;
    for (;;) {
        const uint8_t *e0, *e1;
        blk_part_t p;
        if (depth >= 32) { s->notes |= PSCAN_EBR_LOOP; return; }
        for (i = 0; i < depth; ++i) if (seen[i] == ebr) { s->notes |= PSCAN_EBR_LOOP; return; }
        seen[depth++] = ebr;
        if (ebr >= s->sectors) { s->notes |= PSCAN_OUT_OF_RANGE; return; }
        if (s->read(s->ctx, ebr, 1, s->buf1)) { s->notes |= PSCAN_READ_ERROR; return; }
        if (rd16(s->buf1 + 510) != 0xaa55) return;
        e0 = s->buf1 + 446;
        e1 = e0 + 16;
        if (e0[4] && !is_extended(e0[4]) && rd32(e0 + 12)) {
            memset(&p, 0, sizeof p);
            p.start = ebr + rd32(e0 + 8);
            p.sectors = rd32(e0 + 12);
            p.scheme = PART_SCHEME_MBR;
            p.mbr_type = e0[4];
            p.flags = PARTF_LOGICAL | ((e0[0] & 0x80) ? PARTF_BOOTABLE : 0);
            if (p.start < ext_start || p.start - ext_start >= ext_sectors) s->notes |= PSCAN_OUT_OF_RANGE;
            else if (add(s, &p) < 0) return;
        }
        if (!is_extended(e1[4]) || !rd32(e1 + 12)) return;
        ebr = ext_start + rd32(e1 + 8);
    }
}

static int scan_mbr(scan_t *s)
{
    const uint8_t *m = s->buf0;
    unsigned i;
    uint64_t ext_start = 0, ext_sectors = 0;
    for (i = 0; i < 4; ++i) {
        const uint8_t *e = m + 446 + 16 * i;
        blk_part_t p;
        if (!e[4] || !rd32(e + 12)) continue;
        if (is_extended(e[4])) {
            if (!ext_sectors) { ext_start = rd32(e + 8); ext_sectors = rd32(e + 12); }
            continue;
        }
        memset(&p, 0, sizeof p);
        p.start = rd32(e + 8);
        p.sectors = rd32(e + 12);
        p.scheme = PART_SCHEME_MBR;
        p.mbr_type = e[4];
        p.flags = (e[0] & 0x80) ? PARTF_BOOTABLE : 0;
        if (add(s, &p) < 0) return 1;
    }
    if (ext_sectors && ext_start < s->sectors)
        scan_ebr(s, ext_start, ext_sectors);
    return 1;
}

int blk_part_scan(blk_part_read_fn read, void *ctx, uint32_t sector_size, uint64_t sectors, void *scratch,
                  blk_part_t *out, unsigned max, uint32_t *notes)
{
    scan_t s;
    int protective = 0, other = 0, mbr_ok, i;
    if (!read || !scratch || !out || sector_size < 512 || (sector_size & (sector_size - 1)) || sectors < 2) {
        if (notes) *notes = 0;
        return -1;
    }
    memset(&s, 0, sizeof s);
    s.read = read; s.ctx = ctx; s.ss = sector_size; s.sectors = sectors;
    s.buf0 = scratch; s.buf1 = (uint8_t *)scratch + sector_size;
    s.out = out; s.max = max;
    if (read(ctx, 0, 1, s.buf0)) {
        s.notes |= PSCAN_READ_ERROR;
        if (notes) *notes = s.notes;
        return -1;
    }
    mbr_ok = rd16(s.buf0 + 510) == 0xaa55;
    if (mbr_ok) {
        s.notes |= PSCAN_MBR_VALID;
        for (i = 0; i < 4; ++i) {
            const uint8_t t = s.buf0[446 + 16 * i + 4];
            if (t == 0xee) protective = 1;
            else if (t) other = 1;
        }
        if (protective) s.notes |= PSCAN_PROTECTIVE_MBR;
    }
    /* A valid GPT wins (its header cannot be mistaken for random data: signature + CRC). */
    if (scan_gpt(&s)) {
        if (mbr_ok && other) s.notes |= PSCAN_HYBRID_MBR;      /* real MBR entries beside (or instead of) the 0xEE one */
        if (notes) *notes = s.notes;
        return (int)s.n;
    }
    if (!mbr_ok) {
        if (notes) *notes = s.notes;
        return -1;
    }
    if (protective) {                                   /* protective MBR but both GPT copies unusable: no partitions */
        if (notes) *notes = s.notes;
        return 0;
    }
    if (read(ctx, 0, 1, s.buf0)) { s.notes |= PSCAN_READ_ERROR; if (notes) *notes = s.notes; return -1; }
    scan_mbr(&s);
    if (notes) *notes = s.notes;
    return (int)s.n;
}
