/* SPDX-License-Identifier: GPL-2.0-only
 * Host unit tests of kernel64/sdhci.c against a register-level model of an SDHCI 3.00 controller (ADMA2 32-bit, PIO,
 * Auto CMD12) and of three cards: an SD 1.x standard-capacity card (no CMD8), an SD 2.00 high-capacity card and an
 * eMMC 4.5 device in sector mode. The eMMC case is the reason this exists: QEMU 8.2 (the version the guest runner
 * uses) has no eMMC model, so this is the only place the driver's CMD1 / host-assigned RCA / EXT_CSD / SWITCH path runs.
 * The card model follows the SD Physical Layer Simplified Specification 2.00 and JEDEC JESD84-B45 (command set, R1
 * status bits, CSD/CID/EXT_CSD field positions); it is written independently of the driver and checked by the test
 * (capacities, addressing mode, bus width, commands seen), not by the driver's own output.
 *
 * Memory: kernel "physical" pages come from an arena whose virtual->physical mapping is a fixed permutation in blocks,
 * so ADMA2 tables are built over physically discontiguous buffers (runs merged, runs split) exactly as in the kernel.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdhci_host_shim.h"

/* ---------------------------------------------------------------- host services for the driver */
#define ARENA_PAGES 1024u
#define ARENA_PA 0x10000000ull
static uint8_t *arena;
static unsigned perm[ARENA_PAGES], inv[ARENA_PAGES], next_page;
uint64_t phys_base_va;                                  /* p2v(): identity pages at the start of the permutation */

void kprintf(const char *fmt, ...)
{
    va_list ap;
    char buf[512];
    unsigned i, o = 0;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    for (i = 0; buf[i] && o < sizeof buf - 1; ++i) buf[o++] = buf[i];   /* the kernel %llu/%x set is printf-compatible */
    buf[o] = 0;
    fputs("    | ", stdout);
    fputs(buf, stdout);
}

static void *va_of_pa(uint64_t pa)
{
    const uint64_t off = pa - ARENA_PA;
    if (pa < ARENA_PA || off >= (uint64_t)ARENA_PAGES * 4096) return 0;
    return arena + (uint64_t)inv[off / 4096] * 4096 + off % 4096;
}

uint64_t blk_kva_to_pa(const void *kva)
{
    const uint8_t *p = kva;
    uint64_t off;
    if (p < arena || p >= arena + (uint64_t)ARENA_PAGES * 4096) return 0;
    off = (uint64_t)(p - arena);
    return ARENA_PA + (uint64_t)perm[off / 4096] * 4096 + off % 4096;
}

/* pmm_alloc() hands out single pages; the driver reaches them through p2v(), which in the kernel is phys_base_va + pa.
 * Pages it gets this way come from the first 64 arena pages, whose permutation entries are the identity. */
uint64_t pmm_alloc(void)
{
    const uint64_t pa = ARENA_PA + (uint64_t)next_page++ * 4096;
    if (next_page > 64) { fprintf(stderr, "pmm_alloc: test arena exhausted\n"); exit(2); }
    memset(va_of_pa(pa), 0, 4096);
    return pa;
}
void mutex_init(kmutex_t *m) { m->locked = 0; }
void mutex_lock(kmutex_t *m) { if (m->locked) { fprintf(stderr, "mutex_lock: already locked\n"); exit(2); } m->locked = 1; }
void mutex_unlock(kmutex_t *m) { m->locked = 0; }

/* ---------------------------------------------------------------- card model */
enum { C_SDSC_V1 = 0, C_SDHC = 1, C_EMMC = 2 };
enum { S_IDLE, S_READY, S_IDENT, S_STBY, S_TRAN, S_DATA, S_RCV, S_PRG };
#define R1_OUT_OF_RANGE (1u << 31)
#define R1_ADDRESS_ERROR (1u << 30)
#define R1_ILLEGAL (1u << 22)
#define R1_READY (1u << 8)
#define R1_APP_CMD (1u << 5)
#define R1_SWITCH_ERROR (1u << 7)

typedef struct {
    int type;
    int state, acmd, powered, busy_polls;
    uint32_t rca, ocr, status_err, blk_len;
    uint64_t capacity;                                  /* bytes */
    uint8_t *chunks[1u << 14];                          /* 1 MiB chunks, allocated on first write */
    uint8_t ext_csd[512];
    uint32_t csd[4], cid[4];                            /* 128-bit registers, word 0 = bits 31:0 */
    /* observations for the test */
    unsigned cmd_count[64], acmd_count[64];
    uint32_t last_arg[64];
    unsigned auto12;
} card_t;

static void set_bits(uint32_t *r, unsigned lo, unsigned len, uint32_t v)
{
    unsigned i;
    for (i = 0; i < len; ++i) {
        const unsigned b = lo + i;
        r[b / 32] = (r[b / 32] & ~(1u << (b % 32))) | (((v >> i) & 1u) << (b % 32));
    }
}

static void card_init(card_t *c, int type)
{
    unsigned i;
    for (i = 0; i < (1u << 14); ++i) free(c->chunks[i]);
    memset(c, 0, sizeof *c);
    c->type = type;
    c->blk_len = 512;
    if (type == C_SDSC_V1) {                            /* 16 MiB: (63+1) * 2^(7+2) * 2^9 */
        c->capacity = 16u << 20;
        set_bits(c->csd, 126, 2, 0); set_bits(c->csd, 80, 4, 9); set_bits(c->csd, 62, 12, 63); set_bits(c->csd, 47, 3, 7);
    } else if (type == C_SDHC) {                        /* 4 GiB: (8191+1) * 512 KiB */
        c->capacity = 4ull << 30;
        set_bits(c->csd, 126, 2, 1); set_bits(c->csd, 80, 4, 9); set_bits(c->csd, 48, 22, 8191);
    } else {                                            /* 8 GiB eMMC: CSD says "see EXT_CSD" (C_SIZE 0xFFF) */
        c->capacity = 8ull << 30;
        set_bits(c->csd, 126, 2, 3); set_bits(c->csd, 122, 4, 4); set_bits(c->csd, 80, 4, 9); set_bits(c->csd, 62, 12, 0xfff);
        set_bits(c->csd, 47, 3, 7);
        c->ext_csd[192] = 7;                            /* EXT_CSD_REV 1.7 (eMMC 5.0) */
        c->ext_csd[183] = 0;                            /* BUS_WIDTH 1 bit */
        {
            const uint32_t sec = (uint32_t)(c->capacity / 512);
            c->ext_csd[212] = (uint8_t)sec; c->ext_csd[213] = (uint8_t)(sec >> 8);
            c->ext_csd[214] = (uint8_t)(sec >> 16); c->ext_csd[215] = (uint8_t)(sec >> 24);
        }
    }
    {                                                   /* CID: PNM "SHZSD"/"SHZMMC" from bit 103 down, PSN */
        const char *pnm = type == C_EMMC ? "SHZMMC" : "SHZSD";
        for (i = 0; pnm[i]; ++i) set_bits(c->cid, 96 - 8 * i, 8, (uint8_t)pnm[i]);
        if (type == C_EMMC) set_bits(c->cid, 16, 32, 0x1234abcd); else set_bits(c->cid, 24, 32, 0x5678ef01);
    }
}

static uint8_t *card_byte(card_t *c, uint64_t addr, int alloc)
{
    const uint64_t k = addr >> 20;
    if (!c->chunks[k]) {
        if (!alloc) return 0;
        c->chunks[k] = calloc(1, 1u << 20);
    }
    return c->chunks[k] + (addr & ((1u << 20) - 1));
}

static int card_block_addr(const card_t *c) { return c->type == C_SDHC || c->type == C_EMMC; }

/* ---------------------------------------------------------------- controller model */
enum { NI_CMD = 1, NI_XFER = 2, NI_WRDY = 0x10, NI_RRDY = 0x20, NI_ERR = 0x8000 };
typedef struct {
    uint8_t r[256];
    card_t *card;
    /* data phase */
    int active, reading, dma;
    uint32_t blocks_left, bsize;
    uint64_t addr;                                      /* card byte address of the next block */
    uint8_t fifo[4096];
    unsigned fifo_pos;
    int inject_crc;                                     /* fail this many upcoming data transfers with a data CRC error */
    unsigned adma_descs, adma_xfers, pio_blocks;
    uint64_t now;
} hc_t;
static hc_t hc;

static uint16_t r16(unsigned o) { return (uint16_t)(hc.r[o] | (hc.r[o + 1] << 8)); }
static uint32_t r32(unsigned o) { return (uint32_t)r16(o) | ((uint32_t)r16(o + 2) << 16); }
static void w16(unsigned o, uint16_t v) { hc.r[o] = (uint8_t)v; hc.r[o + 1] = (uint8_t)(v >> 8); }
static void w32(unsigned o, uint32_t v) { w16(o, (uint16_t)v); w16(o + 2, (uint16_t)(v >> 16)); }
static void raise_ni(uint16_t b) { w16(0x30, r16(0x30) | (b & r16(0x34))); }
/* The error summary bit (normal status bit 15) is not gated by the normal status enables; it follows the enabled errors. */
static void raise_err(uint16_t e)
{
    w16(0x32, r16(0x32) | (e & r16(0x36)));
    if (r16(0x32)) w16(0x30, r16(0x30) | NI_ERR);
}

static uint32_t card_r1(card_t *c)
{
    const uint32_t r = c->status_err | ((uint32_t)(c->state == S_PRG ? S_TRAN : c->state) << 9) | R1_READY | (c->acmd ? R1_APP_CMD : 0);
    c->status_err = 0;
    return r;
}

/* Returns the response length (0 = no response, 4 = 48-bit, 16 = 136-bit); resp[0..3] as the host stores them. */
static int card_cmd(card_t *c, unsigned idx, uint32_t arg, uint32_t *resp)
{
    const int app = c->acmd;
    c->acmd = 0;
    if (app) { c->acmd_count[idx & 63]++; } else c->cmd_count[idx & 63]++;
    c->last_arg[idx & 63] = arg;
    if (app) {
        switch (idx) {
        case 41:
            if (c->state != S_IDLE) return 0;
            if (++c->busy_polls >= 3) {                 /* busy for two polls, then powered up */
                c->powered = 1;
                c->ocr = 0x80ff8000u | ((c->type == C_SDHC && (arg & 0x40000000u)) ? 0x40000000u : 0);
                c->state = S_READY;
            } else {
                c->ocr = 0x00ff8000u;
            }
            resp[0] = c->ocr;
            return 4;
        case 6:
            if (c->state != S_TRAN) return 0;
            resp[0] = card_r1(c);
            return 4;
        case 51:
            if (c->state != S_TRAN) return 0;
            resp[0] = card_r1(c);
            c->state = S_DATA;
            return 4;
        default:
            break;                                      /* not an ACMD: fall through as a normal command */
        }
    }
    switch (idx) {
    case 0: c->state = S_IDLE; c->busy_polls = 0; c->rca = 0; return 0;
    case 1:
        if (c->type != C_EMMC || c->state != S_IDLE) return 0;
        if (++c->busy_polls >= 3) { c->ocr = 0xc0ff8080u; c->state = S_READY; }   /* ready, sector mode */
        else c->ocr = 0x40ff8080u;
        resp[0] = c->ocr;
        return 4;
    case 8:
        if (c->type == C_SDHC && c->state == S_IDLE) { resp[0] = arg & 0xfff; return 4; }
        if (c->type == C_EMMC && c->state == S_TRAN) { resp[0] = card_r1(c); c->state = S_DATA; return 4; }
        return 0;                                       /* SD 1.x and eMMC in idle: no response */
    case 55:
        if (c->type == C_EMMC) return 0;
        if (c->state == S_READY || c->state == S_IDENT) return 0;
        if ((arg >> 16) != c->rca) return 0;
        c->acmd = 1;
        resp[0] = card_r1(c);
        return 4;
    case 2:
        if (c->state != S_READY) return 0;
        c->state = S_IDENT;
        memcpy(resp, c->cid, 16);
        return 16;
    case 3:
        if (c->state != S_IDENT) return 0;
        c->state = S_STBY;
        if (c->type == C_EMMC) { c->rca = arg >> 16; resp[0] = card_r1(c); return 4; }
        c->rca = 0xb368;
        resp[0] = (c->rca << 16) | 0x0500;
        return 4;
    case 9:
        if (c->state != S_STBY || (arg >> 16) != c->rca) return 0;
        memcpy(resp, c->csd, 16);
        return 16;
    case 7:
        if ((arg >> 16) != c->rca || c->state != S_STBY) return 0;
        c->state = S_TRAN;
        resp[0] = card_r1(c);
        return 4;
    case 6:                                             /* eMMC SWITCH (write byte) */
        if (c->type != C_EMMC || c->state != S_TRAN) return 0;
        if ((arg >> 24) == 3 && ((arg >> 16) & 0xff) == 183 && ((arg >> 8) & 0xff) <= 2) c->ext_csd[183] = (uint8_t)(arg >> 8);
        else c->status_err |= R1_SWITCH_ERROR;
        resp[0] = card_r1(c);
        return 4;
    case 13:
        if ((arg >> 16) != c->rca) return 0;
        resp[0] = card_r1(c);
        return 4;
    case 16:
        if (c->state != S_TRAN) return 0;
        c->blk_len = arg;
        resp[0] = card_r1(c);
        return 4;
    case 12:
        if (c->state == S_DATA || c->state == S_RCV) c->state = S_TRAN;
        resp[0] = card_r1(c);
        return 4;
    case 17: case 18: case 24: case 25: {
        const uint64_t addr = card_block_addr(c) ? (uint64_t)arg * 512 : arg;
        if (c->state != S_TRAN) return 0;
        if (addr + 512 > c->capacity) {
            c->status_err |= card_block_addr(c) ? R1_OUT_OF_RANGE : R1_ADDRESS_ERROR;
            resp[0] = card_r1(c);
            return 4;
        }
        c->state = idx < 20 ? S_DATA : S_RCV;
        resp[0] = card_r1(c);
        return 4;
    }
    default:
        c->status_err |= R1_ILLEGAL;
        return 0;
    }
}

/* One block from the card for the current data command (zeros when the card is not sending). */
static void card_read_block(card_t *c, unsigned idx, uint64_t addr, uint8_t *out, unsigned n)
{
    unsigned i;
    if (c->state != S_DATA) { memset(out, 0, n); return; }
    if (idx == 8) { memcpy(out, c->ext_csd, n); return; }
    if (idx == 51) { static const uint8_t scr[8] = { 0x02, 0x35, 0x80, 0x00, 0, 0, 0, 0 }; memcpy(out, scr, n); return; }
    for (i = 0; i < n; ++i) { const uint8_t *p = card_byte(c, addr + i, 0); out[i] = p ? *p : 0; }
}

static void card_write_block(card_t *c, uint64_t addr, const uint8_t *in, unsigned n)
{
    unsigned i;
    if (c->state != S_RCV) return;
    for (i = 0; i < n; ++i) *card_byte(c, addr + i, 1) = in[i];
}

static unsigned cur_idx;

static void end_transfer(void)
{
    uint32_t dummy[4];
    if (!(r16(0x0c) & 0x20)) hc.card->state = S_TRAN;                          /* single block: card returns by itself */
    else if (r16(0x0c) & 4) { card_cmd(hc.card, 12, 0, dummy); hc.card->auto12++; }   /* Auto CMD12 */
    hc.active = 0;
    raise_ni(NI_XFER);
}

static int maybe_inject(void)
{
    if (!hc.inject_crc) return 0;
    --hc.inject_crc;
    hc.active = 0;
    raise_err(0x20);                                    /* data CRC */
    return 1;
}

static void adma_run(void)
{
    uint64_t desc = r32(0x58);
    unsigned guard;
    for (guard = 0; guard < 4096 && hc.blocks_left; ++guard) {
        const uint32_t *d = va_of_pa(desc);
        uint32_t attr, len, addr, done = 0;
        if (!d) { raise_err(0x200); hc.active = 0; return; }
        attr = d[0] & 0xffff; len = d[0] >> 16; addr = d[1];
        if (!len) len = 65536;
        ++hc.adma_descs;
        if (!(attr & 1)) { raise_err(0x200); hc.active = 0; return; }
        if ((attr & 0x30) == 0x20) {
            while (done < len && hc.blocks_left) {
                uint8_t *mem = va_of_pa(addr + done);
                if (!mem || len - done < hc.bsize) { raise_err(0x200); hc.active = 0; return; }   /* run not block-aligned */
                if (hc.reading) card_read_block(hc.card, cur_idx, hc.addr, mem, hc.bsize);
                else card_write_block(hc.card, hc.addr, mem, hc.bsize);
                hc.addr += hc.bsize;
                done += hc.bsize;
                --hc.blocks_left;
            }
        }
        if (attr & 2) break;                            /* end */
        desc += 8;
    }
    ++hc.adma_xfers;
    end_transfer();
}

static void pio_next(void)
{
    if (!hc.blocks_left) { end_transfer(); return; }
    if (hc.reading) { card_read_block(hc.card, cur_idx, hc.addr, hc.fifo, hc.bsize); raise_ni(NI_RRDY); }
    else raise_ni(NI_WRDY);
    hc.fifo_pos = 0;
}

static void do_command(void)
{
    const uint16_t cmd = r16(0x0e), tm = r16(0x0c);
    const unsigned idx = cmd >> 8, type = cmd & 3;
    uint32_t resp[4] = { 0, 0, 0, 0 };
    const int n = card_cmd(hc.card, idx, r32(0x08), resp);
    cur_idx = idx;
    if (type && !n) { raise_err(1); raise_ni(NI_CMD); return; }                  /* command timeout */
    if (n == 16) {                                      /* store bits 127:8 */
        w32(0x10, (resp[0] >> 8) | (resp[1] << 24)); w32(0x14, (resp[1] >> 8) | (resp[2] << 24));
        w32(0x18, (resp[2] >> 8) | (resp[3] << 24)); w32(0x1c, resp[3] >> 8);
    } else {
        w32(0x10, resp[0]);
    }
    raise_ni(NI_CMD);
    if (type == 3) raise_ni(NI_XFER);
    if (!(cmd & 0x20)) return;
    hc.active = 1;
    hc.reading = (tm & 0x10) != 0;
    hc.dma = tm & 1;
    hc.bsize = r16(0x04) & 0xfff;
    hc.blocks_left = (tm & 0x20) ? r16(0x06) : 1;
    hc.addr = card_block_addr(hc.card) ? (uint64_t)r32(0x08) * 512 : r32(0x08);
    if (maybe_inject()) return;
    if (hc.dma) {
        if (((hc.r[0x28] >> 3) & 3) != 2) { raise_err(0x200); hc.active = 0; return; }
        adma_run();
    } else {
        pio_next();
    }
}

uint32_t mock_read(volatile uint8_t *regs, unsigned off, unsigned size)
{
    (void)regs;
    hc.now += 1;
    if (off == 0x20 && size == 4 && hc.active && hc.reading && !hc.dma) {
        uint32_t v;
        memcpy(&v, hc.fifo + hc.fifo_pos, 4);
        hc.fifo_pos += 4;
        if (hc.fifo_pos >= hc.bsize) { --hc.blocks_left; hc.addr += hc.bsize; ++hc.pio_blocks; pio_next(); }
        return v;
    }
    if (off == 0x24) {                                  /* present state: card inserted, write enabled, lines idle */
        w32(0x24, (1u << 16) | (1u << 17) | (1u << 18) | (1u << 19) | (hc.active ? 2u : 0u));
    }
    return size == 1 ? hc.r[off] : size == 2 ? r16(off) : r32(off);
}

void mock_write(volatile uint8_t *regs, unsigned off, uint32_t v, unsigned size)
{
    unsigned i;
    (void)regs;
    hc.now += 1;
    if (off == 0x20 && size == 4 && hc.active && !hc.reading && !hc.dma) {
        memcpy(hc.fifo + hc.fifo_pos, &v, 4);
        hc.fifo_pos += 4;
        if (hc.fifo_pos >= hc.bsize) {
            card_write_block(hc.card, hc.addr, hc.fifo, hc.bsize);
            --hc.blocks_left; hc.addr += hc.bsize; ++hc.pio_blocks;
            pio_next();
        }
        return;
    }
    if ((off == 0x30 || off == 0x32) && size == 2) {                            /* W1C; ERR clears with the error bits */
        w16(off, r16(off) & ~(uint16_t)(off == 0x30 ? v & 0x7fff : v));
        if (!r16(0x32)) w16(0x30, r16(0x30) & 0x7fff);
        return;
    }
    if (off == 0x2f && size == 1) {                     /* software reset */
        if (v & 1) {
            uint8_t caps[8];
            memcpy(caps, hc.r + 0x40, 8);
            memset(hc.r, 0, 0xfc);
            memcpy(hc.r + 0x40, caps, 8);
        }
        if (v & 4) hc.active = 0;
        if (v & 2) w16(0x30, r16(0x30) & ~NI_CMD);
        hc.r[0x2f] = 0;
        return;
    }
    for (i = 0; i < size; ++i) hc.r[off + i] = (uint8_t)(v >> (8 * i));
    if (off == 0x2c && size == 2 && (v & 1)) hc.r[0x2c] |= 2;                    /* internal clock stable */
    if (off == 0x0e && size == 2) do_command();
}

uint64_t mock_now_us(void) { return hc.now; }
void mock_relax(void) { hc.now += 10; }

/* ---------------------------------------------------------------- tests */
static int failures, checks;
#define CHECK(cond, ...) do { ++checks; if (cond) { printf("PASS: "); printf(__VA_ARGS__); printf("\n"); } \
                              else { ++failures; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void reset_model(card_t *c)
{
    memset(&hc, 0, sizeof hc);
    hc.card = c;
    w32(0x40, (1u << 24) | (1u << 21) | (1u << 19) | (50u << 8) | 0x80 | 50u);   /* 3.3 V, HS, ADMA2, 50 MHz base */
    w16(0xfe, 0x0002);                                  /* SDHCI 3.00 */
}

static uint8_t *arena_buf(unsigned first_page) { return arena + (uint64_t)first_page * 4096; }

static void data_tests(const char *what, blk_dev_t *d, card_t *c)
{
    uint8_t *w = arena_buf(200), *r = arena_buf(400);   /* 150 pages each: spans several permutation blocks */
    const unsigned n = 300;                             /* sectors (150 KiB) */
    const uint64_t lba = d->sectors - 2000;
    uint64_t out[4];
    unsigned i, a0, s0;
    for (i = 0; i < n * 512; ++i) w[i] = (uint8_t)(i * 7 + (i >> 9) + 3);
    a0 = hc.adma_xfers;
    CHECK(d->write(d, lba, n, w) == 0, "%s: ADMA2 multi-block write of %u sectors at %llu", what, n, (unsigned long long)lba);
    CHECK(c->cmd_count[25] >= 1 && c->auto12 >= 1, "%s: CMD25 with Auto CMD12 (%u CMD25, %u auto CMD12)", what, c->cmd_count[25], c->auto12);
    {
        const uint8_t *p = card_byte(c, lba * 512 + 12345, 0);
        CHECK(p && *p == w[12345], "%s: the card holds the written bytes at the right address", what);
        CHECK(c->last_arg[25] == (card_block_addr(c) ? (uint32_t)lba : (uint32_t)(lba * 512)), "%s: %s addressing in the CMD25 argument (%x)",
              what, card_block_addr(c) ? "block" : "byte", c->last_arg[25]);
    }
    memset(r, 0, n * 512);
    CHECK(d->read(d, lba, n, r) == 0 && !memcmp(w, r, n * 512), "%s: ADMA2 read back identical", what);
    CHECK(hc.adma_xfers - a0 == 2 && hc.adma_descs > 2, "%s: two ADMA2 transfers, %u descriptors so far (discontiguous pages)", what, hc.adma_descs);
    CHECK(d->control(d, BLK_CTL_XFER_MODE, 1, out) == 0 && out[0] == 0, "%s: PIO forced", what);
    s0 = hc.pio_blocks;
    memset(r, 0, n * 512);
    CHECK(d->read(d, lba, n, r) == 0 && !memcmp(w, r, n * 512) && hc.pio_blocks - s0 == n, "%s: PIO read of %u blocks identical", what, n);
    for (i = 0; i < 8 * 512; ++i) w[i] ^= 0xff;
    CHECK(d->write(d, lba + 1, 8, w) == 0, "%s: PIO write of 8 blocks", what);
    d->control(d, BLK_CTL_XFER_MODE, 0, out);
    CHECK(d->read(d, lba + 1, 8, r) == 0 && !memcmp(w, r, 8 * 512), "%s: PIO-written blocks read back via ADMA2", what);
    CHECK(d->read(d, 7, 1, r) == 0, "%s: single-block read (CMD17)", what);
    CHECK(c->cmd_count[17] >= 1, "%s: CMD17 used for one block", what);
    /* transient data CRC error: one retry fixes it */
    hc.inject_crc = 1;
    memset(r, 0, 16 * 512);
    CHECK(d->read(d, lba, 16, r) == 0 && !memcmp(w, r + 512, 8 * 512), "%s: read survives one injected data CRC error (retry)", what);
    CHECK(c->state == S_TRAN, "%s: card back in the transfer state after the retry", what);
    /* persistent errors: the request fails, the card stays usable */
    hc.inject_crc = 2;
    CHECK(d->read(d, lba, 16, r) != 0, "%s: read fails after the retry also fails", what);
    CHECK(d->read(d, lba, 16, r) == 0, "%s: next read works again", what);
    /* out-of-range command */
    memset(out, 0, sizeof out);
    CHECK(d->control(d, BLK_CTL_ERROR_TEST, 0, out) == 0 && (out[1] & 0xc0000000u), "%s: read past the end rejected by the card "
          "(R1 %llx), card recovered (status %llx)", what, (unsigned long long)out[1], (unsigned long long)out[2]);
}

int main(void)
{
    card_t *c = calloc(1, sizeof *c);
    blk_dev_t *d;
    unsigned i;
    arena = aligned_alloc(4096, (size_t)ARENA_PAGES * 4096);
    for (i = 0; i < ARENA_PAGES; ++i) perm[i] = i;
    for (i = 64; i + 8 <= ARENA_PAGES; i += 8) {        /* blocks of 8 pages: 3 contiguous, then a jump, reversed tail */
        const unsigned b = i;
        perm[b + 0] = b + 5; perm[b + 1] = b + 6; perm[b + 2] = b + 7;
        perm[b + 3] = b + 0; perm[b + 4] = b + 1; perm[b + 5] = b + 4; perm[b + 6] = b + 3; perm[b + 7] = b + 2;
    }
    for (i = 0; i < ARENA_PAGES; ++i) inv[perm[i]] = i;
    phys_base_va = (uint64_t)arena - ARENA_PA;

    /* SD 2.00 high capacity */
    card_init(c, C_SDHC);
    reset_model(c);
    CHECK(sdhci_host_test_probe(hc.r, &d) == 0, "SDHC: card initialised");
    CHECK(d->sectors == (4ull << 30) / 512, "SDHC: capacity from CSD 2.0 = %llu sectors", (unsigned long long)d->sectors);
    CHECK(c->cmd_count[8] == 1 && c->acmd_count[41] >= 3 && (c->last_arg[41] & 0x40000000u), "SDHC: CMD8 answered, ACMD41 with HCS polled until ready");
    CHECK(c->acmd_count[6] == 1 && c->last_arg[6] == 2 && (hc.r[0x28] & 2), "SDHC: ACMD6 4-bit bus and host control 4-bit");
    CHECK(!strcmp(d->model, "SHZSD") && !strcmp(d->serial, "5678ef01"), "SDHC: CID product name and serial (%s, %s)", d->model, d->serial);
    CHECK(c->acmd_count[51] == 1, "SDHC: SCR read with ACMD51");
    data_tests("SDHC", d, c);

    /* SD 1.x standard capacity: no CMD8 response */
    card_init(c, C_SDSC_V1);
    reset_model(c);
    CHECK(sdhci_host_test_probe(hc.r, &d) == 0, "SDSC 1.x: card initialised after the CMD8 timeout");
    CHECK(d->sectors == (16u << 20) / 512, "SDSC: capacity from CSD 1.0 = %llu sectors", (unsigned long long)d->sectors);
    CHECK(!(c->last_arg[41] & 0x40000000u), "SDSC 1.x: ACMD41 without HCS");
    data_tests("SDSC", d, c);

    /* eMMC */
    card_init(c, C_EMMC);
    reset_model(c);
    CHECK(sdhci_host_test_probe(hc.r, &d) == 0, "eMMC: device initialised through CMD1");
    CHECK(c->cmd_count[55] >= 1 && c->cmd_count[1] >= 3 && c->last_arg[1] == 0x40ff8080u, "eMMC: CMD55 unanswered, CMD1 (sector mode) polled until ready");
    CHECK(c->rca == 1 && c->cmd_count[3] == 1, "eMMC: host-assigned RCA 1 through CMD3");
    CHECK(c->cmd_count[8] >= 1 && d->sectors == (8ull << 30) / 512, "eMMC: capacity from EXT_CSD SEC_COUNT = %llu sectors (CSD says 1 GiB)",
          (unsigned long long)d->sectors);
    CHECK(c->ext_csd[183] == 1 && (hc.r[0x28] & 2), "eMMC: SWITCH BUS_WIDTH=4 bit, host control 4-bit");
    CHECK(!strcmp(d->model, "SHZMMC") && !strcmp(d->serial, "1234abcd"), "eMMC: CID product name and serial (%s, %s)", d->model, d->serial);
    data_tests("eMMC", d, c);

    printf("test_sdhci: %d checks, %d failed\n", checks, failures);
    for (i = 0; i < (1u << 14); ++i) free(c->chunks[i]);
    free(c);
    free(arena);
    return failures ? 1 : 0;
}
