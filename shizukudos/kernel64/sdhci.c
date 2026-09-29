/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 SD / eMMC driver over a PCI SD Host Controller (SDHCI 2.00/3.00, class 08:05), one block device per card
 * ("mmcblk<n>") in the generic registry (blk.h). STANDALONE PROFILE ONLY: under the Supervisor no device is passed
 * through, so sdhci_blk_init() finds nothing there. QEMU fixture: -device sdhci-pci -device sd-card,drive=..
 * (tests/run_k64_storage.py; one card per controller).
 *
 * Host bring-up: software reset (all), capabilities (base clock, voltages, ADMA2/SDMA, version), bus power at the
 * highest supported voltage, SD clock at <= 400 kHz for identification, every normal/error status enabled (signals off:
 * completion is polled, see below), data timeout at its maximum.
 *
 * Card identification (Physical Layer Simplified Spec 2.00 / JEDEC eMMC 4.x):
 *   CMD0 -> CMD8(0x1AA) [R7 echo: SD 2.00+] -> CMD55+ACMD41 (HCS when CMD8 answered) until OCR busy=1
 *        -> CMD2 (CID) -> CMD3 (SD: card publishes the RCA) -> CMD9 (CSD) -> CMD7 select -> ACMD6 4-bit bus
 *        -> CMD16 512 -> ACMD51 (SCR, spec version) -> 25 MHz.
 *   No answer to CMD55 -> MMC: CMD0 -> CMD1(0x40FF8080, sector mode) until busy=1 -> CMD2 -> CMD3 (host assigns
 *        RCA 1) -> CMD9 -> CMD7 -> CMD8 SEND_EXT_CSD (512 bytes) -> SWITCH(BUS_WIDTH=4 bit) -> CMD16 -> 26 MHz.
 *   Capacity: SD CSD 1.0 (SDSC, byte addressed): (C_SIZE+1) * 2^(C_SIZE_MULT+2) * 2^READ_BL_LEN; CSD 2.0 (SDHC/SDXC,
 *   block addressed, OCR.CCS=1): (C_SIZE+1) * 512 KiB; eMMC: EXT_CSD SEC_COUNT (sector mode) else the CSD formula.
 *   QEMU 8.2 models SD cards only (its "emmc" device arrived in QEMU 9.1), so the MMC branch is written to the JEDEC
 *   spec and exercised only by tests/run_sdhci_host.py's register-level eMMC model, not by a QEMU run.
 *
 * Data: CMD17/CMD18 read, CMD24/CMD25 write, 512-byte blocks, multi-block with Auto CMD12. Transport: ADMA2 with
 * 32-bit descriptors (one per physically contiguous run, <= 32 KiB each; a transfer is <= 1 MiB, the table is one
 * page) when the controller has ADMA2 and the buffer is 4-byte aligned below 4 GiB, else PIO through the buffer data
 * port. BLK_CTL_XFER_MODE forces PIO to test both. After every data command the R1 card status error bits are checked.
 *
 * Errors: a controller error status (command timeout/CRC/end-bit/index, data timeout/CRC/end-bit, Auto CMD12, ADMA)
 * or an R1 error bit fails the command; the driver then resets the CMD/DAT lines, sends CMD12 when a multi-block
 * transfer was open, reads the card state with CMD13 and retries the transfer once. Transfers have a deadline of
 * timeout_ms (default 2000 ms + 1 ms per 64 KiB). BLK_CTL_ERROR_TEST issues a read beyond the card's end on purpose.
 * Completion is polled (yielding to other threads when the scheduler runs): QEMU completes a command inside the
 * register write and an ADMA2 table in steps of 5 descriptors 100 ns apart, so an interrupt would only add latency;
 * the interrupt signal enables stay 0 and no INTx line is claimed.
 * Limits: one slot per controller, no UHS-I/HS200 tuning, no CMD23, no SDIO, no card-detect hot plug (a card removed
 * while mounted fails its I/O), no eMMC boot/RPMB partitions.
 */
#ifdef SDHCI_HOST_TEST
#include "sdhci_host_shim.h"                            /* tests/: host build against a register-level card model */
#else
#include "blk.h"
#include "pci.h"
#endif

#if !defined(SHZ_STANDALONE) && !defined(SDHCI_HOST_TEST)
int sdhci_blk_init(void) { return 0; }                  /* Supervisor profile: no passed-through controller */
#else

#define SD_MAX_HOSTS 4
#define SD_MAX_XFER_SECTORS 2048u                       /* 1 MiB per command */
#define SD_DESC_MAX_LEN 0x8000u

/* SDHCI registers */
enum {
    R_SDMA = 0x00, R_BLKSIZE = 0x04, R_BLKCNT = 0x06, R_ARG = 0x08, R_TRNMOD = 0x0c, R_CMD = 0x0e, R_RESP0 = 0x10,
    R_RESP1 = 0x14, R_RESP2 = 0x18, R_RESP3 = 0x1c, R_DATA = 0x20, R_PRNSTS = 0x24, R_HOSTCTL = 0x28, R_PWRCTL = 0x29,
    R_CLKCTL = 0x2c, R_TIMEOUT = 0x2e, R_SWRST = 0x2f, R_NORINT = 0x30, R_ERRINT = 0x32, R_NORINTEN = 0x34,
    R_ERRINTEN = 0x36, R_NORSIGEN = 0x38, R_ERRSIGEN = 0x3a, R_ACMD12ERR = 0x3c, R_HOSTCTL2 = 0x3e, R_CAPS = 0x40,
    R_CAPS_HI = 0x44, R_ADMAERR = 0x54, R_ADMAADDR = 0x58, R_ADMAADDR_HI = 0x5c, R_VERSION = 0xfe
};
enum { TM_DMA = 1, TM_BLKCNT = 2, TM_ACMD12 = 4, TM_READ = 0x10, TM_MULTI = 0x20 };
enum { CMD_RESP_NONE = 0, CMD_RESP_136 = 1, CMD_RESP_48 = 2, CMD_RESP_48B = 3, CMD_CRC = 8, CMD_IDX = 0x10, CMD_DATA = 0x20 };
enum { NI_CMD = 1, NI_XFER = 2, NI_DMA = 8, NI_WRDY = 0x10, NI_RRDY = 0x20, NI_ERR = 0x8000 };
enum { EI_CMD_TIMEOUT = 1, EI_CMD_CRC = 2, EI_CMD_END = 4, EI_CMD_IDX = 8, EI_DAT_TIMEOUT = 0x10, EI_DAT_CRC = 0x20,
       EI_DAT_END = 0x40, EI_ACMD12 = 0x100, EI_ADMA = 0x200 };
enum { PS_CMD_INHIBIT = 1, PS_DAT_INHIBIT = 2, PS_CARD_IN = 1u << 16, PS_WP = 1u << 19 };
enum { RST_ALL = 1, RST_CMD = 2, RST_DAT = 4 };
/* response kinds */
enum { RSP_NONE = CMD_RESP_NONE, RSP_R1 = CMD_RESP_48 | CMD_CRC | CMD_IDX, RSP_R1B = CMD_RESP_48B | CMD_CRC | CMD_IDX,
       RSP_R2 = CMD_RESP_136 | CMD_CRC, RSP_R3 = CMD_RESP_48, RSP_R6 = CMD_RESP_48 | CMD_CRC | CMD_IDX,
       RSP_R7 = CMD_RESP_48 | CMD_CRC | CMD_IDX };
#define R1_ERRORS 0xfdf98008u                           /* OUT_OF_RANGE .. ERROR, CSD_OVERWRITE, WP_ERASE_SKIP, AKE_SEQ */
#define R1_STATE(r) (((r) >> 9) & 0xf)
enum { SD_OK = 0, SD_ETIMEDOUT = -1, SD_EIO = -2, SD_ECARD = -3 };
enum { KIND_SDSC = 0, KIND_SDHC = 1, KIND_MMC = 2 };
static const char *const kind_names[3] = { "SDSC", "SDHC/SDXC", "eMMC" };

typedef struct {
    blk_dev_t dev;
    unsigned idx;
    pci_dev_t pci;
    volatile uint8_t *r;
    uint32_t caps, caps_hi, base_khz, clock_khz;
    uint16_t version;                                   /* spec version field of the host controller version register */
    int adma, force_pio, kind, block_addr, bus4;
    uint32_t rca, ocr, cid[4], csd[4], scr_hi;
    uint32_t timeout_ms;
    uint32_t *desc;                                     /* ADMA2 descriptor table (one page) */
    uint64_t desc_pa;
    uint8_t *bounce;                                    /* one page: SCR / EXT_CSD / misaligned sectors */
    uint64_t bounce_pa;
    kmutex_t lock;
    uint8_t ext_csd_rev, mmc_bus_width;
    uint64_t cmds, adma_xfers, pio_xfers, errors, retries, line_resets, timeouts;
    uint32_t last_err, last_r1;
} sd_host_t;

static sd_host_t hosts[SD_MAX_HOSTS];
static unsigned nhosts;

/* ---------------------------------------------------------------- register access and time */
#ifndef SDHCI_HOST_TEST
static inline uint8_t rd8(sd_host_t *h, unsigned o) { return *(volatile uint8_t *)(h->r + o); }
static inline uint16_t rd16(sd_host_t *h, unsigned o) { return *(volatile uint16_t *)(h->r + o); }
static inline uint32_t rd32(sd_host_t *h, unsigned o) { return *(volatile uint32_t *)(h->r + o); }
static inline void wr8(sd_host_t *h, unsigned o, uint8_t v) { *(volatile uint8_t *)(h->r + o) = v; }
static inline void wr16(sd_host_t *h, unsigned o, uint16_t v) { *(volatile uint16_t *)(h->r + o) = v; }
static inline void wr32(sd_host_t *h, unsigned o, uint32_t v) { *(volatile uint32_t *)(h->r + o) = v; }
static inline uint64_t now_us(void) { uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); return (((uint64_t)hi << 32) | lo) / 1000u; }
static int can_sleep(void)
{
    uint64_t f;
    __asm__ volatile("pushfq; popq %0" : "=r"(f));
    return (f & 0x200) && thread_current();
}
static void relax(void) { if (can_sleep()) thread_yield(); else __asm__ volatile("pause" ::: "memory"); }
#else
static inline uint8_t rd8(sd_host_t *h, unsigned o) { return (uint8_t)mock_read(h->r, o, 1); }
static inline uint16_t rd16(sd_host_t *h, unsigned o) { return (uint16_t)mock_read(h->r, o, 2); }
static inline uint32_t rd32(sd_host_t *h, unsigned o) { return mock_read(h->r, o, 4); }
static inline void wr8(sd_host_t *h, unsigned o, uint8_t v) { mock_write(h->r, o, v, 1); }
static inline void wr16(sd_host_t *h, unsigned o, uint16_t v) { mock_write(h->r, o, v, 2); }
static inline void wr32(sd_host_t *h, unsigned o, uint32_t v) { mock_write(h->r, o, v, 4); }
static inline uint64_t now_us(void) { return mock_now_us(); }
static void relax(void) { mock_relax(); }
#endif

static int wait_clear(sd_host_t *h, unsigned reg, uint32_t mask, uint32_t ms)
{
    const uint64_t t0 = now_us();
    while (rd32(h, reg) & mask) {
        if (now_us() - t0 > (uint64_t)ms * 1000u) return SD_ETIMEDOUT;
        relax();
    }
    return SD_OK;
}

static int host_reset(sd_host_t *h, uint8_t what)
{
    wr8(h, R_SWRST, what);
    if (wait_clear(h, R_SWRST & ~3u, (uint32_t)what << 24, 100)) {
        kprintf("K64 sdhci%u: software reset %x did not complete\n", h->idx, what);
        return SD_ETIMEDOUT;
    }
    if (what != RST_ALL) ++h->line_resets;
    return SD_OK;
}

/* SD clock: SDHCI 2.00 divides the base clock by a power of two (field = div/2), 3.00 by 2N (10-bit N). */
static int set_clock(sd_host_t *h, uint32_t khz)
{
    uint32_t field, div = 1;
    uint16_t v;
    const uint64_t t0 = now_us();
    wr16(h, R_CLKCTL, 0);
    if (h->version >= 2) {                              /* 3.00 */
        uint32_t n = (h->base_khz + 2 * khz - 1) / (2 * khz);
        if (h->base_khz <= khz) n = 0;
        if (n > 0x3ff) n = 0x3ff;
        field = ((n & 0xff) << 8) | ((n >> 8) << 6);
        div = n ? 2 * n : 1;
    } else {
        while (div < 256 && h->base_khz / div > khz) div <<= 1;
        field = (div >> 1) << 8;
    }
    wr16(h, R_CLKCTL, (uint16_t)(field | 1));           /* internal clock enable */
    while (!((v = rd16(h, R_CLKCTL)) & 2)) {            /* internal clock stable */
        if (now_us() - t0 > 20000) { kprintf("K64 sdhci%u: internal clock not stable\n", h->idx); return SD_ETIMEDOUT; }
        relax();
    }
    wr16(h, R_CLKCTL, (uint16_t)(v | 4));               /* SD clock enable */
    h->clock_khz = h->base_khz / div;
    return SD_OK;
}

/* ---------------------------------------------------------------- commands */
static void clear_status(sd_host_t *h) { wr16(h, R_NORINT, 0xffff); wr16(h, R_ERRINT, 0xffff); }

/* Error path shared by commands and transfers: record, reset the lines, clear the status. */
static int fail(sd_host_t *h, uint16_t err, int data, const char *what)
{
    h->last_err = err;
    ++h->errors;
    if (err & (EI_CMD_TIMEOUT | EI_DAT_TIMEOUT)) ++h->timeouts;
    if (err & EI_ADMA) kprintf("K64 sdhci%u: %s: ADMA error, state %x at %x\n", h->idx, what, rd32(h, R_ADMAERR), rd32(h, R_ADMAADDR));
    host_reset(h, RST_CMD);
    if (data) host_reset(h, RST_DAT);
    clear_status(h);
    return (err & (EI_CMD_TIMEOUT | EI_DAT_TIMEOUT)) ? SD_ETIMEDOUT : SD_EIO;
}

/* Issues one command; for data commands the caller has programmed block size/count and TRNMOD. resp gets 1 dword
 * (R1/R3/R6/R7) or 4 (R2: bits 127:8 of CID/CSD, right-aligned as the controller stores them). */
static int sd_cmd(sd_host_t *h, unsigned idx, uint32_t arg, unsigned flags, uint32_t *resp)
{
    const uint32_t inhibit = PS_CMD_INHIBIT | (((flags & CMD_DATA) || (flags & 3) == CMD_RESP_48B) ? PS_DAT_INHIBIT : 0);
    uint64_t t0;
    uint16_t ni;
    if (wait_clear(h, R_PRNSTS, inhibit, 500)) {
        kprintf("K64 sdhci%u: CMD%u: lines busy (present state %x)\n", h->idx, idx, rd32(h, R_PRNSTS));
        host_reset(h, RST_CMD);
        host_reset(h, RST_DAT);
    }
    clear_status(h);
    ++h->cmds;
    wr32(h, R_ARG, arg);
    wr16(h, R_CMD, (uint16_t)((idx << 8) | (flags & 0x3f)));
    t0 = now_us();
    for (;;) {
        ni = rd16(h, R_NORINT);
        if (ni & (NI_CMD | NI_ERR)) break;
        if (now_us() - t0 > 1000000) { kprintf("K64 sdhci%u: CMD%u: no completion\n", h->idx, idx); return fail(h, EI_CMD_TIMEOUT, 1, "cmd"); }
        relax();
    }
    if (ni & NI_ERR) {
        const uint16_t e = rd16(h, R_ERRINT);
        if (e & 0x000f) return fail(h, e, (flags & CMD_DATA) != 0, "cmd");   /* command-phase error */
    }
    wr16(h, R_NORINT, NI_CMD);
    if (resp) {
        if ((flags & 3) == CMD_RESP_136) {
            resp[0] = rd32(h, R_RESP0); resp[1] = rd32(h, R_RESP1); resp[2] = rd32(h, R_RESP2); resp[3] = rd32(h, R_RESP3);
        } else {
            resp[0] = rd32(h, R_RESP0);
        }
    }
    if ((flags & 3) == CMD_RESP_48B) {                  /* busy on DAT0: transfer complete, or DAT inhibit released */
        t0 = now_us();
        while (!(rd16(h, R_NORINT) & (NI_XFER | NI_ERR)) && (rd32(h, R_PRNSTS) & PS_DAT_INHIBIT)) {
            if (now_us() - t0 > (uint64_t)h->timeout_ms * 1000u) return fail(h, EI_DAT_TIMEOUT, 1, "busy");
            relax();
        }
        if (rd16(h, R_NORINT) & NI_ERR) return fail(h, rd16(h, R_ERRINT), 1, "busy");
        wr16(h, R_NORINT, NI_XFER);
    }
    return SD_OK;
}

static int app_cmd(sd_host_t *h, unsigned idx, uint32_t arg, unsigned flags, uint32_t *resp)
{
    uint32_t r1;
    int rc = sd_cmd(h, 55, h->rca << 16, RSP_R1, &r1);
    if (rc) return rc;
    if (!(r1 & (1u << 5))) return SD_ECARD;             /* APP_CMD not acknowledged */
    return sd_cmd(h, idx, arg, flags, resp);
}

/* CSD/CID bit field [lo, lo+len) of the 128-bit register (the controller drops bits 7:0, the CRC). */
static uint32_t bits128(const uint32_t *r, unsigned lo, unsigned len)
{
    uint32_t v = 0;
    unsigned i;
    for (i = 0; i < len; ++i) {
        const unsigned b = lo + i - 8;
        v |= ((r[b / 32] >> (b % 32)) & 1u) << i;
    }
    return v;
}

/* ---------------------------------------------------------------- data transfers */
/* Builds the ADMA2 table for [buf, buf+bytes); 0 when every run is 4-byte aligned below 4 GiB and fits the table. */
static int adma_table(sd_host_t *h, const void *buf, uint32_t bytes)
{
    uint64_t va = (uint64_t)buf;
    unsigned n = 0;
    while (bytes) {
        const uint64_t pa = blk_kva_to_pa((const void *)va);
        uint32_t run = (uint32_t)(PAGE_SIZE - (va & 0xfff));
        if (run > bytes) run = bytes;
        if (!pa || (pa & 3) || pa + run > 0x100000000ull) return -1;
        if (n && (uint64_t)h->desc[2 * (n - 1) + 1] + (h->desc[2 * (n - 1)] >> 16) == pa &&
            (h->desc[2 * (n - 1)] >> 16) + run <= SD_DESC_MAX_LEN) {
            h->desc[2 * (n - 1)] += run << 16;          /* physically contiguous with the previous run: extend it */
        } else {
            if (n >= PAGE_SIZE / 8) return -1;
            h->desc[2 * n] = (run << 16) | 0x21;        /* length, ACT=tran, valid */
            h->desc[2 * n + 1] = (uint32_t)pa;
            ++n;
        }
        va += run;
        bytes -= run;
    }
    if (!n) return -1;
    h->desc[2 * (n - 1)] |= 2;                          /* end */
    return 0;
}

/* PIO: moves `blocks` blocks of `bsize` bytes through the buffer data port. */
static int pio_move(sd_host_t *h, int write, uint8_t *p, unsigned blocks, unsigned bsize)
{
    unsigned b, i;
    for (b = 0; b < blocks; ++b) {
        const uint16_t want = write ? NI_WRDY : NI_RRDY;
        const uint64_t t0 = now_us();
        uint16_t ni;
        for (;;) {
            ni = rd16(h, R_NORINT);
            if (ni & (want | NI_ERR)) break;
            if (now_us() - t0 > (uint64_t)h->timeout_ms * 1000u) return fail(h, EI_DAT_TIMEOUT, 1, "pio");
            relax();
        }
        if (ni & NI_ERR) return fail(h, rd16(h, R_ERRINT), 1, "pio");
        wr16(h, R_NORINT, want);
        for (i = 0; i < bsize; i += 4) {
            uint32_t w;
            if (write) { memcpy(&w, p + i, 4); wr32(h, R_DATA, w); }
            else { w = rd32(h, R_DATA); memcpy(p + i, &w, 4); }
        }
        p += bsize;
    }
    return SD_OK;
}

/* One data command: CMD17/18/24/25 (or a control read like ACMD51/CMD8 with its own block size). */
static int data_cmd(sd_host_t *h, unsigned idx, uint32_t arg, int write, void *buf, unsigned blocks, unsigned bsize, int auto12)
{
    const uint32_t bytes = blocks * bsize;
    uint16_t tm = TM_BLKCNT | (write ? 0 : TM_READ);
    int dma = 0, rc;
    uint32_t r1 = 0;
    uint64_t t0;
    if (blocks > 1) tm |= TM_MULTI | (auto12 ? TM_ACMD12 : 0);
    if (h->adma && !h->force_pio && bsize % 4 == 0 && adma_table(h, buf, bytes) == 0) {
        dma = 1;
        tm |= TM_DMA;
        wr8(h, R_HOSTCTL, (uint8_t)((rd8(h, R_HOSTCTL) & ~0x18) | 0x10));     /* DMA select: ADMA2 32-bit */
        wr32(h, R_ADMAADDR, (uint32_t)h->desc_pa);
        wr32(h, R_ADMAADDR_HI, 0);
    }
    wr16(h, R_BLKSIZE, (uint16_t)((7u << 12) | bsize));
    wr16(h, R_BLKCNT, (uint16_t)blocks);
    wr16(h, R_TRNMOD, tm);
    rc = sd_cmd(h, idx, arg, RSP_R1 | CMD_DATA, &r1);
    h->last_r1 = r1;
    if (rc) return rc;
    if (r1 & R1_ERRORS) {
        kprintf("K64 sdhci%u: CMD%u arg %x: card status %x (error bits %x)\n", h->idx, idx, arg, r1, r1 & R1_ERRORS);
        ++h->errors;
        host_reset(h, RST_DAT);                         /* abandon the data phase the controller may have started */
        clear_status(h);
        if (blocks > 1) sd_cmd(h, 12, 0, RSP_R1B, 0);
        return SD_ECARD;
    }
    if (!dma) {
        rc = pio_move(h, write, buf, blocks, bsize);
        if (rc) { if (blocks > 1) sd_cmd(h, 12, 0, RSP_R1B, 0); return rc; }
        ++h->pio_xfers;
    } else {
        ++h->adma_xfers;
    }
    t0 = now_us();
    for (;;) {
        const uint16_t ni = rd16(h, R_NORINT);
        if (ni & NI_ERR) {
            const uint16_t e = rd16(h, R_ERRINT);
            rc = fail(h, e, 1, dma ? "adma" : "data");
            if (blocks > 1) sd_cmd(h, 12, 0, RSP_R1B, 0);
            return rc;
        }
        if (ni & NI_XFER) break;
        if (now_us() - t0 > ((uint64_t)h->timeout_ms + bytes / 65536u) * 1000u) {
            kprintf("K64 sdhci%u: CMD%u: transfer of %u bytes did not complete (present %x)\n", h->idx, idx, bytes, rd32(h, R_PRNSTS));
            rc = fail(h, EI_DAT_TIMEOUT, 1, "xfer");
            if (blocks > 1) sd_cmd(h, 12, 0, RSP_R1B, 0);
            return rc;
        }
        relax();
    }
    clear_status(h);
    return SD_OK;
}

static int card_status(sd_host_t *h, uint32_t *st) { return sd_cmd(h, 13, h->rca << 16, RSP_R1, st); }

/* After a failed transfer: bring the card back to the transfer state (4). */
static void card_recover(sd_host_t *h)
{
    uint32_t st = 0;
    unsigned i;
    for (i = 0; i < 3; ++i) {
        if (card_status(h, &st) == SD_OK && R1_STATE(st) == 4) return;
        if (R1_STATE(st) == 5 || R1_STATE(st) == 6) sd_cmd(h, 12, 0, RSP_R1B, 0);   /* data / rcv: stop */
    }
    kprintf("K64 sdhci%u: card did not return to the transfer state (status %x)\n", h->idx, st);
}

static int rw(sd_host_t *h, int write, uint64_t lba, unsigned count, void *buf)
{
    uint8_t *p = buf;
    int rc = SD_OK;
    while (count && rc == SD_OK) {
        const unsigned n = count < SD_MAX_XFER_SECTORS ? count : SD_MAX_XFER_SECTORS;
        const uint32_t arg = h->block_addr ? (uint32_t)lba : (uint32_t)(lba * 512u);
        const unsigned idx = write ? (n > 1 ? 25 : 24) : (n > 1 ? 18 : 17);
        unsigned attempt;
        for (attempt = 0; attempt < 2; ++attempt) {
            rc = data_cmd(h, idx, arg, write, p, n, 512, 1);
            if (rc == SD_OK) break;
            kprintf("K64 sdhci%u: CMD%u lba %llu x%u failed (%d), %s\n", h->idx, idx, lba, n, rc, attempt ? "giving up" : "retrying");
            card_recover(h);
            if (rc == SD_ECARD) break;                  /* the card refused the address: a retry cannot help */
            ++h->retries;
        }
        p += (uint64_t)n * 512u;
        lba += n;
        count -= n;
    }
    return rc;
}

static int sd_read(blk_dev_t *d, uint64_t lba, unsigned count, void *buf)
{
    sd_host_t *h = d->priv;
    int rc;
    mutex_lock(&h->lock);
    rc = rw(h, 0, lba, count, buf);
    mutex_unlock(&h->lock);
    return rc ? -1 : 0;
}

static int sd_write(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf)
{
    sd_host_t *h = d->priv;
    int rc;
    mutex_lock(&h->lock);
    rc = rw(h, 1, lba, count, (void *)buf);
    if (rc == SD_OK) {                                  /* programming finished: CMD13 until ready-for-data again */
        uint32_t st = 0;
        const uint64_t t0 = now_us();
        while (card_status(h, &st) == SD_OK && (R1_STATE(st) == 7 || !(st & (1u << 8)))) {   /* prg / not ready */
            if (now_us() - t0 > (uint64_t)h->timeout_ms * 1000u) { rc = SD_ETIMEDOUT; break; }
            relax();
        }
    }
    mutex_unlock(&h->lock);
    return rc ? -1 : 0;
}

static int sd_flush(blk_dev_t *d) { (void)d; return 0; }   /* writes complete when the card left the programming state */

static int sd_control(blk_dev_t *d, unsigned op, uint64_t arg, uint64_t *out)
{
    sd_host_t *h = d->priv;
    int rc;
    switch (op) {
    case BLK_CTL_XFER_MODE:
        if (arg > 1) return -1;
        h->force_pio = (int)arg;
        d->irq_mode = "poll";
        if (out) out[0] = (h->adma && !h->force_pio) ? 1 : 0;   /* 1 = ADMA2 in use */
        return 0;
    case BLK_CTL_ERROR_TEST: {                          /* a read past the end must fail cleanly, the card must recover */
        const uint64_t e0 = h->errors;
        uint32_t st = 0;
        mutex_lock(&h->lock);
        rc = data_cmd(h, 17, h->block_addr ? (uint32_t)(d->sectors + 8) : (uint32_t)((d->sectors + 8) * 512u), 0,
                      h->bounce, 1, 512, 0);
        card_recover(h);
        if (card_status(h, &st) != SD_OK) st = 0xffffffffu;
        mutex_unlock(&h->lock);
        kprintf("K64 sdhci%u: error self-test: out-of-range read -> %d (card status %x), then status %x\n", h->idx, rc,
                h->last_r1, st);
        if (out) { out[0] = (uint64_t)(int64_t)rc; out[1] = h->last_r1; out[2] = st; out[3] = h->errors - e0; }
        return (rc != SD_OK && R1_STATE(st) == 4) ? 0 : -1;
    }
    case BLK_CTL_STATS:
        if (out) { out[0] = h->adma_xfers; out[1] = h->timeouts; out[2] = h->line_resets; out[3] = h->pio_xfers; }
        return 0;
    case BLK_CTL_SET_TIMEOUT_MS:
        if (arg < 10 || arg > 600000) return -1;
        h->timeout_ms = (uint32_t)arg;
        return 0;
    default:
        return -2;
    }
}

/* ---------------------------------------------------------------- card identification */
static int init_sd(sd_host_t *h, int v2)
{
    uint32_t r = 0;
    int rc;
    const uint64_t t0 = now_us();
    for (;;) {                                          /* ACMD41 until the card reports power-up done */
        rc = app_cmd(h, 41, (v2 ? 0x40000000u : 0) | 0x00ff8000u, RSP_R3, &r);
        if (rc) return rc;
        if (r & 0x80000000u) break;
        if (now_us() - t0 > 1000000) { kprintf("K64 sdhci%u: ACMD41 busy for 1 s\n", h->idx); return SD_ETIMEDOUT; }
        relax();
    }
    h->ocr = r;
    h->block_addr = v2 && (r & 0x40000000u);            /* CCS */
    h->kind = h->block_addr ? KIND_SDHC : KIND_SDSC;
    if ((rc = sd_cmd(h, 2, 0, RSP_R2, h->cid))) return rc;
    if ((rc = sd_cmd(h, 3, 0, RSP_R6, &r))) return rc;
    h->rca = r >> 16;
    if ((rc = sd_cmd(h, 9, h->rca << 16, RSP_R2, h->csd))) return rc;
    if ((rc = sd_cmd(h, 7, h->rca << 16, RSP_R1B, &r))) return rc;
    if (bits128(h->csd, 126, 2) == 0) {                 /* CSD 1.0 */
        const uint32_t c_size = bits128(h->csd, 62, 12), mult = bits128(h->csd, 47, 3), bl = bits128(h->csd, 80, 4);
        h->dev.sectors = (((uint64_t)c_size + 1) << (mult + 2) << bl) / 512u;
    } else {                                            /* CSD 2.0 */
        h->dev.sectors = ((uint64_t)bits128(h->csd, 48, 22) + 1) * 1024u;
    }
    if (app_cmd(h, 6, 2, RSP_R1, &r) == SD_OK) {        /* 4-bit bus */
        wr8(h, R_HOSTCTL, (uint8_t)(rd8(h, R_HOSTCTL) | 2));
        h->bus4 = 1;
    }
    if ((rc = sd_cmd(h, 16, 512, RSP_R1, &r))) return rc;
    /* SCR (ACMD51, 8 bytes big-endian): SD_SPEC in bits 59:56, bus widths in 51:48. Informational only. */
    memset(h->bounce, 0, 8);
    if (sd_cmd(h, 55, h->rca << 16, RSP_R1, &r) == SD_OK) {
        if (data_cmd(h, 51, 0, 0, h->bounce, 1, 8, 0) == SD_OK)
            h->scr_hi = ((uint32_t)h->bounce[0] << 24) | ((uint32_t)h->bounce[1] << 16) | ((uint32_t)h->bounce[2] << 8) | h->bounce[3];
        else
            card_recover(h);
    }
    return SD_OK;
}

static int init_mmc(sd_host_t *h)
{
    uint32_t r = 0;
    int rc;
    const uint64_t t0 = now_us();
    sd_cmd(h, 0, 0, RSP_NONE, 0);
    for (;;) {                                          /* CMD1: sector mode, 2.7-3.6 V (+1.7-1.95 V) */
        rc = sd_cmd(h, 1, 0x40ff8080u, RSP_R3, &r);
        if (rc) return rc;
        if (r & 0x80000000u) break;
        if (now_us() - t0 > 1000000) { kprintf("K64 sdhci%u: CMD1 busy for 1 s\n", h->idx); return SD_ETIMEDOUT; }
        relax();
    }
    h->ocr = r;
    h->kind = KIND_MMC;
    h->block_addr = (r & 0x60000000u) == 0x40000000u;   /* access mode: sector */
    if ((rc = sd_cmd(h, 2, 0, RSP_R2, h->cid))) return rc;
    h->rca = 1;
    if ((rc = sd_cmd(h, 3, h->rca << 16, RSP_R1, &r))) return rc;
    if ((rc = sd_cmd(h, 9, h->rca << 16, RSP_R2, h->csd))) return rc;
    if ((rc = sd_cmd(h, 7, h->rca << 16, RSP_R1B, &r))) return rc;
    {
        const uint32_t c_size = bits128(h->csd, 62, 12), mult = bits128(h->csd, 47, 3), bl = bits128(h->csd, 80, 4);
        h->dev.sectors = (((uint64_t)c_size + 1) << (mult + 2) << bl) / 512u;
    }
    if (bits128(h->csd, 122, 4) >= 4) {                 /* SPEC_VERS 4+: EXT_CSD exists */
        rc = data_cmd(h, 8, 0, 0, h->bounce, 1, 512, 0);
        if (rc) { kprintf("K64 sdhci%u: SEND_EXT_CSD failed (%d)\n", h->idx, rc); card_recover(h); return rc; }
        h->ext_csd_rev = h->bounce[192];
        if (h->block_addr) {
            const uint32_t sec = (uint32_t)h->bounce[212] | ((uint32_t)h->bounce[213] << 8) | ((uint32_t)h->bounce[214] << 16) |
                                 ((uint32_t)h->bounce[215] << 24);
            if (sec) h->dev.sectors = sec;
        }
        /* SWITCH: write byte BUS_WIDTH (183) = 1 (4 bit) */
        if (sd_cmd(h, 6, (3u << 24) | (183u << 16) | (1u << 8), RSP_R1B, &r) == SD_OK && card_status(h, &r) == SD_OK &&
            !(r & (1u << 7))) {                         /* SWITCH_ERROR clear */
            wr8(h, R_HOSTCTL, (uint8_t)(rd8(h, R_HOSTCTL) | 2));
            h->bus4 = 1;
            h->mmc_bus_width = 4;
        }
    }
    if ((rc = sd_cmd(h, 16, 512, RSP_R1, &r))) return rc;
    return SD_OK;
}

static int host_init(sd_host_t *h)
{
    uint32_t r7 = 0, volt;
    int rc;
    if (host_reset(h, RST_ALL)) return -1;
    h->caps = rd32(h, R_CAPS);
    h->caps_hi = rd32(h, R_CAPS_HI);
    h->version = rd16(h, R_VERSION) & 0xff;
    h->base_khz = (h->version >= 2 ? (h->caps >> 8) & 0xff : (h->caps >> 8) & 0x3f) * 1000u;
    if (!h->base_khz) h->base_khz = 50000;              /* "get the base clock another way": assume 50 MHz */
    h->adma = (h->caps >> 19) & 1;
    h->timeout_ms = 2000;
    if (!(rd32(h, R_PRNSTS) & PS_CARD_IN)) { kprintf("K64 sdhci%u: no card in the slot\n", h->idx); return -1; }
    volt = (h->caps & (1u << 24)) ? 0x0e : (h->caps & (1u << 25)) ? 0x0c : 0x0a;   /* 3.3 V, 3.0 V, 1.8 V */
    wr8(h, R_PWRCTL, (uint8_t)volt);
    wr8(h, R_PWRCTL, (uint8_t)(volt | 1));
    wr16(h, R_NORINTEN, 0x01ff & ~0x0100);              /* every status except card interrupt */
    wr16(h, R_ERRINTEN, 0x03ff);
    wr16(h, R_NORSIGEN, 0);                             /* completion is polled (see header) */
    wr16(h, R_ERRSIGEN, 0);
    wr8(h, R_TIMEOUT, 0x0e);
    wr8(h, R_HOSTCTL, 0);
    if (set_clock(h, 400)) return -1;
    clear_status(h);
    sd_cmd(h, 0, 0, RSP_NONE, 0);                       /* GO_IDLE */
    rc = sd_cmd(h, 8, 0x1aa, RSP_R7, &r7);              /* SEND_IF_COND: 2.7-3.6 V, check pattern 0xaa */
    if (rc == SD_OK && (r7 & 0xfff) != 0x1aa) { kprintf("K64 sdhci%u: CMD8 echo %x, unusable card\n", h->idx, r7); return -1; }
    h->rca = 0;
    {
        uint32_t r1;
        const int sd = sd_cmd(h, 55, 0, RSP_R1, &r1) == SD_OK;
        rc = sd ? init_sd(h, rc == SD_OK) : init_mmc(h);
    }
    if (rc) { kprintf("K64 sdhci%u: card initialisation failed (%d)\n", h->idx, rc); return -1; }
    set_clock(h, h->kind == KIND_MMC ? 26000 : 25000);
    return 0;
}

static int host_setup(sd_host_t *h)
{
    uint32_t i, n;
    h->desc_pa = pmm_alloc();
    h->bounce_pa = pmm_alloc();
    if (!h->desc_pa || !h->bounce_pa) return -1;
    h->desc = (uint32_t *)p2v(h->desc_pa);
    h->bounce = (uint8_t *)p2v(h->bounce_pa);
    mutex_init(&h->lock);
    if (host_init(h)) return -1;
    n = 0;
    h->dev.name[n++] = 'm'; h->dev.name[n++] = 'm'; h->dev.name[n++] = 'c'; h->dev.name[n++] = 'b'; h->dev.name[n++] = 'l';
    h->dev.name[n++] = 'k'; h->dev.name[n++] = (char)('0' + h->idx); h->dev.name[n] = 0;
    h->dev.sector_size = 512;
    h->dev.flags = BLK_F_REMOVABLE | ((rd32(h, R_PRNSTS) & PS_WP) ? 0 : BLK_F_READONLY);
    h->dev.read = sd_read;
    h->dev.write = (h->dev.flags & BLK_F_READONLY) ? 0 : sd_write;
    h->dev.flush = sd_flush;
    h->dev.control = sd_control;
    h->dev.priv = h;
    h->dev.driver = "sdhci";
    h->dev.irq_mode = "poll";
    h->dev.queue_depth = 1;
    h->dev.max_sectors = SD_MAX_XFER_SECTORS;
    /* model: CID product name (SD: bits 103:64, 5 chars; MMC: 103:56, 6 chars), serial: PSN */
    n = 0;
    for (i = 0; i < (h->kind == KIND_MMC ? 6u : 5u); ++i) {
        const char c = (char)bits128(h->cid, 96u - 8u * i, 8);   /* PNM: first character in bits 103:96 */
        h->dev.model[n++] = (c >= 0x20 && c < 0x7f) ? c : '?';
    }
    h->dev.model[n] = 0;
    {
        const uint32_t psn = h->kind == KIND_MMC ? bits128(h->cid, 16, 32) : bits128(h->cid, 24, 32);
        static const char hex[] = "0123456789abcdef";
        for (i = 0; i < 8; ++i) h->dev.serial[i] = hex[(psn >> (28 - 4 * i)) & 15];
        h->dev.serial[8] = 0;
    }
    kprintf("K64 sdhci%u: %x:%x.%x %x:%x SDHCI %u.00, base clock %u MHz, %s, card %s \"%s\" sn %s OCR %x RCA %x, %llu sectors "
            "(%llu MiB), %s addressing, %u-bit bus at %u kHz%s, SCR %x\n", h->idx, h->pci.bus, h->pci.dev, h->pci.fn,
            h->pci.vendor, h->pci.device, h->version + 1, h->base_khz / 1000, h->adma ? "ADMA2" : "PIO only",
            kind_names[h->kind], h->dev.model, h->dev.serial, h->ocr, h->rca, h->dev.sectors, h->dev.sectors >> 11,
            h->block_addr ? "block" : "byte", h->bus4 ? 4 : 1, h->clock_khz,
            (h->dev.flags & BLK_F_READONLY) ? ", write-protected" : "", h->scr_hi);
    return 0;
}

#ifndef SDHCI_HOST_TEST
int sdhci_blk_init(void)
{
    pci_dev_t all[32];
    const unsigned n = pci_enumerate(all, 32);
    unsigned i;
    int registered = 0;
    for (i = 0; i < n && nhosts < SD_MAX_HOSTS; ++i) {
        sd_host_t *h;
        uint64_t bar, size;
        int is_io;
        if (all[i].class_code != 8 || all[i].subclass != 5) continue;
        h = &hosts[nhosts];
        memset(h, 0, sizeof *h);
        h->idx = nhosts;
        h->pci = all[i];
        bar = pci_bar(&all[i], 0, &size, &is_io);
        if (!bar || is_io || size < 0x100) { kprintf("K64 sdhci%u: BAR0 unusable\n", h->idx); continue; }
        pci_enable(&all[i], 0, 1, 1);
        pci_intx_disable(&all[i], 1);                   /* polled: keep the shared legacy line quiet */
        h->r = mmio_map(bar, 0x100);
        if (!h->r) continue;
        ++nhosts;
        if (host_setup(h)) { kprintf("K64 sdhci%u: no usable card\n", h->idx); continue; }
        if (!blk_register(&h->dev)) ++registered;
    }
    if (!nhosts) kprintf("K64 sdhci: no SD host controller (class 0805) on PCI bus 0\n");
    return registered;
}
#else
/* host test entry: one controller at `regs` */
int sdhci_host_test_probe(void *regs, blk_dev_t **out)
{
    sd_host_t *h = &hosts[nhosts];
    memset(h, 0, sizeof *h);
    h->idx = nhosts;
    h->r = regs;
    if (host_setup(h)) return -1;
    ++nhosts;
    *out = &h->dev;
    return 0;
}
#endif
#endif
