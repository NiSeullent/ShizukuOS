/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NVMe driver (NVM Express 1.4 base subset, PCI class 01:08:02), one block device per active namespace
 * ("nvme<c>n<nsid>") in the generic registry (blk.h). STANDALONE PROFILE ONLY: under the Supervisor no device is
 * passed through, so nvme_blk_init() finds nothing there. QEMU fixture: -device nvme,serial=..,drive=.. or
 * -device nvme + -device nvme-ns,drive=..[,logical_block_size=4096] (tests/run_k64_storage.py).
 *
 * Bring-up: CAP (MQES, DSTRD, TO, CSS, MPSMIN) -> CC.EN=0 / CSTS.RDY=0 -> admin SQ/CQ (AQA/ASQ/ACQ) -> CC (4 KiB pages,
 * 64-byte SQEs, 16-byte CQEs, NVM command set) -> CSTS.RDY=1 -> IDENTIFY controller (model, serial, MDTS, NN, ONCS,
 * VWC) -> Set Features "number of queues" -> interrupt setup -> one I/O CQ/SQ pair -> IDENTIFY active namespace list
 * and each namespace (NSZE, FLBAS -> LBA format -> sector size; formats with metadata are skipped).
 *
 * I/O: 64-entry I/O SQ/CQ (one physically contiguous page each), NVME_SLOTS commands in flight (CID = slot); each
 * slot owns a PRP-list page, so one command moves up to min(MDTS, 1 MiB). A request bigger than that is split and the
 * pieces are submitted back to back (queue depth > 1); concurrent callers and read_async/write_async share the slots.
 * Buffers are kernel virtual (blk_kva_to_pa per page); one that is not 4-byte aligned (PRP1 needs dword alignment) is
 * bounced through per-slot pages, 4 KiB per command, still pipelined.
 *
 * Completion: MSI-X when the function has it (entry 0 admin CQ, entry 1 I/O CQ, both reap both CQs), else INTx on the
 * shared legacy line (attached lazily: the 8259 is programmed after disk_init()), else polling. Waiters sleep on a
 * per-slot semaphore in 10 ms slices and reap themselves between slices, so a lost interrupt costs latency, not a
 * hang. With interrupts off (disk_init, before the scheduler) everything polls. Async completions run their callback
 * from the "nvme" worker thread, never from the interrupt handler. BLK_CTL_IRQ_MODE switches MSI-X/INTx/poll live.
 *
 * Errors and recovery: a non-zero CQE status fails the request (logged with SCT/SC). A command outstanding longer
 * than the timeout (default 5 s) triggers a controller reset: CC.EN=0, wait RDY=0, rebuild admin + I/O queues,
 * re-enable interrupts, resubmit every outstanding command from its saved SQE (up to NVME_RETRIES times, then it
 * fails). A controller that does not come back is marked dead and every request fails fast. BLK_CTL_TIMEOUT_TEST puts
 * a READ into the SQ without ringing the doorbell to exercise exactly that path. FLUSH is sent when VWC reports a
 * volatile write cache; DSM deallocate (TRIM) when ONCS says DSM is supported.
 * Limits: one I/O queue pair, no metadata/PI formats, no SGLs, no namespace management, no multipath, no CMB/HMB.
 */
#include "blk.h"
#include "pci.h"

#ifndef SHZ_STANDALONE
int nvme_blk_init(void) { return 0; }                   /* Supervisor profile: no passed-through controller */
#else

#define NVME_MAX_CTRL 2
#define NVME_MAX_NS 4
#define NVME_QD 64u                                     /* SQ/CQ entries of the admin and the I/O queue (1 page each) */
#define NVME_SLOTS 32u                                  /* I/O commands in flight */
#define NVME_RETRIES 2u
#define NVME_MAX_XFER (1024u * 1024u)

enum { R_CAP = 0x00, R_VS = 0x08, R_INTMS = 0x0c, R_INTMC = 0x10, R_CC = 0x14, R_CSTS = 0x1c, R_AQA = 0x24, R_ASQ = 0x28,
       R_ACQ = 0x30 };
enum { OP_FLUSH = 0x00, OP_WRITE = 0x01, OP_READ = 0x02, OP_DSM = 0x09 };
enum { ADM_CREATE_SQ = 0x01, ADM_CREATE_CQ = 0x05, ADM_IDENTIFY = 0x06, ADM_SET_FEATURES = 0x09 };
enum { MODE_POLL = 0, MODE_INTX = 1, MODE_MSIX = 2 };
static const char *const mode_names[3] = { "poll", "intx", "msix" };

typedef struct {
    volatile uint32_t *sq;                              /* 16 dwords per entry */
    volatile uint32_t *cq;                              /* 4 dwords per entry */
    uint64_t sq_pa, cq_pa;
    uint16_t qid, sq_tail, sq_head, cq_head;
    uint8_t phase;
} nvme_q_t;

typedef struct nvme_slot nvme_slot_t;
struct nvme_slot {
    volatile int busy, done;
    volatile uint16_t status;                           /* SCT << 8 | SC; 0xffff = aborted by the driver */
    volatile uint32_t result;                           /* CQE dword 0 */
    ksem_t sem;
    blk_done_fn cb;                                     /* async request: callback run by the worker */
    void *cb_ctx;
    uint32_t sqe[16];                                   /* kept for resubmission after a controller reset */
    uint64_t t_submit;                                  /* TSC */
    unsigned retries;
    uint64_t *prp;                                      /* PRP list page (also the DSM range buffer) */
    uint64_t prp_pa;
    uint8_t *bounce;                                    /* one page for buffers that are not 4-byte aligned */
    nvme_slot_t *next_done;
};

typedef struct nvme_ctrl nvme_ctrl_t;
typedef struct {
    blk_dev_t dev;
    nvme_ctrl_t *c;
    uint32_t nsid, lba_shift, max_sectors;
} nvme_ns_t;

struct nvme_ctrl {
    unsigned idx;
    pci_dev_t pci;
    volatile uint8_t *regs;
    uint64_t cap;
    uint32_t dstrd, cap_to_ms, vs, mdts_bytes, nn, oncs, vwc;
    nvme_q_t aq, ioq;
    nvme_slot_t admin;                                  /* one admin command at a time (admin_lock) */
    nvme_slot_t slot[NVME_SLOTS];
    volatile uint32_t free_mask;
    volatile unsigned slot_waiters;
    ksem_t slot_sem;
    kmutex_t admin_lock;
    int mode, want_mode, intx_line, dead;
    volatile int resetting;
    pci_msix_t msix;
    int has_msix;
    uint32_t timeout_ms;
    char model[41], serial[21], fw[9];
    nvme_ns_t ns[NVME_MAX_NS];
    unsigned nns;
    /* async completions */
    nvme_slot_t *done_head, *done_tail;
    ksem_t worker_sem;
    thread_t *worker;
    /* statistics */
    uint64_t irqs, timeouts, resets, submitted, completed, polled;
    unsigned inflight, max_inflight;
    uint64_t *idbuf;                                    /* 4 KiB identify buffer */
    uint64_t idbuf_pa;
};

static nvme_ctrl_t ctrls[NVME_MAX_CTRL];
static unsigned nctrl;

/* ---------------------------------------------------------------- helpers */
static inline uint64_t tsc(void) { uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); return ((uint64_t)hi << 32) | lo; }
static inline uint64_t tsc_ms(uint64_t t0) { return (tsc() - t0) / 1000000u; }   /* nominal 1 GHz TSC (boot32.c) */
static inline void relax(void) { __asm__ volatile("pause" ::: "memory"); }
static inline void wmb(void) { __asm__ volatile("sfence" ::: "memory"); }
static inline void mb(void) { __asm__ volatile("mfence" ::: "memory"); }

static int can_sleep(void)
{
    uint64_t f;
    __asm__ volatile("pushfq; popq %0" : "=r"(f));
    return (f & 0x200) && thread_current();
}

static uint32_t rd32(nvme_ctrl_t *c, unsigned off) { return *(volatile uint32_t *)(c->regs + off); }
static void wr32(nvme_ctrl_t *c, unsigned off, uint32_t v) { *(volatile uint32_t *)(c->regs + off) = v; }
static uint64_t rd64(nvme_ctrl_t *c, unsigned off) { return (uint64_t)rd32(c, off) | ((uint64_t)rd32(c, off + 4) << 32); }
static void wr64(nvme_ctrl_t *c, unsigned off, uint64_t v) { wr32(c, off, (uint32_t)v); wr32(c, off + 4, (uint32_t)(v >> 32)); }
static void sq_doorbell(nvme_ctrl_t *c, nvme_q_t *q) { wr32(c, 0x1000 + (2u * q->qid) * (4u << c->dstrd), q->sq_tail); }
static void cq_doorbell(nvme_ctrl_t *c, nvme_q_t *q) { wr32(c, 0x1000 + (2u * q->qid + 1) * (4u << c->dstrd), q->cq_head); }

static void copy_str(char *dst, const uint8_t *src, unsigned n)
{
    unsigned i, end = 0;
    for (i = 0; i < n; ++i) {
        dst[i] = (src[i] >= 0x20 && src[i] < 0x7f) ? (char)src[i] : ' ';
        if (dst[i] != ' ') end = i + 1;
    }
    dst[end] = 0;
}

/* ---------------------------------------------------------------- completion */
static void slot_complete(nvme_ctrl_t *c, nvme_slot_t *s, uint16_t status, uint32_t result)
{
    s->status = status;
    s->result = result;
    s->done = 1;
    ++c->completed;
    if (c->inflight) --c->inflight;
    if (s->cb) {                                        /* async: hand to the worker */
        s->next_done = 0;
        if (c->done_tail) c->done_tail->next_done = s; else c->done_head = s;
        c->done_tail = s;
        sem_post(&c->worker_sem);
    } else {
        sem_post(&s->sem);
    }
}

/* Drains one completion queue. Caller has interrupts off (IRQ handler, or irq_save in thread context). */
static unsigned reap(nvme_ctrl_t *c, nvme_q_t *q)
{
    unsigned n = 0;
    for (;;) {
        volatile uint32_t *e = q->cq + 4u * q->cq_head;
        const uint32_t dw3 = e[3];
        const uint16_t cid = (uint16_t)dw3;
        nvme_slot_t *s;
        if (((dw3 >> 16) & 1) != q->phase) break;
        q->sq_head = (uint16_t)e[2];
        if (q == &c->aq) s = (cid == 0x8000 && c->admin.busy && !c->admin.done) ? &c->admin : 0;
        else s = (cid < NVME_SLOTS && c->slot[cid].busy && !c->slot[cid].done) ? &c->slot[cid] : 0;
        if (s) slot_complete(c, s, (uint16_t)((dw3 >> 17) & 0x7fff), e[0]);
        else kprintf("K64 nvme%u: stray completion cid %x on queue %u\n", c->idx, cid, q->qid);
        if (++q->cq_head == NVME_QD) { q->cq_head = 0; q->phase ^= 1; }
        ++n;
    }
    if (n) cq_doorbell(c, q);
    return n;
}

static void isr(void *ctx)
{
    nvme_ctrl_t *c = ctx;
    ++c->irqs;
    if (c->resetting || c->dead) return;
    reap(c, &c->ioq);
    reap(c, &c->aq);
}

static void poll_once(nvme_ctrl_t *c)
{
    const uint64_t f = irq_save();
    if (!c->resetting && !c->dead) {
        c->polled += reap(c, &c->ioq);
        reap(c, &c->aq);
    }
    irq_restore(f);
}

/* ---------------------------------------------------------------- submission */
static void push_sqe(nvme_ctrl_t *c, nvme_q_t *q, const uint32_t *sqe, int ring)
{
    volatile uint32_t *dst = q->sq + 16u * q->sq_tail;
    unsigned i;
    for (i = 0; i < 16; ++i) dst[i] = sqe[i];
    if (++q->sq_tail == NVME_QD) q->sq_tail = 0;
    wmb();
    if (ring) sq_doorbell(c, q);
}

static int ctrl_recover(nvme_ctrl_t *c, const char *why);

/* Waits for I/O slot `s`. Returns 0 when it completed (status in s->status; 0xffff when the driver gave up on it after
 * NVME_RETRIES resets), -1 when the controller is dead and `s` never completed. */
static int wait_slot(nvme_ctrl_t *c, nvme_slot_t *s)
{
    uint64_t t0 = tsc();
    while (!s->done) {
        if (c->dead) return -1;
        if (can_sleep() && c->mode != MODE_POLL) {
            sem_wait_timeout(&s->sem, 10);
            if (!s->done) poll_once(c);                 /* lost or not-yet-armed interrupt: look ourselves */
        } else {
            poll_once(c);
            if (!s->done) { if (can_sleep()) thread_yield(); else relax(); }
        }
        if (!s->done && tsc_ms(t0) >= c->timeout_ms) {
            ++c->timeouts;
            kprintf("K64 nvme%u: command %x (cid %u) timed out after %u ms (attempt %u)\n", c->idx, s->sqe[0] & 0xff,
                    s->sqe[0] >> 16, c->timeout_ms, s->retries + 1);
            ctrl_recover(c, "command timeout");        /* resubmits s, or fails it once its retries are used up */
            t0 = tsc();
        }
    }
    return 0;
}

static nvme_slot_t *slot_try(nvme_ctrl_t *c)
{
    const uint64_t f = irq_save();
    nvme_slot_t *s = 0;
    if (c->free_mask) {
        const unsigned i = (unsigned)__builtin_ctz(c->free_mask);
        c->free_mask &= ~(1u << i);
        s = &c->slot[i];
        s->busy = 1;
        s->done = 0;
        s->status = 0;
        s->cb = 0;
        s->retries = 0;
        sem_init(&s->sem, 0);
    }
    irq_restore(f);
    return s;
}

static nvme_slot_t *slot_get(nvme_ctrl_t *c)
{
    for (;;) {
        nvme_slot_t *s = slot_try(c);
        if (s || c->dead) return s;
        if (can_sleep()) {
            uint64_t f = irq_save();
            ++c->slot_waiters;
            irq_restore(f);
            sem_wait_timeout(&c->slot_sem, 10);
            f = irq_save();
            --c->slot_waiters;
            irq_restore(f);
            poll_once(c);
        } else {
            poll_once(c);
            relax();
        }
    }
}

static void slot_put(nvme_ctrl_t *c, nvme_slot_t *s)
{
    const uint64_t f = irq_save();
    s->busy = 0;
    s->cb = 0;
    c->free_mask |= 1u << (unsigned)(s - c->slot);
    if (c->slot_waiters) sem_post(&c->slot_sem);
    irq_restore(f);
}

/* Queues the prepared SQE of I/O slot `s`. ring = 0 leaves the doorbell alone (timeout self-test only). */
static void io_submit(nvme_ctrl_t *c, nvme_slot_t *s, int ring)
{
    uint64_t f;
    while (c->resetting) { if (can_sleep()) thread_yield(); else relax(); }
    f = irq_save();
    s->sqe[0] = (s->sqe[0] & 0xffffu) | ((uint32_t)(s - c->slot) << 16);
    s->t_submit = tsc();
    if (c->dead) {
        irq_restore(f);
        slot_complete(c, s, 0xffff, 0);
        return;
    }
    push_sqe(c, &c->ioq, s->sqe, ring);
    ++c->submitted;
    if (++c->inflight > c->max_inflight) c->max_inflight = c->inflight;
    irq_restore(f);
}

/* Admin command, synchronous (admin_lock held by the caller or single-threaded init). */
static int admin_cmd(nvme_ctrl_t *c, const uint32_t *sqe_in, uint32_t *result)
{
    nvme_slot_t *s = &c->admin;
    uint64_t f, t0 = tsc();
    unsigned i;
    for (i = 0; i < 16; ++i) s->sqe[i] = sqe_in[i];
    s->sqe[0] = (s->sqe[0] & 0xffffu) | (0x8000u << 16);
    s->busy = 1; s->done = 0; s->status = 0; s->cb = 0;
    sem_init(&s->sem, 0);
    f = irq_save();
    push_sqe(c, &c->aq, s->sqe, 1);
    irq_restore(f);
    while (!s->done) {                                  /* admin commands always poll: they are rare and short */
        f = irq_save();
        reap(c, &c->aq);
        irq_restore(f);
        if (s->done) break;
        if (tsc_ms(t0) > c->cap_to_ms + 1000) {
            kprintf("K64 nvme%u: admin opcode %x timed out\n", c->idx, sqe_in[0] & 0xff);
            s->busy = 0;
            return -1;
        }
        if (can_sleep()) thread_yield(); else relax();
    }
    s->busy = 0;
    if (result) *result = s->result;
    if (s->status) {
        kprintf("K64 nvme%u: admin opcode %x failed: sct %x sc %x\n", c->idx, sqe_in[0] & 0xff, (s->status >> 8) & 7, s->status & 0xff);
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------- controller enable / reset */
static int wait_rdy(nvme_ctrl_t *c, int want)
{
    const uint64_t t0 = tsc();
    for (;;) {
        const uint32_t csts = rd32(c, R_CSTS);
        if (csts == 0xffffffffu) return -1;             /* device gone */
        if ((csts & 1) == (uint32_t)want) return 0;
        if (want && (csts & 2)) return -1;              /* CFS */
        if (tsc_ms(t0) > c->cap_to_ms) return -1;
        relax();
    }
}

static int queue_alloc(nvme_q_t *q, uint16_t qid)
{
    if (!q->sq_pa) {
        q->sq_pa = pmm_alloc();
        q->cq_pa = pmm_alloc();
        if (!q->sq_pa || !q->cq_pa) return -1;
        q->sq = (volatile uint32_t *)p2v(q->sq_pa);
        q->cq = (volatile uint32_t *)p2v(q->cq_pa);
    }
    memset((void *)q->sq, 0, PAGE_SIZE);
    memset((void *)q->cq, 0, PAGE_SIZE);
    q->qid = qid;
    q->sq_tail = q->sq_head = q->cq_head = 0;
    q->phase = 1;
    return 0;
}

/* Disables, programs the admin queue and enables the controller. */
static int ctrl_enable(nvme_ctrl_t *c)
{
    if (rd32(c, R_CC) & 1) {
        wr32(c, R_CC, rd32(c, R_CC) & ~1u);
    }
    if (wait_rdy(c, 0)) { kprintf("K64 nvme%u: CSTS.RDY did not clear\n", c->idx); return -1; }
    if (queue_alloc(&c->aq, 0)) return -1;
    wr32(c, R_AQA, ((NVME_QD - 1) << 16) | (NVME_QD - 1));
    wr64(c, R_ASQ, c->aq.sq_pa);
    wr64(c, R_ACQ, c->aq.cq_pa);
    wr32(c, R_INTMS, 0xffffffffu);                      /* pin-based interrupts masked until INTx is armed */
    mb();
    wr32(c, R_CC, (4u << 20) | (6u << 16) | (0u << 11) | (0u << 7) | (0u << 4) | 1u);
    if (wait_rdy(c, 1)) { kprintf("K64 nvme%u: CSTS.RDY did not set (csts %x)\n", c->idx, rd32(c, R_CSTS)); return -1; }
    return 0;
}

/* Number of queues, then the I/O CQ (interrupt vector 1 with MSI-X, 0 with INTx) and SQ. */
static int create_io_queues(nvme_ctrl_t *c)
{
    uint32_t sqe[16], res = 0;
    if (queue_alloc(&c->ioq, 1)) return -1;
    memset(sqe, 0, sizeof sqe);
    sqe[0] = ADM_SET_FEATURES; sqe[10] = 0x07; sqe[11] = 0;          /* 1 SQ + 1 CQ */
    if (admin_cmd(c, sqe, &res)) return -1;
    memset(sqe, 0, sizeof sqe);
    sqe[0] = ADM_CREATE_CQ;
    sqe[6] = (uint32_t)c->ioq.cq_pa; sqe[7] = (uint32_t)(c->ioq.cq_pa >> 32);
    sqe[10] = ((NVME_QD - 1) << 16) | 1;
    sqe[11] = ((c->has_msix ? 1u : 0u) << 16) | 2u | 1u;             /* IV, IEN, PC */
    if (admin_cmd(c, sqe, 0)) return -1;
    memset(sqe, 0, sizeof sqe);
    sqe[0] = ADM_CREATE_SQ;
    sqe[6] = (uint32_t)c->ioq.sq_pa; sqe[7] = (uint32_t)(c->ioq.sq_pa >> 32);
    sqe[10] = ((NVME_QD - 1) << 16) | 1;
    sqe[11] = (1u << 16) | 1u;                                        /* CQID 1, PC */
    return admin_cmd(c, sqe, 0);
}

static void apply_mode(nvme_ctrl_t *c, int mode)
{
    if (mode == MODE_MSIX && c->has_msix) {
        if (c->intx_line >= 0) { pci_intx_detach(&c->pci, isr, c); c->intx_line = -1; }
        wr32(c, R_INTMS, 0xffffffffu);
        pci_msix_enable(&c->msix, 1);
        c->mode = MODE_MSIX;
    } else if (mode == MODE_INTX) {
        pci_msix_enable(&c->msix, 0);
        c->mode = MODE_INTX;
        if (c->intx_line < 0 && pci_intx_ready()) c->intx_line = pci_intx_attach(&c->pci, isr, c);
        if (c->intx_line >= 0) wr32(c, R_INTMC, 0xffffffffu);
        /* else: armed from the first request made with interrupts on (arm_intx) */
    } else {
        pci_msix_enable(&c->msix, 0);
        if (c->intx_line >= 0) { pci_intx_detach(&c->pci, isr, c); c->intx_line = -1; }
        wr32(c, R_INTMS, 0xffffffffu);
        pci_intx_disable(&c->pci, 1);
        c->mode = MODE_POLL;
    }
    {
        unsigned i;
        for (i = 0; i < c->nns; ++i) c->ns[i].dev.irq_mode = mode_names[c->mode];
    }
}

static void arm_intx(nvme_ctrl_t *c)
{
    if (c->mode == MODE_INTX && c->intx_line < 0 && can_sleep() && pci_intx_ready()) {
        c->intx_line = pci_intx_attach(&c->pci, isr, c);
        if (c->intx_line >= 0) {
            wr32(c, R_INTMC, 0xffffffffu);
            kprintf("K64 nvme%u: INTx armed on line %d\n", c->idx, c->intx_line);
        } else {
            unsigned i;
            kprintf("K64 nvme%u: legacy line %u unusable, falling back to polling\n", c->idx, c->pci.irq_line);
            c->mode = c->want_mode = MODE_POLL;
            for (i = 0; i < c->nns; ++i) c->ns[i].dev.irq_mode = mode_names[MODE_POLL];
        }
    }
}

/* Controller reset and recovery (see the header comment). Runs with interrupts off from start to end. */
static int ctrl_recover(nvme_ctrl_t *c, const char *why)
{
    const uint64_t f = irq_save();
    unsigned i, resubmitted = 0, failed = 0;
    int rc;
    if (c->resetting) { irq_restore(f); return 0; }
    c->resetting = 1;
    ++c->resets;
    kprintf("K64 nvme%u: controller reset (%s), %u command(s) outstanding\n", c->idx, why, c->inflight);
    if (c->has_msix) pci_msix_enable(&c->msix, 0);
    rc = ctrl_enable(c);
    if (!rc) {
        apply_mode(c, c->want_mode);                    /* QEMU (and the spec) want MSI-X live before CREATE CQ with IV 1 */
        rc = create_io_queues(c);                       /* admin_cmd polls the fresh admin queue itself */
    }
    c->resetting = 0;
    if (rc) {
        kprintf("K64 nvme%u: recovery failed, controller marked dead\n", c->idx);
        c->dead = 1;
        for (i = 0; i < NVME_SLOTS; ++i)
            if (c->slot[i].busy && !c->slot[i].done) slot_complete(c, &c->slot[i], 0xffff, 0);
        irq_restore(f);
        return -1;
    }
    c->inflight = 0;
    for (i = 0; i < NVME_SLOTS; ++i) {
        nvme_slot_t *s = &c->slot[i];
        if (!s->busy || s->done) continue;
        if (++s->retries > NVME_RETRIES) { slot_complete(c, s, 0xffff, 0); ++failed; continue; }
        s->t_submit = tsc();
        push_sqe(c, &c->ioq, s->sqe, 1);
        ++c->inflight;
        ++resubmitted;
    }
    kprintf("K64 nvme%u: recovered (%s mode), %u command(s) resubmitted, %u failed\n", c->idx, mode_names[c->mode], resubmitted, failed);
    irq_restore(f);
    return 0;
}

/* ---------------------------------------------------------------- data path */
/* Fills PRP1/PRP2 (and the slot's PRP list) for [buf, buf+bytes). */
static int build_prp(nvme_slot_t *s, const void *buf, uint32_t bytes)
{
    uint64_t va = (uint64_t)buf, pa = blk_kva_to_pa(buf), first;
    unsigned n = 0;
    if (!pa || (pa & 3)) return -1;
    s->sqe[6] = (uint32_t)pa; s->sqe[7] = (uint32_t)(pa >> 32);
    s->sqe[8] = s->sqe[9] = 0;
    first = PAGE_SIZE - (va & 0xfff);
    if (bytes <= first) return 0;
    bytes -= (uint32_t)first;
    va = (va & ~0xfffull) + PAGE_SIZE;
    if (bytes <= PAGE_SIZE) {
        pa = blk_kva_to_pa((void *)va);
        if (!pa) return -1;
        s->sqe[8] = (uint32_t)pa; s->sqe[9] = (uint32_t)(pa >> 32);
        return 0;
    }
    while (bytes) {
        if (n >= PAGE_SIZE / 8) return -1;
        pa = blk_kva_to_pa((void *)va);
        if (!pa) return -1;
        s->prp[n++] = pa;
        bytes -= bytes < PAGE_SIZE ? bytes : (uint32_t)PAGE_SIZE;
        va += PAGE_SIZE;
    }
    s->sqe[8] = (uint32_t)s->prp_pa; s->sqe[9] = (uint32_t)(s->prp_pa >> 32);
    return 0;
}

static void prep_rw(nvme_ns_t *ns, nvme_slot_t *s, int write, uint64_t lba, unsigned count)
{
    memset(s->sqe, 0, sizeof s->sqe);
    s->sqe[0] = write ? OP_WRITE : OP_READ;
    s->sqe[1] = ns->nsid;
    s->sqe[10] = (uint32_t)lba; s->sqe[11] = (uint32_t)(lba >> 32);
    s->sqe[12] = (count - 1) & 0xffff;
}

static int finish(nvme_ctrl_t *c, nvme_slot_t *s, const char *what, uint64_t lba)
{
    const uint16_t st = s->status;
    if (st) kprintf("K64 nvme%u: %s lba %llu failed: sct %x sc %x%s\n", c->idx, what, lba, (st >> 8) & 7, st & 0xff,
                    st == 0xffff ? " (aborted)" : "");
    return st ? -1 : 0;
}

/* Is every byte of [buf, buf+bytes) in the kernel mappings? (a PRP needs the physical address of each page) */
static int kva_mapped(const void *buf, uint64_t bytes)
{
    uint64_t va = (uint64_t)buf & ~0xfffull;
    const uint64_t end = (uint64_t)buf + bytes;
    for (; va < end; va += PAGE_SIZE)
        if (!blk_kva_to_pa((const void *)va)) return 0;
    return 1;
}

/* Synchronous read/write: splits into commands of at most max_sectors and keeps them all in flight. A buffer that is
 * not 4-byte aligned (PRP1 requires it; the FAT32 reader reads whole sectors to odd offsets of a heap buffer) goes
 * through the slots' bounce pages, one page per command, still pipelined. */
static int ns_rw(nvme_ns_t *ns, int write, uint64_t lba, unsigned count, const void *buf)
{
    nvme_ctrl_t *c = ns->c;
    nvme_slot_t *fl[NVME_SLOTS];
    uint64_t fl_lba[NVME_SLOTS];
    uint8_t *fl_dst[NVME_SLOTS];
    uint32_t fl_bytes[NVME_SLOTS];
    unsigned head = 0, n = 0, done_sectors = 0;
    int rc = 0;
    const uint8_t *p = buf;
    const int bounce = ((uint64_t)buf & 3) != 0;
    const unsigned per_cmd = bounce ? (unsigned)(PAGE_SIZE >> ns->lba_shift) : ns->max_sectors;
    if (c->dead || !per_cmd) return -1;
    if (!kva_mapped(buf, (uint64_t)count << ns->lba_shift)) {
        kprintf("K64 nvme%u: buffer %p is not a mapped kernel address\n", c->idx, buf);
        return -1;
    }
    arm_intx(c);
    while (done_sectors < count || n) {
        nvme_slot_t *s = 0;
        if (done_sectors < count && !rc) s = n ? slot_try(c) : slot_get(c);
        if (s) {
            const unsigned chunk = count - done_sectors < per_cmd ? count - done_sectors : per_cmd;
            const uint32_t bytes = chunk << ns->lba_shift;
            uint8_t *src = (uint8_t *)p + ((uint64_t)done_sectors << ns->lba_shift);
            const unsigned k = (head + n) % NVME_SLOTS;
            prep_rw(ns, s, write, lba + done_sectors, chunk);
            if (bounce && write) memcpy(s->bounce, src, bytes);
            if (build_prp(s, bounce ? s->bounce : src, bytes)) {
                kprintf("K64 nvme%u: cannot describe buffer %p for DMA\n", c->idx, buf);
                slot_put(c, s);
                rc = -1;
                continue;
            }
            io_submit(c, s, 1);
            fl[k] = s;
            fl_lba[k] = lba + done_sectors;
            fl_dst[k] = (bounce && !write) ? src : 0;
            fl_bytes[k] = bytes;
            ++n;
            done_sectors += chunk;
            continue;
        }
        if (!n) break;
        s = fl[head];
        if (wait_slot(c, s)) { s->status = 0xffff; }
        if (finish(c, s, write ? "write" : "read", fl_lba[head])) rc = -1;
        else if (fl_dst[head]) memcpy(fl_dst[head], s->bounce, fl_bytes[head]);
        slot_put(c, s);
        head = (head + 1) % NVME_SLOTS;
        --n;
    }
    return rc;
}

static int nv_read(blk_dev_t *d, uint64_t lba, unsigned count, void *buf) { return ns_rw(d->priv, 0, lba, count, buf); }
static int nv_write(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf) { return ns_rw(d->priv, 1, lba, count, buf); }

static int simple_cmd(nvme_ns_t *ns, nvme_slot_t *s, const char *what)
{
    nvme_ctrl_t *c = ns->c;
    int rc;
    io_submit(c, s, 1);
    rc = wait_slot(c, s) ? -1 : finish(c, s, what, 0);
    slot_put(c, s);
    return rc;
}

static int nv_flush(blk_dev_t *d)
{
    nvme_ns_t *ns = d->priv;
    nvme_slot_t *s;
    if (!ns->c->vwc) return 0;                          /* no volatile write cache: writes are durable on completion */
    if (ns->c->dead) return -1;
    s = slot_get(ns->c);
    if (!s) return -1;
    memset(s->sqe, 0, sizeof s->sqe);
    s->sqe[0] = OP_FLUSH;
    s->sqe[1] = ns->nsid;
    return simple_cmd(ns, s, "flush");
}

static int nv_discard(blk_dev_t *d, uint64_t lba, unsigned count)
{
    nvme_ns_t *ns = d->priv;
    nvme_slot_t *s;
    if (ns->c->dead) return -1;
    s = slot_get(ns->c);
    if (!s) return -1;
    memset(s->sqe, 0, sizeof s->sqe);
    s->prp[0] = (uint64_t)count << 32;                  /* range 0: context attributes 0, NLB */
    s->prp[1] = lba;                                    /* starting LBA */
    s->sqe[0] = OP_DSM;
    s->sqe[1] = ns->nsid;
    s->sqe[6] = (uint32_t)s->prp_pa; s->sqe[7] = (uint32_t)(s->prp_pa >> 32);
    s->sqe[10] = 0;                                     /* one range */
    s->sqe[11] = 1u << 2;                               /* AD: deallocate */
    return simple_cmd(ns, s, "dsm");
}

/* ---------------------------------------------------------------- async */
static void worker(void *arg)
{
    nvme_ctrl_t *c = arg;
    for (;;) {
        nvme_slot_t *s;
        uint64_t f;
        unsigned i;
        sem_wait_timeout(&c->worker_sem, 20);
        for (;;) {
            f = irq_save();
            s = c->done_head;
            if (s) { c->done_head = s->next_done; if (!c->done_head) c->done_tail = 0; }
            irq_restore(f);
            if (!s) break;
            {
                const blk_done_fn cb = s->cb;
                void *ctx = s->cb_ctx;
                const int st = s->status ? -1 : 0;
                if (s->status) kprintf("K64 nvme%u: async command %x failed: status %x\n", c->idx, s->sqe[0] & 0xff, s->status);
                slot_put(c, s);
                cb(ctx, st);
            }
        }
        /* async commands have no waiter: look for lost interrupts and timeouts here */
        for (i = 0; i < NVME_SLOTS; ++i) {
            nvme_slot_t *t = &c->slot[i];
            if (t->busy && t->cb && !t->done && tsc_ms(t->t_submit) >= c->timeout_ms) {
                poll_once(c);
                if (!t->done) {
                    ++c->timeouts;
                    if (t->retries >= NVME_RETRIES) {
                        f = irq_save();
                        if (!t->done) slot_complete(c, t, 0xffff, 0);
                        irq_restore(f);
                    } else {
                        ctrl_recover(c, "async command timeout");
                    }
                }
                break;
            }
        }
        if (c->mode == MODE_POLL) poll_once(c);
    }
}

static int ns_async(nvme_ns_t *ns, int write, uint64_t lba, unsigned count, const void *buf, blk_done_fn done, void *ctx)
{
    nvme_ctrl_t *c = ns->c;
    nvme_slot_t *s;
    if (c->dead || !can_sleep() || c->mode == MODE_POLL || count > ns->max_sectors || ((uint64_t)buf & 3)) return -1;
    if (!c->worker) {
        const uint64_t f = irq_save();
        if (!c->worker) c->worker = thread_create("nvme", worker, c);
        irq_restore(f);
        if (!c->worker) return -1;
    }
    arm_intx(c);
    s = slot_get(c);
    if (!s) return -1;
    prep_rw(ns, s, write, lba, count);
    if (build_prp(s, buf, count << ns->lba_shift)) { slot_put(c, s); return -1; }
    s->cb = done;
    s->cb_ctx = ctx;
    io_submit(c, s, 1);
    return 0;
}

static int nv_read_async(blk_dev_t *d, uint64_t lba, unsigned count, void *buf, blk_done_fn done, void *ctx)
{
    return ns_async(d->priv, 0, lba, count, buf, done, ctx);
}
static int nv_write_async(blk_dev_t *d, uint64_t lba, unsigned count, const void *buf, blk_done_fn done, void *ctx)
{
    return ns_async(d->priv, 1, lba, count, buf, done, ctx);
}

/* ---------------------------------------------------------------- control */
/* Timeout self-test: a READ of 8 sectors at `lba` is put into the SQ without a doorbell write, so the controller never
 * sees it; the wait must time out, reset the controller and resubmit it; the data must then equal a normal read. */
static int timeout_test(nvme_ns_t *ns, uint64_t lba, uint64_t *out)
{
    nvme_ctrl_t *c = ns->c;
    const uint32_t saved = c->timeout_ms;
    const uint64_t resets0 = c->resets, timeouts0 = c->timeouts, t0 = tsc();
    const unsigned bytes = 8u << ns->lba_shift;
    uint8_t *a = kmalloc(bytes), *b = kmalloc(bytes);
    nvme_slot_t *s;
    int rc = -1;
    if (!a || !b || lba + 8 > ns->dev.sectors) { kfree(a); kfree(b); return -1; }
    memset(a, 0x5a, bytes);
    s = slot_get(c);
    if (s) {
        prep_rw(ns, s, 0, lba, 8);
        if (!build_prp(s, a, bytes)) {
            c->timeout_ms = 300;
            io_submit(c, s, 0);                         /* the lost doorbell */
            rc = wait_slot(c, s) ? -1 : finish(c, s, "timeout-test read", lba);
            c->timeout_ms = saved;
        }
        slot_put(c, s);
    }
    if (!rc) rc = ns_rw(ns, 0, lba, 8, b);
    if (!rc && memcmp(a, b, bytes)) { kprintf("K64 nvme%u: data after recovery differs\n", c->idx); rc = -1; }
    if (!rc && (c->resets == resets0 || c->timeouts == timeouts0)) rc = -1;
    kprintf("K64 nvme%u: timeout self-test %s: %llu timeout(s), %llu reset(s), %llu ms\n", c->idx, rc ? "FAILED" : "passed",
            c->timeouts - timeouts0, c->resets - resets0, tsc_ms(t0));
    if (out) { out[0] = c->timeouts - timeouts0; out[1] = c->resets - resets0; out[2] = tsc_ms(t0); }
    kfree(a);
    kfree(b);
    return rc;
}

static int wait_idle(nvme_ctrl_t *c)
{
    const uint64_t t0 = tsc();
    while (c->inflight) {
        poll_once(c);
        if (tsc_ms(t0) > c->timeout_ms) return -1;
        if (can_sleep()) thread_yield(); else relax();
    }
    return 0;
}

static int nv_control(blk_dev_t *d, unsigned op, uint64_t arg, uint64_t *out)
{
    nvme_ns_t *ns = d->priv;
    nvme_ctrl_t *c = ns->c;
    int rc;
    switch (op) {
    case BLK_CTL_RESET:
        mutex_lock(&c->admin_lock);
        rc = ctrl_recover(c, "requested");
        mutex_unlock(&c->admin_lock);
        if (out) out[0] = c->resets;
        return rc;
    case BLK_CTL_TIMEOUT_TEST:
        mutex_lock(&c->admin_lock);
        rc = timeout_test(ns, arg, out);
        mutex_unlock(&c->admin_lock);
        return rc;
    case BLK_CTL_IRQ_MODE: {
        const int want = arg == 0 ? (c->has_msix ? MODE_MSIX : MODE_INTX) : arg == 1 ? MODE_INTX : MODE_POLL;
        if (arg > 2) return -1;
        mutex_lock(&c->admin_lock);
        if (wait_idle(c)) { mutex_unlock(&c->admin_lock); return -1; }
        c->want_mode = want;
        {
            const uint64_t f = irq_save();
            apply_mode(c, want);
            irq_restore(f);
        }
        arm_intx(c);
        mutex_unlock(&c->admin_lock);
        kprintf("K64 nvme%u: completion mode now %s\n", c->idx, mode_names[c->mode]);
        if (out) out[0] = (uint64_t)c->mode;
        return (c->mode == MODE_INTX && c->intx_line < 0) ? -1 : 0;
    }
    case BLK_CTL_STATS:
        if (out) { out[0] = c->irqs; out[1] = c->timeouts; out[2] = c->resets; out[3] = c->max_inflight; }
        return 0;
    case BLK_CTL_ERROR_TEST: {                          /* READ past the namespace end: expect LBA Out of Range (0/80h) */
        nvme_slot_t *s = slot_get(c);
        uint16_t st;
        uint8_t *b = kmalloc(1u << ns->lba_shift);
        if (!s || !b) { if (s) slot_put(c, s); kfree(b); return -1; }
        prep_rw(ns, s, 0, d->sectors + 8, 1);
        rc = build_prp(s, b, 1u << ns->lba_shift);
        if (!rc) {
            io_submit(c, s, 1);
            rc = wait_slot(c, s);
        }
        st = s->status;
        slot_put(c, s);
        if (!rc) rc = ns_rw(ns, 0, 0, 1, b);            /* the queue must still work afterwards */
        kfree(b);
        kprintf("K64 nvme%u: error self-test: out-of-range read -> sct %x sc %x, then read of LBA 0 -> %d\n", c->idx,
                (st >> 8) & 7, st & 0xff, rc);
        if (out) { out[0] = st; out[1] = (uint64_t)(int64_t)rc; }
        return (!rc && (st & 0x7ff) == 0x0080) ? 0 : -1;          /* DNR (bit 14) may be set */
    }
    case BLK_CTL_SET_TIMEOUT_MS:
        if (arg < 10 || arg > 600000) return -1;
        c->timeout_ms = (uint32_t)arg;
        return 0;
    default:
        return -2;
    }
}

/* ---------------------------------------------------------------- probe */
static int identify(nvme_ctrl_t *c, uint32_t cns, uint32_t nsid)
{
    uint32_t sqe[16];
    memset(sqe, 0, sizeof sqe);
    memset(c->idbuf, 0, PAGE_SIZE);
    sqe[0] = ADM_IDENTIFY;
    sqe[1] = nsid;
    sqe[6] = (uint32_t)c->idbuf_pa; sqe[7] = (uint32_t)(c->idbuf_pa >> 32);
    sqe[10] = cns;
    return admin_cmd(c, sqe, 0);
}

static void add_namespace(nvme_ctrl_t *c, uint32_t nsid)
{
    const uint8_t *id = (const uint8_t *)c->idbuf;
    nvme_ns_t *ns;
    uint64_t nsze;
    unsigned fmt, lbads, ms, k;
    if (c->nns >= NVME_MAX_NS || identify(c, 0, nsid)) return;
    nsze = *(const uint64_t *)id;
    fmt = id[26] & 0x0f;
    ms = *(const uint16_t *)(id + 128 + 4 * fmt);
    lbads = id[128 + 4 * fmt + 2];
    if (!nsze) return;
    if (ms || lbads < 9 || lbads > 12) {
        kprintf("K64 nvme%u: namespace %u skipped: LBA format %u has %u-byte metadata / 2^%u-byte blocks\n", c->idx, nsid, fmt, ms, lbads);
        return;
    }
    ns = &c->ns[c->nns++];
    memset(ns, 0, sizeof *ns);
    ns->c = c;
    ns->nsid = nsid;
    ns->lba_shift = lbads;
    ns->max_sectors = c->mdts_bytes >> lbads;
    if (ns->max_sectors > 0xffffu + 1) ns->max_sectors = 0x10000;
    k = 0;
    ns->dev.name[k++] = 'n'; ns->dev.name[k++] = 'v'; ns->dev.name[k++] = 'm'; ns->dev.name[k++] = 'e';
    ns->dev.name[k++] = (char)('0' + c->idx);
    ns->dev.name[k++] = 'n';
    if (nsid >= 10) ns->dev.name[k++] = (char)('0' + nsid / 10 % 10);
    ns->dev.name[k++] = (char)('0' + nsid % 10);
    ns->dev.name[k] = 0;
    ns->dev.sector_size = 1u << lbads;
    ns->dev.sectors = nsze;
    ns->dev.flags = (c->vwc ? BLK_F_FLUSH : 0) | ((c->oncs & 4) ? BLK_F_DISCARD : 0);
    ns->dev.read = nv_read;
    ns->dev.write = nv_write;
    ns->dev.flush = nv_flush;
    ns->dev.read_async = nv_read_async;
    ns->dev.write_async = nv_write_async;
    ns->dev.discard = (c->oncs & 4) ? nv_discard : 0;
    ns->dev.control = nv_control;
    ns->dev.priv = ns;
    ns->dev.driver = "nvme";
    ns->dev.irq_mode = mode_names[c->mode];
    memcpy(ns->dev.model, c->model, sizeof ns->dev.model);
    memcpy(ns->dev.serial, c->serial, sizeof ns->dev.serial);
    ns->dev.queue_depth = NVME_SLOTS;
    ns->dev.max_sectors = ns->max_sectors;
    kprintf("K64 nvme%u: namespace %u: %llu blocks of %u bytes (%llu MiB), LBA format %u, %u blocks per command\n", c->idx, nsid,
            nsze, 1u << lbads, (nsze << lbads) >> 20, fmt, ns->max_sectors);
}

static int ctrl_init(nvme_ctrl_t *c, const pci_dev_t *pd)
{
    uint64_t bar, size;
    int is_io;
    unsigned i, mps_min;
    const uint8_t *id;
    c->pci = *pd;
    c->intx_line = -1;
    c->timeout_ms = 5000;
    mutex_init(&c->admin_lock);
    sem_init(&c->slot_sem, 0);
    sem_init(&c->worker_sem, 0);
    bar = pci_bar(pd, 0, &size, &is_io);
    if (!bar || is_io || size < 0x2000) { kprintf("K64 nvme%u: BAR0 unusable (%llx, %llu)\n", c->idx, bar, size); return -1; }
    pci_enable(pd, 0, 1, 1);
    c->regs = mmio_map(bar, size);
    if (!c->regs) return -1;
    c->cap = rd64(c, R_CAP);
    c->vs = rd32(c, R_VS);
    c->dstrd = (uint32_t)(c->cap >> 32) & 0xf;
    c->cap_to_ms = (uint32_t)((c->cap >> 24) & 0xff) * 500u;
    if (c->cap_to_ms < 500) c->cap_to_ms = 500;
    mps_min = (unsigned)(c->cap >> 48) & 0xf;
    if (!((c->cap >> 37) & 1) || mps_min > 0 || (c->cap & 0xffff) + 1 < NVME_QD) {
        kprintf("K64 nvme%u: unsupported CAP %llx (NVM set, 4 KiB pages and %u-entry queues needed)\n", c->idx, c->cap, NVME_QD);
        return -1;
    }
    c->idbuf_pa = pmm_alloc();
    if (!c->idbuf_pa) return -1;
    c->idbuf = (uint64_t *)p2v(c->idbuf_pa);
    for (i = 0; i < NVME_SLOTS; ++i) {
        const uint64_t bpa = pmm_alloc();
        c->slot[i].prp_pa = pmm_alloc();
        if (!c->slot[i].prp_pa || !bpa) return -1;
        c->slot[i].prp = (uint64_t *)p2v(c->slot[i].prp_pa);
        c->slot[i].bounce = (uint8_t *)p2v(bpa);
    }
    c->free_mask = NVME_SLOTS >= 32 ? 0xffffffffu : (1u << NVME_SLOTS) - 1;
    if (ctrl_enable(c)) return -1;
    if (identify(c, 1, 0)) return -1;
    id = (const uint8_t *)c->idbuf;
    copy_str(c->serial, id + 4, 20);
    copy_str(c->model, id + 24, 40);
    copy_str(c->fw, id + 64, 8);
    c->mdts_bytes = id[77] ? (uint32_t)(PAGE_SIZE << id[77]) : NVME_MAX_XFER;
    if (c->mdts_bytes > NVME_MAX_XFER || !c->mdts_bytes) c->mdts_bytes = NVME_MAX_XFER;
    c->nn = *(const uint32_t *)(id + 516);
    c->oncs = *(const uint16_t *)(id + 520);
    c->vwc = id[525] & 1;
    kprintf("K64 nvme%u: %x:%x.%x %x:%x \"%s\" sn \"%s\" fw \"%s\" NVMe %u.%u, MQES %u, DSTRD %u, TO %u ms, MDTS %u KiB, NN %u, "
            "ONCS %x, VWC %u\n", c->idx, pd->bus, pd->dev, pd->fn, pd->vendor, pd->device, c->model, c->serial, c->fw,
            c->vs >> 16, (c->vs >> 8) & 0xff, (unsigned)(c->cap & 0xffff) + 1, c->dstrd, c->cap_to_ms, c->mdts_bytes >> 10,
            c->nn, c->oncs, c->vwc);
    /* Interrupts: MSI-X when the function has it, else INTx (armed lazily), polling while neither is live. */
    c->has_msix = pci_msix_init(pd, &c->msix) == 0 && c->msix.entries >= 2 && pci_msix_bind(&c->msix, 0, isr, c) >= 0 &&
                  pci_msix_bind(&c->msix, 1, isr, c) >= 0;
    c->want_mode = c->has_msix ? MODE_MSIX : MODE_INTX;
    apply_mode(c, c->want_mode);
    if (create_io_queues(c)) return -1;
    kprintf("K64 nvme%u: completion by %s%s (MSI-X table %u entries, vectors %x/%x, legacy line %u)\n", c->idx, mode_names[c->mode],
            c->mode == MODE_INTX && c->intx_line < 0 ? " (armed at first use)" : "", c->msix.entries, c->msix.vector[0],
            c->msix.vector[1], pd->irq_line);
    /* namespaces: active list (CNS 2), else probe 1..NN */
    {
        uint32_t list[NVME_MAX_NS], nlist = 0;
        if (!identify(c, 2, 0)) {
            const uint32_t *l = (const uint32_t *)c->idbuf;
            for (i = 0; i < 1024 && l[i] && nlist < NVME_MAX_NS; ++i) list[nlist++] = l[i];
        } else {
            for (i = 1; i <= c->nn && nlist < NVME_MAX_NS; ++i) list[nlist++] = i;
        }
        for (i = 0; i < nlist; ++i) add_namespace(c, list[i]);
    }
    for (i = 0; i < c->nns; ++i) c->ns[i].dev.irq_mode = mode_names[c->mode];
    return c->nns ? 0 : -1;
}

int nvme_blk_init(void)
{
    pci_dev_t all[32];
    const unsigned n = pci_enumerate(all, 32);
    unsigned i, k;
    int registered = 0;
    for (i = 0; i < n && nctrl < NVME_MAX_CTRL; ++i) {
        nvme_ctrl_t *c;
        if (all[i].class_code != 1 || all[i].subclass != 8 || all[i].prog_if != 2) continue;
        c = &ctrls[nctrl];
        memset(c, 0, sizeof *c);
        c->idx = nctrl;
        if (ctrl_init(c, &all[i])) { kprintf("K64 nvme%u: initialisation failed\n", c->idx); continue; }
        ++nctrl;
        for (k = 0; k < c->nns; ++k)
            if (!blk_register(&c->ns[k].dev)) ++registered;
    }
    if (!nctrl) kprintf("K64 nvme: no NVMe controller (class 010802) on PCI bus 0\n");
    return registered;
}
#endif
