/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 Intel AC97 (ICH, PCI 8086:2415 class 04/01) playback backend. SHZ_STANDALONE only: under the Supervisor no
 * device is passed through and the I/O ports are trapped, so no backend exists there and audio reports present=0.
 *
 * Register layout from the Intel ICH AC97 programmer's model as modelled by QEMU's hw/audio/ac97.c (read as a
 * reference only, no code copied): NAM = BAR0 (codec mixer), NABM = BAR1 (bus master). PCM-out engine at NABM+0x10:
 * BDBAR 0x10, CIV 0x14, LVI 0x15, SR 0x16, PICB 0x18, CR 0x1b; GLOB_CNT 0x2c, GLOB_STA 0x30. A buffer descriptor is
 * {uint32 address, uint32 ctl}: ctl low 16 bits = 16-bit SAMPLES, bit 31 IOC.
 *
 * DMA memory: one BDL page and 32 data pages from pmm_alloc(), each verified to end at or below 4 GiB (never truncated),
 * kept for the kernel lifetime so a failed stop proof can never release memory a live engine might still read.
 */
#include "audio.h"
#include "pci.h"
#ifdef SHZ_STANDALONE
#define NABM_PO_BDBAR 0x10
#define NABM_PO_CIV 0x14
#define NABM_PO_LVI 0x15
#define NABM_PO_SR 0x16
#define NABM_PO_PICB 0x18
#define NABM_PO_CR 0x1b
#define NABM_GLOB_CNT 0x2c
#define NABM_GLOB_STA 0x30
#define NAM_RESET 0x00
#define NAM_MASTER 0x02
#define NAM_PCM_OUT 0x18
#define NAM_POWER 0x26
#define NAM_EXT_CTRL 0x2a
#define CR_RUN 0x01
#define CR_RR 0x02
#define CR_LVBIE 0x04
#define CR_FEIE 0x08
#define CR_IOCE 0x10
#define SR_DCH 0x01
#define SR_W1C 0x1c                                /* LVBCI | BCIS | FIFOE */

static pci_dev_t dev;
static uint16_t nam, nabm;
static int ready, tried, irq_on, bus_master;
static uint64_t bdl_pa;
static uint64_t buf_pa[AUDIO_RING_SLOTS];
static volatile uint32_t irqs;

static uint8_t rd8(unsigned r) { return k_inb((uint16_t)(nabm + r)); }
static uint16_t rd16(unsigned r) { return k_inw((uint16_t)(nabm + r)); }
static void wr8(unsigned r, uint8_t v) { k_outb((uint16_t)(nabm + r), v); }
static void wr16(unsigned r, uint16_t v) { k_outw((uint16_t)(nabm + r), v); }
static void wr32(unsigned r, uint32_t v) { k_outl((uint16_t)(nabm + r), v); }

static int spin_sr(uint16_t mask, int want_set)
{
    unsigned i;
    for (i = 0; i < 20000; ++i)
        if (!!(rd16(NABM_PO_SR) & mask) == want_set) return 1;
    return 0;
}

static int alloc_dma(void)
{
    unsigned i;
    bdl_pa = pmm_alloc();
    if (!bdl_pa || bdl_pa + PAGE_SIZE - 1 > 0xffffffffull) goto fail;
    for (i = 0; i < AUDIO_RING_SLOTS; ++i) {
        buf_pa[i] = pmm_alloc();
        if (!buf_pa[i] || buf_pa[i] + PAGE_SIZE - 1 > 0xffffffffull) goto fail;
    }
    return 0;
fail:                                               /* engine never ran: safe to hand every page back */
    for (i = 0; i < AUDIO_RING_SLOTS; ++i) if (buf_pa[i]) { pmm_free(buf_pa[i]); buf_pa[i] = 0; }
    if (bdl_pa) { pmm_free(bdl_pa); bdl_pa = 0; }
    return -1;
}

static int ac97_probe(audio_hw_info *info)
{
    pci_dev_t all[32];
    unsigned n, i, t;
    uint64_t sz0 = 0, sz1 = 0, b0, b1;
    int io0 = 0, io1 = 0;
    if (ready) goto fill;
    if (tried) return -1;                           /* one attempt per boot: a failed codec is not retried */
    tried = 1;
    n = pci_enumerate(all, 32);
    for (i = 0; i < n; ++i)
        if (all[i].vendor == 0x8086 && all[i].device == 0x2415 && all[i].class_code == 4 && all[i].subclass == 1) break;
    if (i == n) return -1;
    dev = all[i];
    if (pci_claimed_by(&dev)) return -1;
    b0 = pci_bar(&dev, 0, &sz0, &io0);
    b1 = pci_bar(&dev, 1, &sz1, &io1);
    if (!io0 || !io1 || !b0 || !b1 || sz0 < 0x40 || sz1 < 0x40 || b0 + sz0 > 0x10000 || b1 + sz1 > 0x10000) return -1;
    nam = (uint16_t)b0; nabm = (uint16_t)b1;
    if (alloc_dma()) return -1;
    pci_enable(&dev, 1, 0, 0);                      /* ports only; bus mastering is enabled by the first start() */
    k_outl((uint16_t)(nabm + NABM_GLOB_CNT), 0x3);  /* cold reset released, global interrupt enable */
    for (t = 0; t < 500 && !(k_inl((uint16_t)(nabm + NABM_GLOB_STA)) & 0x100); ++t) thread_sleep_ms(1);
    if (t == 500) goto fail;
    k_outw((uint16_t)(nam + NAM_RESET), 0);
    for (t = 0; t < 500 && (k_inw((uint16_t)(nam + NAM_POWER)) & 0xf) != 0xf; ++t) thread_sleep_ms(1);
    if (t == 500) goto fail;
    k_outw((uint16_t)(nam + NAM_EXT_CTRL), 0);      /* variable rate off: the engine plays fixed 48 kHz */
    k_outw((uint16_t)(nam + NAM_MASTER), 0x0000);   /* 0 dB, unmuted */
    k_outw((uint16_t)(nam + NAM_PCM_OUT), 0x0808);
    if ((k_inw((uint16_t)(nam + NAM_MASTER)) & 0x8000) || (k_inw((uint16_t)(nam + NAM_PCM_OUT)) & 0x8000)) goto fail;
    pci_claim(&dev, "audio_ac97 (Intel AC97 playback)");
    ready = 1;
fill:
    info->vendor = dev.vendor; info->device = dev.device; info->irq_line = irq_on ? dev.irq_line : 0xffffffffu;
    return 0;
fail:                                               /* engine never started: release DMA pages */
    for (i = 0; i < AUDIO_RING_SLOTS; ++i) if (buf_pa[i]) { pmm_free(buf_pa[i]); buf_pa[i] = 0; }
    pmm_free(bdl_pa); bdl_pa = 0;
    return -1;
}

static uint8_t *ac97_slot_cpu(unsigned s) { return s < AUDIO_RING_SLOTS && buf_pa[s] ? (uint8_t *)p2v(buf_pa[s]) : 0; }

static void ac97_slot_program(unsigned s, uint32_t samples)
{
    volatile uint32_t *bd = (volatile uint32_t *)p2v(bdl_pa);
    if (s >= AUDIO_RING_SLOTS || !samples || samples > 0xffff) return;
    bd[s * 2 + 0] = (uint32_t)buf_pa[s];            /* range proven <= UINT32_MAX in alloc_dma() */
    __asm__ volatile("" ::: "memory");
    bd[s * 2 + 1] = 0x80000000u | samples;
    __asm__ volatile("mfence" ::: "memory");
}

static void irq_fn(void *ctx)
{
    uint16_t sr;
    (void)ctx;
    if (!ready) return;
    sr = rd16(NABM_PO_SR);
    if (sr & SR_W1C) { wr16(NABM_PO_SR, sr & SR_W1C); ++irqs; }     /* acknowledge only; state is read from CIV/DCH */
}

static int ac97_irq_attach(void)
{
    const unsigned line = dev.irq_line;
    if (irq_on) return 0;
    if (!pci_intx_ready() || line == 0 || line >= 16 || line == 2) return -1;
    if (irq_handler_get(standalone_irq_vector(line))) return -1;    /* never take over a line another driver owns */
    if (pci_intx_attach(&dev, irq_fn, 0) < 0) return -1;
    irq_on = 1;
    return 0;
}

static void ac97_irq_detach(void)
{
    if (!irq_on) return;
    pci_intx_detach(&dev, irq_fn, 0);
    irq_on = 0;
}

static int ac97_start(unsigned lvi)
{
    if (!ready || lvi >= AUDIO_RING_SLOTS) return -1;
    if (!bus_master) { pci_enable(&dev, 1, 0, 1); bus_master = 1; }
    wr8(NABM_PO_CR, 0);
    wr32(NABM_PO_BDBAR, (uint32_t)bdl_pa);
    wr16(NABM_PO_SR, SR_W1C);
    wr8(NABM_PO_LVI, (uint8_t)lvi);
    wr8(NABM_PO_CR, CR_RUN | CR_IOCE | CR_LVBIE | CR_FEIE);
    return spin_sr(SR_DCH, 0) ? 0 : -1;
}

static int ac97_extend(unsigned lvi)
{
    const int halted = (rd16(NABM_PO_SR) & SR_DCH) && (rd8(NABM_PO_CR) & CR_RUN);   /* gated engine: resume by pause(0) */
    if (!ready || lvi >= AUDIO_RING_SLOTS) return -1;
    wr8(NABM_PO_LVI, (uint8_t)lvi);
    return halted && !spin_sr(SR_DCH, 0) ? -1 : 0;
}

static void ac97_position(audio_hw_pos *p)
{
    p->sr = rd16(NABM_PO_SR);                       /* DCH first: CIV read afterwards is final once it is set */
    p->civ = rd8(NABM_PO_CIV) & 31u;
    p->picb = rd16(NABM_PO_PICB);
}

static int ac97_pause(int pause)
{
    uint8_t cr = rd8(NABM_PO_CR);
    if (pause) { wr8(NABM_PO_CR, cr & (uint8_t)~CR_RUN); return spin_sr(SR_DCH, 1) ? 0 : -1; }
    wr8(NABM_PO_CR, cr | CR_RUN);
    return spin_sr(SR_DCH, 0) ? 0 : -1;
}

static int ac97_stop(void)
{
    unsigned i;
    if (!ready) return 0;
    wr8(NABM_PO_CR, 0);
    if (!spin_sr(SR_DCH, 1)) return -1;
    wr8(NABM_PO_CR, CR_RR);
    for (i = 0; i < 20000 && (rd8(NABM_PO_CR) & CR_RR); ++i) ;
    if (rd8(NABM_PO_CR) & (CR_RR | CR_RUN)) return -1;
    wr16(NABM_PO_SR, SR_W1C);
    return (rd16(NABM_PO_SR) & SR_DCH) ? 0 : -1;    /* inactive proven: halted, run clear, registers reset */
}

static uint32_t ac97_irq_count(void) { return irqs; }

/* Explicit VM fault-control preparation while the kernel is still healthy.
 * Uses the actual backend lifecycle, before fatal CLI. Ordinary boot never
 * calls this seam. Fatal playback below never probes or allocates. */
int ds_pcm_control_prepare(void)
{
    audio_hw_info info;
    if(ac97_probe(&info))return -1;
    uint8_t *p=ac97_slot_cpu(0);if(!p)return -1;
    memset(p,0,AUDIO_SLOT_BYTES);ac97_slot_program(0,AUDIO_SLOT_FRAMES*2);
    if(ac97_start(0)) {(void)ac97_stop();return -1;}
    return ac97_stop();
}

/* Fatal-only reuse of the retained backend. No allocator, PCI enumeration,
 * scheduler, locks, user memory, normal queue or completion callbacks. The
 * descriptor pages stay owned even when stop fails. DMA progress is evidence
 * of a running engine, never proof that a physical speaker is audible. */
static unsigned panic_pcm, panic_stalled;
static uint32_t panic_position;
int ds_pcm_panic_begin(void)
{
    static const uint16_t hz[12]={659,784,988,784,659,523,587,659,784,659,587,523};
    if(!ready || !bus_master || !bdl_pa || bdl_pa>UINT32_MAX-PAGE_SIZE || ac97_stop())return -1;
    for(unsigned s=0;s<31;s++) {
        if(!buf_pa[s] || buf_pa[s]>UINT32_MAX-PAGE_SIZE)return -1;
        int16_t *samples=(int16_t *)p2v(buf_pa[s]);
        unsigned half=24000u/hz[(s/3)%12];
        for(unsigned i=0;i<AUDIO_SLOT_FRAMES;i++) {
            int16_t v=((s*AUDIO_SLOT_FRAMES+i)/half)&1 ? 5000 : -5000;
            samples[i*2]=v;samples[i*2+1]=v;
        }
        ac97_slot_program(s,AUDIO_SLOT_FRAMES*2);
    }
    wr32(NABM_PO_BDBAR,(uint32_t)bdl_pa);wr16(NABM_PO_SR,SR_W1C);
    wr8(NABM_PO_LVI,30);wr8(NABM_PO_CR,CR_RUN); /* polled, no interrupt dependency */
    const uint16_t first=rd16(NABM_PO_PICB);
    for(unsigned i=0;i<200000;i++) {
        if(!(rd16(NABM_PO_SR)&SR_DCH) && rd16(NABM_PO_PICB)!=first) {panic_pcm=1;panic_stalled=0;panic_position=((uint32_t)rd8(NABM_PO_CIV)<<16)|rd16(NABM_PO_PICB);return 0;}
        __asm__ volatile("pause");
    }
    (void)ac97_stop();return -1;
}
int ds_pcm_panic_poll(void)
{
    if(!panic_pcm || rd16(NABM_PO_SR)==0xffff)return -1;
    if(rd16(NABM_PO_SR)&SR_DCH) {
        if(rd8(NABM_PO_CIV)!=30 || ac97_stop())return -1;
        wr32(NABM_PO_BDBAR,(uint32_t)bdl_pa);wr16(NABM_PO_SR,SR_W1C);
        wr8(NABM_PO_LVI,30);wr8(NABM_PO_CR,CR_RUN);
        if(!spin_sr(SR_DCH,0))return -1;
    }
    /* A run bit alone cannot establish continued DMA progress. The fatal
     * controller polls once per bounded tone interval; refuse a stalled engine
     * after four identical positions. This is not a calibrated time limit. */
    const uint32_t position=((uint32_t)rd8(NABM_PO_CIV)<<16)|rd16(NABM_PO_PICB);
    if(position==panic_position) {if(++panic_stalled>=4)return -1;}
    else {panic_position=position;panic_stalled=0;}
    return 0;
}
void ds_pcm_panic_stop(void) {(void)ac97_stop();panic_pcm=0;}

static const audio_backend ac97 = { ac97_probe, ac97_slot_cpu, ac97_slot_program, ac97_irq_attach, ac97_irq_detach,
                                    ac97_start, ac97_extend, ac97_position, ac97_pause, ac97_stop, ac97_irq_count };
const audio_backend *audio_backend_get(void) { return &ac97; }
#else
const audio_backend *audio_backend_get(void) { return 0; }
#endif
