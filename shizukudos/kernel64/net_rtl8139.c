/* SPDX-License-Identifier: GPL-2.0-only
 * Realtek RTL8139 Ethernet driver (PCI 10ec:8139, I/O-port BAR0), the NIC of the QEMU test profile
 * `-machine pc -device rtl8139,netdev=n0 -netdev user,...`.
 *
 * Chosen over e1000 because the programming model is small: one I/O BAR, one linear receive ring the chip DMAs into
 * (with the WRAP bit a frame that crosses the ring end continues contiguously behind it), and four transmit descriptors.
 * Only the SHZ_STANDALONE profile has a NIC: under the Supervisor no device is passed through and the port I/O of the PCI
 * mechanism traps, so there this file compiles to a "no NIC" driver and touches no hardware.
 *
 * Interrupts: the PIC vector of the PCI interrupt line is registered with irq_register(). The handler runs with
 * interrupts off in whatever thread was interrupted and the kernel sends the EOI after it returns, so it only reads and
 * acknowledges ISR and posts g_nic_kick; the "net" thread drains the ring (nic_rx_drain).
 * Limits: no power management, no multicast filter (broadcast + our unicast address only), 10/100 autonegotiation is
 * left to the chip.
 */
#include "net.h"
#include "pci.h"

ksem_t g_nic_kick;
static uint32_t stats[6];

#ifndef SHZ_STANDALONE
int nic_probe_init(uint8_t mac[6]) { (void)mac; return -1; }
int nic_send(const uint8_t *frame, uint32_t len) { (void)frame; (void)len; return -1; }
int nic_link_up(void) { return 0; }
unsigned nic_rx_drain(void (*cb)(const uint8_t *, uint32_t)) { (void)cb; return 0; }
uint32_t nic_stat(unsigned which) { return which < 6 ? stats[which] : 0; }
#else

#define RTL_VENDOR 0x10ec
#define RTL_DEVICE 0x8139
enum { R_IDR0 = 0x00, R_TSD0 = 0x10, R_TSAD0 = 0x20, R_RBSTART = 0x30, R_CR = 0x37, R_CAPR = 0x38, R_IMR = 0x3c, R_ISR = 0x3e,
       R_TCR = 0x40, R_RCR = 0x44, R_CFG1 = 0x52, R_BMSR = 0x64 };
enum { CR_BUFE = 0x01, CR_TE = 0x04, CR_RE = 0x08, CR_RST = 0x10 };
enum { ISR_ROK = 0x01, ISR_RER = 0x02, ISR_TOK = 0x04, ISR_TER = 0x08, ISR_RXOVW = 0x10, ISR_PUN = 0x20, ISR_FOVW = 0x40,
       ISR_SERR = 0x8000 };
enum { TSD_OWN = 1 << 13, TSD_TUN = 1 << 14, TSD_TOK = 1 << 15 };
/* RCR.RBLEN = 2: 32 KiB + 16. With WRAP set a frame that crosses the ring end continues contiguously behind it. RBLEN = 3 (64 KiB)
 * is avoided on purpose: QEMU's model splits such a frame across the ring end for that size only, real chips do not, so the
 * two would need different receive code. */
#define RX_LEN 32768u
#define RX_ALLOC (RX_LEN + 16 + 1536 + 16)
#define TX_SLOT 2048u

static uint16_t io;
static volatile uint8_t *rx_buf;
static uint8_t *tx_buf[4];
static uint32_t rx_off, tx_cur;
static uint8_t tx_busy[4];
static int present;
static volatile int kick_pending;

static void rtl_irq(struct regs *r)
{
    unsigned guard;
    (void)r;
    for (guard = 0; guard < 64; ++guard) {
        const uint16_t isr = k_inw((uint16_t)(io + R_ISR));
        if (!isr || isr == 0xffff)
            break;
        k_outw((uint16_t)(io + R_ISR), isr);          /* write-1-to-clear: bits raised meanwhile stay pending */
        ++stats[5];
        if (isr & (ISR_RXOVW | ISR_FOVW))
            ++stats[2];
    }
    if (!kick_pending) {
        kick_pending = 1;
        sem_post(&g_nic_kick);
    }
}

static uint64_t phys(const void *p) { return v2p_direct((uint64_t)p); }

int nic_probe_init(uint8_t mac[6])
{
    pci_dev_t d;
    uint64_t size = 0, base;
    int is_io = 0;
    unsigned i, spin;
    if (present)
        return 0;
    if (pci_find(RTL_VENDOR, RTL_DEVICE, &d))
        return -1;
    base = pci_bar(&d, 0, &size, &is_io);
    if (!is_io || !base || base > 0xfff0) {
        kprintf("K64 net: rtl8139 BAR0 is not an I/O BAR (%llx)\n", base);
        return -1;
    }
    io = (uint16_t)base;
    rx_buf = kmalloc(RX_ALLOC);
    tx_buf[0] = kmalloc(TX_SLOT * 4 + 16);
    if (!rx_buf || !tx_buf[0]) {
        kprintf("K64 net: rtl8139 buffer allocation failed\n");
        return -1;
    }
    for (i = 1; i < 4; ++i)
        tx_buf[i] = tx_buf[0] + TX_SLOT * i;
    memset((void *)rx_buf, 0, RX_ALLOC);
    pci_enable(&d, 1, 0, 1);                            /* I/O space + bus mastering (DMA) */
    k_outb((uint16_t)(io + R_CFG1), 0x00);              /* power on */
    k_outb((uint16_t)(io + R_CR), CR_RST);
    for (spin = 0; spin < 1000000 && (k_inb((uint16_t)(io + R_CR)) & CR_RST); ++spin)
        ;
    if (k_inb((uint16_t)(io + R_CR)) & CR_RST) {
        kprintf("K64 net: rtl8139 reset did not complete\n");
        return -1;
    }
    for (i = 0; i < 6; ++i)
        mac[i] = k_inb((uint16_t)(io + R_IDR0 + i));
    k_outl((uint16_t)(io + R_RBSTART), (uint32_t)phys((const void *)rx_buf));
    for (i = 0; i < 4; ++i)
        k_outl((uint16_t)(io + R_TSAD0 + 4 * i), (uint32_t)phys(tx_buf[i]));
    /* RCR: AB | APM (broadcast + our unicast), WRAP, RBLEN=32K, unlimited DMA burst, no early receive threshold. */
    k_outl((uint16_t)(io + R_RCR), 0x08u | 0x02u | 0x80u | (2u << 11) | (7u << 8) | (7u << 13));
    k_outl((uint16_t)(io + R_TCR), 0x03000700u);        /* IFG 96 ns, unlimited DMA burst */
    k_outb((uint16_t)(io + R_CR), CR_RE | CR_TE);
    k_outw((uint16_t)(io + R_CAPR), 0xfff0);            /* read pointer starts at -16 */
    rx_off = 0;
    tx_cur = 0;
    irq_register(standalone_irq_vector(d.irq_line), rtl_irq);
    k_outw((uint16_t)(io + R_IMR), ISR_ROK | ISR_RER | ISR_RXOVW | ISR_PUN | ISR_FOVW | ISR_SERR);
    standalone_irq_unmask(d.irq_line);
    present = 1;
    kprintf("K64 net: rtl8139 io=%x irq=%u mac=%x:%x:%x:%x:%x:%x link=%d\n", (unsigned)io, (unsigned)d.irq_line, mac[0], mac[1],
            mac[2], mac[3], mac[4], mac[5], nic_link_up());
    return 0;
}

int nic_link_up(void)
{
    return present ? (k_inw((uint16_t)(io + R_BMSR)) >> 2) & 1 : 0;
}

int nic_send(const uint8_t *frame, uint32_t len)
{
    const uint32_t i = tx_cur;
    const uint64_t t0 = ticks_now();
    if (!present || len < ETH_HLEN || len > 1514)
        return -1;
    while (tx_busy[i]) {                                /* wait for the chip to release this descriptor */
        if (k_inl((uint16_t)(io + R_TSD0 + 4 * i)) & (TSD_OWN | TSD_TOK | TSD_TUN)) {
            tx_busy[i] = 0;
            break;
        }
        if (ticks_now() - t0 > 100) {
            ++stats[4];
            return -1;
        }
        thread_yield();
    }
    memcpy(tx_buf[i], frame, len);
    if (len < 60) {                                     /* the chip does not pad runt frames */
        memset(tx_buf[i] + len, 0, 60 - len);
        len = 60;
    }
    tx_busy[i] = 1;
    tx_cur = (i + 1) & 3;
    k_outl((uint16_t)(io + R_TSD0 + 4 * i), len | 0x00080000u);   /* size, early TX threshold 256 bytes; writing starts DMA */
    ++stats[1];
    return 0;
}

static void rx_reset(void)
{
    k_outb((uint16_t)(io + R_CR), CR_TE);               /* RE off, then on: the chip restarts at the ring start */
    k_outb((uint16_t)(io + R_CR), CR_RE | CR_TE);
    k_outl((uint16_t)(io + R_RBSTART), (uint32_t)phys((const void *)rx_buf));
    k_outl((uint16_t)(io + R_RCR), 0x08u | 0x02u | 0x80u | (2u << 11) | (7u << 8) | (7u << 13));
    rx_off = 0;
    k_outw((uint16_t)(io + R_CAPR), 0xfff0);
}

unsigned nic_rx_drain(void (*cb)(const uint8_t *, uint32_t))
{
    unsigned n = 0;
    uint64_t f;
    if (!present)
        return 0;
    f = irq_save();
    kick_pending = 0;                                   /* an interrupt from here on posts a fresh kick */
    irq_restore(f);
    while (!(k_inb((uint16_t)(io + R_CR)) & CR_BUFE)) {
        volatile uint8_t *h = rx_buf + rx_off;
        const uint16_t status = (uint16_t)(h[0] | (h[1] << 8)), len = (uint16_t)(h[2] | (h[3] << 8));
        if (!(status & 1) || len < 4 + 14 || len > 4 + 1518 + 4) {      /* RER / runt / giant: the ring is out of sync */
            ++stats[3];
            rx_reset();
            break;
        }
        cb((const uint8_t *)h + 4, (uint32_t)len - 4);
        rx_off = (rx_off + len + 4 + 3) & ~3u;
        if (rx_off >= RX_LEN)
            rx_off -= RX_LEN;
        k_outw((uint16_t)(io + R_CAPR), (uint16_t)(rx_off - 16));
        ++stats[0];
        ++n;
    }
    return n;
}

uint32_t nic_stat(unsigned which) { return which < 6 ? stats[which] : 0; }
#endif
