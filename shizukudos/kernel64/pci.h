/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 PCI configuration access (legacy mechanism #1, ports 0xCF8/0xCFC), BAR decoding and MMIO mapping.
 * Used by device drivers (framebuffer, NIC). Only the SHZ_STANDALONE profile calls into it today: under the
 * Supervisor the I/O bitmap traps these ports and no device is passed through, so nothing here runs there.
 */
#ifndef K64_PCI_H
#define K64_PCI_H
#include "k64.h"

static inline void k_outb(uint16_t p, uint8_t v) { __asm__ volatile("outb %0, %1" : : "a"(v), "Nd"(p)); }
static inline void k_outw(uint16_t p, uint16_t v) { __asm__ volatile("outw %0, %1" : : "a"(v), "Nd"(p)); }
static inline void k_outl(uint16_t p, uint32_t v) { __asm__ volatile("outl %0, %1" : : "a"(v), "Nd"(p)); }
static inline uint8_t k_inb(uint16_t p) { uint8_t v; __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(p)); return v; }
static inline uint16_t k_inw(uint16_t p) { uint16_t v; __asm__ volatile("inw %1, %0" : "=a"(v) : "Nd"(p)); return v; }
static inline uint32_t k_inl(uint16_t p) { uint32_t v; __asm__ volatile("inl %1, %0" : "=a"(v) : "Nd"(p)); return v; }

typedef struct {
    uint8_t bus, dev, fn;
    uint16_t vendor, device;
    uint8_t class_code, subclass, prog_if, irq_line;
} pci_dev_t;

uint32_t pci_cfg_read32(const pci_dev_t *d, unsigned off);
void pci_cfg_write32(const pci_dev_t *d, unsigned off, uint32_t v);
/* All present functions on buses 0..7 (bus 0 plus bridged buses are not walked: QEMU pc/q35 endpoints are on bus 0). */
unsigned pci_enumerate(pci_dev_t *out, unsigned max);
int pci_find(uint16_t vendor, uint16_t device, pci_dev_t *out);
/* BAR `idx` (0..5): returns the base address (memory BARs may be 64-bit), *size by the write-ones probe, *is_io. 0 when unimplemented. */
uint64_t pci_bar(const pci_dev_t *d, unsigned idx, uint64_t *size, int *is_io);
void pci_enable(const pci_dev_t *d, int io, int mem, int bus_master);
/* Maps [pa, pa+size) uncached at DIRECT_MAP + pa (kernel only) and returns the virtual address; NULL on failure. */
void *mmio_map(uint64_t pa, uint64_t size);
void pci_log_devices(void);
/* Standalone-profile PIC control for a device's legacy IRQ line (0..15, PCI config byte 0x3c). standalone_irq_vector(irq) is
 * the IDT vector to pass to irq_register(); the kernel sends the EOI after the handler returns. */
#ifdef SHZ_STANDALONE
void standalone_irq_unmask(unsigned irq);
void standalone_irq_mask(unsigned irq);
unsigned standalone_irq_vector(unsigned irq);
#endif
#endif
