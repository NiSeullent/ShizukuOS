/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_PLATFORM_H
#define SHZ_PLATFORM_H
#include <stdint.h>
#include "../include/shz_info.h"

#define HOST_CS 0x08
#define HOST_DS 0x10
#define HOST_TR 0x18

extern uint8_t sup_stack_top[];
struct dtr;

void load_descriptor_tables(struct dtr *gdt, struct dtr *idt, uint16_t tr);
extern const uint64_t isr_table[256];

/* Installs the Supervisor's own GDT/IDT/TSS and identity page tables. */
void platform_init(shz_info_t *info);
uint64_t platform_gdt_base(void);
uint64_t platform_idt_base(void);
uint64_t platform_tss_base(void);
int platform_ap_prepare(unsigned cpu, uint64_t *cr3, uint64_t *stack);
int platform_ap_enter(unsigned cpu, uint64_t *gdt, uint64_t *idt, uint64_t *tss);
int platform_apic_uncached(uint64_t pa);
void platform_fail(shz_info_t *info, const char *message) __attribute__((noreturn));
#endif
