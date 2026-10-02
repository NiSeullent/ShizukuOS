/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K32_NATIVE_AP_H
#define SHZ_K32_NATIVE_AP_H
#include "k32.h"
#include "../kernel64/smp_acpi.h"
#include "../kernel64/standalone/native_firmware.h"
#include "../kernel64/standalone/qemu_firmware.h"
#include "standalone/native_handoff.h"
#define K32_AP_MAX 4u
#define K32_AP_STACK 16384u
#define K32_AP_RESCHEDULE 0xf0u
#define K32_AP_TIMER 0xf2u
#define K32_AP_SPURIOUS 0xffu
#define K32_AP_TAG 0x32415043u
/* A native admission is not the public CPU-registration API. */
typedef struct {
    uint32_t apic, boot, arch, saved_boot, idle_base;
    uint32_t actual_id,actual_apic,actual_root,actual_gdt,actual_idt,actual_tr,actual_cs,actual_boot_sp,actual_flags;
    uint32_t idle_sp,withdraw_sp,irq_sp;
    volatile uint32_t phase, fatal, ticks, ipis, request, ack, withdrawn;
    volatile uint32_t progress[2], peer[2], done[2], hash[2], stack[2];
    thread_t *idle, *worker[2];
} k32_ap_cpu_t;
typedef struct {
    shz_native_firmware_t native;
    shz_qemu_firmware_t qemu;
    uint64_t rsdp, ebda;
    uint32_t rsdp_bytes, ready, discovery, ram;
} k32_ap_firmware_t;
extern k32_ap_cpu_t k32_ap_cpus[K32_AP_MAX];
int k32_ap_policy(const shz_bootinfo_t *bi, unsigned *count);
int k32_ap_snapshot(const shz_bootinfo_t *bi, unsigned count);
int k32_ap_run(void);
int k32_ap_active(void);
int k32_ap_started(void);
unsigned k32_ap_count(void);
uint32_t k32_ap_physical_id(void);
int k32_ap_identity(unsigned cpu);
int k32_ap_owned(uint32_t base, uint32_t bytes, int heap);
int k32_ap_root_owned(void);
int k32_ap_arch_prepare(unsigned cpu);
int k32_ap_arch_enter(unsigned cpu);
uint32_t k32_ap_arch_anchor(unsigned cpu);
void k32_ap_arch_tss(unsigned cpu, uint32_t top);
void k32_ap_interrupt(struct regs *r, unsigned cpu);
void k32_ap_fault(unsigned cpu, uint32_t reason) __attribute__((noreturn));
void k32_ap_eoi(void);
int k32_ap_send(unsigned cpu);
void k32_ap_idle_main(unsigned cpu);
void k32_ap_stack_enter(uint32_t *saved, uint32_t top, unsigned cpu);
void k32_ap_stack_leave(uint32_t saved, unsigned cpu) __attribute__((noreturn));
void k32_ap_stack_leave_complete(unsigned cpu);
int k32_ap_sched_prepare(unsigned cpu, void (*worker)(void *));
int k32_ap_sched_online(unsigned cpu, uint32_t esp);
int k32_ap_sched_withdraw(unsigned cpu, uint32_t esp);
void k32_ap_sched_tick(unsigned cpu,int ipi);
int k32_ap_sched_terminal(unsigned cpu);
int k32_ap_sched_discard(unsigned cpu);
int k32_ap_firmware_prepare(k32_ap_firmware_t *f);
int k32_ap_firmware_read(void *ctx, uint64_t pa, void *dst, size_t bytes);
int k32_ap_firmware_finish(k32_ap_firmware_t *f, uint64_t pa);
extern const uint8_t k32_ap_blob_start[], k32_ap_blob_end[];
#endif
