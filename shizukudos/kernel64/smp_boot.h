/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K64_SMP_BOOT_H
#define SHZ_K64_SMP_BOOT_H
#include "smp_acpi.h"
#include "smp_boot_guard.h"

/* Only the proven retired native Multiboot PML4 page is reused. GDT0x5000,
 * firmware holes0x6000 and production bootinfo0x7000 stay intact. */
#define SHZ_SMP_TRAMPOLINE_PA SHZ_SMP_RETIRED_PML4_PA
#define SHZ_SMP_VEC_RESCHEDULE 0xf0u
#define SHZ_SMP_VEC_TLB 0xf1u
#define SHZ_SMP_VEC_TIMER 0xf2u
#define SHZ_SMP_VEC_SPURIOUS 0xffu

enum shz_smp_cpu_state { SHZ_SMP_CPU_OFFLINE=0, SHZ_SMP_CPU_ENTERED=1, SHZ_SMP_CPU_ONLINE=2, SHZ_SMP_CPU_FAILED=3 };
typedef struct __attribute__((aligned(64))) shz_smp_cpu {
    /* The first two fields can be addressed through KERNEL_GS_BASE by a future
     * short SWAPGS syscall-stack prologue. Ordinary GS retains NT KPCR/TEB. */
    uint64_t syscall_kstack, syscall_user_rsp;
    uint32_t logical_id, apic_id, state, irq_depth;
    void *current, *idle;
    uint64_t boot_stack_top, irq_stack_top, df_stack_top;
    uint64_t timer_irqs, reschedule_ipis, tlb_ipis;
} shz_smp_cpu_t;
extern shz_smp_cpu_t shz_smp_cpus[SHZ_SMP_MAX_CPUS];
typedef void (*shz_smp_ap_entry_fn)(unsigned cpu);
typedef int (*shz_smp_resource_check_fn)(unsigned count,uint64_t bootstrap_cr3);
/* Optional component seam; the normal production consumer installs its owning
 * validator before startup. It runs after all allocations and before INIT. */
int shz_smp_boot_set_resource_check(shz_smp_resource_check_fn check);

/* This starts real native APs, but does not grant them access to the UP scheduler.
 * The supplied entry must initialize CPU-private arch/scheduler state before
 * calling cpu_online and remain in its CPU loop; returning marks that AP FAILED.
 * No physical IPIs are issued in Supervisor guest builds.
 * BSP must call with IRQs disabled after final GDT/CR3 installation, before any
 * workload. initial_cr3 is captured before mem_init retires the native Multiboot
 * boot tables. rsdp_pa=0 selects BIOS discovery. UEFI needs its own validated
 * retained-page handoff; this native Multiboot contract is not inferred there. */
int shz_smp_boot_start(uint64_t rsdp_pa, shz_smp_ap_entry_fn entry, uint64_t initial_cr3);
/* Firmware ACPI tables can lie outside allocator-owned RAM. The boot loader
 * supplies a reader bounded by its validated E820/EFI memory-map spans. It may
 * establish mappings during discovery, before any AP is launched. The consumer
 * must separately establish ownership of the active kernel page-table pages;
 * the common guard checks their PMM address range and retired-page dependencies,
 * not allocator bitmap ownership or firmware-hole exclusion. */
int shz_smp_boot_start_with_reader(uint64_t rsdp_pa, shz_smp_ap_entry_fn entry,
                                  shz_smp_phys_read_fn read, void *ctx, uint64_t initial_cr3);
unsigned shz_smp_this_cpu(void);
unsigned shz_smp_online_count(void);
const shz_smp_topology_t *shz_smp_topology(void);
int shz_smp_cpu_online(unsigned cpu);
int shz_smp_send_ipi(unsigned cpu, unsigned vector);
void shz_smp_apic_eoi(void);
#endif
