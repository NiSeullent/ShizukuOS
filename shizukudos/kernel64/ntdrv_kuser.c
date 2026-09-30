/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: KUSER_SHARED_DATA in system space.
 *
 * Kernel-mode drivers read the shared data page directly at 0xFFFFF78000000000: KeQueryTickCount is an inline read of the
 * TickCount field, and drivers use the system time, the Windows version fields, the processor feature array and the
 * processor count without calling ntoskrnl. This maps one read-only page there and refreshes the time fields from the
 * host's clocks every millisecond (ntdrv_ke.c's timer thread). Field offsets follow the Windows 10 x64 layout; a field this
 * host has no answer for stays zero, as in a freshly booted machine that has not computed it yet.
 *
 * KSYSTEM_TIME is {LowPart, High1Time, High2Time} written High2, Low, High1 so a reader that loops until High1 == High2 never
 * sees a torn value; the tick counter is the KSYSTEM_TIME at +0x320 (TickCountQuad).
 */
#include "ntdrv.h"

#define KUSER_VA 0xFFFFF78000000000ull

extern int64_t ntdrv_100ns_now(void);

static volatile uint8_t *kuser;                    /* writable alias of the page (host side) */
static int kuser_ready;

static void put32(unsigned off, uint32_t v) { *(volatile uint32_t *)(kuser + off) = v; }
static void put16(unsigned off, uint16_t v) { *(volatile uint16_t *)(kuser + off) = v; }
static void ksystem_time_set(unsigned off, uint64_t v)
{
    volatile uint32_t *p = (volatile uint32_t *)(kuser + off);
    p[2] = (uint32_t)(v >> 32);                    /* High2Time first */
    p[0] = (uint32_t)v;                            /* LowPart */
    p[1] = (uint32_t)(v >> 32);                    /* High1Time last */
}

void ntdrv_kuser_tick(void)
{
    static uint64_t ticks;
    if (!kuser_ready) return;
    ++ticks;
    ksystem_time_set(0x008, shz_time_ns() / 100);  /* InterruptTime */
    ksystem_time_set(0x014, (uint64_t)ntdrv_100ns_now());    /* SystemTime */
    ksystem_time_set(0x320, ticks);                /* TickCount (KeQueryTickCount) */
    put32(0x000, (uint32_t)ticks);                 /* TickCountLowDeprecated */
}

void ntdrv_kuser_init(void)
{
    static const WCHAR root[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', 0 };
    uint64_t pa, alias;
    unsigned i;
    if (kuser_ready) return;
    pa = pmm_alloc();
    alias = ntdrv_alloc_image_va(0x1000);
    if (!pa || !alias) return;
    if (vm_map(kernel_pml4(), alias, pa, PT_W | PT_NX)) return;
    if (vm_map(kernel_pml4(), KUSER_VA, pa, PT_NX)) return;         /* the driver-visible view: read-only */
    kuser = (volatile uint8_t *)alias;
    memset((void *)kuser, 0, 0x1000);
    put32(0x004, (uint32_t)(((uint64_t)(TICK_US * 10) << 24) / 10000u));   /* TickCountMultiplier: tick length in ms << 24 */
    put16(0x02c, 0x8664);                                            /* ImageNumberLow: IMAGE_FILE_MACHINE_AMD64 */
    put16(0x02e, 0x8664);                                            /* ImageNumberHigh */
    for (i = 0; root[i]; ++i) put16(0x030 + 2 * i, root[i]);         /* NtSystemRoot */
    put32(0x260, 22631);                                             /* NtBuildNumber */
    put32(0x264, 1);                                                 /* NtProductType: VER_NT_WORKSTATION */
    kuser[0x268] = 1;                                                /* ProductTypeIsValid */
    put16(0x26a, 9);                                                 /* NativeProcessorArchitecture: PROCESSOR_ARCHITECTURE_AMD64 */
    put32(0x26c, 10);                                                /* NtMajorVersion */
    put32(0x270, 0);                                                 /* NtMinorVersion */
    kuser[0x274 + 2] = 1;                                            /* PF_COMPARE_EXCHANGE_DOUBLE */
    kuser[0x274 + 3] = 1;                                            /* PF_MMX_INSTRUCTIONS_AVAILABLE */
    kuser[0x274 + 6] = 1;                                            /* PF_XMMI_INSTRUCTIONS_AVAILABLE */
    kuser[0x274 + 8] = 1;                                            /* PF_RDTSC_INSTRUCTION_AVAILABLE */
    kuser[0x274 + 9] = 1;                                            /* PF_PAE_ENABLED */
    kuser[0x274 + 10] = 1;                                           /* PF_XMMI64_INSTRUCTIONS_AVAILABLE */
    kuser[0x274 + 12] = 1;                                           /* PF_NX_ENABLED */
    kuser[0x274 + 13] = 1;                                           /* PF_SSE3_INSTRUCTIONS_AVAILABLE */
    kuser[0x274 + 14] = 1;                                           /* PF_COMPARE_EXCHANGE128 */
    put32(0x2f8, 0x110);                                             /* SuiteMask: VER_SUITE_SINGLEUSERTS | VER_SUITE_PERSONAL */
    put32(0x3c0, 1);                                                 /* ActiveProcessorCount */
    kuser[0x3c4] = 1;                                                /* ActiveGroupCount */
    kuser_ready = 1;
    ntdrv_kuser_tick();
}
