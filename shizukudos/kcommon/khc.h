/* SPDX-License-Identifier: GPL-2.0-only
 * Guest-side hypercall and freestanding helpers shared by Kernel32 (i486) and
 * Kernel64 (x86-64). Both call the Supervisor through VMCALL (ABI: shz_abi.h).
 */
#ifndef SHZ_KHC_H
#define SHZ_KHC_H
#include <stddef.h>
#include <stdint.h>
#include "../abi/shz_abi.h"

#if defined(__x86_64__)
typedef uint64_t hcreg_t;
#define HC_REGS_OUT "=a"(status), "=b"(value)
#ifdef SHZ_STANDALONE
/* Kernel64 booted without the Supervisor (QEMU multiboot stub): the same hypercall ABI is served in-kernel
 * by kernel64/standalone/standalone64.c over COM1, PIT/PIC, the RTC and QEMU's isa-debug-exit port. */
long shz_standalone_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value_out);
static inline long shz_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value_out)
{
    return shz_standalone_hcall(op, a, b, value_out);
}
#else
static inline long shz_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value_out)
{
    hcreg_t status = op, value = a, argument = b;
    /* TIME, DOMAIN_STATE and CHANNEL_INFO also return RCX. The generic helper
     * discards that result, but callers' live C values must survive it. */
    __asm__ volatile("vmcall" : "+a"(status), "+b"(value), "+c"(argument) : : "memory", "cc");
    if (value_out)
        *value_out = value;
    return (long)status;
}
#endif
#else
typedef uint32_t hcreg_t;
#ifdef SHZ_STANDALONE
long shz_standalone_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value_out);      /* kernel32/standalone/standalone32.c */
uint64_t shz_standalone_time_ns(void); /* coherent full-width standalone clock */
static inline long shz_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value_out)
{
    return shz_standalone_hcall(op, a, b, value_out);
}
#else
static inline long shz_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value_out)
{
    hcreg_t status = op, value = a, argument = b;
    /* EAX/EBX/ECX are read-write for the same Supervisor ABI as Kernel64. */
    __asm__ volatile("vmcall" : "+a"(status), "+b"(value), "+c"(argument) : : "memory", "cc");
    if (value_out)
        *value_out = value;
    return (long)(int32_t)status;
}
#endif
#endif

/* The guest-physical address of a kernel-virtual buffer must be supplied by the caller
 * (kernels here are identity mapped below 1 GiB, or provide a translation). */
static inline long shz_console_write(uintptr_t gpa, uint32_t len) { return shz_hcall(SHZ_HC_CONSOLE_WRITE, gpa, len, 0); }
static inline void shz_evidence(unsigned slot, uint64_t value)
{
#if defined(__x86_64__)
    shz_hcall(SHZ_HC_EVIDENCE, slot, value, 0);
#else
    /* 32-bit guests report 32-bit values; the Supervisor stores them zero-extended. */
    shz_hcall(SHZ_HC_EVIDENCE, slot, (hcreg_t)value, 0);
#endif
}
static inline void __attribute__((noreturn)) shz_exit(unsigned code)
{
    shz_hcall(SHZ_HC_EXIT, code, 0, 0);
    for (;;)
        __asm__ volatile("cli; hlt");
}
static inline uint64_t shz_time_ns(void)
{
#if defined(__x86_64__)
    hcreg_t v = 0;
    shz_hcall(SHZ_HC_TIME, 0, 0, &v);
    return v;
#elif defined(SHZ_STANDALONE)
    return shz_standalone_time_ns();
#else
    uint32_t status = SHZ_HC_TIME, low = 0, high = 0;
    /* A paired updated Core supplies EBX/ECX from one sample. Old guests
     * still read their previous RBX result; new i386 guests require this
     * additive TIME result instead of guessing an epoch from a low word. */
    __asm__ volatile("vmcall" : "+a"(status), "+b"(low), "+c"(high) : : "memory", "cc");
    return ((uint64_t)high << 32) | low;
#endif
}
static inline long shz_timer_set(unsigned vector, uint32_t period_us) { return shz_hcall(SHZ_HC_TIMER_SET, vector, period_us, 0); }
static inline long shz_notify(unsigned domain, uint32_t mask) { return shz_hcall(SHZ_HC_NOTIFY, domain, mask, 0); }
static inline long shz_set_doorbell_vector(unsigned vector) { return shz_hcall(SHZ_HC_SET_DOORBELL_VECTOR, vector, 0, 0); }
static inline uint32_t shz_doorbell_ack(void)
{
    hcreg_t v = 0;
    shz_hcall(SHZ_HC_DOORBELL_ACK, 0, 0, &v);
    return (uint32_t)v;
}
static inline void shz_wait(void) { shz_hcall(SHZ_HC_WAIT, 0, 0, 0); }
#endif
