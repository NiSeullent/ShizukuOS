/* SPDX-License-Identifier: GPL-2.0-only
 * x86-64 privileged instruction wrappers for the Supervisor (VMX root, ring 0).
 * Freestanding: no libc, general-purpose registers only (no SSE in root mode).
 */
#ifndef SHZ_CPU_H
#define SHZ_CPU_H
#include <stddef.h>
#include <stdint.h>

#define MSR_IA32_TSC 0x10
#define MSR_IA32_APIC_BASE 0x1b
#define MSR_IA32_FEATURE_CONTROL 0x3a
#define MSR_IA32_VMX_BASIC 0x480
#define MSR_IA32_VMX_PINBASED 0x481
#define MSR_IA32_VMX_PROCBASED 0x482
#define MSR_IA32_VMX_EXIT 0x483
#define MSR_IA32_VMX_ENTRY 0x484
#define MSR_IA32_VMX_MISC 0x485
#define MSR_IA32_VMX_CR0_FIXED0 0x486
#define MSR_IA32_VMX_CR0_FIXED1 0x487
#define MSR_IA32_VMX_CR4_FIXED0 0x488
#define MSR_IA32_VMX_CR4_FIXED1 0x489
#define MSR_IA32_VMX_PROCBASED2 0x48b
#define MSR_IA32_VMX_EPT_VPID_CAP 0x48c
#define MSR_IA32_VMX_TRUE_PINBASED 0x48d
#define MSR_IA32_VMX_TRUE_PROCBASED 0x48e
#define MSR_IA32_VMX_TRUE_EXIT 0x48f
#define MSR_IA32_VMX_TRUE_ENTRY 0x490
#define MSR_IA32_EFER 0xc0000080
#define MSR_IA32_PAT 0x277
#define MSR_IA32_SYSENTER_CS 0x174
#define MSR_IA32_SYSENTER_ESP 0x175
#define MSR_IA32_SYSENTER_EIP 0x176
#define MSR_IA32_FS_BASE 0xc0000100
#define MSR_IA32_GS_BASE 0xc0000101
#define MSR_VM_CR 0xc0010114

#define CR0_PE (1ull << 0)
#define CR0_MP (1ull << 1)
#define CR0_NE (1ull << 5)
#define CR0_WP (1ull << 16)
#define CR0_PG (1ull << 31)
#define CR4_PAE (1ull << 5)
#define CR4_VMXE (1ull << 13)
#define EFER_LME (1ull << 8)
#define EFER_LMA (1ull << 10)

struct cpuid_regs { uint32_t eax, ebx, ecx, edx; };

static inline struct cpuid_regs cpuid_count(uint32_t leaf, uint32_t sub)
{
    struct cpuid_regs r;
    __asm__ volatile("cpuid" : "=a"(r.eax), "=b"(r.ebx), "=c"(r.ecx), "=d"(r.edx)
                     : "a"(leaf), "c"(sub));
    return r;
}
static inline struct cpuid_regs cpuid(uint32_t leaf) { return cpuid_count(leaf, 0); }

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}
static inline void wrmsr(uint32_t msr, uint64_t v)
{
    __asm__ volatile("wrmsr" :: "c"(msr), "a"((uint32_t)v), "d"((uint32_t)(v >> 32)) : "memory");
}
static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

#define DEFINE_CR(n) \
static inline uint64_t read_cr##n(void) { uint64_t v; __asm__ volatile("mov %%cr" #n ", %0" : "=r"(v)); return v; } \
static inline void write_cr##n(uint64_t v) { __asm__ volatile("mov %0, %%cr" #n :: "r"(v) : "memory"); }
DEFINE_CR(0) DEFINE_CR(2) DEFINE_CR(3) DEFINE_CR(4)

static inline uint8_t inb(uint16_t p) { uint8_t v; __asm__ volatile("inb %1,%0" : "=a"(v) : "Nd"(p)); return v; }
static inline uint16_t inw(uint16_t p) { uint16_t v; __asm__ volatile("inw %1,%0" : "=a"(v) : "Nd"(p)); return v; }
static inline uint32_t inl(uint16_t p) { uint32_t v; __asm__ volatile("inl %1,%0" : "=a"(v) : "Nd"(p)); return v; }
static inline void outb(uint16_t p, uint8_t v) { __asm__ volatile("outb %0,%1" :: "a"(v), "Nd"(p)); }
static inline void outw(uint16_t p, uint16_t v) { __asm__ volatile("outw %0,%1" :: "a"(v), "Nd"(p)); }
static inline void outl(uint16_t p, uint32_t v) { __asm__ volatile("outl %0,%1" :: "a"(v), "Nd"(p)); }

static inline void cli(void) { __asm__ volatile("cli" ::: "memory"); }
static inline void hlt(void) { __asm__ volatile("hlt"); }
static inline void pause_cpu(void) { __asm__ volatile("pause"); }

struct __attribute__((packed)) dtr { uint16_t limit; uint64_t base; };

/* ---- VMX instructions (Intel SDM Vol. 3C ch. 30). CF/ZF report VMfail. ---- */
static inline int vmx_fail_code(uint8_t cf, uint8_t zf) { return cf ? 1 : (zf ? 2 : 0); }

static inline int vmxon(uint64_t pa)
{
    uint8_t cf, zf;
    __asm__ volatile("vmxon %2; setc %0; setz %1" : "=q"(cf), "=q"(zf) : "m"(pa) : "cc", "memory");
    return vmx_fail_code(cf, zf);
}
static inline void vmxoff(void) { __asm__ volatile("vmxoff" ::: "cc"); }
static inline int vmclear(uint64_t pa)
{
    uint8_t cf, zf;
    __asm__ volatile("vmclear %2; setc %0; setz %1" : "=q"(cf), "=q"(zf) : "m"(pa) : "cc", "memory");
    return vmx_fail_code(cf, zf);
}
static inline int vmptrld(uint64_t pa)
{
    uint8_t cf, zf;
    __asm__ volatile("vmptrld %2; setc %0; setz %1" : "=q"(cf), "=q"(zf) : "m"(pa) : "cc", "memory");
    return vmx_fail_code(cf, zf);
}
static inline int vmwrite(uint64_t field, uint64_t value)
{
    uint8_t cf, zf;
    __asm__ volatile("vmwrite %3, %2; setc %0; setz %1" : "=q"(cf), "=q"(zf)
                     : "r"(field), "r"(value) : "cc", "memory");
    return vmx_fail_code(cf, zf);
}
static inline uint64_t vmread(uint64_t field)
{
    uint64_t v = 0;
    __asm__ volatile("vmread %1, %0" : "=r"(v) : "r"(field) : "cc");
    return v;
}
struct __attribute__((packed)) invept_desc { uint64_t eptp, reserved; };
static inline void invept_all(void)
{
    struct invept_desc d = {0, 0};
    __asm__ volatile("invept %0, %1" :: "m"(d), "r"((uint64_t)2) : "cc", "memory");
}
struct __attribute__((packed)) invvpid_desc { uint64_t vpid, addr; };
static inline void invvpid_all(void)
{
    struct invvpid_desc d = {0, 0};
    __asm__ volatile("invvpid %0, %1" :: "m"(d), "r"((uint64_t)2) : "cc", "memory");
}

/* ---- Freestanding libc subset ---- */
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
void *memmove(void *, const void *, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
#endif
