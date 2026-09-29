/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku Kernel64: a separate x86-64 Long Mode kernel.
 *
 * Own GDT/IDT/TSS, 4-level paging with a higher-half kernel and a direct map of
 * physical memory, user address spaces up to the canonical 47-bit limit, SYSCALL/SYSRET
 * with a Windows-x64-style register convention (number in EAX, arguments in R10/RDX/R8/R9
 * then the user stack), preemptive threads, kernel objects and handles, a RAM file system
 * and a PE32+ loader. It shares no code or state with Kernel32.
 */
#ifndef K64_H
#define K64_H
#include <stddef.h>
#include <stdint.h>
#include "../kcommon/khc.h"

#define KVER "Kernel64 0.1"
#define PAGE_SIZE 4096ull
#define K64_VIRT_BASE 0xffffffff80000000ull
#define DIRECT_MAP 0xffff800000000000ull
#define USER_TOP 0x00007ffffffef000ull            /* end of the user range (exclusive) */
#define USER_MIN 0x0000000000010000ull            /* first mappable user address (null guard below) */
#define VEC_TIMER 0x20
#define VEC_DOORBELL 0x21
#define TICK_US 1000u

extern uint64_t phys_base_va;                   /* boot alias first, DIRECT_MAP once the final tables are live */
static inline uint64_t p2v(uint64_t pa) { return phys_base_va + pa; }
static inline uint64_t v2p_direct(uint64_t va) { return va - DIRECT_MAP; }
static inline uint64_t kimage_v2p(uint64_t va) { return va - K64_VIRT_BASE; }

/* ---- interrupt/syscall frame (matches isr_common in start.asm) ---- */
struct regs {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t vector, error;
    uint64_t rip, cs, rflags, rsp, ss;
};

/* ---- lib.c ---- */
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
void *memmove(void *, const void *, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);
void kprintf(const char *fmt, ...);
void kvprintf(const char *fmt, __builtin_va_list ap);
void kpanic(const char *fmt, ...) __attribute__((noreturn));
#define KASSERT(c) do { if (!(c)) kpanic("assert %s:%d %s", __FILE__, __LINE__, #c); } while (0)

/* ---- arch.c ---- */
void arch_init(void);
void irq_register(unsigned vector, void (*handler)(struct regs *));      /* device IRQ vector >= 0x20 (see arch.c) */
void tss_set_rsp0(uint64_t rsp0);
static inline uint64_t read_cr0(void) { uint64_t v; __asm__ volatile("mov %%cr0, %0" : "=r"(v)); return v; }
static inline uint64_t read_cr2(void) { uint64_t v; __asm__ volatile("mov %%cr2, %0" : "=r"(v)); return v; }
static inline uint64_t read_cr3(void) { uint64_t v; __asm__ volatile("mov %%cr3, %0" : "=r"(v)); return v; }
static inline uint64_t read_cr4(void) { uint64_t v; __asm__ volatile("mov %%cr4, %0" : "=r"(v)); return v; }
static inline void write_cr0(uint64_t v) { __asm__ volatile("mov %0, %%cr0" :: "r"(v) : "memory"); }
static inline void write_cr3(uint64_t v) { __asm__ volatile("mov %0, %%cr3" :: "r"(v) : "memory"); }
static inline void write_cr4(uint64_t v) { __asm__ volatile("mov %0, %%cr4" :: "r"(v) : "memory"); }
static inline void invlpg(uint64_t a) { __asm__ volatile("invlpg (%0)" :: "r"(a) : "memory"); }
static inline uint64_t rdmsr(uint32_t m) { uint32_t lo, hi; __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(m)); return ((uint64_t)hi << 32) | lo; }
static inline void wrmsr(uint32_t m, uint64_t v) { __asm__ volatile("wrmsr" :: "c"(m), "a"((uint32_t)v), "d"((uint32_t)(v >> 32)) : "memory"); }
static inline uint64_t irq_save(void) { uint64_t f; __asm__ volatile("pushfq; popq %0; cli" : "=r"(f) :: "memory"); return f; }
static inline void irq_restore(uint64_t f) { __asm__ volatile("pushq %0; popfq" :: "r"(f) : "memory", "cc"); }
static inline void sti(void) { __asm__ volatile("sti" ::: "memory"); }
static inline void cli(void) { __asm__ volatile("cli" ::: "memory"); }
#define MSR_EFER 0xc0000080u
#define MSR_STAR 0xc0000081u
#define MSR_LSTAR 0xc0000082u
#define MSR_SFMASK 0xc0000084u
#define MSR_FS_BASE 0xc0000100u
#define MSR_GS_BASE 0xc0000101u

/* ---- mem.c ---- */
void mem_init(const shz_bootinfo_t *bi);
uint64_t pmm_alloc(void);                       /* zeroed physical page, 0 on exhaustion */
void pmm_free(uint64_t pa);
uint64_t pmm_free_count(void);
#define PT_P (1ull << 0)
#define PT_W (1ull << 1)
#define PT_U (1ull << 2)
#define PT_PWT (1ull << 3)
#define PT_PCD (1ull << 4)
#define PT_NX (1ull << 63)
uint64_t vm_new_space(void);                    /* new PML4 sharing the kernel half */
void vm_free_space(uint64_t pml4);              /* frees every user page and table */
int vm_map(uint64_t pml4, uint64_t va, uint64_t pa, uint64_t flags);
int vm_unmap(uint64_t pml4, uint64_t va, uint64_t *pa_out);
int vm_protect(uint64_t pml4, uint64_t va, uint64_t flags);
uint64_t vm_lookup(uint64_t pml4, uint64_t va, uint64_t *flags_out);   /* physical page or 0 */
uint64_t kernel_pml4(void);
void *kmalloc(size_t n);
void *kzalloc(size_t n);
void kfree(void *p);
size_t kheap_used(void);

/* ---- sched.c ---- */
typedef struct thread thread_t;
typedef struct process process_t;
typedef struct kobject kobject_t;
typedef struct { volatile int locked; thread_t *owner; thread_t *waiters; } kmutex_t;
typedef struct { volatile int count; thread_t *waiters; } ksem_t;
/* TS_NEW: allocated but still being initialised; never scheduled until thread_resume() (see start_thread_common). */
enum { TS_FREE = 0, TS_READY = 1, TS_RUNNING = 2, TS_BLOCKED = 3, TS_ZOMBIE = 4, TS_NEW = 5 };
struct thread {
    uint64_t rsp;                               /* saved kernel stack pointer */
    uint32_t id, state;
    uint64_t wake_tick;
    thread_t *next;
    uint64_t stack_base;
    process_t *proc;
    int64_t exit_code;
    char name[16];
    uint64_t run_ticks;
    ksem_t *wait_sem;
    int wait_result;
    uint64_t user_gs_base, user_fs_base;
    uint64_t teb;                               /* user address of the TEB, 0 for kernel threads */
    uint8_t fx[512] __attribute__((aligned(16)));
    kobject_t *object;                          /* waitable thread object */
    uint64_t user_rip, user_rsp, user_arg, user_arg2;   /* initial user context: rip, rsp, rcx, rdx */
    uint32_t apc_pending;
    uint64_t tid;                               /* Windows-style thread id (multiple of 4), 0 for kernel threads */
    volatile int alerted, alert_wait;           /* NtAlertThreadByThreadId state */
    void *wait_multi;
};
void sched_init(void);
thread_t *thread_create(const char *name, void (*fn)(void *), void *arg);
thread_t *thread_create_suspended(const char *name, void (*fn)(void *), void *arg);   /* TS_NEW until thread_resume */
void thread_resume(thread_t *t);
void thread_discard(thread_t *t);                                                     /* frees a TS_NEW thread that was never resumed */
thread_t *thread_current(void);
thread_t *thread_find_tid(void *process, uint64_t tid);
void thread_yield(void);
void thread_exit(int64_t code) __attribute__((noreturn));
int64_t thread_join(thread_t *t);
void thread_sleep_ms(uint64_t ms);
uint64_t ticks_now(void);
void sched_tick(void);
void mutex_init(kmutex_t *m);
void mutex_lock(kmutex_t *m);
void mutex_unlock(kmutex_t *m);
void sem_init(ksem_t *s, int count);
void sem_wait(ksem_t *s);
int sem_wait_timeout(ksem_t *s, uint64_t ms);
void sem_post(ksem_t *s);
uint64_t sched_switch_count(void);
void sched_set_current_kstack(uint64_t top);
void thread_block_current(void);                /* mark BLOCKED and switch away (caller holds irq off) */
void thread_wake(thread_t *t);
#define KSTACK_BYTES 32768u

/* ---- ipc64.c ---- */
void ipc64_init(const shz_bootinfo_t *bi);
int ipc64_run_tests(void);
extern uint32_t ipc64_results[16];

/* ---- main.c: boot information (ABI 1.1 tail) ---- */
/* HOOK for a UEFI GOP display backend (kernel64/gfx_fb.c): the linear framebuffer the UEFI boot manager's direct
 * Kernel64 boot handed over (shz_bootinfo_t.fb_*). Returns 0 and fills *out, or -1 when there is none (Supervisor,
 * Multiboot stub, no GOP, or a pixel format other than 32-bit RGBX/BGRX). The range lies outside the direct map:
 * a backend maps it with mmio_map() (pci.h) before drawing. Nothing calls this yet; the Bochs VBE path is unchanged. */
typedef struct {
    uint64_t base, size;                        /* physical */
    uint32_t width, height, pitch, bpp;         /* pitch in bytes */
    uint32_t format;                            /* enum shz_fb_format */
} k64_boot_fb_t;
int k64_boot_framebuffer(k64_boot_fb_t *out);
const char *k64_boot_cmdline(void);             /* shz_bootinfo_t.cmdline, "" when absent */

/* ---- tests.c ---- */
void run_self_tests(const shz_bootinfo_t *bi);
unsigned tests_failed(void);
void report_final(void);

/* embedded flat user programs (incbin) */
extern const uint8_t user_ok_start[], user_ok_end[];
extern const uint8_t user_fault_start[], user_fault_end[];
extern const uint8_t user_wild_start[], user_wild_end[];
extern const uint8_t user_high_start[], user_high_end[];

/* ---- proc.c ---- */
int proc_create_flat(const char *name, const uint8_t *image, uint64_t size, int *pid_out);
int proc_wait(int pid, int64_t *exit_code, int *faulted);
int syscall_dispatch(struct regs *r);      /* nonzero: leave through IRETQ with the full frame (NtContinue) */
int user_fault(struct regs *r);
uint64_t user_syscall_count(void);
uint64_t proc_pml4(process_t *p);
extern uint64_t g_kstack_top;                   /* read by syscall_entry */
extern uint64_t g_user_rsp_scratch;
#endif
