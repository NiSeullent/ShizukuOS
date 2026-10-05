/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku Kernel32: a separate x86 Protected Mode kernel (i486 instruction set).
 * Independent GDT/IDT/TSS, paging, physical/virtual memory, heap, preemptive scheduler,
 * ring-3 processes with an int 0x80 system-call gate, and an IPC endpoint speaking the
 * inter-kernel ABI. CPU entry/state are private; the portable firmware parser is reused.
 */
#ifndef K32_H
#define K32_H
#include <stddef.h>
#include <stdint.h>
#include "../kcommon/khc.h"

#define KVER "Kernel32 10 (ShizukuDOS)"
#define PAGE_SIZE 4096u
#define VEC_TIMER 0x20
#define VEC_DOORBELL 0x21
#define VEC_SYSCALL 0x80
#define TICK_US 1000u

/* ---- interrupt frame (matches isr_common in start.asm) ---- */
struct regs {
    uint32_t gs, fs, es, ds;
    uint32_t edi, esi, ebp, esp_dummy, ebx, edx, ecx, eax;
    uint32_t vector, error;
    uint32_t eip, cs, eflags;
    uint32_t user_esp, user_ss;         /* valid only when cs & 3 */
};

/* ---- arch.c ---- */
void arch_init(void);
uint32_t arch_cpu_id(void);             /* trusted GS identity or UINT32_MAX */
void tss_set_kernel_stack(uint32_t esp0);
static inline uint32_t k32_stack_pointer(void) { uint32_t v; __asm__ volatile("mov %%esp, %0" : "=r"(v)); return v; }
static inline uint32_t k32_flags(void) { uintptr_t v; __asm__ volatile("pushf; pop %0" : "=r"(v)); return v; }
static inline uint32_t read_cr0(void) { uint32_t v; __asm__ volatile("mov %%cr0, %0" : "=r"(v)); return v; }
static inline uint32_t read_cr2(void) { uint32_t v; __asm__ volatile("mov %%cr2, %0" : "=r"(v)); return v; }
static inline uint32_t read_cr3(void) { uint32_t v; __asm__ volatile("mov %%cr3, %0" : "=r"(v)); return v; }
static inline uint32_t read_cr4(void) { uint32_t v; __asm__ volatile("mov %%cr4, %0" : "=r"(v)); return v; }
static inline void write_cr0(uint32_t v) { __asm__ volatile("mov %0, %%cr0" :: "r"(v) : "memory"); }
static inline void write_cr3(uint32_t v) { __asm__ volatile("mov %0, %%cr3" :: "r"(v) : "memory"); }
static inline void write_cr4(uint32_t v) { __asm__ volatile("mov %0, %%cr4" :: "r"(v) : "memory"); }
static inline void invlpg(uint32_t a) { __asm__ volatile("invlpg (%0)" :: "r"(a) : "memory"); }
static inline uint32_t irq_save(void) { uint32_t f; __asm__ volatile("pushf; pop %0; cli" : "=r"(f) :: "memory"); return f; }
static inline void irq_restore(uint32_t f) { __asm__ volatile("push %0; popf" :: "r"(f) : "memory", "cc"); }
static inline void sti(void) { __asm__ volatile("sti" ::: "memory"); }
static inline void cli(void) { __asm__ volatile("cli" ::: "memory"); }

/* ---- lib.c ---- */
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
void *memmove(void *, const void *, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
void kprintf(const char *fmt, ...);
void kvprintf(const char *fmt, __builtin_va_list ap);
void kpanic(const char *fmt, ...) __attribute__((noreturn));
#define KASSERT(c) do { if (!(c)) kpanic("assert %s:%d %s", __FILE__, __LINE__, #c); } while (0)

/* ---- mem.c ---- */
void mem_init(const shz_bootinfo_t *bi);
uint32_t pmm_alloc(void);               /* physical page, zeroed; 0 on exhaustion */
void pmm_free(uint32_t pa);
uint32_t pmm_free_count(void);
uint32_t pmm_total_count(void);
#define PTE_P 1u
#define PTE_W 2u
#define PTE_U 4u
uint32_t vm_new_space(void);            /* new page directory sharing the kernel mappings */
void vm_free_space(uint32_t pd);
int vm_map(uint32_t pd, uint32_t va, uint32_t pa, uint32_t flags);
int vm_map_range(uint32_t pd, uint32_t va, uint32_t bytes, uint32_t flags);   /* fresh zeroed pages */
uint32_t vm_translate(uint32_t pd, uint32_t va);   /* physical or 0 */
void *kmalloc(size_t n);
void kfree(void *p);
size_t kheap_used(void);
uint32_t kernel_space(void);
int k32_pmm_owned(uint32_t pa);
int k32_heap_owned(uint32_t base, uint32_t bytes);
int k32_vm_native_map(uint32_t page, int uc);
void k32_vm_native_rollback(void);
int k32_vm_native_root_owned(void);

/* ---- sched.c ---- */
typedef struct thread thread_t;
typedef struct { volatile int locked; thread_t *owner; thread_t *waiters; int depth; } kmutex_t;
typedef struct { volatile int count; thread_t *waiters; } ksem_t;
struct thread {
    uint32_t esp;                       /* saved kernel stack pointer */
    uint32_t id;
    uint32_t state;                     /* 0 free, 1 ready, 2 running, 3 blocked, 4 zombie */
    uint64_t wake_tick;                 /* 0 = no finite deadline */
    thread_t *next;                     /* semaphore/mutex wait link */
    thread_t *ready_next;               /* separate perCPU FIFO link */
    uint32_t affinity_mask;             /* wholly contained in actual online mask */
    uint32_t ready_cpu, ready_queued;
    uint32_t on_cpu;                    /* ownership until saved stack is inactive */
    uint32_t stack_base;
    uint32_t proc;                      /* owning process id, 0 = kernel */
    uint32_t native_tag;                /* private preallocated cohort only */
    int exit_code;
    char name[16];
    uint64_t run_ticks;
    ksem_t *wait_sem;
};
void sched_init(void);
uint32_t sched_cpu_online_mask(void);
int sched_validate(void);               /* bounded queue/ownership diagnostic */
int sched_cpu_register(uint32_t cpu);    /* -2: architecture/Supervisor handoff absent */
int thread_set_affinity(thread_t *t, uint32_t mask);
uint32_t thread_get_affinity(thread_t *t);
void sched_switch_complete(void);       /* assembly: destination stack, IRQs disabled */
thread_t *thread_create(const char *name, void (*fn)(void *), void *arg);
thread_t *thread_current(void);
void thread_yield(void);
void thread_exit(int code) __attribute__((noreturn));
int thread_join(thread_t *t);
void thread_sleep_ms(uint32_t ms);
uint64_t ticks_now(void);
void sched_tick(void);                  /* timer ISR hook */
void mutex_init(kmutex_t *m);
void mutex_lock(kmutex_t *m);
void mutex_unlock(kmutex_t *m);
void sem_init(ksem_t *s, int count);
void sem_wait(ksem_t *s);
int sem_wait_timeout(ksem_t *s, uint32_t ms);
void sem_post(ksem_t *s);
uint64_t sched_switch_count(void);
void sched_start_idle(void);

/* ---- user.c ---- */
int proc_create(const char *name, const uint8_t *image, uint32_t size, int *pid_out);
int proc_wait(int pid, int *exit_code, int *faulted);
void user_syscall(struct regs *r);
int user_fault(struct regs *r);         /* nonzero if the fault was in user mode and handled by killing */
uint32_t user_syscall_count(void);

/* ---- ipc.c ---- */
/* 1: real K64 endpoint bound; 0: valid handoff without that peer; <0: refused. */
int ipc_init(const shz_bootinfo_t *bi);
void ipc_server_thread(void *arg);
uint32_t ipc_requests_served(void);
uint32_t ipc_protocol_errors(void);

/* ---- tests.c ---- */
void run_self_tests(const shz_bootinfo_t *bi);

/* embedded user programs (user*.bin via incbin) */
extern const uint8_t user_ok_start[], user_ok_end[];
extern const uint8_t user_fault_start[], user_fault_end[];
extern const uint8_t user_wild_start[], user_wild_end[];
#endif
