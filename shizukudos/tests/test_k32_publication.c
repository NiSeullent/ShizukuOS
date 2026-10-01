/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise production user.c and sched.c with deterministic timer opportunities.
 * Host substitutes cover privileged IRQ/MMU operations and allocation only;
 * proc_create, thread_create, runnable selection, syscalls and user_fault are real.
 */
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHZ_STANDALONE
#define irq_save native_irq_save
#define irq_restore native_irq_restore
#define read_cr2 native_read_cr2
#define read_cr3 native_read_cr3
#define write_cr3 native_write_cr3
#define sti native_sti
#define cli native_cli
#include "../kernel32/k32.h"
#undef irq_save
#undef irq_restore
#undef read_cr2
#undef read_cr3
#undef write_cr3
#undef sti
#undef cli

static uint32_t host_flags, host_cr3;
static unsigned observing, watch_publication, timer_observations, failures;
static unsigned heap_offset, live_spaces, freed_spaces;
static int fail_thread_stack;
static unsigned char heap[65536] __attribute__((aligned(16)));
static unsigned char code_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
static jmp_buf fault_exit;

static void timer_opportunity(void);
static uint32_t irq_save(void)
{
    uint32_t f = host_flags;
    host_flags &= ~0x200u;
    return f;
}
static void irq_restore(uint32_t f)
{
    host_flags = f;
    if ((f & 0x200u) && watch_publication && !observing)
        timer_opportunity();
}
static uint32_t read_cr2(void) { return 0x100000u; }
static uint32_t read_cr3(void) { return host_cr3; }
static void write_cr3(uint32_t pd) { host_cr3 = pd; }
static void sti(void) { host_flags |= 0x200u; }
static void cli(void) { host_flags &= ~0x200u; }

#include "../kernel32/sched.c"

/* Fault completion must return to the host harness, rather than change stacks. */
static void host_thread_exit(int code) __attribute__((noreturn));
#define thread_exit host_thread_exit
#include "../kernel32/user.c"
#undef thread_exit

static void expect(const char *name, int okay)
{
    printf("%s: %s\n", okay ? "PASS" : "FAIL", name);
    if (!okay) ++failures;
}

static void timer_opportunity(void)
{
    thread_t *selected = pick_next(), *previous = current;
    struct regs r = {0};
    int contained;
    if (!selected || selected == idle_thread || selected->state != TS_READY)
        return;
    observing = 1;
    watch_publication = 0;
    ++timer_observations;
    current = selected;
    r.eax = SYS_GETPID;
    user_syscall(&r);
    expect("first runnable instruction sees the owning PID", r.eax == 1);
    expect("process and thread backlinks precede first runnable instruction",
           selected->proc == 1 && procs[1].used && procs[1].thread == selected && procs[1].pd != 0);
    r.vector = 14;
    r.cs = 0x1b;
    if (!setjmp(fault_exit)) {
        contained = user_fault(&r);
        expect("first runnable user fault is contained", contained != 0);
    } else {
        expect("first runnable user fault is contained",
               procs[1].done && procs[1].faulted && procs[1].exit_code == (int)0x8000000eu &&
               procs[1].exited.count == 1);
    }
    current = previous;
    observing = 0;
}

static void host_thread_exit(int code)
{
    (void)code;
    longjmp(fault_exit, 1);
}

void *kmalloc(size_t n)
{
    void *p;
    if (fail_thread_stack) return 0;
    if (heap_offset + n > sizeof heap) abort();
    p = heap + heap_offset;
    heap_offset += (unsigned)n;
    return p;
}
void kfree(void *p) { (void)p; }
uint32_t pmm_alloc(void) { return (uint32_t)(uintptr_t)code_page; }
uint32_t vm_new_space(void) { ++live_spaces; return 0x8000u; }
void vm_free_space(uint32_t pd)
{
    if (pd != 0x8000u || !live_spaces) abort();
    --live_spaces;
    ++freed_spaces;
}
int vm_map(uint32_t pd, uint32_t va, uint32_t pa, uint32_t flags)
{
    if (pd != 0x8000u || va != 0x40000000u || pa != (uint32_t)(uintptr_t)code_page || flags != (PTE_U | PTE_W)) abort();
    return 0;
}
int vm_map_range(uint32_t pd, uint32_t va, uint32_t bytes, uint32_t flags)
{
    if (pd != 0x8000u || va != 0x407fe000u || bytes != 8192 || flags != (PTE_U | PTE_W)) abort();
    return 0;
}
uint32_t vm_translate(uint32_t pd, uint32_t va) { (void)pd; (void)va; abort(); }
uint32_t kernel_space(void) { return 0x4000u; }
void tss_set_kernel_stack(uint32_t sp) { (void)sp; }
void enter_user(uint32_t entry, uint32_t esp) { (void)entry; (void)esp; abort(); }
void switch_stacks(uint32_t *saved, uint32_t next) { (void)saved; (void)next; abort(); }
void kprintf(const char *fmt, ...) { (void)fmt; }
void kpanic(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    abort();
}
long shz_standalone_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value)
{
    (void)op; (void)a; (void)b; (void)value;
    abort();
}

static void reset(uint32_t flags)
{
    watch_publication = observing = timer_observations = 0;
    heap_offset = live_spaces = freed_spaces = 0;
    fail_thread_stack = 0;
    memset(procs, 0, sizeof procs);
    host_flags = flags;
    sched_init();
}

int main(void)
{
    const uint8_t image[] = {0x90};
    int pid;
    reset(0x246u);
    watch_publication = 1;
    pid = -7;
    expect("process creation succeeds", proc_create("publication", image, sizeof image, &pid) == 0);
    expect("pending timer selected the production READY thread", timer_observations == 1);
    expect("successful creation preserves incoming flags and PID", host_flags == 0x246u && pid == 1);

    reset(0x46u);
    watch_publication = 1;
    pid = -7;
    expect("creation under disabled interrupts succeeds", proc_create("publication", image, sizeof image, &pid) == 0);
    expect("disabled interrupt state is preserved", host_flags == 0x46u && timer_observations == 0);
    irq_restore(0x246u);
    expect("later enabled timer sees a fully published process", timer_observations == 1);

    reset(0x246u);
    fail_thread_stack = 1;
    pid = -7;
    expect("thread stack exhaustion returns failure", proc_create("publication", image, sizeof image, &pid) == -1);
    expect("failed creation restores incoming flags and leaves PID untouched", host_flags == 0x246u && pid == -7);
    expect("failed thread creation frees the prepared address space", live_spaces == 0 && freed_spaces == 1);
    expect("failed thread creation clears publication", !procs[1].used && !procs[1].thread);
    fail_thread_stack = 0;
    expect("a failed process slot can be retried", proc_create("retry", image, sizeof image, &pid) == 0 && pid == 1);
    return failures ? 1 : 0;
}
