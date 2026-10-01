/* SPDX-License-Identifier: GPL-2.0-only
 * Compile with gcc -O2 -Wall -Wextra -Werror -Wno-unused-parameter -pthread
 * -mno-red-zone -fno-stack-protector -DSHZ_STEAM_FIBER_HOST_TEST this file.
 * Exercises production AMD64 switching on real separate mmap stacks, FPU
 * restoration and synchronized cross-thread migration. Guest t_steam_fiber.c
 * validates the actual FLS callback registry and Kernel64 VM contract. */
#define _GNU_SOURCE
#define SHZ_STEAM_FIBER_HOST_TEST
#include "steam_fiber_host.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdatomic.h>

static _Thread_local unsigned char teb_bytes[0x2000] __attribute__((aligned(16)));
static _Thread_local DWORD last_error;
static unsigned char executable_headers[128] __attribute__((aligned(16)));
static size_t allocated_descriptors;
static void *stack_pointer[16];
static size_t stack_size[16];
static int allocation_failure;
static PFLS_CALLBACK_FUNCTION host_fls_callback;
static unsigned callback_count;
static _Atomic unsigned checks;
#define VERIFY(cond) do { ++checks; if (!(cond)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); abort(); } } while (0)

uint64_t shz_teb(void) { return (uintptr_t)teb_bytes; }
DWORD shz_last_error(void) { return last_error; }
void shz_set_last_error(DWORD error) { last_error = error; }
DWORD shz_tid(void) { return (DWORD)syscall(SYS_gettid); }
BOOL k32_unsupported(const char *api, const char *what, DWORD error)
{
    (void)api; (void)what; shz_set_last_error(error); return FALSE;
}
void *ShzProcessHeap(void) { return (void *)1; }
void *RtlAllocateHeap(void *heap, DWORD flags, size_t bytes)
{
    void *data;
    (void)heap; (void)flags;
    if (allocation_failure) return NULL;
    data = calloc(1, bytes);
    if (data) ++allocated_descriptors;
    return data;
}
BOOL RtlFreeHeap(void *heap, DWORD flags, void *data)
{
    (void)heap; (void)flags;
    if (data) { VERIFY(allocated_descriptors > 0); --allocated_descriptors; free(data); }
    return TRUE;
}
void *WINAPI VirtualAlloc(void *base, SIZE_T bytes, DWORD type, DWORD protect)
{
    unsigned i;
    void *data;
    (void)base; (void)type; (void)protect;
    data = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (data == MAP_FAILED) return NULL;
    for (i = 0; i < 16; ++i) if (!stack_pointer[i]) { stack_pointer[i] = data; stack_size[i] = bytes; return data; }
    abort();
}
BOOL WINAPI VirtualProtect(void *base, SIZE_T bytes, DWORD protect, DWORD *old)
{
    (void)protect;
    *old = PAGE_READWRITE;
    return mprotect(base, bytes, PROT_NONE) == 0;
}
BOOL WINAPI VirtualFree(void *base, SIZE_T bytes, DWORD type)
{
    unsigned i;
    (void)bytes; (void)type;
    for (i = 0; i < 16; ++i) if (stack_pointer[i] == base) {
        VERIFY(munmap(base, stack_size[i]) == 0);
        stack_pointer[i] = 0;
        return TRUE;
    }
    return FALSE;
}
void *WINAPI GetModuleHandleW(const void *name) { (void)name; return executable_headers; }
void WINAPI __attribute__((noreturn)) ExitThread(DWORD code) { pthread_exit((void *)(uintptr_t)code); }
void k32_fls_destroy_data(PVOID *data)
{
    if (!data) return;
    if (data[0] && host_fls_callback) { void *value = data[0]; data[0] = NULL; host_fls_callback(value); }
    free(data);
}

#include "../kernel32/k32_steam_fiber.c"

struct state { void *root, *fiber, *original_root; unsigned visits; void *stack_probe; };
static DWORD mxcsr(void) { DWORD v; __asm__ volatile("stmxcsr %0" : "=m"(v)); return v; }
static void set_mxcsr(DWORD v) { __asm__ volatile("ldmxcsr %0" : : "m"(v)); }
static USHORT x87cw(void) { USHORT v; __asm__ volatile("fnstcw %0" : "=m"(v)); return v; }
static void set_x87cw(USHORT v) { __asm__ volatile("fldcw %0" : : "m"(v)); }

static void WINAPI callback(void *value)
{
    VERIFY(value == (void *)0x2222);
    ++callback_count;
}

static void WINAPI child(void *argument)
{
    struct state *state = argument;
    volatile uint64_t local = 0x123456789abcdef0ull;
    PVOID *values = calloc(128, sizeof(PVOID));
    VERIFY(values != NULL);
    values[0] = (void *)0x2222;
    *(PVOID **)(shz_teb() + TEB_FLS_DATA) = values;
    VERIFY(*(PVOID *)(shz_teb() + TEB_FIBER_DATA) == state->fiber);
    VERIFY(*(PVOID *)state->fiber == state);
    state->stack_probe = (void *)&local;
    VERIFY((uintptr_t)&local >= (uintptr_t)*(PVOID *)(shz_teb() + TEB_STACK_LIMIT));
    VERIFY((uintptr_t)&local < (uintptr_t)*(PVOID *)(shz_teb() + TEB_STACK_BASE));
    set_mxcsr(0x3f80); set_x87cw(0x067f);
    for (;;) {
        VERIFY(local == 0x123456789abcdef0ull);
        VERIFY((mxcsr() & 0x6000) == 0x2000 && (x87cw() & 0x0c00) == 0x0400);
        ++state->visits;
        SwitchToFiber(state->root);
    }
}

static void *migration_thread(void *argument)
{
    struct state *state = argument;
    unsigned i;
    state->root = ConvertThreadToFiber(NULL);
    VERIFY(state->root != NULL);
    SwitchToFiber(state->original_root);
    VERIFY(last_error == ERROR_NOT_SUPPORTED);
    VERIFY(*(PVOID *)(shz_teb() + TEB_FIBER_DATA) == state->root);
    for (i = 0; i < 250; ++i) SwitchToFiber(state->fiber);
    VERIFY(ConvertFiberToThread());
    return NULL;
}

int main(void)
{
    struct state state = {0};
    void *root;
    void *original_base = (void *)0x80000000, *original_limit = (void *)0x7ff00000;
    PVOID initial_values[128] = { (void *)0x1111 };
    DWORD initial_mx = mxcsr();
    USHORT initial_cw = x87cw();
    pthread_t worker;
    unsigned i;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)executable_headers;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(executable_headers + 64);
    dos->e_lfanew = 64; nt->OptionalHeader.SizeOfStackReserve = 0x100000; nt->OptionalHeader.SizeOfStackCommit = 0x1000;
    *(PVOID *)(shz_teb() + TEB_STACK_BASE) = original_base;
    *(PVOID *)(shz_teb() + TEB_STACK_LIMIT) = original_limit;
    *(PVOID *)(shz_teb() + TEB_DEALLOCATION_STACK) = original_limit;
    *(PVOID **)(shz_teb() + TEB_FLS_DATA) = initial_values;
    VERIFY(!ConvertFiberToThread() && last_error == ERROR_ALREADY_THREAD);
    VERIFY(!ConvertThreadToFiberEx(NULL, 2) && last_error == ERROR_INVALID_PARAMETER);
    allocation_failure = 1;
    VERIFY(!ConvertThreadToFiber(NULL) && last_error == ERROR_NOT_ENOUGH_MEMORY);
    allocation_failure = 0;
    root = state.root = state.original_root = ConvertThreadToFiber((void *)0x4444);
    VERIFY(root && *(PVOID *)root == (void *)0x4444);
    VERIFY(!ConvertThreadToFiber(NULL) && last_error == ERROR_ALREADY_FIBER);
    state.fiber = CreateFiberEx(0x4000, 0x10000, FIBER_FLAG_FLOAT_SWITCH, child, &state);
    VERIFY(state.fiber != NULL);
    set_mxcsr(0x5f80); set_x87cw(0x0a7f);
    for (i = 0; i < 10000; ++i) {
        SwitchToFiber(state.fiber);
        VERIFY(state.visits == i + 1);
        VERIFY((mxcsr() & 0x6000) == 0x4000 && (x87cw() & 0x0c00) == 0x0800);
        VERIFY(*(PVOID *)(shz_teb() + TEB_STACK_BASE) == original_base);
        VERIFY(*(PVOID *)(shz_teb() + TEB_STACK_LIMIT) == original_limit);
        VERIFY(*(PVOID **)(shz_teb() + TEB_FLS_DATA) == initial_values && initial_values[0] == (void *)0x1111);
    }
    VERIFY(state.stack_probe != NULL);
    VERIFY(pthread_create(&worker, NULL, migration_thread, &state) == 0);
    VERIFY(pthread_join(worker, NULL) == 0);
    VERIFY(state.visits == 10250);
    state.root = root;
    SwitchToFiber(state.fiber);
    VERIFY(state.visits == 10251);
    host_fls_callback = callback;
    DeleteFiber(state.fiber);
    VERIFY(callback_count == 1);
    VERIFY(ConvertFiberToThread());
    VERIFY(!(*(USHORT *)(shz_teb() + TEB_SAME_FLAGS) & HAS_FIBER_DATA));
    VERIFY(*(PVOID **)(shz_teb() + TEB_FLS_DATA) == initial_values && initial_values[0] == (void *)0x1111);
    VERIFY(allocated_descriptors == 0);
    for (i = 0; i < 16; ++i) VERIFY(!stack_pointer[i]);
    set_mxcsr(initial_mx); set_x87cw(initial_cw);
    printf("STEAM-FIBER-HOST: %u checks, 10251 switches, FPU and cross-thread migration passed\n", checks);
    return 0;
}
