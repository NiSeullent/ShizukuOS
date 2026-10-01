/* SPDX-License-Identifier: GPL-2.0-only: exact user loader bodies, controlled kernel/callback boundaries. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <setjmp.h>
typedef int NTSTATUS;
typedef uint32_t ULONG;
typedef uint64_t ULONG64;
typedef void *PVOID, *PWSTR;
typedef ULONG *PULONG;
typedef struct { int key; } SHZ_UNICODE_STRING;
typedef struct list { struct list *Flink, *Blink; } LIST_ENTRY;
typedef struct entry { LIST_ENTRY InLoadOrderLinks; ULONG Flags; PVOID DllBase; } SHZ_LDR_ENTRY;
typedef struct { LIST_ENTRY InLoadOrderModuleList; } SHZ_PEB_LDR_DATA;
#define SHZ_EXPORT
#define NTAPI
#define DLL_PROCESS_ATTACH 1
#define STATUS_SUCCESS 0
#define SHZ_LDR_CALLBACK_ACTIVE 0x80000000ul
#define CONTAINING_RECORD(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
static SHZ_PEB_LDR_DATA database;
#define PEB_LDR(p) (&database)
static void *shz_peb(void) { return &database; }
static SHZ_LDR_ENTRY prior, outer, dependency, nested;
static unsigned checks, calls, wrong, locks, phase, active_seen, nested_events, outer_events, dependency_events;
static jmp_buf traversal_bound;
static void run_init_routines(int, void *, int);
static void notify_entry(ULONG, SHZ_LDR_ENTRY *);
#include "ldr_notify_production.inc"
#define CHECK(c) do { ++checks; if (!(c)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#c); return 1; } } while(0)
void ShzLoaderLock(void) { ++locks; }
void ShzLoaderUnlock(void) { --locks; }
static void append(SHZ_LDR_ENTRY *e)
{
    LIST_ENTRY *head = &database.InLoadOrderModuleList;
    e->InLoadOrderLinks.Flink = head;
    e->InLoadOrderLinks.Blink = head->Blink;
    head->Blink->Flink = &e->InLoadOrderLinks;
    head->Blink = &e->InLoadOrderLinks;
    e->DllBase = e;
}
NTSTATUS ShzLdrLoadImage(PWSTR path, SHZ_UNICODE_STRING *name, ULONG64 *base)
{
    (void)path;
    if (name->key == 1) { append(&outer); append(&dependency); *base = (uintptr_t)&outer; }
    else if (name->key == 2) { append(&nested); *base = (uintptr_t)&nested; }
    else if (name->key == 3) *base = (uintptr_t)&outer;
    else return -19;
    return 0;
}
static void run_init_routines(int reason, void *reserved, int executable_tls)
{
    SHZ_UNICODE_STRING name = {2}; PVOID handle;
    if (reason != DLL_PROCESS_ATTACH || reserved || executable_tls) ++wrong;
    if (phase++) return;
    /* Real COMMIT's retained entry state after an unrelated prior dynamic
     * tail is retired by the new DllMain, before outer loaded notifications. */
    prior.InLoadOrderLinks.Blink->Flink = prior.InLoadOrderLinks.Flink;
    prior.InLoadOrderLinks.Flink->Blink = prior.InLoadOrderLinks.Blink;
    prior.InLoadOrderLinks.Flink = prior.InLoadOrderLinks.Blink = &prior.InLoadOrderLinks;
    prior.DllBase = 0;
    if (LdrLoadDll(0,0,&name,&handle) || handle != &nested) ++wrong;
}
static void notify_entry(ULONG reason, SHZ_LDR_ENTRY *e)
{
    if (++calls > 16) longjmp(traversal_bound,1); /* actual old body repeats forever; bound host only */
    if (reason != 1 || !locks || !e->DllBase || e == &prior) ++wrong;
    if (e->Flags & SHZ_LDR_CALLBACK_ACTIVE) ++active_seen;
    if (e == &nested) ++nested_events;
    if (e == &outer) ++outer_events;
    if (e == &dependency) ++dependency_events;
}
int main(void)
{
    LIST_ENTRY *head = &database.InLoadOrderModuleList;
    SHZ_UNICODE_STRING name = {1}; PVOID handle = 0;
    head->Flink = head->Blink = head;
    append(&prior);
    CHECK(head->Blink == &prior.InLoadOrderLinks);
    if (setjmp(traversal_bound)) {
        fprintf(stderr,"REPRODUCED old notification traversal: %u callbacks after retired prior tail\n",calls);
        return 2;
    }
    CHECK(LdrLoadDll(0,0,&name,&handle) == 0);
    CHECK(handle == &outer);
    CHECK(!locks);
    CHECK(prior.InLoadOrderLinks.Flink == &prior.InLoadOrderLinks);
    CHECK(prior.DllBase == 0);
    CHECK(calls == 3);
    CHECK(wrong == 0);
    CHECK(active_seen == 3);
    CHECK(outer_events == 1 && dependency_events == 1 && nested_events == 1);
    CHECK(outer.Flags == 0 && dependency.Flags == 0 && nested.Flags == 0);
    CHECK(head->Flink == &outer.InLoadOrderLinks && head->Blink == &nested.InLoadOrderLinks);
    name.key = 3;
    CHECK(LdrLoadDll(0,0,&name,&handle) == 0 && handle == &outer);
    CHECK(calls == 3 && !locks && !wrong); /* no new module: no notification batch */
    name.key = 4;
    CHECK(LdrLoadDll(0,0,&name,&handle) == -19);
    CHECK(calls == 3 && !locks); /* failed mapping never runs callbacks */
    printf("loader notify reentry: %u checks PASS, exact production load/notification bodies\n",checks);
    return 0;
}
