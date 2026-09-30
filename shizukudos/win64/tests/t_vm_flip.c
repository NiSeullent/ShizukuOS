/* SPDX-License-Identifier: GPL-2.0-only
 * Changing the protection of committed, already touched pages with VirtualAlloc(MEM_COMMIT) (what allocators and JITs do to flip
 * memory between writable and executable) and with VirtualProtect. The page-table entries must follow the new protection at once:
 * a stale entry either leaves a write that should fault succeeding or loops the faulting instruction forever (write to a page
 * that became writable, execute of a page that became executable). Expectations are the documented access rules of the
 * protection constants and VirtualQuery's report, never read from the kernel's bookkeeping.
 */
#include "k32test.h"

static volatile LONG g_av;
static volatile ULONG_PTR g_av_kind;      /* ExceptionInformation[0]: 0 read, 1 write, 8 execute */
static LONG CALLBACK av_handler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        ++g_av;
        g_av_kind = ep->ExceptionRecord->ExceptionInformation[0];
        ep->ContextRecord->Rip += ((const BYTE *)ep->ContextRecord->Rip)[0] == 0x88 ? 3 : 0;      /* poke(): "mov %al,(%rdx)" (2) + nop */
        if (g_av_kind == 8) {                                                                      /* a call into a non-executable page: return */
            ep->ContextRecord->Rip = *(const ULONG_PTR *)ep->ContextRecord->Rsp;
            ep->ContextRecord->Rsp += 8;
        } else if (g_av_kind == 0) {                                                               /* peek(): "mov (%rdx),%al" (2) + nop */
            ep->ContextRecord->Rip += 3;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void __attribute__((noinline)) poke(volatile unsigned char *p, unsigned char v)
{
    __asm__ volatile("movb %%al, (%%rdx)\n\tnop" :: "d"(p), "a"(v) : "memory");
}

static unsigned char __attribute__((noinline)) peek(volatile unsigned char *p)
{
    unsigned char v = 0x5a;
    __asm__ volatile("movb (%%rdx), %%al\n\tnop" : "+a"(v) : "d"(p) : "memory");
    return v;
}

/* 1 when the store was refused (an access violation for write), 0 when it landed */
static int write_faults(volatile unsigned char *p, unsigned char v)
{
    const LONG before = g_av;
    poke(p, v);
    return g_av != before && g_av_kind == 1;
}

static int read_faults(volatile unsigned char *p)
{
    const LONG before = g_av;
    (void)peek(p);
    return g_av != before && g_av_kind == 0;
}

/* Calls the page as a function ("ret" at its start); 1 when the call faulted for execute, 0 when it returned normally. */
static int exec_faults(unsigned char *p)
{
    const LONG before = g_av;
    ((void (*)(void))(void *)p)();
    return g_av != before && g_av_kind == 8;
}

static DWORD prot_of(void *p)
{
    MEMORY_BASIC_INFORMATION m;
    if (!VirtualQuery(p, &m, sizeof m)) return 0xffffffffu;
    return m.State == MEM_COMMIT ? m.Protect : 0xfffffffeu;
}

int main(void)
{
    unsigned char *p = VirtualAlloc(0, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    unsigned char *q;
    DWORD old = 0;
    int i;
    AddVectoredExceptionHandler(1, av_handler);
    CHECK(p != 0, "VirtualAlloc 4 pages read/write");
    if (!p) return k32t_finish("t_vm_flip");
    for (i = 0; i < 4; ++i) p[i * 0x1000] = 0x11;                       /* touch every page: entries are now resident read/write/no-execute */
    p[0] = 0xC3;                                                       /* ret */
    CHECK(exec_faults(p), "a read/write page cannot be executed (no-execute)");

    /* ---- read/write -> execute/read through MEM_COMMIT over committed pages */
    CHECK(VirtualAlloc(p, 0x4000, MEM_COMMIT, PAGE_EXECUTE_READ) == p, "VirtualAlloc(MEM_COMMIT, PAGE_EXECUTE_READ) over committed pages succeeds");
    CHECK(prot_of(p) == PAGE_EXECUTE_READ && prot_of(p + 0x3000) == PAGE_EXECUTE_READ, "VirtualQuery reports PAGE_EXECUTE_READ");
    CHECK(p[0] == 0xC3 && p[0x1000] == 0x11, "the contents survive");
    CHECK(!exec_faults(p), "the page executes now (this looped forever with a stale no-execute entry)");
    CHECK(write_faults(p + 0x1000, 0x22) && p[0x1000] == 0x11, "a store to it is refused (a stale writable entry let it through)");
    CHECK(!read_faults(p + 0x2000), "reading it works");

    /* ---- execute/read -> read/write, back again */
    CHECK(VirtualAlloc(p, 0x4000, MEM_COMMIT, PAGE_READWRITE) == p, "MEM_COMMIT with PAGE_READWRITE over them");
    CHECK(!write_faults(p + 0x1000, 0x33) && p[0x1000] == 0x33, "a store works again (this looped forever with a stale read-only entry)");
    CHECK(exec_faults(p), "and execute is refused again");
    CHECK(VirtualProtect(p, 0x4000, PAGE_EXECUTE_READ, &old) && old == PAGE_READWRITE, "VirtualProtect read/write -> execute/read reports the old protection");
    CHECK(!exec_faults(p) && write_faults(p + 0x2000, 1), "VirtualProtect and MEM_COMMIT agree: executes, store refused");

    /* ---- part of the range */
    CHECK(VirtualAlloc(p + 0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE) == p + 0x1000, "MEM_COMMIT over one page only");
    CHECK(prot_of(p) == PAGE_EXECUTE_READ && prot_of(p + 0x1000) == PAGE_READWRITE && prot_of(p + 0x2000) == PAGE_EXECUTE_READ, "only that page changed");
    CHECK(!write_faults(p + 0x1000, 0x44) && write_faults(p, 1) && write_faults(p + 0x2000, 1), "that page is writable, its neighbours are not");

    /* ---- park and restore */
    CHECK(VirtualAlloc(p + 0x1000, 0x1000, MEM_COMMIT, PAGE_NOACCESS) == p + 0x1000, "MEM_COMMIT with PAGE_NOACCESS over a touched page");
    CHECK(read_faults(p + 0x1000) && write_faults(p + 0x1000, 9), "reads and stores fault");
    CHECK(VirtualAlloc(p + 0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE) == p + 0x1000, "MEM_COMMIT with PAGE_READWRITE over the parked page");
    CHECK(!read_faults(p + 0x1000) && p[0x1000] == 0x44, "it is accessible again with its data");

    /* ---- reserved (never touched, never committed) pages committed directly as execute/read */
    q = VirtualAlloc(0, 0x3000, MEM_RESERVE, PAGE_READWRITE);
    CHECK(q != 0, "VirtualAlloc MEM_RESERVE");
    if (q) {
        CHECK(VirtualAlloc(q, 0x3000, MEM_COMMIT, PAGE_EXECUTE_READWRITE) == q, "MEM_COMMIT PAGE_EXECUTE_READWRITE inside the reservation");
        q[0] = 0xC3;
        CHECK(!exec_faults(q) && !write_faults(q + 0x1000, 7) && q[0x2000] == 0, "untouched pages appear zeroed, writable and executable");
        CHECK(VirtualAlloc(q, 0x3000, MEM_COMMIT, PAGE_EXECUTE_READ) == q && !exec_faults(q) && write_faults(q + 0x1000, 8) && q[0x1000] == 7,
              "flipped to execute/read after being touched: still executes, store refused, data kept");
        VirtualFree(q, 0, MEM_RELEASE);
    }
    VirtualFree(p, 0, MEM_RELEASE);
    return k32t_finish("t_vm_flip");
}
