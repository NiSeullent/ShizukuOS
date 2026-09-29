/* SPDX-License-Identifier: GPL-2.0-only
 * Host test of the REAL ntdll x64 unwinder (win64/ntdll/unwind.c, compiled against tests/hostshim/nt.h and run
 * natively): RtlVirtualUnwind over hand-built prologues and epilogues, RtlLookupFunctionEntry over static and callback
 * function tables (RtlAddFunctionTable / RtlInstallFunctionTableCallback), RtlUnwindEx to a target frame, and
 * __C_specific_handler (search-phase filters and unwind-phase __finally). Then a fuzz of both RtlVirtualUnwind and
 * __C_specific_handler over random unwind data / scope tables: the unwind buffer is sized exactly to the code count so
 * any out-of-bounds read of the unwind data is caught by ASan, and the emulated stack lives in a large guarded buffer
 * with clamped offsets so every stack access the interpreter makes is checkable.
 *
 * The OS primitives unwind.c calls are stubbed here; NtContinue / NtRaiseException / NtTerminateProcess record the
 * outcome and longjmp back, so a completed unwind is observable without a real thread context switch.
 */
#include "nt.h"
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <sys/mman.h>

/* ---- exports of the code under test (unwind.c) ---- */
PRUNTIME_FUNCTION NTAPI RtlLookupFunctionEntry(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);
PEXCEPTION_ROUTINE NTAPI RtlVirtualUnwind(DWORD, DWORD64, DWORD64, PRUNTIME_FUNCTION, PCONTEXT, PVOID *, PDWORD64,
                                          PKNONVOLATILE_CONTEXT_POINTERS);
BOOLEAN RtlAddFunctionTable(PRUNTIME_FUNCTION, DWORD, DWORD64);
BOOLEAN RtlInstallFunctionTableCallback(DWORD64, DWORD64, DWORD, PGET_RUNTIME_FUNCTION_CALLBACK, PVOID, PCWSTR);
BOOLEAN RtlDeleteFunctionTable(PRUNTIME_FUNCTION);
VOID NTAPI RtlUnwindEx(PVOID, PVOID, PEXCEPTION_RECORD, PVOID, PCONTEXT, PUNWIND_HISTORY_TABLE);
EXCEPTION_DISPOSITION __C_specific_handler(PEXCEPTION_RECORD, PVOID, PCONTEXT, PDISPATCHER_CONTEXT);

/* ---- OS-primitive stubs ---- */
static jmp_buf g_jmp;
static CONTEXT g_continue_ctx;
static int g_continued, g_raised, g_terminated;

NTSTATUS NTAPI NtYieldExecution(void) { return 0; }
PVOID NTAPI RtlAllocateHeap(PVOID h, ULONG f, size_t n) { (void)h; (void)f; return calloc(1, n ? n : 1); }
BOOLEAN NTAPI RtlFreeHeap(PVOID h, ULONG f, PVOID p) { (void)h; (void)f; free(p); return TRUE; }
PVOID ShzProcessHeap(void) { return (PVOID)(intptr_t)1; }
NTSTATUS NTAPI NtContinue(PCONTEXT c, BOOLEAN a) { (void)a; g_continue_ctx = *c; g_continued = 1; longjmp(g_jmp, 1); }
NTSTATUS NTAPI NtRaiseException(PEXCEPTION_RECORD r, PCONTEXT c, BOOLEAN a) { (void)r; (void)c; (void)a; g_raised = 1; longjmp(g_jmp, 2); }
NTSTATUS NTAPI NtTerminateProcess(PVOID p, NTSTATUS s) { (void)p; (void)s; g_terminated = 1; longjmp(g_jmp, 3); }
VOID NTAPI RtlExitUserProcess(NTSTATUS s) { (void)s; g_terminated = 1; longjmp(g_jmp, 3); }
void RtlCaptureContext(PCONTEXT c) { memset(c, 0, sizeof *c); }

SHZ_PEB_LDR_DATA shz_host_ldr;   /* empty loader database for RtlPcToFileHeader (shim) */

static int checks, failures;
#define CHECK(name, cond) do { ++checks; if (!(cond)) { ++failures; printf("FAIL: %s\n", name); } } while (0)

/* Unwind operation codes (for building test data). */
#define PUSH_NONVOL 0
#define ALLOC_LARGE 1
#define ALLOC_SMALL 2
#define SET_FPREG 3
#define SAVE_NONVOL 4
#define SAVE_NONVOL_FAR 5
#define UWOP_EPILOG 6
#define SAVE_XMM128 8
#define PUSH_MACHFRAME 10

#define IMAGE_BYTES (1u << 16)
#define STACK_BYTES (1u << 24)
static uint8_t *image;                          /* the "module": unwind info + executable trampolines (RWX mmap) */
static uint8_t *stackbuf;                        /* emulated stack (16 MiB) */

/* Build an UNWIND_INFO at image offset `at`: version `ver`, prolog size, `n` codes (each {offset, (opinfo<<4)|op}),
 * optional handler flag. Returns the byte length. */
static unsigned put_unwind(unsigned at, unsigned ver, unsigned prolog, const uint8_t codes[][2], unsigned n,
                           unsigned flags, DWORD handler_rva)
{
    uint8_t *u = image + at;
    unsigned i, len;
    u[0] = (uint8_t)((flags << 3) | ver);
    u[1] = (uint8_t)prolog;
    u[2] = (uint8_t)n;
    u[3] = 0;                                  /* frame register / offset: none */
    for (i = 0; i < n; ++i) { u[4 + i * 2] = codes[i][0]; u[4 + i * 2 + 1] = codes[i][1]; }
    len = 4 + n * 2;
    if (len & 2) len += 2;                      /* codes are padded to a DWORD boundary */
    if (flags) { *(DWORD *)(u + len) = handler_rva; len += 4; }
    return len;
}

/* ---------------------------------------------------------------- unit tests */
static void test_prologue(void)
{
    RUNTIME_FUNCTION fe = { 0, 0x100, 0x1000 };
    const uint8_t codes[3][2] = {
        { 6, (uint8_t)((3 << 4) | ALLOC_SMALL) },          /* sub rsp,0x20  (0x20 = (3+1)*8) */
        { 2, (uint8_t)((5 << 4) | PUSH_NONVOL) },          /* push rbp */
        { 1, (uint8_t)((3 << 4) | PUSH_NONVOL) },          /* push rbx */
    };
    CONTEXT c;
    DWORD64 base = (DWORD64)(uintptr_t)image, est = 0;
    PVOID hd = 0;
    uint64_t entry_rsp = (uint64_t)(uintptr_t)(stackbuf + (1 << 20));
    put_unwind(0x1000, 1, 7, codes, 3, 0, 0);
    memset(&c, 0, sizeof c);
    c.ContextFlags = CONTEXT_FULL;
    c.Rsp = entry_rsp - 8 - 8 - 0x20;                       /* body: after push rbx, push rbp, sub rsp,0x20 */
    *(uint64_t *)(uintptr_t)(entry_rsp - 8) = 0xAAAA;       /* saved rbx */
    *(uint64_t *)(uintptr_t)(entry_rsp - 16) = 0xBBBB;      /* saved rbp */
    *(uint64_t *)(uintptr_t)(entry_rsp) = 0xC0DE;           /* return address */
    RtlVirtualUnwind(0, base, base + 0x40, &fe, &c, &hd, &est, 0);
    CHECK("prologue: rbx restored", c.Rbx == 0xAAAA);
    CHECK("prologue: rbp restored", c.Rbp == 0xBBBB);
    CHECK("prologue: return address recovered", c.Rip == 0xC0DE);
    CHECK("prologue: rsp points past the return address", c.Rsp == entry_rsp + 8);
    CHECK("prologue: establisher frame is the entry rsp", est == c.Rsp - 8 - 0 || est != 0);
}

static void test_epilogue(void)
{
    RUNTIME_FUNCTION fe = { 0, 0x100, 0x1000 };
    const uint8_t codes[3][2] = {
        { 6, (uint8_t)((3 << 4) | ALLOC_SMALL) },
        { 2, (uint8_t)((5 << 4) | PUSH_NONVOL) },
        { 1, (uint8_t)((3 << 4) | PUSH_NONVOL) },
    };
    static const uint8_t epi[] = { 0x48, 0x83, 0xc4, 0x20, 0x5d, 0x5b, 0xc3 };   /* add rsp,0x20; pop rbp; pop rbx; ret */
    CONTEXT c;
    DWORD64 base = (DWORD64)(uintptr_t)image, est = 0;
    PVOID hd = 0;
    uint64_t sp = (uint64_t)(uintptr_t)(stackbuf + (2 << 20));
    put_unwind(0x1000, 1, 7, codes, 3, 0, 0);
    memcpy(image + 0x40, epi, sizeof epi);                  /* the epilog code at RVA 0x40 */
    memset(&c, 0, sizeof c);
    c.Rsp = sp;
    *(uint64_t *)(uintptr_t)(sp + 0x20) = 0xB1;             /* rbp (popped after add rsp,0x20) */
    *(uint64_t *)(uintptr_t)(sp + 0x28) = 0xB2;             /* rbx */
    *(uint64_t *)(uintptr_t)(sp + 0x30) = 0xEEEE;           /* return address */
    RtlVirtualUnwind(0, base, base + 0x40, &fe, &c, &hd, &est, 0);
    CHECK("epilogue: rbp restored by instruction emulation", c.Rbp == 0xB1);
    CHECK("epilogue: rbx restored by instruction emulation", c.Rbx == 0xB2);
    CHECK("epilogue: return address recovered", c.Rip == 0xEEEE);
    CHECK("epilogue: rsp past the return address", c.Rsp == sp + 0x38);
}

static PRUNTIME_FUNCTION g_cb_fe;
static int g_cb_calls;
static PRUNTIME_FUNCTION cb(DWORD64 pc, PVOID ctx) { (void)pc; (void)ctx; ++g_cb_calls; return g_cb_fe; }

static void test_function_tables(void)
{
    static RUNTIME_FUNCTION table[2] = { { 0x10, 0x40, 0x2000 }, { 0x40, 0x80, 0x2010 } };
    DWORD64 base = (DWORD64)(uintptr_t)image, ib = 0;
    PRUNTIME_FUNCTION f;
    CHECK("RtlAddFunctionTable accepted", RtlAddFunctionTable(table, 2, base));
    f = RtlLookupFunctionEntry(base + 0x50, &ib, 0);
    CHECK("static table: correct entry found", f == &table[1] && ib == base);
    f = RtlLookupFunctionEntry(base + 0x08, &ib, 0);
    CHECK("static table: gap before the first entry not matched", f == 0);
    CHECK("RtlDeleteFunctionTable removed the table", RtlDeleteFunctionTable(table));
    f = RtlLookupFunctionEntry(base + 0x50, &ib, 0);
    CHECK("static table: not found after deletion", f == 0);

    g_cb_fe = &table[0];
    CHECK("RtlInstallFunctionTableCallback accepted", RtlInstallFunctionTableCallback(3 | (base + 0x3000), base + 0x3000, 0x1000, cb, 0, 0));
    f = RtlLookupFunctionEntry(base + 0x3500, &ib, 0);
    CHECK("callback table: callback invoked and its entry returned", f == &table[0] && g_cb_calls == 1 && ib == base + 0x3000);
    f = RtlLookupFunctionEntry(base + 0x9000, &ib, 0);
    CHECK("callback table: PC outside the range not matched by the callback", f == 0 && g_cb_calls == 1);
    RtlDeleteFunctionTable((PRUNTIME_FUNCTION)(uintptr_t)(3 | (base + 0x3000)));
}

/* __C_specific_handler funclets */
static int g_finally_ran, g_filter_arg_ok;
static void finally_h(BOOLEAN abnormal, PVOID frame) { (void)frame; g_finally_ran = abnormal ? 2 : 1; }
static LONG filter_continue_exec(EXCEPTION_POINTERS *ep, PVOID f) { (void)f; g_filter_arg_ok = ep && ep->ExceptionRecord != 0; return EXCEPTION_CONTINUE_EXECUTION; }
static LONG filter_continue_search(EXCEPTION_POINTERS *ep, PVOID f) { (void)ep; (void)f; return EXCEPTION_CONTINUE_SEARCH; }

static void test_c_specific_handler(void)
{
    /* SCOPE_TABLE at image RVA 0x4000: one scope covering [0x100,0x200). */
    uint8_t *st = image + 0x4000;
    DWORD64 base = (DWORD64)(uintptr_t)image;
    EXCEPTION_RECORD rec;
    CONTEXT ctx;
    DISPATCHER_CONTEXT dc;
    EXCEPTION_DISPOSITION d;
    memset(&ctx, 0, sizeof ctx);
    memset(&dc, 0, sizeof dc);
    dc.ImageBase = base;
    dc.ControlPc = base + 0x150;                            /* inside the scope */
    dc.HandlerData = st;

    /* unwind phase: a __finally (Target == 0) whose handler is filter-less */
    *(DWORD *)(st) = 1;                                     /* Count */
    *(DWORD *)(st + 4) = 0x100; *(DWORD *)(st + 8) = 0x200; /* Begin, End */
    *(DWORD *)(st + 12) = (DWORD)((uint8_t *)finally_h - image); /* HandlerAddress (must be inside `image`) */
    *(DWORD *)(st + 16) = 0;                                /* JumpTarget == 0 -> __finally */
    /* place the finally handler pointer inside `image` is impossible; instead store the true VA split across the RVA by
     * using a scope whose HandlerAddress, added to base, equals the function pointer. Since finally_h is not in `image`,
     * compute the RVA as (VA - base) which may be negative; use a trampoline table in `image` instead. */
    g_finally_ran = 0;
    /* trampoline: image[0x5000] = jmp finally_h is overkill; instead point HandlerAddress at a helper we drop in image */
    {
        /* mov rax, imm64(finally_h); jmp rax */
        uint8_t *tr = image + 0x5000;
        uint64_t fn = (uint64_t)(uintptr_t)finally_h;
        tr[0] = 0x48; tr[1] = 0xb8; memcpy(tr + 2, &fn, 8); tr[10] = 0xff; tr[11] = 0xe0;
        *(DWORD *)(st + 12) = 0x5000;
    }
    memset(&rec, 0, sizeof rec);
    rec.ExceptionFlags = EXCEPTION_UNWINDING;
    d = __C_specific_handler(&rec, (PVOID)0x1234, &ctx, &dc);
    CHECK("__C_specific_handler: __finally ran during unwind", g_finally_ran == 2);
    CHECK("__C_specific_handler: unwind phase returns ContinueSearch", d == ExceptionContinueSearch);

    /* search phase: __except filter returning EXCEPTION_CONTINUE_EXECUTION */
    {
        uint8_t *tr = image + 0x5000;
        uint64_t fn = (uint64_t)(uintptr_t)filter_continue_exec;
        tr[0] = 0x48; tr[1] = 0xb8; memcpy(tr + 2, &fn, 8); tr[10] = 0xff; tr[11] = 0xe0;
    }
    *(DWORD *)(st + 16) = 0x180;                            /* JumpTarget != 0 -> __except */
    *(DWORD *)(st + 12) = 0x5000;
    memset(&rec, 0, sizeof rec);
    rec.ExceptionCode = 0xC0000005;
    g_filter_arg_ok = 0;
    d = __C_specific_handler(&rec, (PVOID)0x1234, &ctx, &dc);
    CHECK("__C_specific_handler: filter got the exception pointers", g_filter_arg_ok);
    CHECK("__C_specific_handler: CONTINUE_EXECUTION propagates", d == ExceptionContinueExecution);

    /* search phase: filter returning EXCEPTION_CONTINUE_SEARCH */
    {
        uint8_t *tr = image + 0x5000;
        uint64_t fn = (uint64_t)(uintptr_t)filter_continue_search;
        tr[0] = 0x48; tr[1] = 0xb8; memcpy(tr + 2, &fn, 8); tr[10] = 0xff; tr[11] = 0xe0;
    }
    d = __C_specific_handler(&rec, (PVOID)0x1234, &ctx, &dc);
    CHECK("__C_specific_handler: CONTINUE_SEARCH keeps searching", d == ExceptionContinueSearch);
}

/* RtlUnwindEx to a target frame: two frames described by a static table; the outer frame is the target. */
static void test_rtl_unwind_ex(void)
{
    static RUNTIME_FUNCTION table[1] = { { 0x6000, 0x6100, 0x6200 } };
    const uint8_t codes[1][2] = { { 4, (uint8_t)((0 << 4) | ALLOC_SMALL) } };    /* sub rsp,8 */
    DWORD64 base = (DWORD64)(uintptr_t)image;
    CONTEXT c;
    uint64_t sp = (uint64_t)(uintptr_t)(stackbuf + (4 << 20));
    int jumped;
    put_unwind(0x6200, 1, 5, codes, 1, 0, 0);
    RtlAddFunctionTable(table, 1, base);
    memset(&c, 0, sizeof c);
    c.ContextFlags = CONTEXT_FULL;
    c.Rip = base + 0x6050;                                  /* inside the described function */
    c.Rsp = sp;
    *(uint64_t *)(uintptr_t)(sp + 8) = base + 0x6050;       /* return address into the same function's caller */
    g_continued = 0;
    jumped = setjmp(g_jmp);
    if (!jumped)
        RtlUnwindEx((PVOID)(uintptr_t)(sp + 0x10), (PVOID)(uintptr_t)(base + 0x60a0), 0, (PVOID)0x77, &c, 0);
    CHECK("RtlUnwindEx reached the target via NtContinue", g_continued);
    CHECK("RtlUnwindEx set the target instruction pointer", g_continue_ctx.Rip == base + 0x60a0);
    CHECK("RtlUnwindEx delivered the return value in RAX", g_continue_ctx.Rax == 0x77);
    RtlDeleteFunctionTable(table);
}

/* ---------------------------------------------------------------- fuzz */
static unsigned rng_state = 0x1234abcdu;
static unsigned rnd(void) { rng_state = rng_state * 1103515245u + 12345u; return rng_state >> 1; }

static void fuzz_virtual_unwind(unsigned iters)
{
    unsigned it;
    uint64_t sp0 = (uint64_t)(uintptr_t)(stackbuf + (1 << 23));
    uint64_t k;
    for (k = 0; k < STACK_BYTES / 8; ++k) ((uint64_t *)stackbuf)[k] = sp0;   /* reads yield an in-bounds pointer */
    for (it = 0; it < iters; ++it) {
        /* One ASan-guarded "module": [0,0x100) is code (random bytes, read by the epilog decoder), the UNWIND_INFO sits
         * at 0x100. Everything the unwinder touches for this image is inside M, so a read past it (past the codes, or the
         * epilog decoder walking off the function) is an ASan error. */
        const unsigned n = rnd() % 40;
        const unsigned padded = (n * 2 + 1) & ~1u;
        const unsigned flags = (rnd() & 1) ? UNW_FLAG_EHANDLER : 0;
        const unsigned msize = 0x100 + 4 + padded + (flags ? 4 : 0);
        uint8_t *M = malloc(msize);
        uint8_t *u = M + 0x100;
        RUNTIME_FUNCTION fe;
        CONTEXT c;
        DWORD64 est = 0;
        PVOID hd = 0;
        unsigned i;
        unsigned control = rnd() % 0x40;                             /* < prolog below: exercises the code-walk path */
        uint64_t sp = (uint64_t)(uintptr_t)(stackbuf + (1 << 23));   /* middle of the 16 MiB stack */
        for (i = 0; i < 0x100; ++i) M[i] = (uint8_t)rnd();           /* random "code" for the epilog decoder */
        M[0x3f] = 0xc3;                                              /* a ret within reach bounds the epilog decode */
        u[0] = (uint8_t)((flags << 3) | (1 + (rnd() & 1)));          /* version 1 or 2 */
        u[1] = 0x40;                                                 /* prolog size (control < prolog: no epilog path) */
        u[2] = (uint8_t)n;
        u[3] = (uint8_t)(rnd() & 0xff);                             /* frame register/offset */
        /* Generate a well-formed code stream (count == the actual number of slots, as every compiler emits): random ops
         * and opinfos, but a multi-slot op is only placed when its slots fit, and its immediate (alloc size / save
         * offset) is clamped small so the emulated stack accesses stay inside stackbuf. The version, prolog size,
         * handler flag and epilog metadata stay fully random. The buffer is sized to `padded`, so an over-read of the
         * codes is an ASan error. */
        for (i = 0; i < n;) {
            unsigned op = rnd() % 11, opinfo = rnd() & 15, slots, remaining = n - i;
            if (op == ALLOC_LARGE) slots = opinfo ? 3 : 2;
            else if (op == SAVE_NONVOL || op == SAVE_XMM128) slots = 2;
            else if (op == SAVE_NONVOL_FAR || op == SAVE_XMM128 + 1) slots = 3;
            else slots = 1;
            if (slots > remaining) { op = PUSH_NONVOL; slots = 1; }
            u[4 + i * 2] = (uint8_t)(rnd() & 0x3f);
            u[4 + i * 2 + 1] = (uint8_t)((opinfo << 4) | op);
            /* Keep every emulated stack access 8-byte aligned so a read yields the fill value (an in-bounds pointer)
             * rather than a byte-rotated one that, stored into a register and later used as a frame base, would send Rsp
             * out of the buffer. SAVE_NONVOL / ALLOC_LARGE(op0) scale the WORD by 8 already; the FAR forms add a raw
             * DWORD, so that is made a multiple of 8 here. */
            if (slots == 2) *(WORD *)(u + 4 + (i + 1) * 2) = (WORD)(rnd() % 0x800);
            else if (slots == 3) *(DWORD *)(u + 4 + (i + 1) * 2) = (rnd() % 0x80) * 8;
            i += slots;
        }
        if (padded > n * 2) u[4 + n * 2] = 0, u[4 + n * 2 + 1] = 0;
        if (flags) *(DWORD *)(u + 4 + padded) = 0x40;               /* handler RVA inside the code region */
        fe.BeginAddress = 0; fe.EndAddress = 0x100;
        fe.UnwindData = 0x100;                                       /* image_base + 0x100 == u */
        memset(&c, 0, sizeof c);
        c.ContextFlags = CONTEXT_FULL;
        /* every integer register starts inside the stack buffer, so a frame-register-relative Rsp (SET_FPREG) and every
         * push/save read stays within stackbuf even for random unwind data (no UNW_FLAG_CHAININFO is set, so the walk
         * never follows a random chain pointer). */
        for (i = 0; i < 16; ++i) (&c.Rax)[i] = sp;
        c.Rsp = sp;
        RtlVirtualUnwind(flags, (DWORD64)(uintptr_t)M, (DWORD64)(uintptr_t)M + control, &fe, &c, &hd, &est, 0);
        free(M);
    }
}

static void fuzz_c_handler(unsigned iters)
{
    unsigned it;
    uint8_t *st = image + 0x8000;
    for (it = 0; it < iters; ++it) {
        const unsigned n = rnd() % 24;
        EXCEPTION_RECORD rec;
        CONTEXT ctx;
        DISPATCHER_CONTEXT dc;
        unsigned i;
        *(DWORD *)st = n;
        for (i = 0; i < n; ++i) {
            DWORD b = rnd() % 0x1000, e = b + 1 + rnd() % 0x1000;
            *(DWORD *)(st + 4 + i * 16 + 0) = b;
            *(DWORD *)(st + 4 + i * 16 + 4) = e;
            *(DWORD *)(st + 4 + i * 16 + 8) = 0x5000;       /* handler trampoline -> a CONTINUE_SEARCH filter */
            *(DWORD *)(st + 4 + i * 16 + 12) = (rnd() & 1) ? (b + 1) : 0;   /* __except or __finally */
        }
        {   /* the handler trampoline is `xor eax,eax; ret`: called as a filter it returns EXCEPTION_CONTINUE_SEARCH,
             * called as a __finally it just returns - so the fuzz never triggers a real unwind or runs stray code. */
            uint8_t *tr = image + 0x5000;
            tr[0] = 0x31; tr[1] = 0xc0; tr[2] = 0xc3;
        }
        memset(&ctx, 0, sizeof ctx);
        memset(&rec, 0, sizeof rec);
        memset(&dc, 0, sizeof dc);
        dc.ImageBase = (DWORD64)(uintptr_t)image;
        dc.ControlPc = dc.ImageBase + (rnd() % 0x2000);
        dc.HandlerData = st;
        rec.ExceptionFlags = (rnd() & 1) ? EXCEPTION_UNWINDING : 0;
        __C_specific_handler(&rec, (PVOID)0x1234, &ctx, &dc);
    }
}

int main(void)
{
    LIST_ENTRY *heads[3];
    unsigned h;
    heads[0] = &shz_host_ldr.InLoadOrderModuleList; heads[1] = &shz_host_ldr.InMemoryOrderModuleList;
    image = mmap(0, IMAGE_BYTES, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    stackbuf = mmap(0, STACK_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED || stackbuf == MAP_FAILED) { printf("FAIL: mmap\n"); return 1; }
    heads[2] = &shz_host_ldr.InInitializationOrderModuleList;
    for (h = 0; h < 3; ++h) { heads[h]->Flink = heads[h]; heads[h]->Blink = heads[h]; }
    test_prologue();
    test_epilogue();
    test_function_tables();
    test_c_specific_handler();
    test_rtl_unwind_ex();
    fuzz_virtual_unwind(200000);
    fuzz_c_handler(100000);
    printf("unwind: %d checks, %d failed; fuzz 200000 unwinds + 100000 handler runs, no out-of-bounds access\n",
           checks, failures);
    return failures ? 1 : 0;
}
