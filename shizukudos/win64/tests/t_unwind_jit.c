/* SPDX-License-Identifier: GPL-2.0-only
 * JIT code registered with the dynamic function table APIs (ntdll/unwind.c): V8 registers its code range with
 * RtlAddGrowableFunctionTable (Windows 8+) and unwinds through generated frames. The test generates a real x64 function in a
 * fresh PAGE_EXECUTE_READWRITE page, executes it, and from inside a callback that the generated code calls walks up the stack
 * with RtlLookupFunctionEntry / RtlVirtualUnwind through the generated frame. Expectations are computed from the code's own
 * layout (a 0x28-byte frame below the return address), not from what the unwinder reports.
 *
 *   0x00  sub rsp, 0x28            (48 83 EC 28)      prolog, 4 bytes: UWOP_ALLOC_SMALL 0x28
 *   0x04  mov rax, <callback>      (48 B8 imm64)
 *   0x0E  call rax                 (FF D0)
 *   0x10  add rsp, 0x28            (48 83 C4 28)
 *   0x14  ret                      (C3)            function [0x00, 0x15)
 */
#include "k32test.h"

#define CODE_FN_END 0x15
#define UNWIND_AT 0x40
#define TABLE_AT 0x80
#define RET_SITE 0x10                   /* the return address the call pushes: the instruction after `call rax` */

static DWORD64 g_base;
static PRUNTIME_FUNCTION g_found;
static DWORD64 g_found_base;
static CONTEXT g_after;                 /* context after unwinding the generated frame */
static DWORD64 g_jit_rsp;               /* RSP inside the generated function (after its prolog) */
static DWORD64 g_ret_addr;              /* the return address stored above that frame, read while the frame is live */
static int g_hit;

static __attribute__((noinline)) void cb(void)
{
    CONTEXT c;
    DWORD64 image = 0, frame = 0;
    PVOID handler_data = 0;
    PRUNTIME_FUNCTION f;
    RtlCaptureContext(&c);
    f = RtlLookupFunctionEntry(c.Rip, &image, 0);                 /* this callback, from the exe's .pdata */
    if (!f) return;
    RtlVirtualUnwind(0, image, c.Rip, f, &c, &handler_data, &frame, 0);       /* now in the generated function */
    if (c.Rip != g_base + RET_SITE) return;
    g_jit_rsp = c.Rsp;
    g_ret_addr = *(const DWORD64 *)(ULONG_PTR)(c.Rsp + 0x28);        /* the slot above the 0x28-byte frame */
    g_found = RtlLookupFunctionEntry(c.Rip, &g_found_base, 0);
    if (!g_found) return;
    RtlVirtualUnwind(0, g_found_base, c.Rip, g_found, &c, &handler_data, &frame, 0);
    g_after = c;
    g_hit = 1;
}

static unsigned char *make_code(void)
{
    unsigned char *p = VirtualAlloc(0, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    static const unsigned char head[] = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0xB8 };
    static const unsigned char tail[] = { 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3 };
    void *target = (void *)cb;
    RUNTIME_FUNCTION rf;
    if (!p) return 0;
    memcpy(p, head, sizeof head);
    memcpy(p + sizeof head, &target, 8);
    memcpy(p + sizeof head + 8, tail, sizeof tail);
    {   /* UNWIND_INFO: version 1, no flags, prolog size 4, one code (offset 4, UWOP_ALLOC_SMALL, info (0x28-8)/8 = 4), no frame register */
        static const unsigned char ui[] = { 0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00 };
        memcpy(p + UNWIND_AT, ui, sizeof ui);
    }
    rf.BeginAddress = 0; rf.EndAddress = CODE_FN_END; rf.UnwindData = UNWIND_AT;
    memcpy(p + TABLE_AT, &rf, sizeof rf);
    return p;
}

static int run_and_check(unsigned char *code, const char *label)
{
    void (*fn)(void) = (void (*)(void))(void *)code;
    printf("-- %s\n", label);
    g_hit = 0; g_found = 0; g_jit_rsp = 0;
    fn();
    /* the generated function ran and its callback walked up through it */
    CHECK(g_hit, "the generated function ran and its callback walked up through it");
    if (!g_hit) return 0;
    /* RtlLookupFunctionEntry found the registered RUNTIME_FUNCTION */
    CHECK(g_found == (PRUNTIME_FUNCTION)(code + TABLE_AT) && g_found->BeginAddress == 0 && g_found->EndAddress == CODE_FN_END, "RtlLookupFunctionEntry found the registered RUNTIME_FUNCTION");
    /* ImageBase reported for the hit is the registered base */
    CHECK(g_found_base == (DWORD64)(ULONG_PTR)code, "ImageBase reported for the hit is the registered base");
    /* unwinding the generated frame pops its 0x28 bytes and the return address */
    CHECKV(g_after.Rsp == g_jit_rsp + 0x28 + 8 && g_after.Rip == g_ret_addr && g_ret_addr != 0, "unwinding the generated frame pops its 0x28 bytes and the return address",
           "rsp %llx want %llx, rip %llx want %llx", (unsigned long long)g_after.Rsp, (unsigned long long)(g_jit_rsp + 0x30),
           (unsigned long long)g_after.Rip, (unsigned long long)g_ret_addr);
    return 1;
}

int main(void)
{
    unsigned char *code = make_code();
    DWORD64 image = 0;
    PVOID h = 0, h2 = 0;
    DWORD st;
    RUNTIME_FUNCTION *tab;
    CHECK(code != 0, "VirtualAlloc(PAGE_EXECUTE_READWRITE) for generated code");
    if (!code) return k32t_finish("t_unwind_jit");
    g_base = (DWORD64)(ULONG_PTR)code;
    tab = (RUNTIME_FUNCTION *)(code + TABLE_AT);
    CHECK(RtlLookupFunctionEntry(g_base + 4, &image, 0) == 0, "an unregistered generated PC has no function entry");

    /* ---- growable table, the form V8 uses */
    SetLastError(0);
    CHECK((LONG)RtlAddGrowableFunctionTable(0, tab, 0, 4, g_base, g_base + 0x1000) == (LONG)0xC000000D, "a NULL handle pointer is STATUS_INVALID_PARAMETER");
    CHECK((LONG)RtlAddGrowableFunctionTable(&h, 0, 0, 4, g_base, g_base + 0x1000) == (LONG)0xC000000D, "a NULL table is invalid");
    CHECK((LONG)RtlAddGrowableFunctionTable(&h, tab, 5, 4, g_base, g_base + 0x1000) == (LONG)0xC000000D, "EntryCount above MaximumEntryCount is invalid");
    CHECK((LONG)RtlAddGrowableFunctionTable(&h, tab, 0, 4, g_base + 0x1000, g_base + 0x1000) == (LONG)0xC000000D, "an empty range is invalid");
    st = RtlAddGrowableFunctionTable(&h, tab, 0, 4, g_base, g_base + 0x1000);
    CHECKV(st == 0 && h != 0, "RtlAddGrowableFunctionTable(count 0, max 4) succeeds and returns a handle", "status %lx", (unsigned long)st);
    CHECK(RtlLookupFunctionEntry(g_base + 4, &image, 0) == 0, "with EntryCount 0 nothing is found yet (the entry exists in memory but is not counted)");
    RtlGrowFunctionTable(h, 5);
    CHECK(RtlLookupFunctionEntry(g_base + 4, &image, 0) == 0, "growing past MaximumEntryCount is ignored");
    RtlGrowFunctionTable(h, 1);
    CHECK(RtlLookupFunctionEntry(g_base + 4, &image, 0) == tab && image == g_base, "after RtlGrowFunctionTable(1) the entry is found, ImageBase = RangeBase");
    CHECK(RtlLookupFunctionEntry(g_base + CODE_FN_END, &image, 0) == 0, "a PC past EndAddress is not found");
    CHECK(RtlLookupFunctionEntry(g_base + 0x1000 + 4, &image, 0) == 0, "a PC outside [RangeBase, RangeEnd) is never matched");
    run_and_check(code, "growable table");
    RtlGrowFunctionTable((PVOID)((ULONG_PTR)h + 1), 0);        /* a foreign handle is ignored */
    CHECK(RtlLookupFunctionEntry(g_base + 4, &image, 0) == tab, "a misaligned handle does not change the table");
    RtlDeleteGrowableFunctionTable(h);
    CHECK(RtlLookupFunctionEntry(g_base + 4, &image, 0) == 0, "RtlDeleteGrowableFunctionTable unregisters it");
    RtlDeleteGrowableFunctionTable(h);                          /* deleting twice is harmless */
    RtlGrowFunctionTable(h, 1);                                 /* a deleted handle is ignored */
    CHECK(RtlLookupFunctionEntry(g_base + 4, &image, 0) == 0, "a deleted handle cannot be revived by RtlGrowFunctionTable");

    /* ---- two tables at once, then the classic fixed-array form on the same code */
    st = RtlAddGrowableFunctionTable(&h, tab, 1, 1, g_base, g_base + 0x1000);
    CHECK(st == 0 && RtlAddGrowableFunctionTable(&h2, tab, 1, 1, g_base, g_base + 0x1000) == 0 && h2 != h, "two growable tables get distinct handles");
    RtlDeleteGrowableFunctionTable(h);
    CHECK(RtlLookupFunctionEntry(g_base + 4, &image, 0) == tab, "the second table still answers after the first was deleted");
    RtlDeleteGrowableFunctionTable(h2);
    CHECK(RtlLookupFunctionEntry(g_base + 4, &image, 0) == 0, "both gone");
    CHECK(RtlAddFunctionTable(tab, 1, g_base), "RtlAddFunctionTable (classic form) on the same code");
    run_and_check(code, "classic table");
    CHECK(RtlDeleteFunctionTable(tab), "RtlDeleteFunctionTable");
    CHECK(RtlLookupFunctionEntry(g_base + 4, &image, 0) == 0, "classic table removed");
    CHECK(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddGrowableFunctionTable") != 0 && GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlDeleteGrowableFunctionTable") != 0,
          "both names resolve through GetProcAddress (V8 looks them up in ntdll)");
    VirtualFree(code, 0, MEM_RELEASE);
    return k32t_finish("t_unwind_jit");
}
