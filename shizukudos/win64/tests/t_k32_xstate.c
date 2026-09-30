/* SPDX-License-Identifier: GPL-2.0-only
 * XState reporting and CONTEXT construction (kernel32/k32_xstate.c). The expectations are computed independently: the
 * enabled feature mask must agree with what CPUID says the OS enabled (OSXSAVE -> XCR0, else the legacy x87|SSE pair). */
#include "k32test.h"

#ifndef XSTATE_MASK_LEGACY
#define XSTATE_MASK_LEGACY 3ull
#endif
#ifndef CONTEXT_XSTATE
#define CONTEXT_XSTATE (CONTEXT_AMD64 | 0x40)
#endif
#ifndef PF_XSAVE_ENABLED
#define PF_XSAVE_ENABLED 17
#endif
BOOL WINAPI InitializeContext2(PVOID, DWORD, PCONTEXT *, PDWORD, DWORD64);   /* not in mingw-w64 11's headers */

static DWORD64 expected_mask(int *osxsave)
{
    unsigned a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    *osxsave = (c >> 27) & 1;
    if (*osxsave) {
        unsigned lo, hi;
        __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
        return ((DWORD64)hi << 32) | lo;
    }
    return XSTATE_MASK_LEGACY;
}

int main(void)
{
    int osxsave;
    const DWORD64 want = expected_mask(&osxsave);
    const DWORD64 got = GetEnabledXStateFeatures();
    static BYTE raw[sizeof(CONTEXT) + 64];
    PCONTEXT ctx = 0, ctx2 = 0;
    DWORD len = 0, flen = 0;
    DWORD64 m = ~0ull;
    PVOID p;
    static CONTEXT src, dst;
    printf("CPUID.1:ECX.OSXSAVE=%d enabled=%llx\n", osxsave, (unsigned long long)got);
    CHECKV(got == want, "GetEnabledXStateFeatures agrees with CPUID/XCR0", "got %llx want %llx", (unsigned long long)got, (unsigned long long)want);
    CHECK((got & XSTATE_MASK_LEGACY) == XSTATE_MASK_LEGACY, "x87 and SSE state are always enabled");
    CHECKV(IsProcessorFeaturePresent(PF_XSAVE_ENABLED) == (osxsave ? TRUE : FALSE), "PF_XSAVE_ENABLED follows CPUID.OSXSAVE", "%d", (int)IsProcessorFeaturePresent(PF_XSAVE_ENABLED));

    SetLastError(0);
    CHECK(!InitializeContext(0, CONTEXT_ALL, &ctx, &len) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && len >= sizeof(CONTEXT),
          "InitializeContext(NULL) reports the length with ERROR_INSUFFICIENT_BUFFER");
    CHECK(len <= sizeof raw, "the reported length fits sizeof(CONTEXT) + 64");
    CHECK(InitializeContext(raw, CONTEXT_ALL, &ctx, &len) && ctx && ((ULONG_PTR)ctx & 15) == 0 && (BYTE *)ctx >= raw &&
          (BYTE *)ctx + sizeof(CONTEXT) <= raw + len, "InitializeContext places a 16-byte aligned CONTEXT inside the buffer");
    CHECKV(ctx && ctx->ContextFlags == CONTEXT_ALL, "ContextFlags = the requested flags", "%lx", ctx ? (unsigned long)ctx->ContextFlags : 0ul);
    CHECK(GetXStateFeaturesMask(ctx, &m) && m == XSTATE_MASK_LEGACY, "GetXStateFeaturesMask of a CONTEXT_ALL context is the legacy pair");
    if (!osxsave) {
        SetLastError(0);
        CHECK(!SetXStateFeaturesMask(ctx, 4) && GetLastError() == ERROR_INVALID_PARAMETER, "SetXStateFeaturesMask(AVX) fails: the kernel did not enable it");
        SetLastError(0);
        CHECK(!InitializeContext2(raw, CONTEXT_ALL | CONTEXT_XSTATE, &ctx2, &len, 4) && GetLastError() == ERROR_INVALID_PARAMETER,
              "InitializeContext2 asking for AVX state fails the same way");
    }
    CHECK(SetXStateFeaturesMask(ctx, 0) && GetXStateFeaturesMask(ctx, &m) && m == 0 && !(ctx->ContextFlags & 8),
          "SetXStateFeaturesMask(0) drops CONTEXT_FLOATING_POINT and reads back 0");
    CHECK(SetXStateFeaturesMask(ctx, XSTATE_MASK_LEGACY) && GetXStateFeaturesMask(ctx, &m) && m == XSTATE_MASK_LEGACY, "... and the legacy pair restores it");
    CHECK(InitializeContext2(raw, CONTEXT_ALL | CONTEXT_XSTATE, &ctx2, &len, XSTATE_MASK_LEGACY) && ctx2 && (ctx2->ContextFlags & 8),
          "InitializeContext2 with the legacy mask succeeds");
    p = LocateXStateFeature(ctx, 0, &flen);
    CHECKV(p == &ctx->FltSave && flen == 512, "LocateXStateFeature(x87) is FltSave, 512 bytes", "%p %lu", p, (unsigned long)flen);
    p = LocateXStateFeature(ctx, 1, &flen);
    CHECKV(p == (PVOID)ctx->FltSave.XmmRegisters && flen == 256, "LocateXStateFeature(SSE) is XmmRegisters, 256 bytes", "%p %lu", p, (unsigned long)flen);
    if (!osxsave) {
        SetLastError(0);
        CHECK(LocateXStateFeature(ctx, 2, &flen) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "LocateXStateFeature(AVX) is NULL: not enabled");
    }
    memset(&src, 0, sizeof src); memset(&dst, 0, sizeof dst);
    src.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
    src.Rip = 0x1234; src.Rax = 0x55; src.Rsp = 0x7000; src.R15 = 0xf; src.MxCsr = 0x1f80; src.FltSave.XmmRegisters[3].Low = 0xabc;
    dst.ContextFlags = CONTEXT_SEGMENTS; dst.SegDs = 0x2b; dst.Rax = 0x99;
    CHECK(CopyContext(&dst, CONTEXT_CONTROL | CONTEXT_INTEGER, &src) && dst.Rip == 0x1234 && dst.Rax == 0x55 && dst.Rsp == 0x7000 && dst.R15 == 0xf,
          "CopyContext copies the control and integer groups");
    CHECK(dst.FltSave.XmmRegisters[3].Low == 0 && dst.MxCsr == 0, "... and not the floating-point group that was not asked for");
    CHECKV(dst.ContextFlags == (CONTEXT_SEGMENTS | CONTEXT_CONTROL | CONTEXT_INTEGER) && dst.SegDs == 0x2b, "the destination keeps its own groups and gains the copied ones", "%lx", (unsigned long)dst.ContextFlags);
    CHECK(CopyContext(&dst, CONTEXT_ALL, &src) && dst.FltSave.XmmRegisters[3].Low == 0xabc && dst.MxCsr == 0x1f80,
          "CopyContext(CONTEXT_ALL) copies the groups the source has");
    SetLastError(0);
    CHECK(!CopyContext(&dst, CONTEXT_XSTATE, &src) && GetLastError() == ERROR_NOT_SUPPORTED, "CopyContext of XSTATE fails: no extended state exists");
    {
        HMODULE k = GetModuleHandleW(L"kernel32.dll");
        CHECK(GetProcAddress(k, "GetEnabledXStateFeatures") && GetProcAddress(k, "InitializeContext2") && GetProcAddress(k, "LocateXStateFeature"),
              "the XState names resolve through GetProcAddress (crashpad probes them)");
    }
    return k32t_finish("t_k32_xstate");
}
