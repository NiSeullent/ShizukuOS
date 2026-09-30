/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: extended processor state (XState) reporting and the CONTEXT construction helpers built on it.
 *
 * Kernel64 enables the x87/SSE state only: CR4.OSXSAVE is clear (kernel64/arch.c), the scheduler saves FXSAVE images
 * (sched.c), so CPUID.1:ECX.OSXSAVE reads 0 in user mode and no AVX/AVX-512 register state is preserved across a context
 * switch. GetEnabledXStateFeatures therefore reports exactly the legacy pair (XSTATE_MASK_LEGACY = x87 | SSE), which is
 * what Windows reports on a system whose kernel has XSAVE disabled, and callers such as crashpad and V8's CPU probe then
 * take their no-AVX paths. Should the kernel ever enable OSXSAVE, the mask is read from XCR0 (XGETBV) instead, so this
 * file needs no change; the CONTEXT helpers below would then need the XSAVE_AREA layout for the extended features.
 *
 * InitializeContext(2), GetXStateFeaturesMask, SetXStateFeaturesMask, LocateXStateFeature, CopyContext follow the
 * documented Windows 7 SP1+ semantics for a machine without enabled extended features: a CONTEXT is exactly
 * sizeof(CONTEXT) bytes aligned to 16, the feature mask of a context is the legacy pair when its ContextFlags carry
 * CONTEXT_FLOATING_POINT, and asking for a feature the system does not enable fails with ERROR_INVALID_PARAMETER.
 */
#include "k32.h"

#ifndef XSTATE_MASK_LEGACY_FLOATING_POINT
#define XSTATE_MASK_LEGACY_FLOATING_POINT 1ull
#define XSTATE_MASK_LEGACY_SSE 2ull
#define XSTATE_MASK_LEGACY 3ull
#endif
#ifndef CONTEXT_XSTATE
#define CONTEXT_XSTATE (CONTEXT_AMD64 | 0x40)
#endif
#define XSTATE_LEGACY_FLOATING_POINT_ 0
#define XSTATE_LEGACY_SSE_ 1

static DWORD64 enabled_features(void)
{
    unsigned a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    if (c & (1u << 27)) {                                            /* OSXSAVE: the OS enabled XSAVE, XCR0 is the truth */
        unsigned lo, hi;
        __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
        return ((DWORD64)hi << 32) | lo;
    }
    return XSTATE_MASK_LEGACY;
}

K32API DWORD64 WINAPI GetEnabledXStateFeatures(void)
{
    return enabled_features();
}

K32API BOOL WINAPI GetXStateFeaturesMask(PCONTEXT ctx, PDWORD64 mask)
{
    if (!ctx || !mask) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    *mask = (ctx->ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT ? XSTATE_MASK_LEGACY : 0;
    return TRUE;
}

K32API BOOL WINAPI SetXStateFeaturesMask(PCONTEXT ctx, DWORD64 mask)
{
    if (!ctx || (mask & ~enabled_features())) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (mask & XSTATE_MASK_LEGACY) ctx->ContextFlags |= CONTEXT_FLOATING_POINT;
    else ctx->ContextFlags &= ~(CONTEXT_FLOATING_POINT & ~CONTEXT_AMD64);
    return TRUE;
}

static BOOL init_context(PVOID buffer, DWORD flags, DWORD64 xstate_mask, PCONTEXT *ctx, PDWORD length)
{
    const DWORD need = sizeof(CONTEXT) + 15;                        /* room to align the CONTEXT to 16 inside the buffer */
    ULONG_PTR p;
    if (!length || (flags & CONTEXT_AMD64) != CONTEXT_AMD64) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (xstate_mask & ~enabled_features()) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!buffer || *length < need) {
        *length = need;
        shz_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!ctx) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    p = ((ULONG_PTR)buffer + 15) & ~(ULONG_PTR)15;
    memset((void *)p, 0, sizeof(CONTEXT));
    *ctx = (PCONTEXT)p;
    (*ctx)->ContextFlags = flags;
    if (xstate_mask & XSTATE_MASK_LEGACY) (*ctx)->ContextFlags |= CONTEXT_FLOATING_POINT;
    return TRUE;
}

K32API BOOL WINAPI InitializeContext(PVOID buffer, DWORD flags, PCONTEXT *ctx, PDWORD length)
{
    return init_context(buffer, flags, 0, ctx, length);
}

K32API BOOL WINAPI InitializeContext2(PVOID buffer, DWORD flags, PCONTEXT *ctx, PDWORD length, DWORD64 xstate_mask)
{
    return init_context(buffer, flags, xstate_mask, ctx, length);
}

K32API PVOID WINAPI LocateXStateFeature(PCONTEXT ctx, DWORD feature, PDWORD length)
{
    if (!ctx) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (feature == XSTATE_LEGACY_FLOATING_POINT_) {
        if (length) *length = sizeof(XSAVE_FORMAT);                 /* the 512-byte FXSAVE image */
        return &ctx->FltSave;
    }
    if (feature == XSTATE_LEGACY_SSE_) {
        if (length) *length = 16 * sizeof(M128A);                   /* XMM0..XMM15 */
        return ctx->FltSave.XmmRegisters;
    }
    if (feature < 64 && ((1ull << feature) & enabled_features()))   /* an XSAVE feature the kernel enabled: not the case today */
        shz_set_last_error(ERROR_NOT_SUPPORTED);
    else
        shz_set_last_error(ERROR_INVALID_PARAMETER);
    return 0;
}

K32API BOOL WINAPI CopyContext(PCONTEXT dst, DWORD flags, PCONTEXT src)
{
    DWORD both;
    if (!dst || !src || (flags & CONTEXT_AMD64) != CONTEXT_AMD64) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (flags & (CONTEXT_XSTATE & ~CONTEXT_AMD64)) { shz_set_last_error(ERROR_NOT_SUPPORTED); return FALSE; }   /* no extended state exists */
    both = flags & src->ContextFlags;
    if ((both & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
        dst->SegSs = src->SegSs; dst->SegCs = src->SegCs; dst->EFlags = src->EFlags;
        dst->Rsp = src->Rsp; dst->Rip = src->Rip;
    }
    if ((both & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
        dst->Rax = src->Rax; dst->Rcx = src->Rcx; dst->Rdx = src->Rdx; dst->Rbx = src->Rbx; dst->Rbp = src->Rbp;
        dst->Rsi = src->Rsi; dst->Rdi = src->Rdi; dst->R8 = src->R8; dst->R9 = src->R9; dst->R10 = src->R10;
        dst->R11 = src->R11; dst->R12 = src->R12; dst->R13 = src->R13; dst->R14 = src->R14; dst->R15 = src->R15;
    }
    if ((both & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
        dst->SegDs = src->SegDs; dst->SegEs = src->SegEs; dst->SegFs = src->SegFs; dst->SegGs = src->SegGs;
    }
    if ((both & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT) {
        dst->FltSave = src->FltSave;
        dst->MxCsr = src->MxCsr;
    }
    if ((both & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
        dst->Dr0 = src->Dr0; dst->Dr1 = src->Dr1; dst->Dr2 = src->Dr2; dst->Dr3 = src->Dr3; dst->Dr6 = src->Dr6; dst->Dr7 = src->Dr7;
    }
    dst->ContextFlags = (dst->ContextFlags & ~(flags & ~CONTEXT_AMD64)) | both;
    return TRUE;
}
