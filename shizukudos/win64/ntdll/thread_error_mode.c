/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Thread error-mode storage ported from Wine dlls/ntdll/thread.c, commit
 * db11d0fe6a169c457e23d007e20404643d067aa8, RtlSet/GetThreadErrorMode.
 * Copyright 1996, 2003 Alexandre Julliard; Wine authors.
 * Adaptation: Shizuku's existing x64 TEB accessor and export declarations.
 * Wine include/winternl.h at the same commit identifies HardErrorMode at 0x16b0.
 * This implements the thread field; effective process fallback and error UI
 * are separate facilities and are not supplied by these accessors.
 */
#include "ntdll_int.h"

#define SHZ_TEB_HARD_ERROR_MODE 0x16b0u
#define SHZ_RTL_THREAD_ERROR_MASK 0x70u

SHZ_EXPORT ULONG NTAPI RtlGetThreadErrorMode(void)
{
    return *(const volatile ULONG *)(uintptr_t)(shz_teb() + SHZ_TEB_HARD_ERROR_MODE);
}

SHZ_EXPORT NTSTATUS NTAPI RtlSetThreadErrorMode(ULONG mode, PULONG old_mode)
{
    volatile ULONG *slot;
    if (mode & ~SHZ_RTL_THREAD_ERROR_MASK) return STATUS_INVALID_PARAMETER_1;
    slot = (volatile ULONG *)(uintptr_t)(shz_teb() + SHZ_TEB_HARD_ERROR_MODE);
    if (old_mode) *old_mode = *slot;
    *slot = mode;
    return STATUS_SUCCESS;
}
