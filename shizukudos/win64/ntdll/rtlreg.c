/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll: helpers the registry layer needs (RtlFreeUnicodeString, RtlFormatCurrentUserKeyPath, RtlGetLastNtStatus).
 * The registry system calls themselves (NtCreateKey ...) are generated stubs, see win64/build.py.
 */
#include "nt.h"
#include "ntdll_int.h"
#include "../include/ntreg.h"

/* Frees a string whose buffer was allocated from the process heap (RtlFormatCurrentUserKeyPath, ...). */
VOID NTAPI RtlFreeUnicodeString(SHZ_UNICODE_STRING *s)
{
    if (s->Buffer) RtlFreeHeap(ShzProcessHeap(), 0, s->Buffer);
    s->Buffer = 0;
    s->Length = s->MaximumLength = 0;
}

/* "\Registry\User\<SID>" of the current user. Windows derives the SID from the process token; Kernel64 has no tokens and a
 * single interactive identity, SHZ_USER_SID_W (documented in ntreg.h). The caller frees with RtlFreeUnicodeString. */
NTSTATUS NTAPI RtlFormatCurrentUserKeyPath(SHZ_UNICODE_STRING *out)
{
    static const WCHAR prefix[] = L"\\Registry\\User\\";
    static const WCHAR sid[] = SHZ_USER_SID_W;
    const ULONG pn = sizeof prefix / sizeof(WCHAR) - 1, sn = sizeof sid / sizeof(WCHAR) - 1;
    WCHAR *buf;
    ULONG i;
    if (!out) return STATUS_INVALID_PARAMETER;
    buf = RtlAllocateHeap(ShzProcessHeap(), 0, (pn + sn + 1) * sizeof(WCHAR));
    if (!buf) return STATUS_NO_MEMORY;
    for (i = 0; i < pn; ++i) buf[i] = prefix[i];
    for (i = 0; i < sn; ++i) buf[pn + i] = sid[i];
    buf[pn + sn] = 0;
    out->Buffer = buf;
    out->Length = (USHORT)((pn + sn) * sizeof(WCHAR));
    out->MaximumLength = (USHORT)((pn + sn + 1) * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlGetLastNtStatus(void) { return shz_last_status(); }
