/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll.dll: RtlGUIDFromString / RtlStringFromGUID, the documented conversions between a GUID and its registry form
 * "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" (hexadecimal digits of either case accepted, braces required).
 * Added for the DLLs ported from Wine (wintrust, setupapi); Shizuku-original code.
 */
#include "../include/nt.h"

NTSTATUS NTAPI RtlGUIDFromString(const SHZ_UNICODE_STRING *str, GUID *guid)
{
    static const BYTE layout[] = { 8, 4, 4, 2, 2, 2, 2, 2, 2, 2, 2 };   /* hex digits per field */
    const WCHAR *s;
    ULONG64 v;
    unsigned i, k, pos = 1;
    if (!str || !guid || str->Length != 38 * sizeof(WCHAR)) return STATUS_INVALID_PARAMETER;
    s = str->Buffer;
    if (s[0] != '{' || s[37] != '}') return STATUS_INVALID_PARAMETER;
    for (i = 0; i < sizeof layout; ++i) {
        v = 0;
        if (pos == 9 || pos == 14 || pos == 19 || pos == 24) { if (s[pos] != '-') return STATUS_INVALID_PARAMETER; ++pos; }
        for (k = 0; k < layout[i]; ++k, ++pos) {
            WCHAR c = s[pos];
            unsigned d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') d = (c | 0x20) - 'a' + 10;
            else return STATUS_INVALID_PARAMETER;
            v = v * 16 + d;
        }
        if (i == 0) guid->Data1 = (ULONG)v;
        else if (i == 1) guid->Data2 = (USHORT)v;
        else if (i == 2) guid->Data3 = (USHORT)v;
        else guid->Data4[i - 3] = (UCHAR)v;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlStringFromGUID(const GUID *guid, SHZ_UNICODE_STRING *str)
{
    static const char hex[] = "0123456789ABCDEF";
    WCHAR *p;
    int i;
    if (!guid || !str) return STATUS_INVALID_PARAMETER;
    str->Length = 38 * sizeof(WCHAR);
    str->MaximumLength = str->Length + sizeof(WCHAR);
    if (!(p = str->Buffer = RtlAllocateHeap(ShzProcessHeap(), 0, str->MaximumLength))) return STATUS_NO_MEMORY;
    *p++ = '{';
    for (i = 28; i >= 0; i -= 4) *p++ = hex[(guid->Data1 >> i) & 15];
    *p++ = '-';
    for (i = 12; i >= 0; i -= 4) *p++ = hex[(guid->Data2 >> i) & 15];
    *p++ = '-';
    for (i = 12; i >= 0; i -= 4) *p++ = hex[(guid->Data3 >> i) & 15];
    *p++ = '-';
    for (i = 0; i < 8; ++i) {
        if (i == 2) *p++ = '-';
        *p++ = hex[guid->Data4[i] >> 4];
        *p++ = hex[guid->Data4[i] & 15];
    }
    *p++ = '}';
    *p = 0;
    return STATUS_SUCCESS;
}

/* RtlImageNtHeader: the IMAGE_NT_HEADERS of a mapped image (NULL if the DOS/NT signatures do not match). */
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(HMODULE module)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)module;
    const IMAGE_NT_HEADERS *nt;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x10000000) return 0;
    nt = (const IMAGE_NT_HEADERS *)((const BYTE *)dos + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE ? (PIMAGE_NT_HEADERS)nt : 0;
}
