/* SPDX-License-Identifier: GPL-2.0-only
 * CreateFileW -> NtCreateFile desired-access translation (kernel32.dll).
 * Win32 always adds SYNCHRONIZE | FILE_READ_ATTRIBUTES. FILE_FLAG_DELETE_ON_CLOSE
 * becomes the native FILE_DELETE_ON_CLOSE option, which ZwCreateFile requires to
 * be accompanied by DELETE in DesiredAccess; the wrapper requests DELETE so the
 * kernel still authorizes deletion (path/share/read-only/authority checks) and
 * a raw native caller without DELETE keeps being rejected before mutation.
 */
#ifndef K32_CREATE_ACCESS_H
#define K32_CREATE_ACCESS_H
#include <stdint.h>

#define K32_FILE_FLAG_DELETE_ON_CLOSE 0x04000000u
#define K32_NT_DELETE 0x00010000u
#define K32_NT_SYNCHRONIZE 0x00100000u
#define K32_NT_FILE_READ_ATTRIBUTES 0x00000080u

static inline uint32_t k32_create_native_access(uint32_t access, uint32_t flags)
{
    uint32_t native = access | K32_NT_SYNCHRONIZE | K32_NT_FILE_READ_ATTRIBUTES;
    if (flags & K32_FILE_FLAG_DELETE_ON_CLOSE) native |= K32_NT_DELETE;
    return native;
}
#endif
