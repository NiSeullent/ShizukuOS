/* SPDX-License-Identifier: GPL-2.0-only
 * MSVC x64 directory enumeration ABI: 64-bit time, unsigned 32-bit file size.
 * Distinct from _finddata64 (64-bit size); this is not a symbol alias.
 */
#ifndef SHZ_UCRT_OFFICE_FIND_H
#define SHZ_UCRT_OFFICE_FIND_H
#include <stdint.h>
#include <stddef.h>
struct crt_finddata64 {
    unsigned attrib;
    long long time_create, time_access, time_write, size;
    char name[260];
};
struct crt_finddata64i32 {
    unsigned attrib;
    long long time_create, time_access, time_write;
    uint32_t size;
    char name[260];
};
_Static_assert(sizeof(struct crt_finddata64) == 304, "MSVC x64 finddata64 extent");
_Static_assert(sizeof(struct crt_finddata64i32) == 296, "MSVC x64 finddata64i32 extent");
_Static_assert(offsetof(struct crt_finddata64i32, time_create) == 8, "MSVC x64 time field");
_Static_assert(offsetof(struct crt_finddata64i32, size) == 32, "MSVC x64 32-bit size field");
_Static_assert(offsetof(struct crt_finddata64i32, name) == 36, "MSVC x64 filename field");
#endif
