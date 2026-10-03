/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NT_FILE_RIGHTS_H
#define SHZ_NT_FILE_RIGHTS_H
#include <stdint.h>
#define SHZ_FILE_READ_DATA 0x0001u
#define SHZ_FILE_WRITE_DATA 0x0002u
#define SHZ_FILE_APPEND_DATA 0x0004u
#define SHZ_FILE_WRITE_ATTRIBUTES 0x0100u
#define SHZ_FILE_DELETE 0x00010000u
#define SHZ_FILE_GENERIC_READ 0x00120089u
#define SHZ_FILE_GENERIC_WRITE 0x00120116u
#define SHZ_FILE_GENERIC_EXECUTE 0x001200a0u
#define SHZ_FILE_ALL_ACCESS 0x001f01ffu
/* Generic access is resolved to concrete file rights before handle publication.
 * WRITE_DAC/WRITE_OWNER alone grant no payload or directory mutation right. */
static inline uint32_t shz_file_access(uint32_t access)
{
    uint32_t mapped = access & ~0xf0000000u;
    if (access & 0x80000000u) mapped |= SHZ_FILE_GENERIC_READ;
    if (access & 0x40000000u) mapped |= SHZ_FILE_GENERIC_WRITE;
    if (access & 0x20000000u) mapped |= SHZ_FILE_GENERIC_EXECUTE;
    if (access & 0x10000000u) mapped |= SHZ_FILE_ALL_ACCESS;
    return mapped;
}
static inline int shz_file_can_read(uint32_t access)
{ return (shz_file_access(access) & SHZ_FILE_READ_DATA) != 0; }
static inline int shz_file_can_write(uint32_t access)
{ return (shz_file_access(access) & (SHZ_FILE_WRITE_DATA | SHZ_FILE_APPEND_DATA)) != 0; }
#endif
