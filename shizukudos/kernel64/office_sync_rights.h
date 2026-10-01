/* SPDX-License-Identifier: GPL-2.0-only: exact event/semaphore rights mapping. */
#ifndef SHZ_OFFICE_SYNC_RIGHTS_H
#define SHZ_OFFICE_SYNC_RIGHTS_H
#include <stdint.h>
#define SHZ_SYNC_ALL_ACCESS 0x001f0003u
#define SHZ_SYNC_MODIFY 2u
#define SHZ_SYNC_QUERY 1u
#define SHZ_SYNCHRONIZE 0x00100000u
static inline int shz_sync_map_access(uint32_t requested,uint32_t *mapped)
{
    uint32_t value=requested & 0x0fffffffu;
    if(requested & 0x80000000u)value|=0x00120001u;
    if(requested & 0x40000000u)value|=0x00120002u;
    if(requested & 0x20000000u)value|=0x00120000u;
    if(requested & 0x10000000u)value|=SHZ_SYNC_ALL_ACCESS;
    if(value & 0x02000000u){value&=~0x02000000u;value|=SHZ_SYNC_ALL_ACCESS;}
    if(value & ~SHZ_SYNC_ALL_ACCESS)return 0;
    *mapped=value;return 1;
}
static inline int shz_sync_rights_present(uint32_t granted,uint32_t needed)
{return (granted & needed)==needed;}
#endif
