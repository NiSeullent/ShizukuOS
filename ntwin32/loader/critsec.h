/* SPDX-License-Identifier: GPL-2.0-only
 * 32-bit critical section. Layout matches RTL_CRITICAL_SECTION.
 * See PROVENANCE.md. This is not a success-only stub.
 */
#ifndef NTW_CRITSEC_H
#define NTW_CRITSEC_H
#include <stdint.h>
#define NTW_CS_NO_DEBUG_INFO 0x01000000u
#define NTW_CS_DYNAMIC_SPIN 0x02000000u
#define NTW_CS_STATIC_INIT 0x04000000u
#define NTW_CS_RESOURCE_TYPE 0x08000000u
#define NTW_CS_FORCE_DEBUG_INFO 0x10000000u
#define NTW_CS_FLAG_BITS 0xff000000u
#define NTW_CS_ALLOWED (NTW_CS_NO_DEBUG_INFO | NTW_CS_DYNAMIC_SPIN | NTW_CS_STATIC_INIT | \
    NTW_CS_RESOURCE_TYPE | NTW_CS_FORCE_DEBUG_INFO)
enum { NTW_CS_OK = 0, NTW_CS_INVALID = 87, NTW_CS_NO_MEMORY = 8, NTW_CS_NOT_OWNER = 288 };
typedef struct ntw_critical_section {
    uint32_t debug_info;
    int32_t lock_count;
    int32_t recursion_count;
    uint32_t owning_thread;
    uint32_t lock_semaphore;
    uint32_t spin_count;
} ntw_critical_section;
int ntw_cs_initialize(ntw_critical_section *section, uint32_t spin_count, uint32_t flags);
void ntw_cs_enter(ntw_critical_section *section);
void ntw_cs_leave(ntw_critical_section *section);
int ntw_cs_try_enter(ntw_critical_section *section);
void ntw_cs_delete(ntw_critical_section *section);
uint32_t ntw_cs_last_error(void);
/* Supplied by the host test or the i386 loader. */
uint32_t ntw_cs_thread_id(void);
void ntw_cs_yield(void);
#endif
