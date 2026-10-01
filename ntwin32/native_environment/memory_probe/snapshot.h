/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MEMPROBE_SNAPSHOT_H
#define MEMPROBE_SNAPSHOT_H
#include <stddef.h>
#include <stdint.h>
/* Exact PE32 MEMORYSTATUS wire layout, all raw byte counts are DWORDs. */
typedef struct mp_status {
 uint32_t length,load,total_phys,avail_phys,total_page,avail_page,total_virtual,avail_virtual;
} mp_status;
enum { MP_BAD_LENGTH=1,MP_BAD_LOAD=2,MP_PHYS_RELATION=4,MP_PAGE_RELATION=8,
       MP_VIRTUAL_RELATION=16,MP_DWORD_MAX=32 };
uint32_t mp_flags(const mp_status *);
/* Trusted live inputs. Failure leaves the entire destination untouched.
 * Emits NAME=XXXXXXXX\r\n without a terminator; no libc, API or 64-bit math. */
size_t mp_line(char *,size_t,const char *,uint32_t);
uint32_t mp_tick_delta(uint32_t,uint32_t);
#endif
