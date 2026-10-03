/* SPDX-License-Identifier: GPL-2.0-only
 * Stack capture for Windows 98 (no CaptureStackBackTrace/RtlCaptureStackBackTrace in KERNEL32/NTDLL exports).
 * Walks the EBP frame chain with every dereference validated by a readability callback. Limit (truthful):
 * only code compiled with frame pointers is walked; a frame-pointer-omitting caller ends the walk early.
 */
#ifndef SHZ_OFFICE_SAL_DIAG_H
#define SHZ_OFFICE_SAL_DIAG_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* read two consecutive words at addr (saved frame pointer, return address); 0 = unreadable */
typedef int (*ofd_read2)(void *ctx, uintptr_t addr, uintptr_t out[2]);
/* Returns frames stored (<= max). Frames below `skip` are dropped. Stops on misalignment, unreadable
 * memory, a null return address, a non-increasing frame pointer or a step above 1 MiB. */
uint32_t ofd_walk_frames(uintptr_t frame, ofd_read2 rd, void *ctx, uint32_t skip, uint32_t max, uintptr_t *out);
#ifdef __cplusplus
}
#endif
#endif
