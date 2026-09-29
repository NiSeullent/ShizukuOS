/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 window manager ("win32k-lite"): syscall entry for the graphics range 0x60-0x7f. (Step 1: display only.) */
#include "gfx.h"

int32_t sys_ext_graphics(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)r; (void)a3; (void)a4;
    switch (num) {
    case SYS_NtUserQueryDisplay: return gfx_syscall_display(cur, a1, a2);
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}
