/* SPDX-License-Identifier: GPL-2.0-only
 * Syscall extension dispatch: numbers >= 0x50 are routed by range to the subsystem that owns them. Every subsystem
 * overrides its weak handler below from its own file (registry.c, gfx*.c, net*.c, ...), so adding a subsystem never
 * edits shared code. A number inside a range but unknown to the owner returns STATUS_INVALID_SYSTEM_SERVICE.
 */
#include "proc_internal.h"

#define EXT_WEAK(name) int32_t __attribute__((weak)) name(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, \
                                                           uint64_t a2, uint64_t a3, uint64_t a4) \
    { (void)cur; (void)r; (void)num; (void)a1; (void)a2; (void)a3; (void)a4; return STATUS_NOT_IMPLEMENTED; }

EXT_WEAK(sys_ext_registry)
EXT_WEAK(sys_ext_graphics)
EXT_WEAK(sys_ext_net)
EXT_WEAK(sys_ext_k32)
EXT_WEAK(sys_ext_misc)
EXT_WEAK(sys_ext_gpu)

int32_t sysext_dispatch(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    if (num >= 0x50 && num < 0x60) return sys_ext_registry(cur, r, num, a1, a2, a3, a4);
    if (num >= 0x60 && num < 0x80) return sys_ext_graphics(cur, r, num, a1, a2, a3, a4);
    if (num >= 0x80 && num < 0x90) return sys_ext_net(cur, r, num, a1, a2, a3, a4);
    if (num >= 0x90 && num < 0xa0) return sys_ext_k32(cur, r, num, a1, a2, a3, a4);
    if (num >= 0xa0 && num < 0xb0) return sys_ext_misc(cur, r, num, a1, a2, a3, a4);
    if (num >= 0xd0 && num < 0xe0) return sys_ext_gpu(cur, r, num, a1, a2, a3, a4);
    return STATUS_INVALID_SYSTEM_SERVICE;
}
