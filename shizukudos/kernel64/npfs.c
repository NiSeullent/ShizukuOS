/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 named pipes (placeholder while the subsystem is brought up). */
#include "ipc.h"
void npfs_handle_closed(kobject_t *o) { (void)o; }
void npfs_free(kobject_t *o) { (void)o; }
int32_t npfs_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                     int *handled)
{ (void)p; (void)r; (void)num; (void)a1; (void)a2; (void)a3; (void)a4; *handled = 0; return 0; }
