/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_EXIT_ORIGINAL_KERNEL_H
#define NTW_EXIT_ORIGINAL_KERNEL_H
#include <windows.h>
/* Outside DllMain only; refuses an installed core with no original resolver.
 * Reports 1 for the pinned KernelEx original-export SDK route, 0 when no core
 * is resident. Results must belong to native Kernel32 committed image memory.
 */
FARPROC px_original_kernel(const char *,int *);
int px_original_win98(void);
#endif
