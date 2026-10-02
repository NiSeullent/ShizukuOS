/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PERSCHK_PROBE_H
#define PERSCHK_PROBE_H
#include <windows.h>
/* Explicit manual command, Windows boundary required; not cold-boot evidence. */
DWORD perschk_run(const char *command);
#endif
