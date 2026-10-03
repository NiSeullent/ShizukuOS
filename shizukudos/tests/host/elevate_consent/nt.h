/* SPDX-License-Identifier: GPL-2.0-only -- user/kernel IPC is recorded/refused. */
#ifndef SHZ_ELEVATE_HOST_NT_H
#define SHZ_ELEVATE_HOST_NT_H
#include "windows.h"
typedef int32_t NTSTATUS;
typedef uintptr_t ULONG_PTR;
NTSTATUS NtShzToken(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);
#endif
