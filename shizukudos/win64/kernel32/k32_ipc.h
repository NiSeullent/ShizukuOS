/* SPDX-License-Identifier: GPL-2.0-only
 * Internal header of kernel32's IPC / process-model files (k32_ipc_*.c): file mappings, pipes, overlapped I/O and
 * completion ports, process creation, jobs, waits and timers over the Kernel64 IPC system calls (nt_ipc.h). */
#ifndef SHZ_K32_IPC_H
#define SHZ_K32_IPC_H
#include "k32.h"
#include "../include/nt_ipc.h"

/* Object attributes for an optional object name. `name` may start with Local\ or Global\ (the kernel resolves them).
 * Returns ERROR_* (0 on success). */
static inline DWORD k32_ipc_oa(LPCWSTR name, BOOL inherit, BOOL openif, SHZ_OBJECT_ATTRIBUTES *oa, SHZ_UNICODE_STRING *us)
{
    memset(oa, 0, sizeof *oa);
    oa->Length = sizeof *oa;
    oa->Attributes = (inherit ? SHZ_OBJ_INHERIT : 0) | (openif ? SHZ_OBJ_OPENIF : 0);
    if (name && name[0]) {
        size_t n = 0;
        while (name[n]) ++n;
        if (n > 60) return ERROR_FILENAME_EXCED_RANGE;
        us->Buffer = (PWSTR)name;
        us->Length = (USHORT)(n * 2);
        us->MaximumLength = us->Length;
        oa->ObjectName = us;
    }
    return 0;
}

static inline BOOL k32_ipc_fail(NTSTATUS st) { k32_nt_error(st); return FALSE; }

/* UTF-8 (the "ANSI" code page of this system) <-> UTF-16, k32_file.c */
int k32_utf8_to_wide(const char *s, int n, WCHAR *w, int cap);
int k32_wide_to_utf8(const WCHAR *w, int n, char *s, int cap);

/* the 100 ns relative timeout of a millisecond count (INFINITE -> no timeout) */
static inline PLARGE_INTEGER k32_ipc_timeout(DWORD ms, LARGE_INTEGER *li)
{
    if (ms == INFINITE) return 0;
    li->QuadPart = -(LONGLONG)ms * 10000;
    return li;
}
#endif
