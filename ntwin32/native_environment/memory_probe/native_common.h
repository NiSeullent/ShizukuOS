/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MEMPROBE_NATIVE_COMMON_H
#define MEMPROBE_NATIVE_COMMON_H
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "snapshot.h"
typedef struct mp_report {HANDLE file;int failed;} mp_report;
typedef struct mp_api_identity {DWORD pointer,kernel,rva,route,page_base,page_bytes,protection;} mp_api_identity;
int mp_report_open(mp_report *,const char *);
void mp_value(mp_report *,const char *,DWORD);
int mp_report_close(mp_report *);
/* Outside DllMain, single consumer. Saves/restores actual thread LastError on
 * every return. Resolution failure is represented only by NULL. Requires the
 * original Win98 guard and exact native Kernel32 named EAT identity. */
FARPROC mp_original(const char *,mp_api_identity *);
void mp_identity(mp_report *,const mp_api_identity *);
#endif
