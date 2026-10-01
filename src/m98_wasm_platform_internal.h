/* SPDX-License-Identifier: GPL-2.0-only
 * Original single-owner platform for pinned WAMR. No WASI, sockets or threads. */
#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
typedef CRITICAL_SECTION korp_mutex;
typedef intptr_t ssize_t;
#else
#include <pthread.h>
typedef pthread_mutex_t korp_mutex;
#endif
typedef uintptr_t korp_tid;
typedef uintptr_t korp_thread;
typedef int korp_cond;
typedef int korp_rwlock;
typedef int korp_sem;
typedef int os_file_handle;
typedef int os_raw_file_handle;
typedef void *os_dir_stream;
typedef int os_poll_file_handle;
typedef unsigned os_nfds_t;
typedef struct timespec os_timespec;
/* Global initialization is protected by the embedding's actual CAS gate. */
/* Only the explicitly guarded owner can enter WAMR, so no Win98 DLL TLS. */
#define os_thread_local_attribute
#define BH_APPLET_PRESERVED_STACK_SIZE (32768)
#define BH_THREAD_DEFAULT_PRIORITY 0
#define BH_HAS_DLFCN 0
static inline os_file_handle os_get_invalid_handle(void){return -1;}
uint32_t m98_wasm_thread_id(void);
unsigned os_getpagesize(void);
int m98_wasm_platform_ready(void);
int m98_wasm_snprintf(char *,size_t,const char *,...);
int m98_wasm_vsnprintf(char *,size_t,const char *,va_list);
int m98_wasm_start_budget(void);
char *m98_wasm_strtok_r(char *,const char *,char **);
#ifdef _WIN32
#define strtok_s m98_wasm_strtok_r
#endif
#define snprintf m98_wasm_snprintf
#define vsnprintf m98_wasm_vsnprintf
#endif
