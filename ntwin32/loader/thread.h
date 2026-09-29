/* SPDX-License-Identifier: GPL-2.0-only
 * Win32 thread handles. The start routine runs on the spawn callback's flow.
 * Compared with CreateThread. Wine thread.c was not copied.
 */
#ifndef NTW_THREAD_H
#define NTW_THREAD_H
#include <stdint.h>
#ifdef NTW_I386_LOADER
typedef uint32_t __attribute__((stdcall)) (*ntw_thread_start)(void *param);
#else
typedef uint32_t (*ntw_thread_start)(void *param);
#endif
typedef void (*ntw_thread_body)(void *slot);
typedef int (*ntw_thread_spawn)(void *user, ntw_thread_body body, void *slot);
typedef void (*ntw_thread_enter)(uint32_t index, uint32_t handle);
typedef void (*ntw_thread_leave)(uint32_t code);
typedef void (*ntw_thread_pause)(void);
typedef uint32_t (*ntw_thread_tid)(void);
void ntw_thread_set_spawn(ntw_thread_spawn spawn, ntw_thread_enter enter, ntw_thread_leave leave,
                          ntw_thread_pause pause, ntw_thread_tid tid, void *user);
int ntw_thread_flags_ok(uint32_t flags);
int ntw_thread_create(ntw_thread_start start, void *param, int suspended, uint32_t *handle, uint32_t *tid, uint32_t *error);
int ntw_thread_resume(uint32_t handle, uint32_t *previous, uint32_t *error);
int ntw_thread_exit_code(uint32_t handle, uint32_t *code, uint32_t *error);
int ntw_thread_wait(uint32_t handle, int block, uint32_t *result, uint32_t *error);
int ntw_thread_owns(uint32_t handle);
int ntw_thread_close(uint32_t handle, uint32_t *error);
uint32_t ntw_thread_self(void);
int ntw_thread_duplicate(uint32_t source, uint32_t *out, uint32_t *error);
void ntw_thread_complete(uint32_t handle, uint32_t code);
#endif
