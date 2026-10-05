/* SPDX-License-Identifier: GPL-2.0-only
 * winmm -> ShizukuOS Core audio transport. Thin typed wrappers over the single NtShzSound service (shizukudos/abi/shz_audio.h).
 * No other backend exists or is probed. Every function returns the NTSTATUS of the Core service unchanged. */
#ifndef SHZ_WAVXP_H
#define SHZ_WAVXP_H
#include "nt.h"
#define _WINMM_
#include <mmsystem.h>
#ifndef WAVE_FORMAT_EXTENSIBLE
#define WAVE_FORMAT_EXTENSIBLE 0xFFFE
#endif
#include "../../../abi/shz_audio.h"

NTSTATUS xp_query(shz_snd_caps *caps);              /* STATUS_DEVICE_NOT_READY when no initialised hardware */
NTSTATUS xp_open(unsigned ch, unsigned bits, unsigned rate, uint64_t *handle);
NTSTATUS xp_write(uint64_t h, const void *data, uint32_t len, uint64_t cookie, uint32_t *accepted, uint32_t *flags);
NTSTATUS xp_status(uint64_t h, shz_snd_status *st);
NTSTATUS xp_pause(uint64_t h, int pause);
NTSTATUS xp_reset(uint64_t h);
NTSTATUS xp_close(uint64_t h);
/* Worker module lifetime. xp_modref takes one real loader reference on this image (GetModuleHandleExW, refcounted, not
 * pinned); a worker thread that runs this DLL's code owns exactly one and must end with xp_modexit(m), which is
 * FreeLibraryAndExitThread: the reference is dropped from kernel32 code, so the image can only be unmapped after the thread
 * has left it. As long as a worker lives the image cannot reach DLL_PROCESS_DETACH, so DllMain never has to wait for a
 * worker (the wait would deadlock with the thread-exit path that takes the loader lock). */
HMODULE xp_modref(void);
void xp_modunref(HMODULE m);                        /* failure path before the thread ran */
void __attribute__((noreturn)) xp_modexit(HMODULE m);
int xp_present(shz_snd_caps *caps);                 /* 1 only if QUERY succeeded and caps.present == 1 */
MMRESULT xp_mm(NTSTATUS st);                        /* Core status -> MMRESULT (never maps failure to success) */
int xp_format_ok(unsigned ch, unsigned bits, unsigned rate, const shz_snd_caps *caps);
#endif
