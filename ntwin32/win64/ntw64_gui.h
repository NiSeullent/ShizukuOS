/* SPDX-License-Identifier: GPL-2.0-only
 * NTW32 native Win64 GUI frame-pull client (draft wire: shizukudos/abi/shz_w64_gui.h). Six exports, distinct from
 * the runtime/W64/clock exports. Calls are serialized with the rest of ntw64.c (single-threaded callers). A
 * process HANDLE from NtwCreateProcess64W selects the local record; the server binds identity itself. */
#ifndef NTW64_GUI_H
#define NTW64_GUI_H
#include <windows.h>
#include <stdint.h>

typedef struct { ULONGLONG view_id, default_window_id; DWORD max_width, max_height, max_frame_bytes, max_chunk, lease_ms,
                 display_backend; /* SHZ_W64_GUI_DISPLAY_SCANOUT (1) or _HOSTED_PRIVATE (2) */ } NTW64_GUI_VIEW;
typedef struct { ULONGLONG snapshot_id, window_id; DWORD width, height, stride, byte_length, pixel_format, pixels_crc32; } NTW64_GUI_FRAME;
typedef struct { DWORD kind, flags; LONG x, y; DWORD key, scancode, clock_ms; } NTW64_GUI_INPUT;   /* SHZ_W64_GUI_IN_* */

BOOL WINAPI NtwQueryGui64(HANDLE process, NTW64_GUI_VIEW *view);
BOOL WINAPI NtwAcquireGuiFrame64(HANDLE process, NTW64_GUI_FRAME *frame);
BOOL WINAPI NtwReadGuiFrame64(HANDLE process, ULONGLONG snapshot_id, DWORD offset, DWORD length, void *out);
BOOL WINAPI NtwReleaseGuiFrame64(HANDLE process, ULONGLONG snapshot_id);
BOOL WINAPI NtwSendGuiInput64(HANDLE process, const NTW64_GUI_INPUT *input, DWORD *sequence);
BOOL WINAPI NtwCloseGui64(HANDLE process);

/* NTW32-internal (ntw64.c), not exported. */
BOOL ntw64_gui_transact(HANDLE handle, uint32_t opcode, uint8_t *payload, uint16_t len, uint8_t *reply_payload,
                        uint16_t want_len, int32_t *status);
BOOL ntw64_gui_poll_exit(HANDLE handle, int *exited, DWORD *exit_code);
#endif
