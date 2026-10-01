/* SPDX-License-Identifier: GPL-2.0-only
 * NTWin32Wrapper9x WIN64 subsystem client: lets a 32-bit Windows 98 program start, feed, observe and kill a
 * Win64 PE32+ program that runs in the ShizukuDOS Kernel64 domain. Transport: NTWRAP9X.VXD DeviceIoControl
 * (ntwrapper/vxd/bridge.h), wire format: shizukudos/abi/shz_ipc.h (ABI 1.1, opcodes 0x200..). No handle
 * returned here is a Win32 kernel handle: it names a record inside NTW32.DLL and is only valid with these
 * functions. Every failure returns FALSE with a Win32 error from SetLastError(). Calls are not thread-safe:
 * serialize them (one thread per process is the tested model).
 *
 * Paths name files in the Kernel64 file system (for example \SHZ\TESTS\T_HELLO.EXE on WIN64.IMG), not
 * Windows 98 paths. The command line is passed verbatim (argv[0] included, as on Windows). */
#ifndef NTW64_H
#define NTW64_H
#include <stdint.h>

#define NTW64_INFO_SIZE 56u
typedef struct ntw64_info {
    uint32_t size;                      /* NTW64_INFO_SIZE on return */
    uint32_t abi_major, abi_minor;      /* inter-kernel ABI served by Kernel64 */
    uint32_t subsystem_version;         /* SHZ_W64_SUBSYS_VERSION */
    uint32_t capabilities;              /* SHZ_W64_CAP_* */
    uint32_t max_processes, active_processes;
    uint32_t console_window, console_chunk;
    uint32_t channel_id, generation;    /* as mapped by the VxD */
    uint32_t vxd_sent, vxd_received;    /* frames the VxD moved so far */
    uint32_t vxd_proto_errors;
} ntw64_info_t;

/* Win32 errors used by this client (numeric values of winerror.h). */
#define NTW64_ERROR_INVALID_HANDLE 6u
#define NTW64_ERROR_HANDLE_EOF 38u
#define NTW64_ERROR_TIMEOUT 1460u

#ifdef _WIN32
#include <windows.h>
/* FALSE with the VxD's error when the bridge is unavailable: 2 (VxD not loadable), 50 (no Shizuku Supervisor),
 * 55 (no Kernel64 channel), 1306 (ABI major mismatch). */
BOOL WINAPI NtwQuerySubsystem64(ntw64_info_t *info);
/* path: 1..260 UTF-16 units; path + cmdline + cwd <= 2,008 units (4,016 bytes through the VxD). Arguments that
 * do not fit one 192-byte frame travel in a shared-pool buffer. FALSE/2 when Kernel64 cannot find the image,
 * 193 for a bad image, 8 when all four Kernel64 slots are busy, 4 when all local records are occupied
 * or retired after generation exhaustion (retired records can have no open handle). */
BOOL WINAPI NtwCreateProcess64W(LPCWSTR path, LPCWSTR cmdline, LPCWSTR cwd, HANDLE *handle);
BOOL WINAPI NtwWaitProcess64(HANDLE handle, DWORD timeout_ms, DWORD *exit_code);           /* FALSE/1460 on timeout */
BOOL WINAPI NtwReadConsole64(HANDLE handle, void *buffer, DWORD capacity, DWORD *got);      /* blocks; FALSE/38 at end */
BOOL WINAPI NtwWriteConsole64(HANDLE handle, const void *buffer, DWORD bytes, DWORD *written);
BOOL WINAPI NtwCloseConsole64(HANDLE handle);                                              /* end of the process's stdin */
BOOL WINAPI NtwKillProcess64(HANDLE handle, DWORD exit_code);
BOOL WINAPI NtwCloseProcess64(HANDLE handle);   /* a running process keeps running; its slot is released at exit */
#endif
#endif
