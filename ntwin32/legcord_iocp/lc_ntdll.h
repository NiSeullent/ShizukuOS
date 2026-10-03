/* ntdll entry points required by libuv 1.52.1 winapi.c, implemented for Win98.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * uv__winapi_init (pinned libuv v1.52.1, deps/uv of Node 24.18.0) treats these
 * ntdll exports as mandatory and aborts when one is absent: RtlNtStatusToDosError,
 * NtDeviceIoControlFile, NtQueryInformationFile, NtSetInformationFile,
 * NtQueryVolumeInformationFile, NtQueryDirectoryFile, NtQuerySystemInformation,
 * NtQueryInformationProcess. RtlGetVersion is optional (NULL tolerated). Win98
 * has no NT ntdll, so LCIOCP.DLL provides them under ShizukuLc_* names.
 *
 * Only semantically valid Win98 equivalents are mapped. Anything else returns
 * the exact NTSTATUS (STATUS_NOT_IMPLEMENTED / STATUS_INVALID_DEVICE_REQUEST /
 * STATUS_INVALID_INFO_CLASS) with no side effect; nothing reports success it did
 * not perform. Structure layouts are the NT x86 MSVC-ABI layouts (explicit byte
 * offsets, independent of the compiler used for this module).
 */
#ifndef LC_NTDLL_H
#define LC_NTDLL_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
    LC_STATUS_SUCCESS = 0x00000000u,
    LC_STATUS_NOT_IMPLEMENTED = 0xC0000002u,
    LC_STATUS_INVALID_INFO_CLASS = 0xC0000003u,
    LC_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004u,
    LC_STATUS_INVALID_HANDLE = 0xC0000008u,
    LC_STATUS_INVALID_PARAMETER = 0xC000000Du,
    LC_STATUS_INVALID_DEVICE_REQUEST = 0xC0000010u,
    LC_ERROR_MR_MID_NOT_FOUND = 317 /* RtlNtStatusToDosError result for an unmapped status */
};

/* FILE_INFORMATION_CLASS / FS_INFORMATION_CLASS / PROCESSINFOCLASS values. */
enum {
    LC_FileBasicInformation = 4, LC_FileStandardInformation = 5, LC_FilePositionInformation = 14,
    LC_FileAllInformation = 18, LC_FileEndOfFileInformation = 20,
    LC_FileFsVolumeInformation = 1, LC_ProcessBasicInformation = 0
};
enum { LC_SEEK_SET = 0, LC_SEEK_CUR = 1, LC_SEEK_END = 2 };

typedef struct lc_nt_file_info {
    uint32_t attributes, volume_serial, links;
    uint64_t creation, access, write; /* FILETIME ticks (100 ns since 1601) */
    uint64_t size, index;
} lc_nt_file_info;

/* Win98 backend. Each call returns 1 on success, 0 on failure with error()
 * giving the Win32 error. Handles are provider-opaque. */
typedef struct lc_nt_ops {
    void *opaque;
    int (*file_info)(void *, uintptr_t handle, lc_nt_file_info *);
    int (*seek)(void *, uintptr_t handle, int64_t offset, int whence, uint64_t *position);
    int (*set_eof)(void *, uintptr_t handle);
    int (*set_times)(void *, uintptr_t handle, const uint64_t *creation, const uint64_t *access,
                     const uint64_t *write); /* NULL = leave unchanged */
    int (*process_ids)(void *, uintptr_t handle, uint32_t *pid, uint32_t *parent_pid);
    uint32_t (*error)(void *);
} lc_nt_ops;

/* NTSTATUS <-> Win32. to_dos follows RtlNtStatusToDosError: 0 -> 0, the
 * FACILITY_NTWIN32 forms 0xC007xxxx / 0x8007xxxx -> low 16 bits (the encoding
 * lc_sock.c stores in OVERLAPPED.Internal), table hit, else ERROR_MR_MID_NOT_FOUND. */
uint32_t lc_nt_status_to_dos(uint32_t status);
/* Inverse for backend errors: table first match, else 0xC0070000 | error (which
 * round-trips through lc_nt_status_to_dos). 0 -> STATUS_SUCCESS. */
uint32_t lc_nt_status_from_win32(uint32_t error);

/* All return an NTSTATUS; *information is the IO_STATUS_BLOCK.Information value
 * (bytes written/consumed, 0 on failure). */
uint32_t lc_nt_query_information_file(const lc_nt_ops *, uintptr_t handle, void *buffer, uint32_t length,
                                      uint32_t info_class, uint32_t *information);
uint32_t lc_nt_set_information_file(const lc_nt_ops *, uintptr_t handle, const void *buffer, uint32_t length,
                                    uint32_t info_class, uint32_t *information);
uint32_t lc_nt_query_volume_information_file(const lc_nt_ops *, uintptr_t handle, void *buffer, uint32_t length,
                                             uint32_t info_class, uint32_t *information);
uint32_t lc_nt_query_information_process(const lc_nt_ops *, uintptr_t handle, void *buffer, uint32_t length,
                                         uint32_t info_class, uint32_t *return_length);

#ifdef __cplusplus
}
#endif
#endif
