/* SPDX-License-Identifier: GPL-2.0-only
 * Actual default-stream copying required by current Steam's CopyFileExW import.
 * Microsoft CopyFileExW/LPPROGRESS_ROUTINE contract; original implementation.
 * Supported: ordinary Kernel64 files, FAIL_IF_EXISTS, OPEN_SOURCE_FOR_WRITE,
 * progress/quiet/stop/cancel, attributes and timestamps. Extended streams,
 * ACL/EFS/reparse/sparse/compressed semantics and restart checkpoints require
 * filesystem work; their explicit flags/attributes fail before destination opens.
 */
#ifdef SHZ_STEAM_IO_HOST_TEST
#include "../tests/steam_io_host.h"
#else
#include "k32.h"
#endif

static DWORD copy_progress(LPPROGRESS_ROUTINE *callback, LPVOID data, LPBOOL cancel,
                           LARGE_INTEGER size, LARGE_INTEGER copied, DWORD reason, HANDLE source, HANDLE target)
{
    DWORD action = PROGRESS_CONTINUE;
    if (cancel && *cancel) return PROGRESS_CANCEL;
    if (*callback) action = (*callback)(size, copied, size, copied, 1, reason, source, target, data);
    if (cancel && *cancel) return PROGRESS_CANCEL;
    if (action == PROGRESS_QUIET) { *callback = 0; return PROGRESS_CONTINUE; }
    return action;
}

K32API BOOL WINAPI CopyFileExW(LPCWSTR from, LPCWSTR to, LPPROGRESS_ROUTINE callback,
                              LPVOID data, LPBOOL cancel, DWORD flags)
{
    const DWORD supported = COPY_FILE_FAIL_IF_EXISTS | COPY_FILE_OPEN_SOURCE_FOR_WRITE;
    HANDLE source = INVALID_HANDLE_VALUE, target = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER size, copied;
    BYTE *buffer = 0;
    DWORD error = 0, attributes, got, put, offset, action;
    BOOL created = FALSE, keep_partial = FALSE, result = FALSE;
    if (!from || !to || !*from || !*to) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (flags & ~supported) return k32_unsupported("CopyFileExW", "requested copy mode requires filesystem support", ERROR_NOT_SUPPORTED);
    if (cancel && *cancel) { shz_set_last_error(ERROR_REQUEST_ABORTED); return FALSE; }
    source = CreateFileW(from, GENERIC_READ | ((flags & COPY_FILE_OPEN_SOURCE_FOR_WRITE) ? GENERIC_WRITE : 0),
                         FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);
    if (source == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileInformationByHandle(source, &info) || !GetFileSizeEx(source, &size)) { error = shz_last_error(); goto done; }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { error = ERROR_ACCESS_DENIED; goto done; }
    if (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_ENCRYPTED |
                                 FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE)) {
        error = ERROR_NOT_SUPPORTED; goto done;
    }
    if (size.QuadPart < 0) { error = ERROR_INVALID_PARAMETER; goto done; }
    attributes = GetFileAttributesW(to);
    if (attributes != INVALID_FILE_ATTRIBUTES && (flags & COPY_FILE_FAIL_IF_EXISTS)) { error = ERROR_FILE_EXISTS; goto done; }
    if (attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE))) {
        error = ERROR_NOT_SUPPORTED; goto done;
    }
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY))) {
        error = ERROR_ACCESS_DENIED; goto done;
    }
    buffer = RtlAllocateHeap(ShzProcessHeap(), 0, 65536);
    if (!buffer) { error = ERROR_NOT_ENOUGH_MEMORY; goto done; }
    target = CreateFileW(to, GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, 0, 0,
                         (flags & COPY_FILE_FAIL_IF_EXISTS) ? CREATE_NEW : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (target == INVALID_HANDLE_VALUE) { error = shz_last_error(); goto done; }
    created = TRUE;
    copied.QuadPart = 0;
    action = copy_progress(&callback, data, cancel, size, copied, CALLBACK_STREAM_SWITCH, source, target);
    for (;;) {
        if (action != PROGRESS_CONTINUE) {
            keep_partial = action == PROGRESS_STOP;
            error = (action == PROGRESS_CANCEL || action == PROGRESS_STOP) ? ERROR_REQUEST_ABORTED : ERROR_INVALID_PARAMETER;
            goto done;
        }
        if (cancel && *cancel) { error = ERROR_REQUEST_ABORTED; goto done; }
        if (copied.QuadPart == size.QuadPart) break;
        if (!ReadFile(source, buffer, (DWORD)((size.QuadPart - copied.QuadPart) < 65536 ? size.QuadPart - copied.QuadPart : 65536), &got, 0)) {
            error = shz_last_error(); goto done;
        }
        if (!got) { error = ERROR_HANDLE_EOF; goto done; }
        offset = 0;
        while (offset < got) {
            if (cancel && *cancel) { error = ERROR_REQUEST_ABORTED; goto done; }
            if (!WriteFile(target, buffer + offset, got - offset, &put, 0)) { error = shz_last_error(); goto done; }
            if (!put || put > got - offset) { error = ERROR_WRITE_FAULT; goto done; }
            offset += put;
            copied.QuadPart += put;
            action = copy_progress(&callback, data, cancel, size, copied, CALLBACK_CHUNK_FINISHED, source, target);
            if (action != PROGRESS_CONTINUE) break;
        }
    }
    if (!SetFileTime(target, &info.ftCreationTime, &info.ftLastAccessTime, &info.ftLastWriteTime)) { error = shz_last_error(); goto done; }
    if (!CloseHandle(target)) { error = shz_last_error(); target = INVALID_HANDLE_VALUE; goto done; }
    target = INVALID_HANDLE_VALUE;
    if (!SetFileAttributesW(to, info.dwFileAttributes)) { error = shz_last_error(); goto done; }
    result = TRUE;
 done:
    if (target != INVALID_HANDLE_VALUE) CloseHandle(target);
    if (source != INVALID_HANDLE_VALUE) CloseHandle(source);
    if (buffer) RtlFreeHeap(ShzProcessHeap(), 0, buffer);
    if (!result && created && !keep_partial) DeleteFileW(to);
    if (!result) shz_set_last_error(error);
    return result;
}
