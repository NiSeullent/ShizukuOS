/* SPDX-License-Identifier: GPL-2.0-only
 * Common modern file APIs, using actual native file/handle/metadata backends.
 * No app-specific path or successful no-op. Current storage has no EAs,
 * named streams, EFS, reparse, or resumable checkpoints; explicit requests
 * requiring those facilities fail rather than silently discard semantics.
 */
#include "k32.h"
#include <fileapi.h>

K32API HANDLE WINAPI CreateFile2(LPCWSTR name, DWORD access, DWORD share, DWORD disposition,
                                 LPCREATEFILE2_EXTENDED_PARAMETERS extended)
{
    DWORD flags = FILE_ATTRIBUTE_NORMAL;
    LPSECURITY_ATTRIBUTES security = NULL;
    if (extended) {
        const DWORD supported_flags = FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN |
                                      FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_BACKUP_SEMANTICS;
        /* Native creation currently drops nondefault initial attributes. Do
         * not report those requests successful until that backend exists. */
        const DWORD supported_attributes = FILE_ATTRIBUTE_NORMAL;
        if (extended->dwSize != sizeof *extended || (extended->dwFileAttributes & 0xffff0000u)) {
            shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE;
        }
        if ((extended->dwFileAttributes & ~supported_attributes) || (extended->dwFileFlags & ~supported_flags) ||
            extended->dwSecurityQosFlags || extended->hTemplateFile ||
            (extended->lpSecurityAttributes && extended->lpSecurityAttributes->lpSecurityDescriptor)) {
            k32_unsupported("CreateFile2", "requested flags/template/security metadata require a backend", ERROR_NOT_SUPPORTED);
            return INVALID_HANDLE_VALUE;
        }
        flags = extended->dwFileAttributes | extended->dwFileFlags;
        security = extended->lpSecurityAttributes;
    }
    return CreateFileW(name, access, share, security, disposition, flags, NULL);
}

typedef struct {
    PCOPYFILE2_PROGRESS_ROUTINE callback;
    void *context;
    BOOL *cancel;
    BOOL keep;
} file2_progress;

static DWORD file2_notify(file2_progress *progress, COPYFILE2_MESSAGE *message)
{
    COPYFILE2_MESSAGE_ACTION action;
    if (progress->cancel && *progress->cancel) return ERROR_REQUEST_ABORTED;
    if (!progress->callback) return 0;
    action = progress->callback(message, progress->context);
    if (progress->cancel && *progress->cancel) return ERROR_REQUEST_ABORTED;
    switch (action) {
    case COPYFILE2_PROGRESS_CONTINUE: return 0;
    case COPYFILE2_PROGRESS_QUIET: progress->callback = NULL; return 0;
    case COPYFILE2_PROGRESS_CANCEL: return ERROR_REQUEST_ABORTED;
    case COPYFILE2_PROGRESS_STOP: progress->keep = TRUE; return ERROR_REQUEST_ABORTED;
    case COPYFILE2_PROGRESS_PAUSE: return ERROR_NOT_SUPPORTED; /* No persisted restart context yet. */
    default: return ERROR_INVALID_PARAMETER;
    }
}

K32API HRESULT WINAPI CopyFile2(PCWSTR from, PCWSTR to, COPYFILE2_EXTENDED_PARAMETERS *extended)
{
    HANDLE source = INVALID_HANDLE_VALUE, target = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER size;
    BYTE *buffer = NULL;
    DWORD flags = 0, error = 0, attributes, got, put, offset, chunk_size;
    ULONGLONG copied = 0, chunk = 0;
    BOOL created = FALSE;
    file2_progress progress = {0};
    COPYFILE2_MESSAGE message;
    if (!from || !to || !*from || !*to || (extended && extended->dwSize != sizeof *extended))
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    if (extended) {
        flags = extended->dwCopyFlags;
        progress.callback = extended->pProgressRoutine;
        progress.context = extended->pvCallbackContext;
        progress.cancel = extended->pfCancel;
    }
    if (flags & ~(COPY_FILE_FAIL_IF_EXISTS | COPY_FILE_OPEN_SOURCE_FOR_WRITE))
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    if (progress.cancel && *progress.cancel) return HRESULT_FROM_WIN32(ERROR_REQUEST_ABORTED);
    source = CreateFileW(from, GENERIC_READ | ((flags & COPY_FILE_OPEN_SOURCE_FOR_WRITE) ? GENERIC_WRITE : 0),
                         FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (source == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(shz_last_error());
    if (!GetFileInformationByHandle(source, &info) || !GetFileSizeEx(source, &size)) { error = shz_last_error(); goto done; }
    if (size.QuadPart < 0) { error = ERROR_INVALID_PARAMETER; goto done; }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { error = ERROR_ACCESS_DENIED; goto done; }
    if (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_ENCRYPTED |
                                 FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE)) { error = ERROR_NOT_SUPPORTED; goto done; }
    attributes = GetFileAttributesW(to);
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        if (flags & COPY_FILE_FAIL_IF_EXISTS) { error = ERROR_FILE_EXISTS; goto done; }
        if (attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY)) {
            error = ERROR_ACCESS_DENIED; goto done;
        }
        if (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_ENCRYPTED |
                           FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE)) { error = ERROR_NOT_SUPPORTED; goto done; }
        /* Use the actual volume and file identifier, not spelling: aliases
         * must not let CREATE_ALWAYS truncate or delete the source. */
        BY_HANDLE_FILE_INFORMATION destination_info;
        HANDLE existing = CreateFileW(to, FILE_READ_ATTRIBUTES,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        BOOL same;
        if (existing == INVALID_HANDLE_VALUE) { error = shz_last_error(); goto done; }
        if (!GetFileInformationByHandle(existing, &destination_info)) {
            error = shz_last_error(); CloseHandle(existing); goto done;
        }
        same = info.dwVolumeSerialNumber == destination_info.dwVolumeSerialNumber &&
               info.nFileIndexHigh == destination_info.nFileIndexHigh &&
               info.nFileIndexLow == destination_info.nFileIndexLow;
        if (!CloseHandle(existing)) { error = shz_last_error(); goto done; }
        if (same) { error = ERROR_SHARING_VIOLATION; goto done; }
    } else {
        DWORD lookup_error = shz_last_error();
        if (lookup_error != ERROR_FILE_NOT_FOUND && lookup_error != ERROR_PATH_NOT_FOUND) {
            error = lookup_error; goto done;
        }
    }
    buffer = RtlAllocateHeap(ShzProcessHeap(), 0, 65536);
    if (!buffer) { error = ERROR_NOT_ENOUGH_MEMORY; goto done; }
    target = CreateFileW(to, GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, 0, NULL,
                         flags & COPY_FILE_FAIL_IF_EXISTS ? CREATE_NEW : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (target == INVALID_HANDLE_VALUE) { error = shz_last_error(); goto done; }
    created = TRUE;
    memset(&message, 0, sizeof message); message.Type = COPYFILE2_CALLBACK_STREAM_STARTED;
    message.Info.StreamStarted.dwStreamNumber = 1;
    message.Info.StreamStarted.hSourceFile = source; message.Info.StreamStarted.hDestinationFile = target;
    message.Info.StreamStarted.uliStreamSize.QuadPart = size.QuadPart;
    message.Info.StreamStarted.uliTotalFileSize.QuadPart = size.QuadPart;
    if ((error = file2_notify(&progress, &message))) goto done;
    while (copied < (ULONGLONG)size.QuadPart) {
        chunk_size = (DWORD)(((ULONGLONG)size.QuadPart - copied) < 65536 ? (ULONGLONG)size.QuadPart - copied : 65536);
        memset(&message, 0, sizeof message); message.Type = COPYFILE2_CALLBACK_CHUNK_STARTED;
        message.Info.ChunkStarted.dwStreamNumber = 1;
        message.Info.ChunkStarted.hSourceFile = source; message.Info.ChunkStarted.hDestinationFile = target;
        message.Info.ChunkStarted.uliChunkNumber.QuadPart = chunk;
        message.Info.ChunkStarted.uliChunkSize.QuadPart = chunk_size;
        message.Info.ChunkStarted.uliStreamSize.QuadPart = size.QuadPart;
        message.Info.ChunkStarted.uliTotalFileSize.QuadPart = size.QuadPart;
        if ((error = file2_notify(&progress, &message))) goto done;
        offset = 0;
        while (offset < chunk_size) {
            if (progress.cancel && *progress.cancel) { error = ERROR_REQUEST_ABORTED; goto done; }
            if (!ReadFile(source, buffer + offset, chunk_size - offset, &got, NULL)) { error = shz_last_error(); goto done; }
            if (!got || got > chunk_size - offset) { error = ERROR_HANDLE_EOF; goto done; }
            offset += got;
        }
        got = chunk_size;
        offset = 0;
        while (offset < got) {
            if (progress.cancel && *progress.cancel) { error = ERROR_REQUEST_ABORTED; goto done; }
            if (!WriteFile(target, buffer + offset, got - offset, &put, NULL)) { error = shz_last_error(); goto done; }
            if (!put || put > got - offset) { error = ERROR_WRITE_FAULT; goto done; }
            offset += put; copied += put;
        }
        memset(&message, 0, sizeof message); message.Type = COPYFILE2_CALLBACK_CHUNK_FINISHED;
        message.Info.ChunkFinished.dwStreamNumber = 1;
        message.Info.ChunkFinished.hSourceFile = source; message.Info.ChunkFinished.hDestinationFile = target;
        message.Info.ChunkFinished.uliChunkNumber.QuadPart = chunk++;
        message.Info.ChunkFinished.uliChunkSize.QuadPart = chunk_size;
        message.Info.ChunkFinished.uliStreamSize.QuadPart = size.QuadPart;
        message.Info.ChunkFinished.uliTotalFileSize.QuadPart = size.QuadPart;
        message.Info.ChunkFinished.uliStreamBytesTransferred.QuadPart = copied;
        message.Info.ChunkFinished.uliTotalBytesTransferred.QuadPart = copied;
        if ((error = file2_notify(&progress, &message))) goto done;
    }
    memset(&message, 0, sizeof message); message.Type = COPYFILE2_CALLBACK_STREAM_FINISHED;
    message.Info.StreamFinished.dwStreamNumber = 1;
    message.Info.StreamFinished.hSourceFile = source; message.Info.StreamFinished.hDestinationFile = target;
    message.Info.StreamFinished.uliStreamSize.QuadPart = size.QuadPart;
    message.Info.StreamFinished.uliTotalFileSize.QuadPart = size.QuadPart;
    message.Info.StreamFinished.uliStreamBytesTransferred.QuadPart = copied;
    message.Info.StreamFinished.uliTotalBytesTransferred.QuadPart = copied;
    if ((error = file2_notify(&progress, &message))) goto done;
    if (!SetFileTime(target, &info.ftCreationTime, &info.ftLastAccessTime, &info.ftLastWriteTime)) { error = shz_last_error(); goto done; }
    if (!CloseHandle(target)) { error = shz_last_error(); target = INVALID_HANDLE_VALUE; goto done; }
    target = INVALID_HANDLE_VALUE;
    if (!SetFileAttributesW(to, info.dwFileAttributes)) error = shz_last_error();
 done:
    /* STOP completes this real stream with its actual partial byte count;
     * the original stop result is retained regardless of this notification. */
    if (progress.keep && target != INVALID_HANDLE_VALUE) {
        memset(&message, 0, sizeof message); message.Type = COPYFILE2_CALLBACK_STREAM_FINISHED;
        message.Info.StreamFinished.dwStreamNumber = 1;
        message.Info.StreamFinished.hSourceFile = source; message.Info.StreamFinished.hDestinationFile = target;
        message.Info.StreamFinished.uliStreamSize.QuadPart = size.QuadPart;
        message.Info.StreamFinished.uliTotalFileSize.QuadPart = size.QuadPart;
        message.Info.StreamFinished.uliStreamBytesTransferred.QuadPart = copied;
        message.Info.StreamFinished.uliTotalBytesTransferred.QuadPart = copied;
        if (progress.callback) progress.callback(&message, progress.context);
    }
    if (target != INVALID_HANDLE_VALUE) CloseHandle(target);
    if (source != INVALID_HANDLE_VALUE) CloseHandle(source);
    if (buffer) RtlFreeHeap(ShzProcessHeap(), 0, buffer);
    if (error && created && !progress.keep) DeleteFileW(to);
    return error ? HRESULT_FROM_WIN32(error) : S_OK;
}
