/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Shared native shell file operations over the existing Win32/NT filesystem.
 * No independent namespace, package database, daemon or fake successful API.
 */
#ifndef SHZ_FILEOPS_H
#define SHZ_FILEOPS_H
#include <windows.h>

#define SHZ_FILE_PATH_CAP 260
#define SHZ_FILE_BLOB_CAP (1u << 20)
typedef enum {
    SHZ_FILE_COPY = 1, SHZ_FILE_MOVE, SHZ_FILE_RENAME, SHZ_FILE_TRASH,
    SHZ_FILE_RESTORE, SHZ_FILE_MKDIR, SHZ_FILE_WRITE
} SHZ_FILE_OPERATION;
typedef enum {
    SHZ_FILE_RUNNING = 1, SHZ_FILE_DONE, SHZ_FILE_FAILED,
    SHZ_FILE_CANCELLED, SHZ_FILE_PARTIAL
} SHZ_FILE_STATE;
typedef struct {
    SHZ_FILE_STATE state;
    DWORD error, cleanup_error;
    ULONGLONG total_bytes, completed_bytes;
    BOOL namespace_committed; /* Real rename/create succeeded; later flush/cleanup can still fail. */
    WCHAR result_path[SHZ_FILE_PATH_CAP];
    WCHAR recovery_path[SHZ_FILE_PATH_CAP]; /* Existing temp or .info if cleanup/recovery needs attention. */
} SHZ_FILE_RESULT;
typedef struct SHZ_FILE_JOB SHZ_FILE_JOB;

/* Strict absolute DOS path for the CURRENT backend: valid UTF16, <=127 UTF8
 * bytes/component, <300 NT UTF8 bytes, <260 NT UTF16 units. Never truncates.
 * Reserved names, relative/device/stream paths and trailing dots/spaces fail.
 */
BOOL ShzFilePathValidW(const WCHAR *path);
/* UI-only provisional path: bounded environment parsing, no I/O/auth query.
 * TRUE does not certify UID ownership, persistence or a mounted directory. */
BOOL ShzFileDocumentsPathW(WCHAR out[SHZ_FILE_PATH_CAP]);
/* Worker resolver: actual auth subject/UID and directory checks. create=FALSE
 * never creates a namespace entry (search uses this); TRUE ensures/flushes the
 * approved folder. Anonymous un-enrolled development uses E:\SHZ\DOCUMENTS.
 * Authenticated profiles must be E:\Users\<UID>\Documents; C: RAM rejected. */
BOOL ShzFileResolveDocumentsW(WCHAR out[SHZ_FILE_PATH_CAP],BOOL create);
BOOL ShzFileDefaultDocumentsW(WCHAR out[SHZ_FILE_PATH_CAP]);
BOOL ShzFileTrashDirectoryW(const WCHAR *source, WCHAR out[SHZ_FILE_PATH_CAP]);

/* Blocking helpers for a worker, never a UI thread. CREATE_NEW conflict policy
 * unless replace=TRUE is explicitly requested. Content is written to a real
 * sibling temp, flushed and byte-verified before the existing rename path.
 * This is verified publication, not a promised power-loss atomic snapshot.
 * For errors AFTER namespace publication, result.state=PARTIAL and the result
 * describes the actual committed state. Preserve the user's buffer/document.
 */
BOOL ShzFileWriteVerifiedW(const WCHAR *path, const void *bytes, DWORD count,
                          BOOL replace, SHZ_FILE_RESULT *result);

/* Owned job copies all paths/blob on submission. Each job has one bounded
 * native CreateThread; UI polls through its existing WM_TIMER. Closing a
 * window cancels/detaches safely; the worker owns its remaining reference.
 */
SHZ_FILE_JOB *ShzFileJobStart(SHZ_FILE_OPERATION op, const WCHAR *source,
                            const WCHAR *destination, const void *bytes,
                            DWORD count, BOOL replace);
void ShzFileJobPoll(SHZ_FILE_JOB *job, SHZ_FILE_RESULT *out);
void ShzFileJobCancel(SHZ_FILE_JOB *job);
void ShzFileJobRelease(SHZ_FILE_JOB *job);
/* Optional weak UI owner. No worker posts job pointers or owns a window. */
void ShzFileJobSetOwner(SHZ_FILE_JOB *job, HWND owner);
#define SHZ_FILEOPS_EXIT_BLOCKED (WM_APP + 112)
/* FALSE while an actual worker or verified editor write still owns work.
 * Focuses an existing Files owner and posts a status-only message. */
BOOL ShzFileOpsCanExit(void);
/* UI can observe completed namespace commits even when the original window
 * detached. Workers never call the shared UI/search subsystem directly. */
DWORD ShzFileOpsGeneration(void);
#endif
