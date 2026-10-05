/* SPDX-License-Identifier: GPL-2.0-only
 * Native ShizukuOS text editor, extracted and extended from the real editor in
 * shizukudos/win64/apps/shzdesk/main.c (ShizukuOS, GPL-2.0-only).
 * Keeps its bounded read/edit/unsaved-document model; replaces ASCII/fixed
 * geometry and synchronous destructive saving with the existing Noto shell
 * helpers and shared verified-publication file engine. No EDIT class exists
 * in the current USER32, so this is a cohosted shell module, not another shell.
 * ReactOS Notepad main.c reviewed for command/selection/find flow (ideas only).
 */
#ifdef SHZ_EDITOR_MODEL_TEST
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef uint16_t WCHAR;
typedef uint32_t DWORD;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define SHZ_EDITOR_TEXT_CAP 32767u
#define SHZ_EDITOR_FILE_CAP 131072u
static int ed_test_fail_alloc;
static void *EdAlloc(size_t n) { if (ed_test_fail_alloc) return NULL; return calloc(1, n); }
static void EdFree(void *p) { free(p); }
#else
#include "shzcrt.h"
#include "shell.h"
#include "layout.h"
#include "editor.h"
#include "fileops.h"
#include "search.h"
static void *EdAlloc(SIZE_T n) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n); }
static void EdFree(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }
#endif

#define ED_HISTORY 16u
#define ED_SEARCH_CAP 128u
typedef struct ED_SNAPSHOT {
    DWORD len, caret, anchor;
    unsigned long long revision;
    WCHAR text[1];
} ED_SNAPSHOT;
typedef struct ED_BUFFER {
    WCHAR text[SHZ_EDITOR_TEXT_CAP + 1];
    DWORD len, caret, anchor;
    unsigned long long revision, saved, serial;
    ED_SNAPSHOT *undo[ED_HISTORY], *redo[ED_HISTORY];
    unsigned nu, nr;
} ED_BUFFER;

/* Additional validation is necessary: current kernel32 UTF8 strict flags do
 * not reject every overlong/surrogate/out-of-range sequence. Conversion itself
 * remains the existing native MultiByteToWideChar/WideCharToMultiByte path. */
static BOOL EdTextScalar(unsigned cp)
{
    return cp && cp <= 0x10ffffu && !(cp >= 0xd800u && cp <= 0xdfffu) &&
        (cp >= 32u || cp == 9u || cp == 10u || cp == 13u) && cp != 127u;
}
static BOOL EdUtf8Valid(const unsigned char *p, DWORD n)
{
    DWORD i = 0;
    while (i < n) {
        unsigned cp, c = p[i++], k, need, minimum;
        if (c < 0x80u) { cp = c; need = 0; minimum = 0; }
        else if (c >= 0xc2u && c <= 0xdfu) { cp = c & 31u; need = 1; minimum = 0x80u; }
        else if (c >= 0xe0u && c <= 0xefu) { cp = c & 15u; need = 2; minimum = 0x800u; }
        else if (c >= 0xf0u && c <= 0xf4u) { cp = c & 7u; need = 3; minimum = 0x10000u; }
        else return FALSE;
        if (need > n - i) return FALSE;
        for (k = 0; k < need; ++k) {
            if ((p[i] & 0xc0u) != 0x80u) return FALSE;
            cp = (cp << 6) | (p[i++] & 63u);
        }
        if (cp < minimum || !EdTextScalar(cp)) return FALSE;
    }
    return TRUE;
}
static BOOL EdUtf16Valid(const WCHAR *p, DWORD n)
{
    DWORD i = 0;
    while (i < n) {
        unsigned cp = p[i++];
        if (cp >= 0xd800u && cp <= 0xdbffu) {
            if (i == n || p[i] < 0xdc00u || p[i] > 0xdfffu) return FALSE;
            cp = 0x10000u + ((cp - 0xd800u) << 10) + (p[i++] - 0xdc00u);
        }
        if (!EdTextScalar(cp)) return FALSE;
    }
    return TRUE;
}
static DWORD EdPrevious(const ED_BUFFER *b, DWORD p)
{
    if (!p) return 0;
    --p;
    if (p && ((b->text[p] >= 0xdc00u && b->text[p] <= 0xdfffu) ||
        (b->text[p] == 10 && b->text[p - 1] == 13))) --p;
    return p;
}
static DWORD EdNext(const ED_BUFFER *b, DWORD p)
{
    if (p >= b->len) return b->len;
    if ((b->text[p] >= 0xd800u && b->text[p] <= 0xdbffu) ||
        (b->text[p] == 13 && p + 1 < b->len && b->text[p + 1] == 10)) ++p;
    return p + 1;
}
static BOOL EdBoundary(const ED_BUFFER *b, DWORD p)
{
    return p <= b->len && (!p || p == b->len ||
        !((b->text[p] >= 0xdc00u && b->text[p] <= 0xdfffu) ||
          (b->text[p] == 10 && b->text[p - 1] == 13)));
}
static void EdClearStack(ED_SNAPSHOT **v, unsigned *n)
{
    while (*n) EdFree(v[--*n]);
}
static ED_SNAPSHOT *EdSnapshot(const ED_BUFFER *b)
{
    ED_SNAPSHOT *s = EdAlloc(sizeof(*s) + b->len * sizeof(WCHAR));
    if (!s) return NULL;
    s->len = b->len; s->caret = b->caret; s->anchor = b->anchor; s->revision = b->revision;
    memcpy(s->text, b->text, (b->len + 1) * sizeof(WCHAR));
    return s;
}
static void EdPush(ED_SNAPSHOT **v, unsigned *n, ED_SNAPSHOT *s)
{
    unsigned i;
    if (*n == ED_HISTORY) {
        EdFree(v[0]);
        for (i = 1; i < *n; ++i) v[i - 1] = v[i];
        --*n;
    }
    v[(*n)++] = s;
}
static BOOL EdReplace(ED_BUFFER *b, DWORD lo, DWORD hi, const WCHAR *text, DWORD n)
{
    ED_SNAPSHOT *s;
    if (lo > hi || !EdBoundary(b, lo) || !EdBoundary(b, hi) ||
        n > SHZ_EDITOR_TEXT_CAP - (b->len - (hi - lo)) ||
        !EdUtf16Valid(text, n) || b->serial == ~0ull) return FALSE;
    if (lo == hi && !n) return TRUE;
    s = EdSnapshot(b);
    if (!s) return FALSE; /* Never change the document if undo allocation fails. */
    EdClearStack(b->redo, &b->nr); EdPush(b->undo, &b->nu, s);
    memmove(b->text + lo + n, b->text + hi, (b->len - hi + 1) * sizeof(WCHAR));
    if (n) memcpy(b->text + lo, text, n * sizeof(WCHAR));
    b->len = b->len - (hi - lo) + n; b->caret = b->anchor = lo + n;
    b->revision = ++b->serial;
    return TRUE;
}
static BOOL EdHistory(ED_BUFFER *b, BOOL redo)
{
    ED_SNAPSHOT **from = redo ? b->redo : b->undo, **to = redo ? b->undo : b->redo;
    unsigned *nf = redo ? &b->nr : &b->nu, *nt = redo ? &b->nu : &b->nr;
    ED_SNAPSHOT *cur, *old;
    if (!*nf) return FALSE;
    cur = EdSnapshot(b); if (!cur) return FALSE;
    old = from[--*nf]; EdPush(to, nt, cur);
    memcpy(b->text, old->text, (old->len + 1) * sizeof(WCHAR));
    b->len = old->len; b->caret = old->caret; b->anchor = old->anchor; b->revision = old->revision;
    EdFree(old); return TRUE;
}
static DWORD EdLineStart(const ED_BUFFER *b, DWORD p)
{
    while (p && b->text[p - 1] != 10 && b->text[p - 1] != 13) --p;
    return p;
}
static DWORD EdLineEnd(const ED_BUFFER *b, DWORD p)
{
    while (p < b->len && b->text[p] != 10 && b->text[p] != 13) ++p;
    return p;
}
static DWORD EdFind(const ED_BUFFER *b, const WCHAR *needle, DWORD n, DWORD begin)
{
    DWORD p, i;
    if (!n || n > b->len || !EdUtf16Valid(needle, n)) return (DWORD)-1;
    for (p = begin; p <= b->len - n; ++p) {
        if (!EdBoundary(b, p) || !EdBoundary(b, p + n)) continue;
        for (i = 0; i < n && b->text[p + i] == needle[i]; ++i) { }
        if (i == n) return p;
    }
    return (DWORD)-1;
}

#ifndef SHZ_EDITOR_MODEL_TEST
#define ED_TIMER 1u
enum { IO_READ = 1, IO_SAVE, IO_DEFAULT };
enum { DLG_NONE, DLG_OPEN, DLG_SAVE, DLG_OVERWRITE, DLG_CLOSE };
enum { BTN_NEW, BTN_OPEN, BTN_SAVE, BTN_SAVEAS, BTN_UNDO, BTN_REDO, BTN_FIND, BTN_COUNT };
typedef struct ED_IO {
    volatile LONG refs, cancel;
    HANDLE thread;
    int kind;
    BOOL replace, ok, bom;
    DWORD len, error;
    WCHAR path[SHZ_FILE_PATH_CAP];
    WCHAR *text;
    SHZ_FILE_RESULT result;
} ED_IO;
typedef struct EDITOR {
    HWND hwnd;
    ED_BUFFER *b;
    ED_IO *io;
    WCHAR path[SHZ_FILE_PATH_CAP], input[SHZ_FILE_PATH_CAP];
    WCHAR find[ED_SEARCH_CAP], replacement[ED_SEARCH_CAP];
    WCHAR message[512];
    WCHAR pending_high;
    BOOL bom, input_replace, finding, dragging, close_after_save, swallow_enter;
    unsigned dialog, dialog_focus, search_focus;
    DWORD first_line;
    int horizontal;
} EDITOR;
static EDITOR *g_editor;
static const WCHAR g_editor_class[] = L"ShizukuTextEditor";

static void EdIoRelease(ED_IO *io)
{
    if (!InterlockedDecrement(&io->refs)) { EdFree(io->text); EdFree(io); }
}
static DWORD EdLastError(DWORD fallback) { DWORD e = GetLastError(); return e ? e : fallback; }
static void EdMessage(EDITOR *e, const WCHAR *text, DWORD error)
{
    WCHAR number[24];
    ShzWcsCopy(e->message, 512, text);
    if (error) {
        ShzFormatU64(error, number, 24);
        ShzWcsCat(e->message, 512, L" (오류 "); ShzWcsCat(e->message, 512, number); ShzWcsCat(e->message, 512, L")");
    }
    InvalidateRect(e->hwnd, NULL, TRUE);
}
static void EdTitle(EDITOR *e)
{
    WCHAR title[SHZ_FILE_PATH_CAP + 40];
    const WCHAR *name = e->path, *p;
    for (p = e->path; *p; ++p) if (*p == L'\\') name = p + 1;
    ShzWcsCopy(title, SHZ_FILE_PATH_CAP + 40, e->b->revision != e->b->saved ? L"* " : L"");
    ShzWcsCat(title, SHZ_FILE_PATH_CAP + 40, *name ? name : L"새 문서");
    ShzWcsCat(title, SHZ_FILE_PATH_CAP + 40, L" — 텍스트 편집기");
    SetWindowTextW(e->hwnd, title);
}
static DWORD WINAPI EdWorker(void *parameter)
{
    ED_IO *io = parameter;
    unsigned char *raw = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD n = 0, got, offset = 0, skip = 0;
    LARGE_INTEGER size;
    int units;
    if (io->kind == IO_DEFAULT) {
        io->ok = ShzFileDefaultDocumentsW(io->path);
        if (!io->ok) io->error = EdLastError(ERROR_PATH_NOT_FOUND);
        goto done;
    }
    if (!ShzFilePathValidW(io->path)) { io->error = ERROR_INVALID_NAME; goto done; }
    if (io->kind == IO_READ) {
        file = CreateFileW(io->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) { io->error = EdLastError(ERROR_OPEN_FAILED); goto done; }
        if (!GetFileSizeEx(file, &size)) { io->error = EdLastError(ERROR_READ_FAULT); goto done; }
        if (size.QuadPart < 0 || size.QuadPart > SHZ_EDITOR_FILE_CAP) { io->error = ERROR_FILE_TOO_LARGE; goto done; }
        n = (DWORD)size.QuadPart;
        raw = EdAlloc(n ? n : 1);
        if (!raw) { io->error = ERROR_NOT_ENOUGH_MEMORY; goto done; }
        while (offset < n) {
            DWORD amount = n - offset > 16384 ? 16384 : n - offset;
            if (InterlockedCompareExchange(&io->cancel, 0, 0)) { io->error = ERROR_CANCELLED; goto done; }
            if (!ReadFile(file, raw + offset, amount, &got, NULL) || !got || got > amount) {
                io->error = EdLastError(ERROR_READ_FAULT); goto done;
            }
            offset += got;
        }
        if (!CloseHandle(file)) { file = INVALID_HANDLE_VALUE; io->error = EdLastError(ERROR_READ_FAULT); goto done; }
        file = INVALID_HANDLE_VALUE;
        if (n >= 3 && raw[0] == 0xef && raw[1] == 0xbb && raw[2] == 0xbf) { skip = 3; io->bom = TRUE; }
        if (!EdUtf8Valid(raw + skip, n - skip)) { io->error = ERROR_NO_UNICODE_TRANSLATION; goto done; }
        units = n == skip ? 0 : MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)raw + skip, (int)(n - skip), NULL, 0);
        if (units < 0 || (!units && n != skip)) { io->error = EdLastError(ERROR_NO_UNICODE_TRANSLATION); goto done; }
        if ((DWORD)units > SHZ_EDITOR_TEXT_CAP) { io->error = ERROR_FILE_TOO_LARGE; goto done; }
        io->text = EdAlloc(((DWORD)units + 1) * sizeof(WCHAR));
        if (!io->text) { io->error = ERROR_NOT_ENOUGH_MEMORY; goto done; }
        if (units && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)raw + skip, (int)(n - skip), io->text, units) != units) {
            io->error = EdLastError(ERROR_NO_UNICODE_TRANSLATION); goto done;
        }
        io->len = (DWORD)units; io->ok = !InterlockedCompareExchange(&io->cancel, 0, 0);
        if (!io->ok) io->error = ERROR_CANCELLED;
    } else {
        if (!EdUtf16Valid(io->text, io->len)) { io->error = ERROR_NO_UNICODE_TRANSLATION; goto done; }
        units = io->len ? WideCharToMultiByte(CP_UTF8, 0, io->text, (int)io->len, NULL, 0, NULL, NULL) : 0;
        if (units < 0 || (!units && io->len) || (DWORD)units > SHZ_EDITOR_FILE_CAP - 3) {
            io->error = EdLastError(ERROR_NO_UNICODE_TRANSLATION); goto done;
        }
        skip = io->bom ? 3 : 0; n = (DWORD)units + skip;
        raw = EdAlloc(n ? n : 1);
        if (!raw) { io->error = ERROR_NOT_ENOUGH_MEMORY; goto done; }
        if (skip) { raw[0] = 0xef; raw[1] = 0xbb; raw[2] = 0xbf; }
        if (units && WideCharToMultiByte(CP_UTF8, 0, io->text, (int)io->len, (char *)raw + skip, units, NULL, NULL) != units) {
            io->error = EdLastError(ERROR_NO_UNICODE_TRANSLATION); goto done;
        }
        io->ok = ShzFileWriteVerifiedW(io->path, raw, n, io->replace, &io->result);
        if (io->ok && (io->result.state != SHZ_FILE_DONE || !io->result.namespace_committed)) io->ok = FALSE;
        if (!io->ok) io->error = io->result.error ? io->result.error : EdLastError(ERROR_WRITE_FAULT);
    }
done:
    if (file != INVALID_HANDLE_VALUE && !CloseHandle(file) && !io->error) io->error = EdLastError(ERROR_READ_FAULT);
    EdFree(raw);
    EdIoRelease(io); /* Worker never refers to HWND/editor; UI detach is safe. */
    return 0;
}
static BOOL EdStartIo(EDITOR *e, int kind, const WCHAR *path, BOOL replace)
{
    ED_IO *io;
    if (e->io) { EdMessage(e, L"작업이 끝난 뒤 다시 시도하세요.", 0); return FALSE; }
    io = EdAlloc(sizeof *io);
    if (!io) { EdMessage(e, L"문서를 위한 메모리가 부족합니다.", ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    io->refs = 2; io->kind = kind; io->replace = replace; io->bom = e->bom;
    if (path && !ShzWcsCopy(io->path, SHZ_FILE_PATH_CAP, path)) { EdFree(io); return FALSE; }
    if (kind == IO_SAVE) {
        io->len = e->b->len; io->text = EdAlloc((io->len + 1) * sizeof(WCHAR));
        if (!io->text) { EdFree(io); EdMessage(e, L"저장 버퍼를 만들지 못했습니다.", ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        memcpy(io->text, e->b->text, (io->len + 1) * sizeof(WCHAR));
    }
    io->thread = CreateThread(NULL, 0, EdWorker, io, 0, NULL);
    if (!io->thread) {
        DWORD error = EdLastError(ERROR_NOT_ENOUGH_MEMORY);
        EdIoRelease(io); EdIoRelease(io); EdMessage(e, L"파일 작업을 시작하지 못했습니다.", error); return FALSE;
    }
    e->io = io; e->pending_high = 0;
    EdMessage(e, kind == IO_SAVE ? L"저장 중… 내용을 쓰고 확인하고 있습니다." : L"문서를 여는 중…", 0);
    return TRUE;
}
static void EdReset(EDITOR *e)
{
    ED_BUFFER *b = e->b;
    EdClearStack(b->undo, &b->nu); EdClearStack(b->redo, &b->nr);
    b->len = b->caret = b->anchor = 0; b->text[0] = 0;
    b->revision = b->saved = ++b->serial;
    e->path[0] = 0; e->bom = FALSE; e->first_line = 0; e->horizontal = 0; e->dialog = DLG_NONE;
    e->close_after_save = FALSE; e->pending_high = 0;
    EdTitle(e); EdMessage(e, L"새 UTF-8 문서입니다. Ctrl+S로 저장하세요.", 0);
}
static void EdPoll(EDITOR *e)
{
    ED_IO *io = e->io;
    DWORD wait;
    BOOL close;
    if (!io) return;
    wait = WaitForSingleObject(io->thread, 0);
    if (wait == WAIT_TIMEOUT) return;
    if (wait != WAIT_OBJECT_0) { EdMessage(e, L"파일 작업의 종료 상태를 확인하지 못했습니다. 문서를 유지합니다.", EdLastError(ERROR_GEN_FAILURE)); return; }
    /* A signalled thread is the publication/acquire boundary. Never consume
     * unsynchronised worker result fields or free a still-running job. */
    if (!CloseHandle(io->thread)) { EdMessage(e, L"파일 작업 핸들을 닫지 못했습니다. 문서를 유지합니다.", EdLastError(ERROR_GEN_FAILURE)); return; }
    io->thread = NULL; e->io = NULL;
    close = e->close_after_save;
    if (io->kind == IO_SAVE && io->result.namespace_committed) ShzSearchInvalidateFiles();
    if (io->ok) {
        if (io->kind == IO_DEFAULT) {
            if (!ShzWcsCopy(e->input, SHZ_FILE_PATH_CAP, io->path) || !ShzWcsCat(e->input, SHZ_FILE_PATH_CAP, L"\\새 문서.txt")) {
                EdMessage(e, L"문서 경로가 너무 깁니다.", ERROR_FILENAME_EXCED_RANGE);
            } else { e->dialog = DLG_SAVE; e->dialog_focus = 0; e->input_replace = TRUE; EdMessage(e, L"저장할 파일의 전체 경로를 입력하세요.", 0); }
        } else if (io->kind == IO_READ) {
            EdReset(e);
            memcpy(e->b->text, io->text, (io->len + 1) * sizeof(WCHAR)); e->b->len = io->len;
            ShzWcsCopy(e->path, SHZ_FILE_PATH_CAP, io->path); e->bom = io->bom;
            EdTitle(e); EdMessage(e, L"UTF-8 문서를 열었습니다.", 0);
            printf("SHZ-EDITOR opened=1 units=%lu utf8=1 bom=%d\n", (unsigned long)io->len, io->bom ? 1 : 0);
        } else {
            ShzWcsCopy(e->path, SHZ_FILE_PATH_CAP, io->path);
            e->b->saved = e->b->revision; e->dialog = DLG_NONE; e->close_after_save = FALSE;
            EdTitle(e); EdMessage(e, L"저장 완료 — 파일 내용을 다시 읽어 확인했습니다.", 0);
            printf("SHZ-EDITOR saved=1 units=%lu verified=1\n", (unsigned long)e->b->len);
        }
    } else {
        if (io->kind == IO_SAVE && io->result.namespace_committed) {
            EdMessage(e, L"파일 이름 변경은 완료됐지만 최종 기록 확인이 실패했습니다. 수정 내용은 유지됩니다.", io->error);
        } else if (io->kind == IO_DEFAULT) EdMessage(e, L"문서 폴더를 준비하지 못했습니다. E: 드라이브와 쓰기 권한을 확인하세요.", io->error);
        else if (io->kind == IO_READ && io->error == ERROR_NO_UNICODE_TRANSLATION) EdMessage(e, L"올바른 UTF-8 텍스트가 아닙니다. 현재 문서는 유지됩니다.", io->error);
        else if (io->kind == IO_READ && io->error == ERROR_FILE_TOO_LARGE) EdMessage(e, L"문서가 128KiB 또는 32767자 편집 한도를 넘었습니다. 현재 문서는 유지됩니다.", io->error);
        else EdMessage(e, io->kind == IO_SAVE ? L"저장하지 못했습니다. 수정 내용은 유지됩니다." : L"파일을 열지 못했습니다. 현재 문서는 유지됩니다.", io->error);
        if (io->result.namespace_committed && io->result.result_path[0]) { ShzWcsCat(e->message, 512, L" 기록된 파일: "); ShzWcsCat(e->message, 512, io->result.result_path); }
        if (io->result.cleanup_error) { WCHAR number[24]; ShzFormatU64(io->result.cleanup_error, number, 24); ShzWcsCat(e->message, 512, L" 정리 오류: "); ShzWcsCat(e->message, 512, number); }
        if (io->result.recovery_path[0]) { ShzWcsCat(e->message, 512, L" 복구 파일: "); ShzWcsCat(e->message, 512, io->result.recovery_path); }
        if (io->kind == IO_SAVE && !io->replace && !io->result.namespace_committed &&
            (io->error == ERROR_FILE_EXISTS || io->error == ERROR_ALREADY_EXISTS)) {
            ShzWcsCopy(e->input, SHZ_FILE_PATH_CAP, io->path);
            e->dialog = DLG_OVERWRITE; e->dialog_focus = 1;
            EdMessage(e, L"같은 이름의 파일이 있습니다. 내용을 덮어쓰려면 직접 덮어쓰기를 선택하세요.", io->error);
        } else e->close_after_save = FALSE;
        printf("SHZ-EDITOR io_failed=%d error=%lu committed=%d\n", io->kind, (unsigned long)io->error, io->result.namespace_committed ? 1 : 0);
    }
    {
        BOOL saved = io->kind == IO_SAVE && io->ok;
        EdIoRelease(io);
        if (close && saved) { DestroyWindow(e->hwnd); return; }
    }
    InvalidateRect(e->hwnd, NULL, TRUE);
}

static BOOL EdDirty(const EDITOR *e) { return e->b->revision != e->b->saved; }
static void EdDialog(EDITOR *e, unsigned dialog)
{
    if (e->io) { EdMessage(e, L"파일 작업이 끝난 뒤 다시 시도하세요.", 0); return; }
    e->dialog = dialog; e->dialog_focus = 0; e->pending_high = 0;
    if (dialog == DLG_OPEN) {
        ShzWcsCopy(e->input, SHZ_FILE_PATH_CAP, e->path[0] ? e->path : L"E:\\SHZ\\DOCUMENTS\\");
        e->input_replace = TRUE; EdMessage(e, L"열 문서의 전체 경로를 입력하세요. Escape로 취소합니다.", 0);
    } else if (dialog == DLG_SAVE) {
        if (!e->path[0]) { e->dialog = DLG_NONE; EdStartIo(e, IO_DEFAULT, NULL, FALSE); }
        else { ShzWcsCopy(e->input, SHZ_FILE_PATH_CAP, e->path); e->input_replace = TRUE; EdMessage(e, L"새 파일 경로를 입력하세요. 기존 파일은 덮어쓰기 전에 확인합니다.", 0); }
    } else if (dialog == DLG_CLOSE) {
        e->dialog_focus = 2; /* Cancel is the initial choice. */
        EdMessage(e, L"저장하지 않은 수정 내용이 있습니다. 저장 / 명시적 폐기 / 취소를 선택하세요.", 0);
    }
}
static void EdSave(EDITOR *e, BOOL save_as)
{
    if (e->io) { EdMessage(e, L"현재 파일 작업을 마친 뒤 저장하세요.", 0); return; }
    if (save_as || !e->path[0]) { EdDialog(e, DLG_SAVE); return; }
    e->dialog = DLG_NONE;
    if (!EdStartIo(e, IO_SAVE, e->path, TRUE)) e->close_after_save = FALSE;
}
static void EdClose(EDITOR *e)
{
    if (e->io) { EdMessage(e, L"파일 작업이 끝나기 전에는 문서를 닫을 수 없습니다.", 0); return; }
    if (EdDirty(e)) EdDialog(e, DLG_CLOSE);
    else DestroyWindow(e->hwnd);
}
static void EdDialogAction(EDITOR *e, unsigned action)
{
    if (action == 2 || (e->dialog != DLG_CLOSE && action == 1 && e->dialog != DLG_OVERWRITE)) {
        e->dialog = DLG_NONE; e->close_after_save = FALSE; e->pending_high = 0; EdMessage(e, L"취소했습니다. 문서를 유지합니다.", 0); return;
    }
    if (e->dialog == DLG_CLOSE) {
        if (action == 0) { e->close_after_save = TRUE; EdSave(e, FALSE); }
        else if (action == 1) { /* Dedicated visible discard action, never an implicit second-close. */
            e->b->saved = e->b->revision; DestroyWindow(e->hwnd);
        }
        return;
    }
    if (e->dialog == DLG_OVERWRITE) {
        if (action == 0) { e->dialog = DLG_NONE; EdStartIo(e, IO_SAVE, e->input, TRUE); }
        else { e->dialog = DLG_SAVE; e->dialog_focus = 0; EdMessage(e, L"다른 파일 이름을 입력하세요.", 0); }
        return;
    }
    if (!ShzFilePathValidW(e->input)) { EdMessage(e, L"파일 경로가 유효하지 않거나 너무 깁니다. 드라이브와 전체 경로를 입력하세요.", ERROR_INVALID_NAME); return; }
    if (e->dialog == DLG_OPEN) {
        e->dialog = DLG_NONE; EdStartIo(e, IO_READ, e->input, FALSE);
    } else {
        e->dialog = DLG_NONE;
        /* CREATE_NEW policy is checked by shared engine at actual publication;
         * no existence check on UI and no check-then-create overwrite race. */
        EdStartIo(e, IO_SAVE, e->input, FALSE);
    }
}

static void EdChange(EDITOR *e, const WCHAR *text, DWORD n)
{
    DWORD lo = e->b->caret < e->b->anchor ? e->b->caret : e->b->anchor;
    DWORD hi = e->b->caret > e->b->anchor ? e->b->caret : e->b->anchor;
    if (!EdReplace(e->b, lo, hi, text, n)) EdMessage(e, L"변경하지 못했습니다. 문서 크기 또는 메모리를 확인하세요.", 0);
    else { EdTitle(e); InvalidateRect(e->hwnd, NULL, TRUE); }
}
static void EdEnsureCaret(EDITOR *e);
static BOOL EdPasteField(EDITOR *e, WCHAR *field, DWORD cap);
static void EdFindNext(EDITOR *e, BOOL replace)
{
    DWORD n = (DWORD)ShzWcsLen(e->find), p, lo, hi;
    lo = e->b->caret < e->b->anchor ? e->b->caret : e->b->anchor;
    hi = e->b->caret > e->b->anchor ? e->b->caret : e->b->anchor;
    if (!n) { EdMessage(e, L"찾을 내용을 입력하세요.", 0); return; }
    if (replace && hi - lo == n && EdFind(e->b, e->find, n, lo) == lo) {
        EdChange(e, e->replacement, (DWORD)ShzWcsLen(e->replacement));
        EdMessage(e, L"선택한 내용을 바꿨습니다.", 0); return;
    }
    p = EdFind(e->b, e->find, n, hi);
    if (p == (DWORD)-1 && hi) p = EdFind(e->b, e->find, n, 0);
    if (p == (DWORD)-1) EdMessage(e, L"찾는 내용이 없습니다. 대소문자를 구분합니다.", 0);
    else { e->b->anchor = p; e->b->caret = p + n; EdEnsureCaret(e); EdMessage(e, L"일치하는 내용을 선택했습니다.", 0); }
}
static void EdActivate(EDITOR *e, unsigned button)
{
    if (e->io || e->dialog) return;
    if (button == BTN_NEW) {
        if (EdDirty(e)) EdMessage(e, L"새 문서를 만들기 전에 저장하거나 현재 문서를 닫고 폐기를 선택하세요.", 0);
        else EdReset(e);
    } else if (button == BTN_OPEN) {
        if (EdDirty(e)) EdMessage(e, L"다른 문서를 열기 전에 현재 수정 내용을 저장하세요.", 0);
        else EdDialog(e, DLG_OPEN);
    } else if (button == BTN_SAVE) EdSave(e, FALSE);
    else if (button == BTN_SAVEAS) EdSave(e, TRUE);
    else if (button == BTN_FIND) { e->finding = !e->finding; e->search_focus = 0; e->pending_high = 0; }
    else { if (!EdHistory(e->b, button == BTN_REDO)) EdMessage(e, L"되돌릴 변경이 없거나 메모리가 부족합니다.", 0); EdTitle(e); }
    InvalidateRect(e->hwnd, NULL, TRUE);
}

static BOOL EdClipboard(EDITOR *e, BOOL paste, BOOL cut)
{
    ED_BUFFER *b = e->b;
    DWORD lo = b->caret < b->anchor ? b->caret : b->anchor, hi = b->caret > b->anchor ? b->caret : b->anchor;
    HANDLE h;
    WCHAR *text;
    SIZE_T size;
    DWORD n;
    BOOL ok = FALSE;
    if (!OpenClipboard(e->hwnd)) { EdMessage(e, L"클립보드를 열지 못했습니다.", GetLastError()); return FALSE; }
    if (paste) {
        h = GetClipboardData(CF_UNICODETEXT);
        if (!h) goto done;
        size = GlobalSize(h); text = GlobalLock(h);
        if (!text || size < sizeof(WCHAR)) goto done;
        for (n = 0; n < size / sizeof(WCHAR) && n <= SHZ_EDITOR_TEXT_CAP && text[n]; ++n) { }
        if (n < size / sizeof(WCHAR) && n <= SHZ_EDITOR_TEXT_CAP && EdUtf16Valid(text, n)) {
            ok = EdReplace(b, lo, hi, text, n); if (ok) EdTitle(e);
        }
        GlobalUnlock(h);
    } else if (hi > lo) {
        h = GlobalAlloc(GMEM_MOVEABLE, (hi - lo + 1) * sizeof(WCHAR));
        if (!h) goto done;
        text = GlobalLock(h);
        if (!text) { GlobalFree(h); goto done; }
        memcpy(text, b->text + lo, (hi - lo) * sizeof(WCHAR)); text[hi - lo] = 0; GlobalUnlock(h);
        if (!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT, h)) GlobalFree(h);
        else { ok = TRUE; if (cut) { ok = EdReplace(b, lo, hi, NULL, 0); if (ok) EdTitle(e); } }
    }
done:
    CloseClipboard();
    if (!ok) EdMessage(e, L"클립보드 작업을 하지 못했습니다. 문서 크기와 UTF-16 텍스트를 확인하세요.", 0);
    InvalidateRect(e->hwnd, NULL, TRUE); return ok;
}

static int EdRowHeight(void) { return ShzPx(TH()->typography_line_height < 24 ? 24 : TH()->typography_line_height); }
static RECT EdTextRect(const EDITOR *e, const RECT *c)
{
    RECT r = { ShzPx(12), ShzPx(e->finding ? 162 : 92), c->right - ShzPx(12), c->bottom - ShzPx(58) };
    if (r.right < r.left) r.right = r.left;
    if (r.bottom < r.top) r.bottom = r.top;
    return r;
}
static DWORD EdLineNumber(const ED_BUFFER *b, DWORD pos)
{
    DWORD p = 0, line = 0;
    while (p < pos) {
        DWORD next = EdNext(b, p);
        if (b->text[p] == 10 || b->text[p] == 13) ++line;
        p = next;
    }
    return line;
}
static DWORD EdLineOffset(const ED_BUFFER *b, DWORD line)
{
    DWORD p = 0;
    while (p < b->len && line) {
        if (b->text[p] == 10 || b->text[p] == 13) --line;
        p = EdNext(b, p);
    }
    return p;
}
/* Proportional advances come from the SAME Noto provider as painting. Tabs
 * advance to a four-space stop; no fixed ASCII cell assumptions survive. */
static int EdRunWidth(const WCHAR *text, DWORD n)
{
    SIZE sz;
    return n && ShzTextMeasureW(text, (int)n, 1, &sz) ? sz.cx : 0;
}
static int EdPrefixWidth(const ED_BUFFER *b, DWORD lo, DWORD hi)
{
    DWORD p, run = lo;
    int x = 0, tab = EdRunWidth(L"    ", 4);
    if (tab < 1) tab = 16;
    for (p = lo; p < hi; ++p) if (b->text[p] == 9) {
        x += EdRunWidth(b->text + run, p - run); x += tab - x % tab; run = p + 1;
    }
    return x + EdRunWidth(b->text + run, hi - run);
}
static void EdEnsureCaret(EDITOR *e)
{
    RECT c, r;
    DWORD line = EdLineNumber(e->b, e->b->caret), start = EdLineStart(e->b, e->b->caret);
    int rows, x;
    GetClientRect(e->hwnd, &c); r = EdTextRect(e, &c);
    rows = (r.bottom - r.top) / EdRowHeight(); if (rows < 1) rows = 1;
    if (line < e->first_line) e->first_line = line;
    if (line >= e->first_line + (DWORD)rows) e->first_line = line - (DWORD)rows + 1;
    x = EdPrefixWidth(e->b, start, e->b->caret);
    if (x < e->horizontal) e->horizontal = x;
    if (x > e->horizontal + r.right - r.left - 4) e->horizontal = x - (r.right - r.left) + 4;
    if (e->horizontal < 0) e->horizontal = 0;
}
static void EdMove(EDITOR *e, DWORD p, BOOL extend)
{
    if (!EdBoundary(e->b, p)) return;
    e->b->caret = p; if (!extend) e->b->anchor = p;
    EdEnsureCaret(e); InvalidateRect(e->hwnd, NULL, TRUE);
}
static DWORD EdColumnTarget(EDITOR *e, DWORD start, DWORD end, int target)
{
    DWORD lo = start, hi = end, p;
    /* Binary search avoids an O(n^2) prefix scan on a maximum-length line. */
    while (lo < hi) {
        p = lo + (hi - lo) / 2;
        if (!EdBoundary(e->b, p)) --p;
        if (EdPrefixWidth(e->b, start, p) >= target) hi = p;
        else lo = EdNext(e->b, p);
    }
    if (lo > start) {
        DWORD previous = EdPrevious(e->b, lo);
        int a = EdPrefixWidth(e->b, start, previous), z = EdPrefixWidth(e->b, start, lo);
        if (target - a < z - target) lo = previous;
    }
    return lo;
}
static void EdVertical(EDITOR *e, BOOL down, BOOL extend)
{
    DWORD start = EdLineStart(e->b, e->b->caret), end = EdLineEnd(e->b, start), next;
    int x = EdPrefixWidth(e->b, start, e->b->caret);
    if (down) { if (end == e->b->len) return; next = EdNext(e->b, end); }
    else { if (!start) return; next = EdLineStart(e->b, EdPrevious(e->b, start)); }
    EdMove(e, EdColumnTarget(e, next, EdLineEnd(e->b, next), x), extend);
}
static void EdKey(EDITOR *e, UINT key)
{
    BOOL ctrl = GetKeyState(VK_CONTROL) < 0, shift = GetKeyState(VK_SHIFT) < 0;
    ED_BUFFER *b = e->b;
    if (e->io) {
        if (key == VK_ESCAPE && e->io->kind == IO_READ) InterlockedExchange(&e->io->cancel, 1);
        return;
    }
    e->pending_high = 0;
    if (e->dialog) {
        if (ctrl && key == 'V' && (e->dialog == DLG_OPEN || e->dialog == DLG_SAVE) && !e->dialog_focus) EdPasteField(e, e->input, SHZ_FILE_PATH_CAP);
        else if (ctrl && key == 'A' && (e->dialog == DLG_OPEN || e->dialog == DLG_SAVE) && !e->dialog_focus) e->input_replace = TRUE;
        else if (key == VK_ESCAPE) EdDialogAction(e, 2);
        else if (key == VK_TAB) {
            unsigned count = e->dialog == DLG_CLOSE ? 3 : e->dialog == DLG_OVERWRITE ? 2 : 3;
            e->dialog_focus = (e->dialog_focus + (shift ? count - 1 : 1)) % count;
        } else if (key == VK_RETURN && (e->dialog == DLG_CLOSE || e->dialog == DLG_OVERWRITE || e->dialog_focus)) {
            unsigned action = e->dialog_focus;
            e->swallow_enter = TRUE;
            if (e->dialog != DLG_CLOSE && e->dialog != DLG_OVERWRITE) --action;
            EdDialogAction(e, action);
        }
        if (g_editor == e) InvalidateRect(e->hwnd, NULL, TRUE);
        return;
    }
    if (ctrl) {
        if (key == 'N') EdActivate(e, BTN_NEW);
        else if (key == 'O') EdActivate(e, BTN_OPEN);
        else if (key == 'S') EdActivate(e, shift ? BTN_SAVEAS : BTN_SAVE);
        else if (key == 'Z') EdActivate(e, shift ? BTN_REDO : BTN_UNDO);
        else if (key == 'Y') EdActivate(e, BTN_REDO);
        else if (key == 'F' || key == 'H') { e->finding = TRUE; e->search_focus = key == 'H' ? 1 : 0; }
        else if (key == 'A') { if (e->finding && e->search_focus < 2) { e->input_replace = TRUE; }
            else { b->anchor = 0; b->caret = b->len; } }
        else if (key == 'V' && e->finding && e->search_focus < 2) EdPasteField(e, e->search_focus ? e->replacement : e->find, ED_SEARCH_CAP);
        else if ((key == 'V' || key == 'C' || key == 'X') && !e->finding) EdClipboard(e, key == 'V', key == 'X');
        else if (key == VK_HOME) EdMove(e, 0, shift);
        else if (key == VK_END) EdMove(e, b->len, shift);
    } else if (e->finding) {
        if (key == VK_ESCAPE) { e->finding = FALSE; e->pending_high = 0; }
        else if (key == VK_TAB) { e->search_focus = (e->search_focus + (shift ? 3 : 1)) % 4; e->input_replace = FALSE; }
        else if (key == VK_RETURN && e->search_focus >= 2) { e->swallow_enter = TRUE; EdFindNext(e, e->search_focus == 3); }
    } else if (key == VK_LEFT) EdMove(e, b->caret != b->anchor && !shift ? (b->caret < b->anchor ? b->caret : b->anchor) : EdPrevious(b, b->caret), shift);
    else if (key == VK_RIGHT) EdMove(e, b->caret != b->anchor && !shift ? (b->caret > b->anchor ? b->caret : b->anchor) : EdNext(b, b->caret), shift);
    else if (key == VK_HOME) EdMove(e, EdLineStart(b, b->caret), shift);
    else if (key == VK_END) EdMove(e, EdLineEnd(b, b->caret), shift);
    else if (key == VK_UP || key == VK_DOWN) EdVertical(e, key == VK_DOWN, shift);
    else if (key == VK_PRIOR || key == VK_NEXT) {
        unsigned i; for (i = 0; i < 10; ++i) EdVertical(e, key == VK_NEXT, shift);
    } else if (key == VK_DELETE) {
        if (b->caret == b->anchor) b->anchor = EdNext(b, b->caret);
        EdChange(e, NULL, 0); EdEnsureCaret(e);
    }
    if (!e->dialog && !e->finding) EdEnsureCaret(e);
    InvalidateRect(e->hwnd, NULL, TRUE);
}
static void EdFieldChar(EDITOR *e, WCHAR *field, DWORD cap, const WCHAR *text, DWORD n, BOOL back)
{
    DWORD length = (DWORD)ShzWcsLen(field);
    if (back) {
        if (e->input_replace) { field[0] = 0; e->input_replace = FALSE; }
        else if (length) { --length; if (length && field[length] >= 0xdc00 && field[length] <= 0xdfff) --length; field[length] = 0; }
    } else if (n) {
        if (e->input_replace) { length = 0; e->input_replace = FALSE; }
        if (n < cap - length) { memcpy(field + length, text, n * sizeof(WCHAR)); field[length + n] = 0; }
        else EdMessage(e, L"입력 길이 제한에 도달했습니다.", ERROR_FILENAME_EXCED_RANGE);
    }
}
static BOOL EdPasteField(EDITOR *e, WCHAR *field, DWORD cap)
{
    HANDLE h; WCHAR *text; SIZE_T size; DWORD n, i, old; BOOL ok = FALSE;
    if (!OpenClipboard(e->hwnd)) { EdMessage(e, L"클립보드를 열지 못했습니다.", GetLastError()); return FALSE; }
    h = GetClipboardData(CF_UNICODETEXT);
    if (h) {
        size = GlobalSize(h); text = GlobalLock(h);
        if (text) {
            for (n = 0; n < size / sizeof(WCHAR) && n < cap && text[n]; ++n) { }
            old = e->input_replace ? 0 : (DWORD)ShzWcsLen(field);
            if (n < size / sizeof(WCHAR) && n < cap - old && EdUtf16Valid(text, n)) {
                for (i = 0; i < n && text[i] >= 32; ++i) { }
                if (i == n) { memcpy(field + old, text, n * sizeof(WCHAR)); field[old + n] = 0; e->input_replace = FALSE; ok = TRUE; }
            }
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    if (!ok) EdMessage(e, L"한 줄 텍스트만 붙여넣을 수 있습니다. 길이와 문자를 확인하세요.", 0);
    InvalidateRect(e->hwnd, NULL, TRUE); return ok;
}
static void EdChar(EDITOR *e, WCHAR c)
{
    WCHAR pair[2]; DWORD n = 1;
    if (c == 13 && e->swallow_enter) { e->swallow_enter = FALSE; return; }
    if (e->io || GetKeyState(VK_CONTROL) < 0 || GetKeyState(VK_MENU) < 0) return;
    if (c >= 0xd800 && c <= 0xdbff) { e->pending_high = c; return; }
    pair[0] = c;
    if (e->pending_high) {
        if (c < 0xdc00 || c > 0xdfff) { e->pending_high = 0; EdMessage(e, L"잘못된 UTF-16 입력을 무시했습니다.", 0); return; }
        pair[0] = e->pending_high; pair[1] = c; n = 2; e->pending_high = 0;
    }
    if (e->dialog) {
        if (e->dialog != DLG_OPEN && e->dialog != DLG_SAVE) return;
        if (e->dialog_focus) return;
        if (c == 13) EdDialogAction(e, 0);
        else if (c == 8 || (c >= 32 && EdUtf16Valid(pair, n))) EdFieldChar(e, e->input, SHZ_FILE_PATH_CAP, pair, n, c == 8);
    } else if (e->finding) {
        if (c == 13 && e->search_focus < 2) EdFindNext(e, e->search_focus == 1);
        else if (e->search_focus < 2 && (c == 8 || (c >= 32 && EdUtf16Valid(pair, n))))
            EdFieldChar(e, e->search_focus ? e->replacement : e->find, ED_SEARCH_CAP, pair, n, c == 8);
    } else {
        if (c == 8) { if (e->b->caret == e->b->anchor) e->b->anchor = EdPrevious(e->b, e->b->caret); EdChange(e, NULL, 0); }
        else if (c == 13) { pair[0] = 10; EdChange(e, pair, 1); }
        else if (EdUtf16Valid(pair, n)) EdChange(e, pair, n);
        EdEnsureCaret(e);
    }
    InvalidateRect(e->hwnd, NULL, TRUE);
}

static void EdButton(HDC dc, const RECT *r, const WCHAR *label, BOOL focus, BOOL enabled)
{
    RECT text = *r;
    ShzFillGradientV(dc, r, TC(focus ? TH()->buttons_active_top : TH()->buttons_normal_top), TC(focus ? TH()->buttons_active_bottom : TH()->buttons_normal_bottom));
    ShzFrame(dc, r, TC(focus ? TH()->border_focus : TH()->buttons_edge), 1);
    SetTextColor(dc, TC(enabled ? TH()->buttons_text : TH()->menu_disabled_text));
    InflateRect(&text, -ShzPx(4), 0); ShzDrawText(dc, label, &text, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_END_ELLIPSIS);
}
static RECT EdToolRect(const RECT *c, unsigned index)
{
    int available = c->right - ShzPx(16), width = available / BTN_COUNT;
    RECT r = { ShzPx(8) + (int)index * width, ShzPx(8), ShzPx(8) + (int)(index + 1) * width - ShzPx(3), ShzPx(38) };
    return r;
}
static BOOL EdInside(const RECT *r, int x, int y) { return x >= r->left && x < r->right && y >= r->top && y < r->bottom; }
static RECT EdDialogButton(const RECT *c, unsigned dialog, unsigned index)
{
    int count = dialog == DLG_CLOSE ? 3 : 2, width = (c->right - ShzPx(40)) / count;
    RECT r = { ShzPx(20) + (int)index * width, ShzPx(216), ShzPx(20) + (int)(index + 1) * width - ShzPx(8), ShzPx(250) };
    return r;
}
static RECT EdSearchRect(const RECT *c, unsigned index)
{
    int width = (c->right - ShzPx(24)) / 2;
    RECT r = { ShzPx(12) + (int)(index % 2) * width, ShzPx(index < 2 ? 94 : 126),
        ShzPx(12) + (int)(index % 2 + 1) * width - ShzPx(6), ShzPx(index < 2 ? 122 : 154) };
    return r;
}
static void EdPaintField(HDC dc, const RECT *r, const WCHAR *text, BOOL focus)
{
    RECT t = *r;
    ShzFill(dc, r, TC(TH()->background_input_bg));
    ShzFrame(dc, r, TC(focus ? TH()->border_focus : TH()->background_input_border), focus ? 2 : 1);
    InflateRect(&t, -ShzPx(6), 0); SetTextColor(dc, TC(TH()->background_surface_text));
    ShzDrawText(dc, text, &t, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
}
static void EdPaintLine(HDC dc, EDITOR *e, const RECT *r, DWORD start, DWORD end, int y)
{
    DWORD p, run = start, lo = e->b->caret < e->b->anchor ? e->b->caret : e->b->anchor;
    DWORD hi = e->b->caret > e->b->anchor ? e->b->caret : e->b->anchor;
    int x = r->left - e->horizontal, total = 0, tab = EdRunWidth(L"    ", 4);
    if (tab < 1) tab = 16;
    if (lo < end && hi > start) {
        DWORD a = lo > start ? lo : start, z = hi < end ? hi : end;
        RECT selected = { x + EdPrefixWidth(e->b, start, a), y, x + EdPrefixWidth(e->b, start, z), y + EdRowHeight() };
        ShzFill(dc, &selected, TC(TH()->selection_top));
    }
    for (p = start; p <= end; ++p) {
        if (p == end || e->b->text[p] == 9) {
            DWORD at = run;
            while (at < p) {
                DWORD stop = p;
                COLORREF color = TC(TH()->background_surface_text);
                if (at < lo && lo < stop) stop = lo;
                else if (at >= lo && at < hi) { if (hi < stop) stop = hi; color = TC(TH()->selection_text); }
                if (x + total < r->right && stop > at) {
                    if (!ShzTextDrawW(dc, x + total, y, e->b->text + at, (int)(stop - at), color, 1)) ++g_shell.draw_text_failures;
                }
                total += EdRunWidth(e->b->text + at, stop - at); at = stop;
            }
            if (p < end) total += tab - total % tab;
            run = p + 1;
        }
    }
    if (!e->dialog && !e->finding && !e->io && e->b->caret >= start && e->b->caret <= end) {
        int caret = x + EdPrefixWidth(e->b, start, e->b->caret);
        RECT cr = { caret, y, caret + 2, y + EdRowHeight() - 3 };
        ShzFill(dc, &cr, TC(TH()->background_surface_text));
    }
}
static void EdPaint(EDITOR *e, HDC dc, const RECT *c)
{
    static const WCHAR *labels[BTN_COUNT] = { L"새 문서", L"열기", L"저장", L"다른 이름", L"실행 취소", L"다시 실행", L"찾기/바꾸기" };
    RECT r, body = EdTextRect(e, c), status = { ShzPx(12), c->bottom - ShzPx(54), c->right - ShzPx(12), c->bottom - ShzPx(28) };
    DWORD start, end, line;
    WCHAR info[96], number[24];
    int y, saved;
    unsigned i;
    SetBkMode(dc, TRANSPARENT); ShzFill(dc, c, TC(TH()->background_surface));
    r = *c; r.bottom = ShzPx(84); ShzFill(dc, &r, TC(TH()->background_panel_face));
    for (i = 0; i < BTN_COUNT; ++i) { r = EdToolRect(c, i); EdButton(dc, &r, labels[i], FALSE, !e->io && !e->dialog); }
    r.left = ShzPx(12); r.right = c->right - ShzPx(12); r.top = ShzPx(44); r.bottom = ShzPx(78);
    SetTextColor(dc, TC(TH()->background_panel_text)); ShzDrawText(dc, e->path[0] ? e->path : L"새 문서 · UTF-8", &r, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    if (e->finding) {
        for (i = 0; i < 2; ++i) { r = EdSearchRect(c, i); EdPaintField(dc, &r, i ? e->replacement : e->find, e->search_focus == i); }
        r = EdSearchRect(c, 2); EdButton(dc, &r, L"다음 찾기 (대소문자 구분)", e->search_focus == 2, !e->io);
        r = EdSearchRect(c, 3); EdButton(dc, &r, L"선택 내용 바꾸기", e->search_focus == 3, !e->io);
    }
    saved = SaveDC(dc);
    if (saved) {
        IntersectClipRect(dc, body.left, body.top, body.right, body.bottom);
        start = EdLineOffset(e->b, e->first_line);
        for (y = body.top; y + EdRowHeight() <= body.bottom; y += EdRowHeight()) {
            end = EdLineEnd(e->b, start); EdPaintLine(dc, e, &body, start, end, y);
            if (end == e->b->len) break;
            start = EdNext(e->b, end);
        }
        RestoreDC(dc, saved);
    }
    SetTextColor(dc, TC(TH()->files_error_text)); ShzDrawText(dc, e->message, &status, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    line = EdLineNumber(e->b, e->b->caret) + 1; ShzWcsCopy(info, 96, L"UTF-8 · ");
    ShzFormatU64(line, number, 24); ShzWcsCat(info, 96, number); ShzWcsCat(info, 96, L"행 · ");
    ShzFormatU64(e->b->len, number, 24); ShzWcsCat(info, 96, number); ShzWcsCat(info, 96, L"/32767 · ");
    ShzWcsCat(info, 96, EdDirty(e) ? L"수정됨" : L"수정 없음");
    status.top = c->bottom - ShzPx(27); status.bottom = c->bottom - ShzPx(3);
    SetTextColor(dc, TC(TH()->background_surface_dim_text)); ShzDrawText(dc, info, &status, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    if (e->dialog) {
        const WCHAR *heading = e->dialog == DLG_OPEN ? L"문서 열기" : e->dialog == DLG_SAVE ? L"다른 이름으로 저장" : e->dialog == DLG_OVERWRITE ? L"기존 파일을 덮어쓸까요?" : L"변경 내용을 저장할까요?";
        r.left = ShzPx(10); r.top = ShzPx(96); r.right = c->right - ShzPx(10); r.bottom = ShzPx(260);
        ShzFill(dc, &r, TC(TH()->background_panel_face)); ShzFrame(dc, &r, TC(TH()->border_focus), 2);
        r.left += ShzPx(10); r.right -= ShzPx(10); r.top = ShzPx(105); r.bottom = ShzPx(138);
        SetTextColor(dc, TC(TH()->background_panel_text)); ShzDrawText(dc, heading, &r, DT_SINGLELINE | DT_VCENTER);
        r.top = ShzPx(146); r.bottom = ShzPx(178);
        if (e->dialog == DLG_OPEN || e->dialog == DLG_SAVE) EdPaintField(dc, &r, e->input, e->dialog_focus == 0);
        else ShzDrawText(dc, e->dialog == DLG_CLOSE ? L"폐기를 선택하면 저장하지 않은 내용이 사라집니다." : e->input, &r, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        for (i = 0; i < (e->dialog == DLG_CLOSE ? 3u : 2u); ++i) {
            const WCHAR *label = e->dialog == DLG_CLOSE ? (i == 0 ? L"저장" : i == 1 ? L"명시적 폐기" : L"취소") :
                e->dialog == DLG_OVERWRITE ? (i == 0 ? L"덮어쓰기" : L"돌아가기") : (i == 0 ? (e->dialog == DLG_OPEN ? L"열기" : L"저장") : L"취소");
            r = EdDialogButton(c, e->dialog, i);
            EdButton(dc, &r, label, e->dialog_focus == i + (e->dialog == DLG_OPEN || e->dialog == DLG_SAVE ? 1 : 0), TRUE);
        }
    }
}
static BOOL EdClick(EDITOR *e, int x, int y, BOOL extend)
{
    RECT c, r;
    unsigned i;
    DWORD start, end;
    GetClientRect(e->hwnd, &c);
    if (e->io) return FALSE;
    if (e->dialog) {
        for (i = 0; i < (e->dialog == DLG_CLOSE ? 3u : 2u); ++i) {
            r = EdDialogButton(&c, e->dialog, i);
            if (EdInside(&r, x, y)) { EdDialogAction(e, i); return FALSE; }
        }
        if (y >= ShzPx(146) && y < ShzPx(178) && (e->dialog == DLG_OPEN || e->dialog == DLG_SAVE)) e->dialog_focus = 0;
        InvalidateRect(e->hwnd, NULL, TRUE); return FALSE;
    }
    for (i = 0; i < BTN_COUNT; ++i) { r = EdToolRect(&c, i); if (EdInside(&r, x, y)) { EdActivate(e, i); return FALSE; } }
    if (e->finding) for (i = 0; i < 4; ++i) {
        r = EdSearchRect(&c, i);
        if (EdInside(&r, x, y)) { e->search_focus = i; if (i >= 2) EdFindNext(e, i == 3); InvalidateRect(e->hwnd, NULL, TRUE); return FALSE; }
    }
    r = EdTextRect(e, &c);
    if (!EdInside(&r, x, y)) return FALSE;
    if (e->finding) { e->finding = FALSE; r = EdTextRect(e, &c); }
    start = EdLineOffset(e->b, e->first_line + (DWORD)((y - r.top) / EdRowHeight())); end = EdLineEnd(e->b, start);
    EdMove(e, EdColumnTarget(e, start, end, x - r.left + e->horizontal), extend);
    return TRUE;
}
static void EdDrag(EDITOR *e, int x, int y)
{
    RECT c, r; DWORD start, end;
    GetClientRect(e->hwnd, &c); r = EdTextRect(e, &c);
    if (r.right <= r.left || r.bottom <= r.top) return;
    x = ShzClamp(x, r.left, r.right - 1); y = ShzClamp(y, r.top, r.bottom - 1);
    start = EdLineOffset(e->b, e->first_line + (DWORD)((y - r.top) / EdRowHeight())); end = EdLineEnd(e->b, start);
    EdMove(e, EdColumnTarget(e, start, end, x - r.left + e->horizontal), TRUE);
}
static LRESULT CALLBACK EdWindow(HWND hwnd, UINT message, WPARAM wp, LPARAM lp)
{
    EDITOR *e = (EDITOR *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (!e) return DefWindowProcW(hwnd, message, wp, lp);
    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT ps; RECT c; HDC dc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &c); if (dc) EdPaint(e, dc, &c); EndPaint(hwnd, &ps); return 0;
    }
    case WM_TIMER: if (wp == ED_TIMER) { EdPoll(e); return 0; } break;
    case WM_KEYDOWN: EdKey(e, (UINT)wp); return 0;
    case WM_CHAR: EdChar(e, (WCHAR)wp); return 0;
    case WM_LBUTTONDOWN:
        SetFocus(hwnd); e->pending_high = 0;
        if (EdClick(e, (short)LOWORD(lp), (short)HIWORD(lp), GetKeyState(VK_SHIFT) < 0) && g_editor == e) { e->dragging = TRUE; SetCapture(hwnd); } return 0;
    case WM_MOUSEMOVE: if (e->dragging && (wp & MK_LBUTTON)) { EdDrag(e, (short)LOWORD(lp), (short)HIWORD(lp)); } return 0;
    case WM_LBUTTONUP: e->dragging = FALSE; ReleaseCapture(); return 0;
    case WM_CAPTURECHANGED: e->dragging = FALSE; return 0;
    case WM_MOUSEWHEEL: {
        int delta = (short)HIWORD(wp), lines = delta / WHEEL_DELTA * 3;
        DWORD max = EdLineNumber(e->b, e->b->len);
        if (lines > 0) e->first_line = e->first_line > (DWORD)lines ? e->first_line - (DWORD)lines : 0;
        else if (lines < 0) e->first_line = e->first_line + (DWORD)(-lines) < max ? e->first_line + (DWORD)(-lines) : max;
        InvalidateRect(hwnd, NULL, TRUE); return 0;
    }
    case WM_SIZE: InvalidateRect(hwnd, NULL, TRUE); return 0;
    case WM_CLOSE: EdClose(e); return 0;
    case WM_DESTROY:
        KillTimer(hwnd, ED_TIMER);
        if (e->io) { InterlockedExchange(&e->io->cancel, 1); CloseHandle(e->io->thread); EdIoRelease(e->io); e->io = NULL; }
        EdClearStack(e->b->undo, &e->b->nu); EdClearStack(e->b->redo, &e->b->nr); EdFree(e->b);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0); if (g_editor == e) g_editor = NULL; EdFree(e);
        ShzTasksRefresh(); ShzTaskbarInvalidate(); return 0;
    }
    return DefWindowProcW(hwnd, message, wp, lp);
}
BOOL ShzEditorRegister(void)
{
    WNDCLASSW wc;
    ZeroMemory(&wc, sizeof wc); wc.style = CS_HREDRAW | CS_VREDRAW; wc.lpfnWndProc = EdWindow;
    wc.hInstance = g_shell.inst; wc.hCursor = LoadCursorW(NULL, IDC_ARROW); wc.lpszClassName = g_editor_class;
    return RegisterClassW(&wc) != 0;
}
HWND ShzEditorOpen(const WCHAR *path)
{
    EDITOR *e = g_editor;
    RECT work;
    HWND hwnd;
    if (path && !ShzFilePathValidW(path)) { ShzSetStatus(IDS_ERR_PATH_LONG, ERROR_INVALID_NAME); return NULL; }
    if (!e) {
        e = EdAlloc(sizeof *e); if (!e) return NULL;
        e->b = EdAlloc(sizeof *e->b); if (!e->b) { EdFree(e); return NULL; }
        work.left = work.top = 0; work.right = GetSystemMetrics(SM_CXSCREEN); work.bottom = GetSystemMetrics(SM_CYSCREEN);
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
        hwnd = CreateWindowExW(0, g_editor_class, L"텍스트 편집기", WS_OVERLAPPEDWINDOW,
            work.left + ShzPx(40), work.top + ShzPx(32), ShzClamp(work.right - work.left - ShzPx(80), 360, ShzPx(900)),
            ShzClamp(work.bottom - work.top - ShzPx(64), 380, ShzPx(660)), NULL, NULL, g_shell.inst, NULL);
        if (!hwnd) { EdFree(e->b); EdFree(e); return NULL; }
        e->hwnd = hwnd; SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)e); g_editor = e;
        if (!SetTimer(hwnd, ED_TIMER, 100, NULL)) { DestroyWindow(hwnd); return NULL; }
        EdReset(e);
    }
    ShowWindow(e->hwnd, SW_RESTORE); ShowWindow(e->hwnd, SW_SHOW); SetForegroundWindow(e->hwnd); SetFocus(e->hwnd);
    if (e->io || EdDirty(e)) { EdMessage(e, L"현재 문서를 저장하거나 닫은 뒤 다른 문서를 여세요.", 0); return NULL; }
    ShzTasksRefresh(); ShzTaskbarInvalidate();
    if (path) { e->dialog = DLG_NONE; return EdStartIo(e, IO_READ, path, FALSE) ? e->hwnd : NULL; }
    EdReset(e); return e->hwnd;
}
BOOL ShzEditorCanExit(void)
{
    EDITOR *e = g_editor;
    if (!e) return TRUE;
    EdPoll(e); e = g_editor; if (!e) return TRUE;
    if (e->io || EdDirty(e)) {
        ShowWindow(e->hwnd, SW_RESTORE); SetForegroundWindow(e->hwnd); SetFocus(e->hwnd);
        if (e->io) EdMessage(e, L"파일 작업 중입니다. 작업을 마친 뒤 종료하세요.", 0);
        else EdDialog(e, DLG_CLOSE);
        printf("SHZ-EDITOR exit_refused=1 busy=%d dirty=%d\n", e->io ? 1 : 0, EdDirty(e) ? 1 : 0);
        return FALSE;
    }
    return TRUE;
}
void ShzEditorCloseAll(void) { if (g_editor && !g_editor->io && !EdDirty(g_editor)) DestroyWindow(g_editor->hwnd); }
void ShzEditorRelayout(void) { if (g_editor) { EdEnsureCaret(g_editor); InvalidateRect(g_editor->hwnd, NULL, TRUE); } }
#endif
