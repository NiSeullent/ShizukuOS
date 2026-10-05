/* SPDX-License-Identifier: GPL-2.0-only */
#include "noto_win32.h"

static void vfree(void *ctx, const void *data) { (void)ctx; VirtualFree((LPVOID)data, 0, MEM_RELEASE); }

NotoStatus noto_win32_load_file(const WCHAR *path, long face_index, NotoFontSource *src)
{
    HANDLE h; LARGE_INTEGER sz; BYTE *buf; SIZE_T got = 0, total;
    if (!path || !src) return NOTO_E_PARAM;
    src->data = NULL; src->size = 0; src->release = NULL; src->ctx = NULL; src->face_index = face_index;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NOTO_E_FONT;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (LONGLONG)NOTO_MAX_FONT_BYTES) {
        CloseHandle(h); return NOTO_E_FONT;
    }
    total = (SIZE_T)sz.QuadPart;
    buf = VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(h); return NOTO_E_NOMEM; }
    while (got < total) {
        DWORD n = 0, want = (DWORD)(total - got > 0x100000 ? 0x100000 : total - got);
        if (!ReadFile(h, buf + got, want, &n, NULL) || !n) break;
        got += n;
    }
    CloseHandle(h);
    if (got != total) { VirtualFree(buf, 0, MEM_RELEASE); return NOTO_E_FONT; }
    src->data = buf; src->size = got; src->release = vfree;
    return NOTO_OK;
}

NotoStatus noto_win32_open_default(NotoProvider **out)
{
    NotoFontSource a, b; NotoStatus st;
    if (!out) return NOTO_E_PARAM;
    *out = NULL;
    st = noto_win32_load_file(NOTO_WIN32_LATIN_PATH, 0, &a);
    if (st != NOTO_OK) return st;
    st = noto_win32_load_file(NOTO_WIN32_KR_PATH, 0, &b);
    if (st != NOTO_OK) { vfree(NULL, a.data); return st; }
    return noto_create(&a, &b, out);   /* takes ownership of both */
}
