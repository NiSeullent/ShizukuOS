/* SPDX-License-Identifier: GPL-2.0-only */
#include "noto_win32.h"

static void vfree(void *ctx, const void *data) { (void)ctx; VirtualFree((LPVOID)data, 0, MEM_RELEASE); }

NotoStatus noto_win32_load_file(const WCHAR *path, long face_index, const uint8_t *pin, NotoFontSource *src)
{
    HANDLE h; LARGE_INTEGER sz; BYTE *buf; SIZE_T got = 0, total; DWORD err;
    if (!src) return NOTO_E_PARAM;
    src->data = NULL; src->size = 0; src->release = NULL; src->ctx = NULL; src->face_index = face_index;
    src->expected_sha256 = pin;
    if (!path || !pin || face_index < 0) return NOTO_E_PARAM;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        return (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ? NOTO_E_UNAVAILABLE : NOTO_E_FONT;
    }
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

NotoStatus noto_win32_open(const NotoWin32Assets *a, NotoProvider **out)
{
    NotoFontSource l, k; NotoStatus st;
    if (!out) return NOTO_E_PARAM;
    *out = NULL;
    if (!a || !a->latin_sha256 || !a->kr_sha256) return NOTO_E_PARAM;
    st = noto_win32_load_file(a->latin_path ? a->latin_path : NOTO_WIN32_LATIN_PATH, a->latin_face, a->latin_sha256, &l);
    if (st != NOTO_OK) return st;
    st = noto_win32_load_file(a->kr_path ? a->kr_path : NOTO_WIN32_KR_PATH, a->kr_face, a->kr_sha256, &k);
    if (st != NOTO_OK) { vfree(NULL, l.data); return st; }
    return noto_create_ex(a->cfg, &l, &k, out);   /* takes ownership of both */
}
