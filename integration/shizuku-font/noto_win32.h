/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32-only font-file loader for noto_provider (separate from the ShzText wrapper).
 * There is NO hash-less open: the caller supplies the expected SHA-256 pins (full original fonts, or the
 * compiled pinned manifest of the future licensed static KR subset). Absent files -> NOTO_E_UNAVAILABLE. */
#ifndef NOTO_WIN32_H
#define NOTO_WIN32_H
#include <windows.h>
#include "noto_provider.h"
#define NOTO_WIN32_LATIN_PATH L"C:\\SHZ\\FONTS\\NotoSans.ttf"     /* default path, face index 0 */
#define NOTO_WIN32_KR_PATH    L"C:\\SHZ\\FONTS\\NotoSansKR.otf"   /* default path, face index 0 (static subset) */
/* Original full CJK TTC is face index 1 ("Noto Sans CJK KR"); a static subset OTF/TTF is index 0. */
typedef struct NotoWin32Assets {
    const WCHAR *latin_path; long latin_face; const uint8_t *latin_sha256;
    const WCHAR *kr_path;    long kr_face;    const uint8_t *kr_sha256;
    const NotoConfig *cfg;   /* may be NULL */
} NotoWin32Assets;
/* Read a whole file (VirtualAlloc, owned by src, release=VirtualFree) and attach pin/face. NOTO_E_UNAVAILABLE if
 * the file does not exist. src->expected_sha256 is set to `pin` (must outlive noto_create). */
NotoStatus noto_win32_load_file(const WCHAR *path, long face_index, const uint8_t *pin, NotoFontSource *src);
NotoStatus noto_win32_open(const NotoWin32Assets *assets, NotoProvider **out);
#endif
