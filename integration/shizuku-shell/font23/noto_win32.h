/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32-only font-file loader for noto_provider (separate from the ShzText wrapper). */
#ifndef NOTO_WIN32_H
#define NOTO_WIN32_H
#include <windows.h>
#include "noto_provider.h"
#define NOTO_WIN32_LATIN_PATH L"C:\\SHZ\\FONTS\\NotoSans.ttf"
#define NOTO_WIN32_KR_PATH    L"C:\\SHZ\\FONTS\\NotoSansKR.otf"
NotoStatus noto_win32_load_file(const WCHAR *path, long face_index, NotoFontSource *src);  /* VirtualAlloc, owned */
NotoStatus noto_win32_open_default(NotoProvider **out);
#endif
