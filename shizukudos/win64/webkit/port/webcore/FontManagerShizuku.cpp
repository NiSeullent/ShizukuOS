/*
 * SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS "Shizuku" WebKit port: FreeType fonts from the system font directory for Skia (replaces the Windows
 * port's DirectWrite font manager, FontCacheSkiaWin.cpp).
 */
#include "config.h"
#include "FontManagerShizuku.h"

#include <windows.h>
#include <wtf/text/CString.h>
#include <wtf/text/WTFString.h>

WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_BEGIN
#include <skia/ports/SkFontMgr_directory.h>
WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_END

namespace WebCore {

static CString fontDirectory()
{
    char buffer[MAX_PATH + 16];
    DWORD size = GetEnvironmentVariableA("WEBKIT_TESTFONTS", buffer, MAX_PATH);
    if (size && size < MAX_PATH)
        return CString(buffer);
    UINT length = GetWindowsDirectoryA(buffer, MAX_PATH);
    if (!length || length >= MAX_PATH)
        return CString("C:\\SHZ\\FONTS");
    return makeString(String::fromLatin1(buffer), "\\fonts"_s).utf8();
}

sk_sp<SkFontMgr> shizukuCreateFontManager()
{
    return SkFontMgr_New_Custom_Directory(fontDirectory().data());
}

} // namespace WebCore
