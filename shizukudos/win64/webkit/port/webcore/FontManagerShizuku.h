/*
 * SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS "Shizuku" WebKit port: the Skia font manager WebCore's FontCacheSkia.cpp uses under USE(SHIZUKU).
 */
#pragma once

#include <skia/core/SkFontMgr.h>
#include <skia/core/SkRefCnt.h>

namespace WebCore {

// Skia's directory font manager (FreeType scaler) over the system font directory: %WEBKIT_TESTFONTS% when set, else
// <GetWindowsDirectory>\fonts (\SHZ\FONTS in WIN64.IMG: Noto Sans/Serif/Mono, Tahoma). Never null: an empty
// directory gives an empty manager (Skia then draws nothing for text).
sk_sp<SkFontMgr> shizukuCreateFontManager();

} // namespace WebCore
