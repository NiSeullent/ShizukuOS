/* SPDX-License-Identifier: GPL-2.0-only
 * Link-control entry for the narrow native FreeType link (tools/font_native_link.py). Not shipped; not executed on
 * Linux. It exercises the real init path (ShzTextFontInit -> noto_win32_open (compiled SHA-256 pins) -> FT) and a real measure. */
#include "shz_text_diag.h"
DECLSPEC_NORETURN void ShzFontProbeStart(void)
{
    DWORD w = 0; int n = 0; SIZE s; unsigned miss = 0; int asc = 0;
    UINT code = 0;
    if (!ShzTextFontInit(&w, &n)) code = 100 + (UINT)n;
    else if (!ShzTextMeasurePxExW(L"Ag\xAC00", 3, 18, &s, &miss, &asc)) code = 200;
    if (!code && !ShzTextFontShutdown()) code = 300;
    ExitProcess(code);
}
