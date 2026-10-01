/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite (shzlite.dll) - DLL entry and the exported ShzEngineGetInterface (engine.h). Owner: core.
 *
 * The DLL is linked -nostdlib with DllMain as its entry: there is no C runtime to initialize (see DESIGN.md
 * section 3, "Memory and CRT").
 */
#include "winglue.h"
#include "../core/font.h"
#include "paint.h"
#include "view.h"

HINSTANCE shz_win_instance;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    SHZ_UNUSED(reserved);
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        shz_font_backend *fonts;
        shz_win_instance = instance;
        shz_paint_process_attach();
        fonts = shz_gdi_font_backend();
        if (fonts) shz_font_set_backend(fonts);
        shz_view_process_attach();
        break;
    }
    case DLL_PROCESS_DETACH:
        shz_view_process_detach();
        shz_paint_process_detach();
        break;
    default:
        break;
    }
    return TRUE;
}

__declspec(dllexport) const shzeng_vtbl * WINAPI ShzEngineGetInterface(UINT api_version)
{
    return api_version == SHZENG_API_VERSION ? shz_win_vtbl() : NULL;
}
