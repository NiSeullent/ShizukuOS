/* SPDX-License-Identifier: GPL-2.0-only
 * A real display information context, with measured capabilities and no bitmap.
 * Only the current primary DISPLAY is supported. Device initialization/printers
 * and additional IC queries need separate driver support; drawing is rejected.
 */
#include "gdi_internal.h"

static int same_name(LPCWSTR left, LPCWSTR right)
{
    unsigned i;
    if (!left) return FALSE;
    for (i = 0; left[i] && right[i]; ++i)
        if ((left[i] | 0x20) != (right[i] | 0x20)) return FALSE;
    return left[i] == right[i];
}

DLLAPI HDC WINAPI CreateICW(LPCWSTR driver, LPCWSTR device, LPCWSTR port, const DEVMODEW *initial)
{
    shz_display_info_t display;
    dc_t *dc;
    HGDIOBJ handle;
    (void)port;                                              /* documented legacy parameter ignored */
    if (!driver) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!same_name(driver, L"DISPLAY") || (device && *device && !same_name(device, L"DISPLAY") && !same_name(device, L"\\\\.\\DISPLAY1")) || initial) {
        SetLastError(ERROR_NOT_SUPPORTED); return 0;
    }
    memset(&display, 0, sizeof display); display.size = sizeof display;
    if (NtUserQueryDisplay(&display, SHZ_DISP_QUERY) < 0) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }
    GDI_ENTER();
    dc = gdi_alloc(sizeof *dc);
    if (!dc) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); RET(0); }
    gdi_dc_defaults(dc); dc->info_only = 1;
    dc->wcx = (int)display.width; dc->wcy = (int)display.height;
    handle = gdi_obj_new(OBJ_DC, dc, 0);
    if (!handle) { gdi_free(dc); SetLastError(ERROR_NOT_ENOUGH_MEMORY); }
    RET((HDC)handle);
}
