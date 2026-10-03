/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SZC_CHROME_NATIVE_H
#define SZC_CHROME_NATIVE_H
#include <windows.h>
/* Both return ERROR_SUCCESS or a Win32 error. Apply saves the user's original metrics
 * once (never overwriting an earlier backup), applies through
 * SystemParametersInfo(SPI_SETNONCLIENTMETRICS, SPIF_UPDATEINIFILE|SPIF_SENDCHANGE) which
 * Windows persists per user, verifies by readback and rolls back on mismatch.
 * Restore re-applies the saved classic metrics and clears the applied flag. */
DWORD szc_native_apply(void);
DWORD szc_native_restore(void);
/* 1 when the modern profile is recorded as applied for this user. */
int szc_native_is_applied(void);
#endif
