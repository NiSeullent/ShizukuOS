/* SPDX-License-Identifier: GPL-2.0-only
 * The two WER exclusion APIs implemented by Shizuku. Older mingw-w64
 * werapi.h versions contain unrelated report declarations with missing types.
 * Keep these documented declarations independent of that report backend.
 * https://learn.microsoft.com/windows/win32/api/werapi/nf-werapi-weraddexcludedapplication
 * https://learn.microsoft.com/windows/win32/api/werapi/nf-werapi-werremoveexcludedapplication
 */
#ifndef SHZ_WER_EXCLUSIONS_H
#define SHZ_WER_EXCLUSIONS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

HRESULT WINAPI WerAddExcludedApplication(PCWSTR executable, BOOL all_users);
HRESULT WINAPI WerRemoveExcludedApplication(PCWSTR executable, BOOL all_users);

#ifdef __cplusplus
}
#endif

#endif
