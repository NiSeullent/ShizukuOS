/* SPDX-License-Identifier: GPL-2.0-only
 * Locale-name NLS provider for LibreOffice SAL on genuine Windows 98.
 *
 * LibreOffice 26.8 sal/osl/w32/nlsupport.cxx (commit bce0998afefd) calls
 * GetUserDefaultLocaleName, GetLocaleInfoEx (LOCALE_SISO639LANGNAME,
 * LOCALE_SISO3166CTRYNAME, LOCALE_IDEFAULTANSICODEPAGE|LOCALE_RETURN_NUMBER)
 * and ResolveLocaleName while computing the process locale and text encoding.
 * None of these names is exported by the Windows 98 SE kernel32, and the
 * existing ntwin32 loader returns fixed en-US data and has no ResolveLocaleName.
 *
 * This provider derives every answer from the real LCID-based NLS data of
 * the running system (GetLocaleInfoA / EnumSystemLocalesA / Get*DefaultLCID)
 * through a narrow backend table. Unsupported locale names, LCTYPEs and flags
 * fail with the Win32 error the Vista+ contract specifies; nothing is guessed.
 * Contract reviewed against Microsoft documentation and Wine 11
 * dlls/kernelbase/locale.c; original implementation, no code copied.
 */
#ifndef SHZ_OFFICE_NLS_H
#define SHZ_OFFICE_NLS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OFN_NAME_MAX 85u            /* LOCALE_NAME_MAX_LENGTH */
#define OFN_MAX_LOCALES 512u

#define OFN_OK 0u
#define OFN_ERROR_INVALID_FUNCTION 1u
#define OFN_ERROR_NOT_ENOUGH_MEMORY 8u
#define OFN_ERROR_NOT_SUPPORTED 50u
#define OFN_ERROR_INVALID_PARAMETER 87u
#define OFN_ERROR_INSUFFICIENT_BUFFER 122u
#define OFN_ERROR_INVALID_FLAGS 1004u

/* Real system services. query/to_wide follow GetLocaleInfoA and
 * MultiByteToWideChar return conventions (0 = failure, else count incl. NUL
 * for query). enumerate fills at most max installed LCIDs and returns the
 * count, or (uint32_t)-1 if the system list exceeds max or enumeration failed. */
struct ofn_backend {
    void *ctx;
    int (*query)(void *ctx, uint32_t lcid, uint32_t lctype, char *out, int cch);
    uint32_t (*enumerate)(void *ctx, uint32_t *lcids, uint32_t max);
    uint32_t (*user_lcid)(void *ctx);
    uint32_t (*system_lcid)(void *ctx);
    int (*to_wide)(void *ctx, uint32_t codepage, const char *in, int in_bytes, uint16_t *out, int cch);
};

/* All functions return OFN_OK or a Win32 error; *result receives the Win32
 * API return value (characters including NUL, or bytes/LCID as documented). */
uint32_t ofn_lcid_to_name(const struct ofn_backend *b, uint32_t lcid, uint16_t *out, uint32_t cch, uint32_t *result);
uint32_t ofn_name_to_lcid(const struct ofn_backend *b, const uint16_t *name, uint32_t *lcid);
uint32_t ofn_resolve_locale_name(const struct ofn_backend *b, const uint16_t *name, uint16_t *out, uint32_t cch, uint32_t *result);
uint32_t ofn_get_locale_info_ex(const struct ofn_backend *b, const uint16_t *name, uint32_t lctype,
                                uint16_t *out, uint32_t cch, uint32_t *result);
uint32_t ofn_user_default_locale_name(const struct ofn_backend *b, uint16_t *out, uint32_t cch, uint32_t *result);

#ifdef __cplusplus
}
#endif
#endif
