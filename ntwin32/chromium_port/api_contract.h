/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_BROWSER_API_CONTRACT_H
#define NTW_BROWSER_API_CONTRACT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { AC_PRIVATE_ADDRESS=1, AC_NATIVE_POWER=2 };
typedef struct ac_target { uint8_t digest[32]; unsigned magic; } ac_target;
typedef struct ac_route { unsigned kind; const char *provider,*symbol; } ac_route;
/* Hashes immutable original file bytes, not a basename/version string. Only
 * the preserved Chromium157 x86 chrome.exe root is presently authorized.
 * A route is a candidate, never a loaded provider or callable address. */
int ac_init(ac_target *,const uint8_t *,size_t);
int ac_lookup(const ac_target *,const char *,const char *,uint16_t,ac_route *);
#ifdef __cplusplus
}
#endif
#endif
