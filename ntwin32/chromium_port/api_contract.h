/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_BROWSER_API_CONTRACT_H
#define NTW_BROWSER_API_CONTRACT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { AC_PRIVATE_ADDRESS=1, AC_NATIVE_POWER=2, AC_PRIVATE_NT_REGISTRY=3, AC_PRIVATE_KERNEL32=4, AC_KERNEL32_UNSUPPORTED=5 };
enum { AC_ROLE_CHROME_EXE=1, AC_ROLE_CHROME_ELF=2 };
typedef struct ac_target { uint8_t digest[32]; unsigned magic,role; } ac_target;
typedef struct ac_route { unsigned kind; const char *provider,*symbol; } ac_route;
/* Hashes immutable original file bytes, not a basename/version string. Only
 * the preserved Chromium157 x86 chrome.exe root (2616320 bytes, 7335c449...)
 * and its chrome_elf.dll (1276928 bytes, 54ffa9ed..., snapshot 1707946) are
 * authorized; each importer is bound to its own routes, never by name.
 * A route is a candidate, never a loaded provider or callable address.
 * AC_KERNEL32_UNSUPPORTED names bind to M98K32CE exports that always fail
 * with ERROR_NOT_SUPPORTED (or its HRESULT) because Win98 has no backend. */
int ac_init(ac_target *,const uint8_t *,size_t);
int ac_lookup(const ac_target *,const char *,const char *,uint16_t,ac_route *);
#ifdef __cplusplus
}
#endif
#endif
