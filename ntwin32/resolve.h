/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_RESOLVE_H
#define NTW_RESOLVE_H
#include <stdint.h>
/* This generic function pointer carries an address only. A caller must restore
 * the actual calling convention and signature before invoking it. */
typedef void (*ntw_proc)(void);
typedef ntw_proc (*ntw_owned_lookup)(void *context, const char *name);
typedef ntw_proc (*ntw_native_lookup)(void *context, uintptr_t module, const char *name);
struct ntw_resolver {
    uintptr_t kernel32_module;
    ntw_owned_lookup owned;
    ntw_native_lookup native;
    void *context;
};
/* Only exact KERNEL32 module identity and a named owned export are redirected.
 * Other modules, ordinals and unknown names reach the native loader unchanged.
 * Lookup callbacks and resolved addresses must outlive their use. */
ntw_proc ntw_resolve(const struct ntw_resolver *, uintptr_t module, const char *name);
int ntw_export_name_equal(const char *, const char *);
#endif
