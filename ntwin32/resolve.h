/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_RESOLVE_H
#define NTW_RESOLVE_H
#include <stdint.h>
#include "routing.h"
/* This generic function pointer carries an address only. A caller must restore
 * the actual calling convention and signature before invoking it. */
typedef void (*ntw_proc)(void);
typedef ntw_proc (*ntw_owned_lookup)(void *context, const char *name);
typedef ntw_proc (*ntw_native_lookup)(void *context, uintptr_t module, const char *name);
/* Returns 1 when `address` lies inside a detected KernelEx API library image.
 * Only then is a native-loader result attributed to the KernelEx provider. */
typedef int (*ntw_kernelex_owner)(void *context, ntw_proc address);
struct ntw_resolver {
    uintptr_t kernel32_module;
    ntw_owned_lookup owned;
    ntw_native_lookup native;
    void *context;
    /* Routing policy (v2). Every pointer may be NULL: no table means the
     * default Auto order and no stub list; no policy means mode Own without
     * tracing; no owner callback means KernelEx is never attributed. */
    const struct ntw_route_table *table;
    const struct ntw_route_policy *policy;
    ntw_kernelex_owner kernelex_owns;
    unsigned kernelex_state;   /* NTW_KERNELEX_*, reported in diagnostics */
    ntw_route_log log;         /* diagnostics and traces; may be NULL */
};
/* Only exact KERNEL32 module identity and a named import are subject to the
 * routing policy. Other modules and ordinals reach the native loader unchanged
 * in every mode. Lookup callbacks and resolved addresses must outlive their use.
 * An unresolved name returns 0 after a diagnostic naming module and function
 * (except in mode Native, which is a silent passthrough). */
ntw_proc ntw_resolve(const struct ntw_resolver *, uintptr_t module, const char *name);
/* Resolve a KERNEL32 export name under the policy and report which provider
 * supplied it (NTW_PROVIDER_NONE when unresolved). Used for static-export
 * forwarding decisions as well as dynamic lookups. */
ntw_proc ntw_resolve_named(const struct ntw_resolver *, const char *name, unsigned *provider);
int ntw_export_name_equal(const char *, const char *);
#endif
