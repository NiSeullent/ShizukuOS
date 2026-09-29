/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded routing policy. Never load a library or fabricate a handle. */
#include "resolve.h"
int ntw_export_name_equal(const char *left, const char *right) {
    /* Valid export names are NUL-terminated; invalid string pointers retain the
     * native caller contract. Do not dereference ordinal-valued parameters. */
    while (*left && *left == *right) { ++left; ++right; }
    return *left == *right;
}
ntw_proc ntw_resolve(const struct ntw_resolver *r, uintptr_t module, const char *name) {
    ntw_proc found;
    if (!r || !r->native) return (ntw_proc)0;
    if (r->kernel32_module && module == r->kernel32_module &&
        (uintptr_t)name > UINT16_MAX && r->owned) {
        found = r->owned(r->context, name);
        if (found) return found;
    }
    return r->native(r->context, module, name);
}
