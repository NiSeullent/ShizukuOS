/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded routing policy. Never load a library or fabricate a handle. */
#include "resolve.h"
#define NTW_SOURCE_MODULE "KERNEL32.DLL"
int ntw_export_name_equal(const char *left, const char *right) {
    /* Valid export names are NUL-terminated; invalid string pointers retain the
     * native caller contract. Do not dereference ordinal-valued parameters. */
    while (*left && *left == *right) { ++left; ++right; }
    return *left == *right;
}

struct lookup {
    const struct ntw_resolver *r;
    const char *name;
    ntw_proc own, hooked;
    int own_done, hooked_done, hooked_is_kernelex;
};
static ntw_proc own_candidate(struct lookup *l) {
    if (!l->own_done) {
        l->own = l->r->owned ? l->r->owned(l->r->context, l->name) : (ntw_proc)0;
        l->own_done = 1;
    }
    return l->own;
}
static void hooked_lookup(struct lookup *l) {
    const struct ntw_resolver *r = l->r;
    if (l->hooked_done) return;
    l->hooked = r->native(r->context, r->kernel32_module, l->name);
    l->hooked_is_kernelex = l->hooked && r->kernelex_owns && r->kernelex_owns(r->context, l->hooked);
    l->hooked_done = 1;
}
static ntw_proc candidate(struct lookup *l, unsigned provider) {
    switch (provider) {
    case NTW_PROVIDER_OWN: return own_candidate(l);
    case NTW_PROVIDER_NATIVE: hooked_lookup(l); return l->hooked_is_kernelex ? (ntw_proc)0 : l->hooked;
    case NTW_PROVIDER_KERNELEX: hooked_lookup(l); return l->hooked_is_kernelex ? l->hooked : (ntw_proc)0;
    default: return (ntw_proc)0;
    }
}
static void say(const struct ntw_resolver *r, const char *name, const char *tail_a,
                const char *tail_b, unsigned mode) {
    char buffer[NTW_ROUTE_MESSAGE_MAX];
    struct ntw_text text;
    if (!r->log) return;
    ntw_text_start(&text, buffer, sizeof buffer);
    ntw_text_add(&text, "NTW32: " NTW_SOURCE_MODULE "!");
    ntw_text_add_bounded(&text, name, NTW_ROUTE_NAME_MAX);
    ntw_text_add(&text, tail_a);
    if (tail_b) ntw_text_add(&text, tail_b);
    ntw_text_add(&text, " (mode ");
    ntw_text_add(&text, ntw_route_mode_name(mode));
    ntw_text_add(&text, ")");
    r->log(r->context, buffer);
}
static void say_unresolved(const struct ntw_resolver *r, struct lookup *l, unsigned mode) {
    char buffer[NTW_ROUTE_MESSAGE_MAX];
    struct ntw_text text;
    if (!r->log) return;
    ntw_text_start(&text, buffer, sizeof buffer);
    ntw_text_add(&text, "NTW32: " NTW_SOURCE_MODULE "!");
    ntw_text_add_bounded(&text, l->name, NTW_ROUTE_NAME_MAX);
    ntw_text_add(&text, " unresolved (mode ");
    ntw_text_add(&text, ntw_route_mode_name(mode));
    ntw_text_add(&text, "; native ");
    ntw_text_add(&text, !l->hooked_done ? "not consulted" : !l->hooked ? "absent" :
                 l->hooked_is_kernelex ? "result attributed to KernelEx and rejected" : "present but not selected");
    ntw_text_add(&text, "; own ");
    ntw_text_add(&text, !l->own_done ? "not consulted" : l->own ? "present but not selected" : "absent");
    ntw_text_add(&text, "; kernelex ");
    ntw_text_add(&text, ntw_route_kernelex_name(r->kernelex_state));
    ntw_text_add(&text, ")");
    r->log(r->context, buffer);
}

ntw_proc ntw_resolve_named(const struct ntw_resolver *r, const char *name, unsigned *provider) {
    struct lookup l;
    unsigned mode, order, pass, slot;
    if (provider) *provider = NTW_PROVIDER_NONE;
    if (!r || !r->native || !name) return (ntw_proc)0;
    l.r = r; l.name = name; l.own = 0; l.hooked = 0;
    l.own_done = 0; l.hooked_done = 0; l.hooked_is_kernelex = 0;
    mode = ntw_route_effective_mode(r->policy, NTW_SOURCE_MODULE, name);
    if (mode == NTW_MODE_NATIVE) {
        /* Pure passthrough: whatever the native loader answers, no diagnostics. */
        ntw_proc found = r->native(r->context, r->kernel32_module, name);
        if (provider && found) *provider = NTW_PROVIDER_NATIVE;
        return found;
    }
    order = ntw_route_order(mode, r->table, name);
    /* Pass 0 tries providers in order, skipping any listed as a known stub for
     * this name; pass 1 accepts a stub provider only as the last resort. */
    for (pass = 0; pass < 2; ++pass) {
        for (slot = 0; slot < NTW_ORDER_SLOTS; ++slot) {
            unsigned p = NTW_ORDER_AT(order, slot);
            ntw_proc found;
            if (p == NTW_PROVIDER_NONE) break;
            if ((unsigned)ntw_route_is_stub(r->table, NTW_SOURCE_MODULE, name, p) != pass) continue;
            found = candidate(&l, p);
            if (!found) continue;
            if (provider) *provider = p;
            if (pass) {
                /* Always visible: a known stub answered because nothing else could. */
                say(r, name, " -> known-stub provider used as last resort: ",
                    ntw_route_provider_name(p), mode);
            } else if (r->policy && r->policy->log) {
                say(r, name, " -> ", ntw_route_provider_name(p), mode);
            }
            return found;
        }
    }
    say_unresolved(r, &l, mode);
    return (ntw_proc)0;
}

ntw_proc ntw_resolve(const struct ntw_resolver *r, uintptr_t module, const char *name) {
    if (!r || !r->native) return (ntw_proc)0;
    if (!r->kernel32_module || module != r->kernel32_module || (uintptr_t)name <= UINT16_MAX)
        return r->native(r->context, module, name);
    return ntw_resolve_named(r, name, 0);
}
