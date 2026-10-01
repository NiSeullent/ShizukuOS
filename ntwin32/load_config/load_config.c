/* SPDX-License-Identifier: GPL-2.0-only
 * Independently authored bounded PE32 Load Config reader and mapped /GS cookie
 * preparation. No Wine/ReactOS implementation body is copied.
 * Compared loader ordering, original-size checks and cookie preservation with:
 * Wine df15af3652511150490934682202d45af892f887 dlls/ntdll/loader.c,
 * set_security_cookie/update_load_config (LGPL-2.1-or-later):
 * https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/ntdll/loader.c
 * ReactOS 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8 dll/ntdll/ldr/ldrinit.c,
 * LdrpFetchAddressOfSecurityCookie/LdrpInitSecurityCookie:
 * https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/ntdll/ldr/ldrinit.c
 * Its sdk/lib/crt/startup/gs_support.c (public-domain mingw-runtime) was also
 * compared. Those loader implementations initialize legacy 16-bit cookies;
 * this restricted x86 contract ONLY mutates zero/default 32-bit cookies.
 * Neither their NT memory protection machinery nor PRNGs can be used on Win98
 * by name alone. Entropy and exclusive pre-entry ownership belong to caller.
 * Public layout/semantics, including readonly guard pointer STORAGE:
 * https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory32
 * https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata
 * https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/security-init-cookie
 * Reads below use explicit little-endian offsets, never host struct layout.
 */
#include "load_config.h"

static const np_load_config_limits lc_default_limits = {
    {NP_FILE_LIMIT, NP_IMAGE_LIMIT, NP_FILE_LIMIT + NP_IMAGE_LIMIT},
    NP_LC_TABLE_LIMIT, 6u * NP_LC_TABLE_LIMIT
};

typedef struct lc_budget {
    uint32_t per_table, total, used;
} lc_budget;

static int lc_fail(const char **error, const char *text)
{
    if (error) *error = text;
    return 0;
}

static void lc_zero(void *out, unsigned bytes)
{
    uint8_t *p = out;
    while (bytes--) *p++ = 0;
}

static int lc_pointer_overlap(const void *a, uintptr_t an,
                              const void *b, uintptr_t bn)
{
    uintptr_t av = (uintptr_t)a, bv = (uintptr_t)b;
    if (!a || !b || !an || !bn) return 0;
    if (av > UINTPTR_MAX - an || bv > UINTPTR_MAX - bn) return 1;
    return av >= bv ? av - bv < bn : bv - av < an;
}

static int lc_input_alias(const np_image *p, const void *out, uintptr_t bytes)
{
    return p && (lc_pointer_overlap(out, bytes, p, sizeof(*p)) ||
                 lc_pointer_overlap(out, bytes, p->file, p->bytes));
}

static uint32_t lc_field(const uint8_t *d, uint32_t size, unsigned offset)
{
    return size >= offset + 4u ? np_u32(d + offset) : 0;
}

static uint16_t lc_word(const uint8_t *d, uint32_t size, unsigned offset)
{
    return size >= offset + 2u ? np_u16(d + offset) : 0;
}

static int lc_va(const np_image *p, uint32_t va, uint32_t bytes,
                 int kind, uint32_t *rva)
{
    uint32_t at;
    if (va < p->base) return 0;
    at = va - p->base;
    if (at > p->size || bytes > p->size - at ||
        !np_memory(p, at, bytes, kind)) return 0;
    *rva = at;
    return 1;
}

static int lc_overlap(uint32_t a, uint32_t an, uint32_t b, uint32_t bn)
{
    /* Subtraction avoids overflow, including adversarial near-UINT32_MAX RVAs. */
    if (!an || !bn) return 0;
    return a >= b ? a - b < bn : b - a < an;
}

/* A guard field is a VA of DATA containing a function pointer, not code. */
static int lc_slot(const np_image *p, uint32_t va, uint32_t *rva,
                   uint32_t *protection, uint32_t bit, const char **error)
{
    const uint8_t *q;
    uint32_t target, ignored;
    if (!va) return 1;
    if ((va & 3u) || !lc_va(p, va, 4, 2, rva))
        return lc_fail(error, "LC_GUARD_SLOT_BOUNDS");
    if (!np_memory(p, *rva, 4, 3)) *protection |= bit;
    q = np_raw(p, *rva, 4);
    if (q) {
        target = np_u32(q);
        if (target && !lc_va(p, target, 1, 1, &ignored))
            return lc_fail(error, "LC_GUARD_INITIAL_TARGET");
    }
    return 1;
}

/* kind 1: executable RVAs, kind 2: readable non-executable IAT-slot RVAs.
 * Only GFIDS permits the documented first extra-byte flags 0x1/0x2.
 * All other extra metadata must be zero until its semantics are implemented.
 */
static int lc_table(const np_image *p, uint32_t va, uint32_t count,
                    uint32_t stride, int kind, int gfids,
                    np_load_config_table *table, lc_budget *budget,
                    const char **error)
{
    const uint8_t *raw;
    uint32_t bytes, i, j, previous = 0;
    if (!!va != !!count) return lc_fail(error, "LC_TABLE_PAIR");
    table->stride = stride;
    if (!count) return 1;
    if (stride < 4 || stride > 19 || count > 0xffffffffu / stride)
        return lc_fail(error, "LC_TABLE_OVERFLOW");
    if (count > budget->per_table) return lc_fail(error, "LC_TABLE_LIMIT");
    if (count > budget->total - budget->used)
        return lc_fail(error, "LC_TOTAL_TABLE_LIMIT");
    budget->used += count;
    bytes = count * stride;
    /* LLVM-linked x86 images pack these DWORD records at byte-aligned VAs.
     * Their public contract requires ordering, not a DWORD-aligned table base;
     * np_u32 reads individual bytes, so it is safe on those original files. */
    if (!lc_va(p, va, bytes, 2, &table->rva) ||
        !(raw = np_raw(p, table->rva, bytes)))
        return lc_fail(error, "LC_TABLE_BOUNDS");
    for (i = 0; i < count; i++) {
        const uint8_t *entry = raw + i * stride;
        uint32_t at = np_u32(entry);
        if (i && at <= previous) return lc_fail(error, "LC_TABLE_ORDER");
        if (!np_memory(p, at, kind == 2 ? 4u : 1u, kind) ||
            (kind == 2 && (at & 3u)))
            return lc_fail(error, "LC_TABLE_TARGET");
        for (j = 4; j < stride; j++) {
            uint8_t allowed = gfids && j == 4 ? 3u : 0u;
            if (entry[j] & (uint8_t)~allowed)
                return lc_fail(error, "LC_TABLE_METADATA_UNSUPPORTED");
        }
        previous = at;
    }
    table->count = count;
    return 1;
}

static int lc_lock_prefix(const np_image *p, uint32_t va,
                          np_load_config_info *info, lc_budget *budget,
                          const char **error)
{
    uint32_t at, n;
    if (!va) return 1;
    if (!lc_va(p, va, 4, 2, &info->lock_prefix_rva))
        return lc_fail(error, "LC_LOCK_PREFIX_TABLE");
    at = info->lock_prefix_rva;
    for (n = 0; n <= budget->per_table; n++) {
        const uint8_t *q, *opcode;
        uint32_t value, target;
        if (at > 0xffffffffu - n * 4u ||
            !np_memory(p, at + n * 4u, 4, 2) ||
            !(q = np_raw(p, at + n * 4u, 4)))
            return lc_fail(error, "LC_LOCK_PREFIX_UNTERMINATED");
        value = np_u32(q);
        if (!value) {
            info->lock_prefix_count = n;
            return 1;
        }
        if (n == budget->per_table) return lc_fail(error, "LC_LOCK_PREFIX_LIMIT");
        if (budget->used == budget->total)
            return lc_fail(error, "LC_TOTAL_TABLE_LIMIT");
        budget->used++;
        if (!lc_va(p, value, 1, 1, &target) ||
            !(opcode = np_raw(p, target, 1)) || *opcode != 0xf0)
            return lc_fail(error, "LC_LOCK_PREFIX_TARGET");
    }
    return lc_fail(error, "LC_LOCK_PREFIX_LIMIT");
}

static int lc_storage_overlap(const np_load_config_info *t, uint32_t rva)
{
    const np_load_config_table *tables[5];
    unsigned i;
    if (!rva) return 0;
    if (lc_overlap(rva, 4, t->directory_rva, t->directory_bytes)) return 1;
    tables[0] = &t->seh; tables[1] = &t->cfg;
    tables[2] = &t->address_taken_iat; tables[3] = &t->long_jump;
    tables[4] = &t->eh_continuation;
    for (i = 0; i < 5; i++)
        if (lc_overlap(rva, 4, tables[i]->rva,
                       tables[i]->count * tables[i]->stride)) return 1;
    return t->lock_prefix_rva &&
        lc_overlap(rva, 4, t->lock_prefix_rva, (t->lock_prefix_count + 1u) * 4u);
}

int np_load_config_limited(const np_image *p, np_load_config_info *info,
                           const np_load_config_limits *limits,
                           const char **error)
{
    const uint8_t *d, *cookie;
    np_load_config_info t;
    uint32_t rva, bytes, size, n, stride, cookie_va, mask, slots[9];
    unsigned i;
    lc_budget budget;
    /* Reject illegal output aliasing BEFORE clearing an output; otherwise even
     * a failing parser could corrupt its supposedly immutable source file. */
    if (error && (lc_input_alias(p, error, sizeof(*error)) ||
                  lc_pointer_overlap(error, sizeof(*error), limits, sizeof(*limits)) ||
                  lc_pointer_overlap(error, sizeof(*error), info, sizeof(*info))))
        return 0;
    if (info && lc_input_alias(p, info, sizeof(*info)))
        return lc_fail(error, "LC_OUTPUT_ALIASES_INPUT");
    if (info && lc_pointer_overlap(info, sizeof(*info), limits, sizeof(*limits)))
        return lc_fail(error, "LC_OUTPUT_ALIASES_LIMITS");
    if (error) *error = 0;
    if (!info) return lc_fail(error, "LC_OUTPUT_NULL");
    lc_zero(info, sizeof(*info));
    lc_zero(&t, sizeof(t));
    if (!limits || !limits->image.file_bytes ||
        limits->image.file_bytes > NP_LARGE_FILE_LIMIT ||
        !limits->image.image_bytes || limits->image.image_bytes > NP_LARGE_IMAGE_LIMIT ||
        !limits->image.total_bytes || limits->image.total_bytes > NP_LARGE_TOTAL_LIMIT ||
        !limits->table_entries || limits->table_entries > NP_LC_LARGE_TABLE_LIMIT ||
        !limits->total_table_entries || limits->total_table_entries > NP_LC_LARGE_TABLE_LIMIT)
        return lc_fail(error, "LC_LIMITS_INVALID");
    if (!p || !p->file || !p->bytes || p->bytes > limits->image.file_bytes ||
        !p->size || p->size > limits->image.image_bytes ||
        p->bytes > limits->image.total_bytes ||
        p->size > limits->image.total_bytes - p->bytes ||
        !p->sections || p->sections > NP_SECTIONS)
        return lc_fail(error, "LC_IMAGE_INVALID");
    budget.per_table = limits->table_entries;
    budget.total = limits->total_table_entries;
    budget.used = 0;
    rva = p->directory[10][0]; bytes = p->directory[10][1];
    if (!!rva != !!bytes) return lc_fail(error, "LC_DIRECTORY_PAIR");
    if (!rva) return 1;
    if ((rva & 3u) || bytes < 4 || bytes > NP_LC_DIRECTORY_LIMIT ||
        !(d = np_raw(p, rva, bytes)))
        return lc_fail(error, "LC_DIRECTORY_BOUNDS");
    size = np_u32(d);
    /* A DWORD-granularity version must not cut any known field in half. */
    if (size < 4 || (size & 3u) || size > bytes)
        return lc_fail(error, "LC_DECLARED_SIZE");
    if (size > 92u && size < 104u)
        return lc_fail(error, "LC_CODE_INTEGRITY_TRUNCATED");
    /* UmaFunctionPointers (offset 192) and future extension bytes are not
     * implemented. Zero extensions/padding are harmless, bounded metadata. */
    for (n = size < 192u ? size : 192u; n < bytes; n++)
        if (d[n]) return lc_fail(error, "LC_EXTENSION_NONZERO_UNSUPPORTED");
    t.present = 1; t.directory_rva = rva; t.directory_bytes = bytes;
    t.declared_size = size; t.timestamp = lc_field(d, size, 4);
    t.major_version = lc_word(d, size, 8); t.minor_version = lc_word(d, size, 10);
    t.global_flags_clear = lc_field(d, size, 12);
    t.global_flags_set = lc_field(d, size, 16);
    t.critical_section_timeout = lc_field(d, size, 20);
    t.decommit_free = lc_field(d, size, 24);
    t.decommit_total = lc_field(d, size, 28);
    t.maximum_allocation = lc_field(d, size, 36);
    t.virtual_memory_threshold = lc_field(d, size, 40);
    /* LC32 winnt.h order; the PE-format prose table swaps these two fields. */
    t.process_heap_flags = lc_field(d, size, 44);
    t.affinity_mask = lc_field(d, size, 48);
    t.csd_version = lc_word(d, size, 52);
    t.dependent_load_flags = lc_word(d, size, 54);
    if (lc_field(d, size, 56)) return lc_fail(error, "LC_RESERVED_EDIT_LIST");
    if (!lc_lock_prefix(p, lc_field(d, size, 32), &t, &budget, error)) return 0;
    if (t.global_flags_clear || t.global_flags_set || t.critical_section_timeout ||
        t.decommit_free || t.decommit_total || t.maximum_allocation ||
        t.virtual_memory_threshold || t.process_heap_flags || t.affinity_mask ||
        t.csd_version || t.dependent_load_flags || t.lock_prefix_rva)
        t.prerequisites |= NP_LC_PREREQ_LEGACY_CONFIG;
    cookie_va = lc_field(d, size, 60);
    if (cookie_va) {
        if ((cookie_va & 3u) || !lc_va(p, cookie_va, 4, 3, &t.cookie_rva))
            return lc_fail(error, "LC_COOKIE_WRITABLE_NONEXEC");
        cookie = np_raw(p, t.cookie_rva, 4);
        if (cookie) {
            t.cookie_raw_backed = 1; t.cookie_initial = np_u32(cookie);
        } else {
            /* Only actual section zero-fill, not a partial/truncated raw word. */
            for (i = 0; i < p->sections; i++) {
                const np_section *s = &p->section[i];
                if (t.cookie_rva >= s->va && t.cookie_rva - s->va < s->span) {
                    if (t.cookie_rva - s->va < s->bytes)
                        return lc_fail(error, "LC_COOKIE_RAW_TRUNCATED");
                    break;
                }
            }
        }
        t.prerequisites |= NP_LC_PREREQ_COOKIE;
        if (t.cookie_initial && t.cookie_initial != NP_LC_DEFAULT_COOKIE &&
            !(t.cookie_initial & 0xffff0000u))
            t.prerequisites |= NP_LC_PREREQ_COOKIE_CRT_REINIT;
    }
    t.guard_flags = lc_field(d, size, 88);
    mask = NP_LC_CF_INSTRUMENTED | NP_LC_CFW_INSTRUMENTED |
        NP_LC_CF_FUNCTION_TABLE_PRESENT | NP_LC_SECURITY_COOKIE_UNUSED |
        NP_LC_PROTECT_DELAYLOAD_IAT | NP_LC_DELAYLOAD_IAT_IN_OWN_SECTION |
        NP_LC_CF_EXPORT_SUPPRESSION_INFO | NP_LC_CF_ENABLE_EXPORT_SUPPRESSION |
        NP_LC_CF_LONGJUMP_TABLE_PRESENT | NP_LC_RF_INSTRUMENTED | NP_LC_RF_ENABLE |
        NP_LC_RF_STRICT | NP_LC_RETPOLINE_PRESENT |
        NP_LC_EH_CONTINUATION_TABLE_PRESENT | NP_LC_XFG_ENABLED |
        NP_LC_CASTGUARD_PRESENT | NP_LC_MEMCPY_PRESENT | NP_LC_CF_TABLE_SIZE_MASK;
    if (t.guard_flags & ~mask) return lc_fail(error, "LC_GUARD_FLAGS_UNSUPPORTED");
    stride = 4u + (t.guard_flags >> NP_LC_CF_TABLE_SIZE_SHIFT);
    if (!lc_table(p, lc_field(d, size, 64), lc_field(d, size, 68), 4, 1, 0,
                  &t.seh, &budget, error) ||
        !lc_table(p, lc_field(d, size, 80), lc_field(d, size, 84), stride, 1, 1,
                  &t.cfg, &budget, error) ||
        !lc_table(p, lc_field(d, size, 104), lc_field(d, size, 108), stride, 2, 0,
                  &t.address_taken_iat, &budget, error) ||
        !lc_table(p, lc_field(d, size, 112), lc_field(d, size, 116), stride, 1, 0,
                  &t.long_jump, &budget, error) ||
        !lc_table(p, lc_field(d, size, 164), lc_field(d, size, 168), 4, 1, 0,
                  &t.eh_continuation, &budget, error)) return 0;
    if (!lc_slot(p, lc_field(d, size, 72), &t.cf_check_rva,
                 &t.protection_needed, NP_LC_PROTECT_CF_CHECK, error) ||
        !lc_slot(p, lc_field(d, size, 76), &t.cf_dispatch_rva,
                 &t.protection_needed, NP_LC_PROTECT_CF_DISPATCH, error) ||
        !lc_slot(p, lc_field(d, size, 132), &t.rf_failure_slot_rva,
                 &t.protection_needed, NP_LC_PROTECT_RF_FAILURE, error) ||
        !lc_slot(p, lc_field(d, size, 144), &t.rf_verify_slot_rva,
                 &t.protection_needed, NP_LC_PROTECT_RF_VERIFY, error) ||
        !lc_slot(p, lc_field(d, size, 172), &t.xfg_check_rva,
                 &t.protection_needed, NP_LC_PROTECT_XFG_CHECK, error) ||
        !lc_slot(p, lc_field(d, size, 176), &t.xfg_dispatch_rva,
                 &t.protection_needed, NP_LC_PROTECT_XFG_DISPATCH, error) ||
        !lc_slot(p, lc_field(d, size, 180), &t.xfg_table_rva,
                 &t.protection_needed, NP_LC_PROTECT_XFG_TABLE, error) ||
        !lc_slot(p, lc_field(d, size, 188), &t.memcpy_rva,
                 &t.protection_needed, NP_LC_PROTECT_MEMCPY, error)) return 0;
    n = lc_field(d, size, 128);
    if (n && !lc_va(p, n, 1, 1, &t.rf_failure_rva))
        return lc_fail(error, "LC_RF_FAILURE_TARGET");
    n = lc_field(d, size, 184);
    if (n) {
        if ((n & 3u) || !lc_va(p, n, 4, 2, &t.castguard_rva))
            return lc_fail(error, "LC_CASTGUARD_STORAGE");
        if (!np_memory(p, t.castguard_rva, 4, 3))
            t.protection_needed |= NP_LC_PROTECT_CASTGUARD;
    }
    if (lc_field(d, size, 100) || lc_word(d, size, 142) || lc_field(d, size, 152))
        return lc_fail(error, "LC_RESERVED_NONZERO");
    if (lc_field(d, size, 120) || lc_field(d, size, 136) || lc_word(d, size, 140))
        return lc_fail(error, "LC_DYNAMIC_RELOC_UNSUPPORTED");
    if (lc_field(d, size, 124)) return lc_fail(error, "LC_CHPE_UNSUPPORTED");
    if (lc_field(d, size, 148)) return lc_fail(error, "LC_HOTPATCH_UNSUPPORTED");
    if (lc_field(d, size, 156)) return lc_fail(error, "LC_ENCLAVE_UNSUPPORTED");
    if (lc_field(d, size, 160)) return lc_fail(error, "LC_VOLATILE_UNSUPPORTED");
    if (lc_word(d, size, 92) || lc_word(d, size, 94) || lc_field(d, size, 96))
        t.prerequisites |= NP_LC_PREREQ_CODE_INTEGRITY;
    if (t.seh.count) t.prerequisites |= NP_LC_PREREQ_SAFESEH;
    if (t.cfg.count || t.address_taken_iat.count || t.long_jump.count ||
        t.cf_check_rva || t.cf_dispatch_rva ||
        (t.guard_flags & (NP_LC_CF_INSTRUMENTED | NP_LC_CF_FUNCTION_TABLE_PRESENT |
                         NP_LC_CF_EXPORT_SUPPRESSION_INFO |
                         NP_LC_CF_ENABLE_EXPORT_SUPPRESSION |
                         NP_LC_CF_LONGJUMP_TABLE_PRESENT)))
        t.prerequisites |= NP_LC_PREREQ_CFG;
    if (t.guard_flags & NP_LC_CFW_INSTRUMENTED) t.prerequisites |= NP_LC_PREREQ_CFW;
    if (t.guard_flags & (NP_LC_PROTECT_DELAYLOAD_IAT | NP_LC_DELAYLOAD_IAT_IN_OWN_SECTION))
        t.prerequisites |= NP_LC_PREREQ_DELAY_IAT;
    if (t.eh_continuation.count || (t.guard_flags & NP_LC_EH_CONTINUATION_TABLE_PRESENT))
        t.prerequisites |= NP_LC_PREREQ_EHCONT;
    if (t.xfg_check_rva || t.xfg_dispatch_rva || t.xfg_table_rva ||
        (t.guard_flags & NP_LC_XFG_ENABLED)) t.prerequisites |= NP_LC_PREREQ_XFG;
    if (t.rf_failure_rva || t.rf_failure_slot_rva || t.rf_verify_slot_rva ||
        (t.guard_flags & (NP_LC_RF_INSTRUMENTED | NP_LC_RF_ENABLE | NP_LC_RF_STRICT)))
        t.prerequisites |= NP_LC_PREREQ_RF;
    if (t.guard_flags & NP_LC_RETPOLINE_PRESENT) t.prerequisites |= NP_LC_PREREQ_RETPOLINE;
    if (t.castguard_rva || (t.guard_flags & NP_LC_CASTGUARD_PRESENT))
        t.prerequisites |= NP_LC_PREREQ_CASTGUARD;
    if (t.memcpy_rva || (t.guard_flags & NP_LC_MEMCPY_PRESENT))
        t.prerequisites |= NP_LC_PREREQ_MEMCPY;
    slots[0] = t.cf_check_rva; slots[1] = t.cf_dispatch_rva;
    slots[2] = t.rf_failure_slot_rva; slots[3] = t.rf_verify_slot_rva;
    slots[4] = t.xfg_check_rva; slots[5] = t.xfg_dispatch_rva;
    slots[6] = t.xfg_table_rva; slots[7] = t.memcpy_rva; slots[8] = t.castguard_rva;
    if (lc_storage_overlap(&t, t.cookie_rva))
        return lc_fail(error, "LC_COOKIE_METADATA_OVERLAP");
    for (i = 0; i < 9; i++) {
        if (lc_storage_overlap(&t, slots[i]))
            return lc_fail(error, "LC_GUARD_METADATA_OVERLAP");
        if (slots[i] && t.cookie_rva && lc_overlap(slots[i], 4, t.cookie_rva, 4))
            return lc_fail(error, "LC_COOKIE_GUARD_OVERLAP");
    }
    *info = t;
    return 1;
}

int np_load_config_cookie_limited(const np_image *p, void *mapped,
                                  uint32_t mapped_bytes, uint32_t entropy,
                                  np_load_config_cookie_result *result,
                                  const np_load_config_limits *limits,
                                  const char **error)
{
    np_load_config_info t;
    np_load_config_cookie_result out;
    uint8_t *slot;
    uintptr_t map_address, file_address;
    uint32_t value;
    if (error && (lc_input_alias(p, error, sizeof(*error)) ||
                  lc_pointer_overlap(error, sizeof(*error), limits, sizeof(*limits)) ||
                  lc_pointer_overlap(error, sizeof(*error), mapped, mapped_bytes) ||
                  lc_pointer_overlap(error, sizeof(*error), result, sizeof(*result))))
        return 0;
    if (result && lc_input_alias(p, result, sizeof(*result)))
        return lc_fail(error, "LC_COOKIE_OUTPUT_ALIASES_INPUT");
    if (result && lc_pointer_overlap(result, sizeof(*result), limits, sizeof(*limits)))
        return lc_fail(error, "LC_COOKIE_OUTPUT_ALIASES_LIMITS");
    if (result && lc_pointer_overlap(result, sizeof(*result), mapped, mapped_bytes))
        return lc_fail(error, "LC_COOKIE_OUTPUT_ALIASES_MAPPING");
    if (error) *error = 0;
    if (!result) return lc_fail(error, "LC_COOKIE_OUTPUT_NULL");
    lc_zero(result, sizeof(*result)); lc_zero(&out, sizeof(out));
    if (!np_load_config_limited(p, &t, limits, error)) return 0;
    out.remaining_prerequisites = t.prerequisites;
    if (!t.cookie_rva) { *result = out; return 1; }
    if (!mapped || mapped_bytes < p->size || t.cookie_rva > mapped_bytes ||
        mapped_bytes - t.cookie_rva < 4)
        return lc_fail(error, "LC_COOKIE_MAPPING_BOUNDS");
    map_address = (uintptr_t)mapped; file_address = (uintptr_t)p->file;
    if (map_address > UINTPTR_MAX - mapped_bytes ||
        file_address > UINTPTR_MAX - p->bytes)
        return lc_fail(error, "LC_COOKIE_MAPPING_OVERFLOW");
    if (map_address < file_address + p->bytes &&
        file_address < map_address + mapped_bytes)
        return lc_fail(error, "LC_COOKIE_MAPPING_ALIASES_FILE");
    if (lc_pointer_overlap(mapped, mapped_bytes, p, sizeof(*p)))
        return lc_fail(error, "LC_COOKIE_MAPPING_ALIASES_IMAGE");
    if (lc_pointer_overlap(mapped, mapped_bytes, limits, sizeof(*limits)))
        return lc_fail(error, "LC_COOKIE_MAPPING_ALIASES_LIMITS");
    if ((map_address + t.cookie_rva) & 3u)
        return lc_fail(error, "LC_COOKIE_MAPPING_ALIGNMENT");
    slot = (uint8_t *)mapped + t.cookie_rva;
    out.present = 1; out.rva = t.cookie_rva;
    out.previous = out.value = np_u32(slot);
    out.remaining_prerequisites &= ~NP_LC_PREREQ_COOKIE;
    if (!out.previous || out.previous == NP_LC_DEFAULT_COOKIE) {
        /* Normalize a caller-provided x86 CRT entropy sample, with no fixed
         * fallback RNG and no pointer-truncation entropy on a 64-bit host. */
        value = entropy;
        if (value == NP_LC_DEFAULT_COOKIE) value++;
        else if (!(value & 0xffff0000u)) value |= (value | 0x4711u) << 16;
        slot[0] = (uint8_t)value; slot[1] = (uint8_t)(value >> 8);
        slot[2] = (uint8_t)(value >> 16); slot[3] = (uint8_t)(value >> 24);
        out.value = value; out.initialized = 1;
        out.remaining_prerequisites &= ~NP_LC_PREREQ_COOKIE_CRT_REINIT;
    } else if (!(out.previous & 0xffff0000u)) {
        /* Preserve caller/module-established nondefault values, even though
         * the x86 CRT must reinitialize this legacy highword-zero value. */
        out.needs_crt_reinit = 1;
        out.remaining_prerequisites |= NP_LC_PREREQ_COOKIE_CRT_REINIT;
    } else {
        out.remaining_prerequisites &= ~NP_LC_PREREQ_COOKIE_CRT_REINIT;
    }
    *result = out;
    return 1;
}

int np_load_config_execution_profile_limited(const np_image *p,
                                             const np_load_config_limits *limits,
                                             const char **error)
{
    np_load_config_info t;
    if (!np_load_config_limited(p, &t, limits, error)) return 0;
    if (t.prerequisites & NP_LC_PREREQ_SAFESEH) return lc_fail(error, "LC_SAFESEH_RUNTIME_REQUIRED");
    if (t.prerequisites & NP_LC_PREREQ_CFG) return lc_fail(error, "LC_CFG_RUNTIME_REQUIRED");
    if (t.prerequisites & NP_LC_PREREQ_XFG) return lc_fail(error, "LC_XFG_RUNTIME_REQUIRED");
    if (t.prerequisites & NP_LC_PREREQ_EHCONT) return lc_fail(error, "LC_EHCONT_RUNTIME_REQUIRED");
    if (t.prerequisites & NP_LC_PREREQ_CFW) return lc_fail(error, "LC_CFW_RUNTIME_REQUIRED");
    if (t.prerequisites & NP_LC_PREREQ_RF) return lc_fail(error, "LC_RF_RUNTIME_REQUIRED");
    if (t.prerequisites & NP_LC_PREREQ_DELAY_IAT) return lc_fail(error, "LC_DELAY_IAT_RUNTIME_REQUIRED");
    if (t.prerequisites & NP_LC_PREREQ_CODE_INTEGRITY) return lc_fail(error, "LC_CODE_INTEGRITY_RUNTIME_REQUIRED");
    if (t.prerequisites & NP_LC_PREREQ_LEGACY_CONFIG) return lc_fail(error, "LC_LEGACY_CONFIG_RUNTIME_REQUIRED");
    if (t.prerequisites & NP_LC_PREREQ_COOKIE_CRT_REINIT) return lc_fail(error, "LC_COOKIE_CRT_REINIT_REQUIRED");
    if (t.prerequisites & NP_LC_PREREQ_COOKIE) return lc_fail(error, "LC_COOKIE_INITIALIZATION_REQUIRED");
    if (t.prerequisites) return lc_fail(error, "LC_ADDITIONAL_RUNTIME_REQUIRED");
    return 1;
}

int np_load_config(const np_image *p, np_load_config_info *info,
                   const char **error)
{
    return np_load_config_limited(p, info, &lc_default_limits, error);
}

int np_load_config_cookie(const np_image *p, void *mapped, uint32_t mapped_bytes,
                          uint32_t entropy, np_load_config_cookie_result *result,
                          const char **error)
{
    return np_load_config_cookie_limited(p, mapped, mapped_bytes, entropy, result,
                                         &lc_default_limits, error);
}

int np_load_config_execution_profile(const np_image *p, const char **error)
{
    return np_load_config_execution_profile_limited(p, &lc_default_limits, error);
}
