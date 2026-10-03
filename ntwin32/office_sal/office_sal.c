/* SPDX-License-Identifier: GPL-2.0-only
 * Pure decision logic of the Win98 LibreOffice SAL provider; see office_sal.h. */
#include "office_sal.h"
#include <stddef.h>

uint32_t ofs_w2a(const struct ofs_backend *b, const uint16_t *w, char *out, uint32_t cap)
{
    uint32_t n = 0;
    int got, lossy = 0;
    uint16_t back[OFS_PATH_MAX];
    if (!b || !b->to_ansi || !b->to_wide || !w || !out || !cap) return OFS_ERROR_INVALID_PARAMETER;
    while (w[n]) {
        if (++n >= OFS_PATH_MAX) return OFS_ERROR_FILENAME_EXCED_RANGE;
    }
    if (n >= 4 && w[0] == '\\' && w[1] == '\\' && w[2] == '?' && w[3] == '\\') return OFS_ERROR_INVALID_NAME;
    if (n + 1 > cap) return OFS_ERROR_INSUFFICIENT_BUFFER;
    got = n ? b->to_ansi(b->ctx, w, (int)n, out, (int)cap - 1, &lossy) : 0;
    if (n && (got <= 0 || lossy)) return OFS_ERROR_NO_UNICODE_TRANSLATION;
    out[n ? got : 0] = 0;
    if (n) {   /* round trip: refuse best-fit mappings the lossy flag did not report */
        int rt = b->to_wide(b->ctx, out, got, back, OFS_PATH_MAX);
        uint32_t i;
        if (rt != (int)n) return OFS_ERROR_NO_UNICODE_TRANSLATION;
        for (i = 0; i < n; ++i) if (back[i] != w[i]) return OFS_ERROR_NO_UNICODE_TRANSLATION;
    }
    return OFS_OK;
}

uint32_t ofs_set_file_pointer_ex(const struct ofs_backend *b, void *h, int64_t dist, int64_t *newpos, uint32_t method)
{
    int32_t hi = (int32_t)(dist >> 32);
    uint32_t lo, err = 0;
    if (!b || !b->set_fp || method > 2) return OFS_ERROR_INVALID_PARAMETER;
    lo = b->set_fp(b->ctx, h, (int32_t)(uint32_t)(dist & 0xFFFFFFFFu), &hi, method, &err);
    if (lo == 0xFFFFFFFFu && err) return err;
    if (newpos) *newpos = (int64_t)(((uint64_t)(uint32_t)hi << 32) | lo);
    return OFS_OK;
}

uint32_t ofs_get_file_size_ex(const struct ofs_backend *b, void *h, int64_t *size)
{
    uint32_t hi = 0, lo, err = 0;
    if (!b || !b->get_size || !size) return OFS_ERROR_INVALID_PARAMETER;
    lo = b->get_size(b->ctx, h, &hi, &err);
    if (lo == 0xFFFFFFFFu && err) return err;
    *size = (int64_t)(((uint64_t)hi << 32) | lo);
    return OFS_OK;
}

static int append_suffix(char *s, uint32_t cap, const char *suffix)
{
    uint32_t n = 0, i = 0;
    while (s[n]) ++n;
    while (suffix[i]) { if (n + i + 1 >= cap) return 0; s[n + i] = suffix[i]; ++i; }
    s[n + i] = 0;
    return 1;
}

uint32_t ofs_replace_file(const struct ofs_backend *b, const uint16_t *replaced, const uint16_t *replacement,
                          const uint16_t *backup, uint32_t flags, const void *reserved1, const void *reserved2)
{
    char dst[OFS_PATH_MAX + 16], src[OFS_PATH_MAX], bk[OFS_PATH_MAX + 16];
    uint32_t e, i;
    int explicit_backup = backup != NULL;
    if (!b || !b->path_exists || !b->move_replace || !b->remove_file || !b->same_volume || !b->flush_file)
        return OFS_ERROR_INVALID_PARAMETER;
    if (reserved1 || reserved2 || !replaced || !replacement) return OFS_ERROR_INVALID_PARAMETER;
    if (flags & ~(OFS_REPLACEFILE_WRITE_THROUGH | OFS_REPLACEFILE_IGNORE_MERGE_ERRORS | OFS_REPLACEFILE_IGNORE_ACL_ERRORS))
        return OFS_ERROR_INVALID_PARAMETER;
    if ((e = ofs_w2a(b, replaced, dst, OFS_PATH_MAX))) return e;
    if ((e = ofs_w2a(b, replacement, src, OFS_PATH_MAX))) return e;
    if (explicit_backup) { if ((e = ofs_w2a(b, backup, bk, OFS_PATH_MAX))) return e; }
    else { for (i = 0; (bk[i] = dst[i]) != 0; ++i) { } if (!append_suffix(bk, sizeof bk, ".~ofs")) return OFS_ERROR_FILENAME_EXCED_RANGE; }
    for (i = 0; dst[i] && dst[i] == src[i]; ++i) { }
    if (!dst[i] && !src[i]) return OFS_ERROR_INVALID_PARAMETER;      /* same path */
    if (!b->path_exists(b->ctx, dst)) return OFS_ERROR_FILE_NOT_FOUND;
    if (!b->path_exists(b->ctx, src)) return OFS_ERROR_FILE_NOT_FOUND;
    if (!b->same_volume(b->ctx, src, dst)) return OFS_ERROR_UNABLE_TO_MOVE_REPLACEMENT;
    if (!explicit_backup && b->path_exists(b->ctx, bk)) return OFS_ERROR_UNABLE_TO_REMOVE_REPLACED;
    if ((flags & OFS_REPLACEFILE_WRITE_THROUGH) && b->flush_file(b->ctx, src)) return OFS_ERROR_UNABLE_TO_MOVE_REPLACEMENT;
    if (b->move_replace(b->ctx, dst, bk)) return OFS_ERROR_UNABLE_TO_REMOVE_REPLACED;
    if (b->move_replace(b->ctx, src, dst)) {
        /* put the original back so a failed replace never loses the destination */
        if (b->move_replace(b->ctx, bk, dst)) return OFS_ERROR_UNABLE_TO_MOVE_REPLACEMENT_2;
        return OFS_ERROR_UNABLE_TO_MOVE_REPLACEMENT;
    }
    if (!explicit_backup) (void)b->remove_file(b->ctx, bk);   /* data already safe; a leftover .~ofs is possible */
    return OFS_OK;
}

uint32_t ofs_get_module_handle_ex(const struct ofs_backend *b, uint32_t flags, const uint16_t *name_or_addr, void **out)
{
    void *m;
    char name[OFS_PATH_MAX];
    uint32_t e;
    if (!out) return OFS_ERROR_INVALID_PARAMETER;
    *out = NULL;
    if (!b || !b->module_by_name || !b->module_from_address || !b->module_addref) return OFS_ERROR_INVALID_PARAMETER;
    if (flags & ~(OFS_GMHE_PIN | OFS_GMHE_UNCHANGED_REFCOUNT | OFS_GMHE_FROM_ADDRESS)) return OFS_ERROR_INVALID_PARAMETER;
    if ((flags & OFS_GMHE_PIN) && (flags & OFS_GMHE_UNCHANGED_REFCOUNT)) return OFS_ERROR_INVALID_PARAMETER;
    if (flags & OFS_GMHE_PIN) return OFS_ERROR_NOT_SUPPORTED;      /* Windows 98 cannot pin a module */
    if (flags & OFS_GMHE_FROM_ADDRESS) {
        if (!name_or_addr) return OFS_ERROR_INVALID_PARAMETER;
        m = b->module_from_address(b->ctx, name_or_addr);
    } else if (!name_or_addr) {
        m = b->module_by_name(b->ctx, NULL);
    } else {
        if ((e = ofs_w2a(b, name_or_addr, name, sizeof name))) return e;
        m = b->module_by_name(b->ctx, name);
    }
    if (!m) return OFS_ERROR_MOD_NOT_FOUND;
    if (!(flags & OFS_GMHE_UNCHANGED_REFCOUNT) && (e = b->module_addref(b->ctx, m))) return e;
    *out = m;
    return OFS_OK;
}

uint32_t ofs_search_path_mode_check(uint32_t flags)
{
    uint32_t mode = flags & ~OFS_SEARCH_PERMANENT;
    if (mode != OFS_SEARCH_ENABLE_SAFE && mode != OFS_SEARCH_DISABLE_SAFE) return OFS_ERROR_INVALID_PARAMETER;
    return OFS_ERROR_CALL_NOT_IMPLEMENTED;     /* Windows 98 SearchPath has no safe mode */
}

uint32_t ofs_proc_register(struct ofs_proc_table *t, void *h, uint32_t pid)
{
    uint32_t i, free_slot = OFS_PROC_TABLE;
    if (!t || !h || h == (void *)(uintptr_t)-1 || !pid) return OFS_ERROR_INVALID_PARAMETER;
    for (i = 0; i < OFS_PROC_TABLE; ++i) {
        if (t->h[i] == h) { t->pid[i] = pid; return OFS_OK; }
        if (!t->h[i] && free_slot == OFS_PROC_TABLE) free_slot = i;
    }
    if (free_slot == OFS_PROC_TABLE) return 8u;      /* ERROR_NOT_ENOUGH_MEMORY */
    t->h[free_slot] = h; t->pid[free_slot] = pid;
    return OFS_OK;
}

uint32_t ofs_proc_forget(struct ofs_proc_table *t, void *h)
{
    uint32_t i;
    if (!t || !h) return OFS_ERROR_INVALID_PARAMETER;
    for (i = 0; i < OFS_PROC_TABLE; ++i) if (t->h[i] == h) { t->h[i] = NULL; t->pid[i] = 0; return OFS_OK; }
    return 6u;      /* ERROR_INVALID_HANDLE */
}

uint32_t ofs_proc_lookup(const struct ofs_proc_table *t, void *h, uint32_t *pid)
{
    uint32_t i;
    if (!t || !h || !pid) return OFS_ERROR_INVALID_PARAMETER;
    for (i = 0; i < OFS_PROC_TABLE; ++i) if (t->h[i] == h) { *pid = t->pid[i]; return OFS_OK; }
    return OFS_ERROR_NOT_SUPPORTED;
}
