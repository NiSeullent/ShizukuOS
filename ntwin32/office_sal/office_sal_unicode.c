/* SPDX-License-Identifier: GPL-2.0-only
 * Pure logic of the Windows 98 Unicode path layer; see office_sal_unicode.h. */
#include "office_sal_unicode.h"
#include <stddef.h>

#define NEED(b) do { if (!(b)) return OFS_ERROR_INVALID_PARAMETER; } while (0)

/* ANSI -> UTF-16 for an OS supplied name; refuses anything that does not convert back byte-exactly. */
static uint32_t a2w(const struct ofs_backend *cv, const char *a, uint32_t alen, uint16_t *w, uint32_t cap, uint32_t *wlen)
{
    int n, back, lossy = 0;
    uint32_t i;
    char chk[OFS_PATH_MAX];
    if (alen == 0) { if (!cap) return OFS_ERROR_INSUFFICIENT_BUFFER; w[0] = 0; *wlen = 0; return OFS_OK; }
    if (alen >= OFS_PATH_MAX) return OFS_ERROR_FILENAME_EXCED_RANGE;
    if (cap < alen + 1) return OFS_ERROR_INSUFFICIENT_BUFFER;
    n = cv->to_wide(cv->ctx, a, (int)alen, w, (int)cap - 1);
    if (n <= 0) return OFS_ERROR_NO_UNICODE_TRANSLATION;
    back = cv->to_ansi(cv->ctx, w, n, chk, (int)sizeof chk, &lossy);
    if (back != (int)alen || lossy) return OFS_ERROR_NO_UNICODE_TRANSLATION;
    for (i = 0; i < alen; ++i) if (chk[i] != a[i]) return OFS_ERROR_NO_UNICODE_TRANSLATION;
    w[n] = 0; *wlen = (uint32_t)n;
    return OFS_OK;
}

#define PATH1(cv, fs, fn, p, buf) \
    char buf[OFS_PATH_MAX]; uint32_t e_; \
    NEED(cv && fs && fs->fn); \
    if ((e_ = ofs_w2a(cv, p, buf, sizeof buf))) return e_

uint32_t ofu_create_file(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, uint32_t access,
                         uint32_t share, const void *sa, uint32_t disp, uint32_t flags, void *tmpl, void **h)
{
    PATH1(cv, fs, create_file, path, a);
    NEED(h);
    *h = (void *)-1;
    return fs->create_file(fs->ctx, a, access, share, sa, disp, flags, tmpl, h);
}
uint32_t ofu_get_attr(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, uint32_t *attr)
{ PATH1(cv, fs, get_attr, path, a); NEED(attr); return fs->get_attr(fs->ctx, a, attr); }
uint32_t ofu_get_attr_ex(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, uint32_t level, void *info)
{
    PATH1(cv, fs, get_attr_ex, path, a);
    NEED(info);
    if (level != 0) return OFS_ERROR_INVALID_PARAMETER;      /* GetFileExInfoStandard only */
    return fs->get_attr_ex(fs->ctx, a, level, info);
}
uint32_t ofu_set_attr(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, uint32_t attr)
{ PATH1(cv, fs, set_attr, path, a); return fs->set_attr(fs->ctx, a, attr); }
uint32_t ofu_mkdir(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, const void *sa)
{ PATH1(cv, fs, mkdir, path, a); return fs->mkdir(fs->ctx, a, sa); }
uint32_t ofu_rmdir(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path)
{ PATH1(cv, fs, rmdir, path, a); return fs->rmdir(fs->ctx, a); }
uint32_t ofu_delete(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path)
{ PATH1(cv, fs, del, path, a); return fs->del(fs->ctx, a); }

uint32_t ofu_move(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *src, const uint16_t *dst, uint32_t flags)
{
    char s[OFS_PATH_MAX], d[OFS_PATH_MAX];
    uint32_t e;
    NEED(cv && fs && fs->move);
    if (flags & ~0x3Fu) return OFS_ERROR_INVALID_PARAMETER;
    if (flags & 0x30u) return OFS_ERROR_NOT_SUPPORTED;        /* hard links / tracking: no Windows 98 equivalent */
    if ((e = ofs_w2a(cv, src, s, sizeof s)) || (e = ofs_w2a(cv, dst, d, sizeof d))) return e;
    return fs->move(fs->ctx, s, d, flags);
}
uint32_t ofu_copy(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *src, const uint16_t *dst, int fail_if_exists)
{
    char s[OFS_PATH_MAX], d[OFS_PATH_MAX];
    uint32_t e;
    NEED(cv && fs && fs->copy);
    if ((e = ofs_w2a(cv, src, s, sizeof s)) || (e = ofs_w2a(cv, dst, d, sizeof d))) return e;
    return fs->copy(fs->ctx, s, d, fail_if_exists);
}

static uint32_t find_out(const struct ofs_backend *cv, const struct ofu_find_a *a, struct ofu_find_w *w)
{
    uint32_t e, n, l = 0;
    while (a->name[l] && l < sizeof a->name) ++l;
    if (l == sizeof a->name) return OFS_ERROR_NO_UNICODE_TRANSLATION;
    if ((e = a2w(cv, a->name, l, w->name, 260, &n))) return e;
    for (l = 0; a->alt[l] && l < sizeof a->alt; ++l) { }
    if (l == sizeof a->alt) return OFS_ERROR_NO_UNICODE_TRANSLATION;
    if ((e = a2w(cv, a->alt, l, w->alt, 14, &n))) return e;
    w->attr = a->attr; w->size_hi = a->size_hi; w->size_lo = a->size_lo; w->res0 = a->res0; w->res1 = a->res1;
    for (l = 0; l < 6; ++l) w->times[l] = a->times[l];
    return OFS_OK;
}

uint32_t ofu_find_first(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, struct ofu_find_w *d, void **h)
{
    struct ofu_find_a a;
    uint32_t e;
    PATH1(cv, fs, find_first, path, p);
    NEED(d && h);
    *h = (void *)-1;
    if ((e = fs->find_first(fs->ctx, p, &a, h))) return e;
    if ((e = find_out(cv, &a, d))) {            /* name not representable: do not leak the search handle */
        if (fs->find_close) fs->find_close(fs->ctx, *h);
        *h = (void *)-1;
        return e;
    }
    return OFS_OK;
}
uint32_t ofu_find_next(const struct ofs_backend *cv, const struct ofu_fs *fs, void *h, struct ofu_find_w *d)
{
    struct ofu_find_a a;
    uint32_t e;
    NEED(cv && fs && fs->find_next && d);
    if ((e = fs->find_next(fs->ctx, h, &a))) return e;
    return find_out(cv, &a, d);
}
uint32_t ofu_set_cwd(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path)
{ PATH1(cv, fs, set_cwd, path, a); return fs->set_cwd(fs->ctx, a); }
uint32_t ofu_drive_type(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *root, uint32_t *type)
{
    char a[OFS_PATH_MAX];
    uint32_t e;
    NEED(cv && fs && fs->drive_type && type);
    if (!root) return fs->drive_type(fs->ctx, 0, type);
    if ((e = ofs_w2a(cv, root, a, sizeof a))) return e;
    return fs->drive_type(fs->ctx, a, type);
}

uint32_t ofu_get_string(const struct ofs_backend *cv, const struct ofu_fs *fs, int which, const uint16_t *arg,
                        void *module, uint16_t *out, uint32_t cap, uint32_t *ret)
{
    char in[OFS_PATH_MAX], res[OFS_PATH_MAX];
    uint16_t tmp[OFS_PATH_MAX];
    uint32_t e, len = 0, wlen = 0;
    NEED(cv && fs && fs->get_str && ret);
    *ret = 0;
    if (which == OFU_FULLPATH || which == OFU_LONGPATH) {
        NEED(arg);
        if ((e = ofs_w2a(cv, arg, in, sizeof in))) return e;
    }
    if (cap && !out) return OFS_ERROR_INVALID_PARAMETER;
    if ((e = fs->get_str(fs->ctx, which, which == OFU_FULLPATH || which == OFU_LONGPATH ? in : 0, module, res, sizeof res, &len))) return e;
    if (len == 0) return OFS_ERROR_INVALID_PARAMETER;       /* backend must report an error when it returns 0 */
    if (len >= OFS_PATH_MAX) return OFS_ERROR_FILENAME_EXCED_RANGE;
    if ((e = a2w(cv, res, len, tmp, OFS_PATH_MAX, &wlen))) return e;
    if (cap < wlen + 1) { *ret = wlen + 1; return OFS_OK; }
    { uint32_t i; for (i = 0; i <= wlen; ++i) out[i] = tmp[i]; }
    *ret = wlen;
    return OFS_OK;
}
