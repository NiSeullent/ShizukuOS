/* SPDX-License-Identifier: GPL-2.0-only
 * Windows 98 Unicode path layer for the LibreOffice SAL. Windows 98 KERNEL32 exports CreateFileW,
 * GetFileAttributesW, FindFirstFileW ... but implements them as stubs that fail with
 * ERROR_CALL_NOT_IMPLEMENTED. Every W entry here converts the UTF-16 path to the active ANSI code
 * page, REFUSES (ERROR_NO_UNICODE_TRANSLATION) any path that does not round-trip exactly (no '?'
 * substitution, no best-fit), enforces the Windows 98 MAX_PATH limit and calls the ANSI API.
 * Pure decision logic over a narrow backend (host-testable); the Win98 backend is office_sal_win98.c.
 * Names returned by the OS (find data, full paths) are converted back and verified the same way.
 */
#ifndef SHZ_OFFICE_SAL_UNICODE_H
#define SHZ_OFFICE_SAL_UNICODE_H
#include "office_sal.h"
#ifdef __cplusplus
extern "C" {
#endif

struct ofu_find_a { uint32_t attr, times[6], size_hi, size_lo, res0, res1; char name[260]; char alt[14]; };
struct ofu_find_w { uint32_t attr, times[6], size_hi, size_lo, res0, res1; uint16_t name[260]; uint16_t alt[14]; };

enum ofu_str { OFU_FULLPATH = 1, OFU_CWD, OFU_TEMP, OFU_MODULE, OFU_LONGPATH };

/* All backend functions take ANSI strings and return a Win32 error (0 = success). */
struct ofu_fs {
    void *ctx;
    uint32_t (*create_file)(void *ctx, const char *p, uint32_t access, uint32_t share, const void *sa,
                            uint32_t disp, uint32_t flags, void *tmpl, void **h);
    uint32_t (*get_attr)(void *ctx, const char *p, uint32_t *attr);
    uint32_t (*get_attr_ex)(void *ctx, const char *p, uint32_t level, void *info);
    uint32_t (*set_attr)(void *ctx, const char *p, uint32_t attr);
    uint32_t (*mkdir)(void *ctx, const char *p, const void *sa);
    uint32_t (*rmdir)(void *ctx, const char *p);
    uint32_t (*del)(void *ctx, const char *p);
    uint32_t (*move)(void *ctx, const char *src, const char *dst, uint32_t flags);
    uint32_t (*copy)(void *ctx, const char *src, const char *dst, int fail_if_exists);
    uint32_t (*find_first)(void *ctx, const char *p, struct ofu_find_a *d, void **h);
    uint32_t (*find_next)(void *ctx, void *h, struct ofu_find_a *d);
    uint32_t (*find_close)(void *ctx, void *h);
    uint32_t (*set_cwd)(void *ctx, const char *p);
    uint32_t (*drive_type)(void *ctx, const char *root, uint32_t *type);
    /* get_str: which = enum ofu_str; *len is the raw return value of the ANSI API (0 = failure). */
    uint32_t (*get_str)(void *ctx, int which, const char *arg, void *module, char *out, uint32_t cap, uint32_t *len);
};

uint32_t ofu_create_file(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, uint32_t access,
                         uint32_t share, const void *sa, uint32_t disp, uint32_t flags, void *tmpl, void **h);
uint32_t ofu_get_attr(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, uint32_t *attr);
uint32_t ofu_get_attr_ex(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, uint32_t level, void *info);
uint32_t ofu_set_attr(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, uint32_t attr);
uint32_t ofu_mkdir(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, const void *sa);
uint32_t ofu_rmdir(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path);
uint32_t ofu_delete(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path);
/* flags: MOVEFILE_*; MoveFileW == flags 0. CREATE_HARDLINK/FAIL_IF_NOT_TRACKABLE -> ERROR_NOT_SUPPORTED. */
uint32_t ofu_move(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *src, const uint16_t *dst, uint32_t flags);
uint32_t ofu_copy(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *src, const uint16_t *dst, int fail_if_exists);
uint32_t ofu_find_first(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path, struct ofu_find_w *d, void **h);
uint32_t ofu_find_next(const struct ofs_backend *cv, const struct ofu_fs *fs, void *h, struct ofu_find_w *d);
uint32_t ofu_set_cwd(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *path);
uint32_t ofu_drive_type(const struct ofs_backend *cv, const struct ofu_fs *fs, const uint16_t *root, uint32_t *type);
/* Get*W string semantics: *ret = chars written excluding NUL; if cap is too small *ret = required size
 * including NUL and the buffer is untouched (returns OFS_OK); on failure returns the error and *ret = 0. */
uint32_t ofu_get_string(const struct ofs_backend *cv, const struct ofu_fs *fs, int which, const uint16_t *arg,
                        void *module, uint16_t *out, uint32_t cap, uint32_t *ret);

#ifdef __cplusplus
}
#endif
#endif
