/* SPDX-License-Identifier: GPL-2.0-only
 * Win98 provider for the LibreOffice 26.8.0.3 SAL (sal/osl/w32) startup, process,
 * module and file calls that Windows 98 SE KERNEL32 does not export:
 *   SetProcessDEPPolicy, SetDllDirectoryW, SetSearchPathMode, GetProcessId,
 *   GetModuleHandleExW, GetFileSizeEx, SetFilePointerEx, ReplaceFileW.
 * Decisions are pure logic over a narrow backend so they are host-testable; the
 * Win98 backend lives in office_sal_win98.c. Contracts follow Microsoft docs and
 * Wine 11 kernelbase behaviour; original implementation, no code copied.
 * Unrepresentable Unicode paths and unsupported features fail with a Win32 error.
 */
#ifndef SHZ_OFFICE_SAL_H
#define SHZ_OFFICE_SAL_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define OFS_OK 0u
#define OFS_ERROR_FILE_NOT_FOUND 2u
#define OFS_ERROR_NOT_SUPPORTED 50u
#define OFS_ERROR_INVALID_PARAMETER 87u
#define OFS_ERROR_INSUFFICIENT_BUFFER 122u
#define OFS_ERROR_CALL_NOT_IMPLEMENTED 120u
#define OFS_ERROR_INVALID_NAME 123u
#define OFS_ERROR_MOD_NOT_FOUND 126u
#define OFS_ERROR_NEGATIVE_SEEK 131u
#define OFS_ERROR_FILENAME_EXCED_RANGE 206u
#define OFS_ERROR_NO_UNICODE_TRANSLATION 1113u
#define OFS_ERROR_UNABLE_TO_REMOVE_REPLACED 1175u
#define OFS_ERROR_UNABLE_TO_MOVE_REPLACEMENT 1176u
#define OFS_ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 1177u

#define OFS_PATH_MAX 260u   /* Windows 98 MAX_PATH including NUL */
#define OFS_REPLACEFILE_WRITE_THROUGH 1u
#define OFS_REPLACEFILE_IGNORE_MERGE_ERRORS 2u
#define OFS_REPLACEFILE_IGNORE_ACL_ERRORS 4u
#define OFS_GMHE_PIN 1u
#define OFS_GMHE_UNCHANGED_REFCOUNT 2u
#define OFS_GMHE_FROM_ADDRESS 4u
#define OFS_SEARCH_ENABLE_SAFE 1u
#define OFS_SEARCH_DISABLE_SAFE 2u
#define OFS_SEARCH_PERMANENT 0x8000u
#define OFS_PROC_TABLE 64u

struct ofs_backend {
    void *ctx;
    /* Unicode layer: convert UTF-16 (n units, no NUL) to / from the ANSI code page. 0 = failure,
     * else units written. *lossy is set if a default/best-fit substitution happened. */
    int (*to_ansi)(void *ctx, const uint16_t *w, int n, char *out, int cap, int *lossy);
    int (*to_wide)(void *ctx, const char *a, int n, uint16_t *out, int cap);
    /* ANSI-path file system (Windows 98 W-APIs are stubs) */
    int (*path_exists)(void *ctx, const char *path);
    int (*same_volume)(void *ctx, const char *a, const char *b);
    uint32_t (*move_replace)(void *ctx, const char *src, const char *dst);  /* Win32 error */
    uint32_t (*remove_file)(void *ctx, const char *path);
    uint32_t (*flush_file)(void *ctx, const char *path);
    /* file handles: SetFilePointer / GetFileSize conventions; *err is the Win32 last error */
    uint32_t (*set_fp)(void *ctx, void *h, int32_t lo, int32_t *hi, uint32_t method, uint32_t *err);
    uint32_t (*get_size)(void *ctx, void *h, uint32_t *hi, uint32_t *err);
    /* modules */
    void *(*module_by_name)(void *ctx, const char *name_or_null);
    void *(*module_from_address)(void *ctx, const void *addr);   /* verified loaded image base or NULL */
    uint32_t (*module_addref)(void *ctx, void *module);
};

uint32_t ofs_w2a(const struct ofs_backend *b, const uint16_t *w, char *out, uint32_t cap);
uint32_t ofs_set_file_pointer_ex(const struct ofs_backend *b, void *h, int64_t dist, int64_t *newpos, uint32_t method);
uint32_t ofs_get_file_size_ex(const struct ofs_backend *b, void *h, int64_t *size);
uint32_t ofs_replace_file(const struct ofs_backend *b, const uint16_t *replaced, const uint16_t *replacement,
                          const uint16_t *backup, uint32_t flags, const void *reserved1, const void *reserved2);
uint32_t ofs_get_module_handle_ex(const struct ofs_backend *b, uint32_t flags, const uint16_t *name_or_addr, void **out);
uint32_t ofs_search_path_mode_check(uint32_t flags);

/* handle -> pid registry (Windows 98 has no GetProcessId and no handle query; only handles
 * registered by their creator can be answered). Caller serialises. */
struct ofs_proc_table { void *h[OFS_PROC_TABLE]; uint32_t pid[OFS_PROC_TABLE]; };
uint32_t ofs_proc_register(struct ofs_proc_table *t, void *h, uint32_t pid);
uint32_t ofs_proc_forget(struct ofs_proc_table *t, void *h);
uint32_t ofs_proc_lookup(const struct ofs_proc_table *t, void *h, uint32_t *pid);

#ifdef __cplusplus
}
#endif
#endif
