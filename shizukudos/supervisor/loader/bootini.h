/* SPDX-License-Identifier: GPL-2.0-only
 * Boot-manager policy file \EFI\SHIZUKU\BOOT.INI: strict parser.
 *
 * Freestanding (no libc, no UEFI types) so the same file is linked into the UEFI
 * loader and exercised by the host test (shizukudos/supervisor/test_bootmgr.py).
 *
 * Grammar (ASCII, one entry per line, LF or CRLF line ends, at most 4096 bytes):
 *     ; comment            # comment             (blank lines are ignored)
 *     mode = auto | supervisor | csm             (keys and mode values: any case)
 *     csm_path = \EFI\SHIZUKU\CSMWRAP.EFI        (absolute path on the boot volume)
 * Anything else -- unknown or repeated keys, sections, a missing '=', inline
 * comments, control or non-ASCII bytes, bad paths -- rejects the whole file.
 */
#ifndef SHZ_BOOTINI_H
#define SHZ_BOOTINI_H
#include <stddef.h>

#define BOOTINI_MAX_BYTES 4096
#define BOOTINI_PATH_MAX 128            /* including the terminating NUL */
#define BOOTINI_DEFAULT_CSM_PATH "\\EFI\\SHIZUKU\\CSMWRAP.EFI"

enum bootini_mode { BOOT_MODE_AUTO = 0, BOOT_MODE_SUPERVISOR = 1, BOOT_MODE_CSM = 2 };

typedef struct {
    int mode;                           /* enum bootini_mode */
    char csm_path[BOOTINI_PATH_MAX];    /* ASCII, starts with '\' */
    int mode_set, csm_path_set;         /* which keys the file provided */
} bootini_policy_t;

/* Built-in policy used when BOOT.INI does not exist: mode=auto, default csm_path. */
void bootini_defaults(bootini_policy_t *policy);

/* Parses `len` bytes. Returns 0 and fills `policy` (defaults for absent keys), or
 * returns the 1-based line number of the first error (or 1 for whole-file errors)
 * with a NUL-terminated reason in `err` (at most errlen bytes, errlen >= 1). */
int bootini_parse(const char *text, size_t len, bootini_policy_t *policy, char *err, size_t errlen);

const char *bootini_mode_name(int mode);
#endif
