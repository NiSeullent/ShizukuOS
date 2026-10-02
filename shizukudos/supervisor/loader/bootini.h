/* SPDX-License-Identifier: GPL-2.0-only
 * Boot-manager policy file \EFI\SHIZUKU\BOOT.INI and \SHZDOS\KERNEL64.INI: strict parsers.
 *
 * Freestanding (no libc, no UEFI types) so the same file is linked into the UEFI
 * loader and exercised by the host test (shizukudos/supervisor/test_bootmgr.py).
 *
 * Common grammar (ASCII, one entry per line, LF or CRLF line ends, at most 4096 bytes):
 *     ; comment            # comment             (blank lines are ignored)
 *     key = value                                (keys and keyword values: any case)
 * Anything else -- unknown or repeated keys, sections, a missing '=', inline
 * comments, control or non-ASCII bytes, bad values -- rejects the whole file.
 *
 * BOOT.INI keys:
 *     mode = auto | supervisor | csm | kernel64 | install
 *     csm_path = \EFI\SHIZUKU\CSMWRAP.EFI             absolute path on the boot volume
 *     auto_kernel64 = yes | no                        mode=auto without VMX may boot Kernel64
 *                                                     directly before trying CSM (default no)
 *     menu_timeout = 0 .. 30                          seconds the boot manager menu waits for a key
 *                                                     (A/Enter = the policy above, K = Kernel64 direct,
 *                                                     I = interactive installer, C = CSM, S = Supervisor) before it follows the
 *                                                     policy; 0 = no menu (default)
 * KERNEL64.INI keys:
 *     cmdline = <printable ASCII, may be empty>       copied into shz_bootinfo_t.cmdline
 */
#ifndef SHZ_BOOTINI_H
#define SHZ_BOOTINI_H
#include <stddef.h>

#define BOOTINI_MAX_BYTES 4096
#define BOOTINI_PATH_MAX 128            /* including the terminating NUL */
#define BOOTINI_DEFAULT_CSM_PATH "\\EFI\\SHIZUKU\\CSMWRAP.EFI"
#define BOOTINI_MENU_TIMEOUT_MAX 30
#define BOOTINI_WIN98_VGA 1

enum bootini_mode { BOOT_MODE_AUTO = 0, BOOT_MODE_SUPERVISOR = 1, BOOT_MODE_CSM = 2, BOOT_MODE_KERNEL64 = 3,
                    BOOT_MODE_INSTALL = 4 };

typedef struct {
    int mode;                           /* enum bootini_mode */
    char csm_path[BOOTINI_PATH_MAX];    /* ASCII, starts with '\' */
    int auto_kernel64;                  /* mode=auto without VMX: try Kernel64 direct boot before CSM */
    int menu_timeout;                   /* seconds; 0 = no boot manager menu */
    int win98_vga;                      /* explicit native VGA pair, default no */
    int mode_set, csm_path_set, auto_kernel64_set, menu_timeout_set;  /* which keys the file provided */
    int win98_vga_set;
} bootini_policy_t;

/* Built-in policy used when BOOT.INI does not exist: mode=auto, default csm_path, auto_kernel64=no, no menu. */
void bootini_defaults(bootini_policy_t *policy);

/* Parses `len` bytes. Returns 0 and fills `policy` (defaults for absent keys), or
 * returns the 1-based line number of the first error (or 1 for whole-file errors)
 * with a NUL-terminated reason in `err` (at most errlen bytes, errlen >= 1). */
int bootini_parse(const char *text, size_t len, bootini_policy_t *policy, char *err, size_t errlen);

/* KERNEL64.INI: same return convention; `cmdline` receives the value (cap >= 2 bytes,
 * NUL-terminated, empty when the key is absent; a longer value is an error, never truncated). */
int k64ini_parse(const char *text, size_t len, char *cmdline, size_t cap, char *err, size_t errlen);

const char *bootini_mode_name(int mode);
#endif
