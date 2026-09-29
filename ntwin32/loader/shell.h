/* SPDX-License-Identifier: GPL-2.0-only
 * Shell contracts used by Chromium's delay load.
 * Command lines and known folders follow the public Win32 shapes.
 * m98shell.c and Wine shell32 were not copied.
 */
#ifndef NTW_SHELL_H
#define NTW_SHELL_H
#include <stdint.h>
#define NTW_SHELL_OK 0u
#define NTW_SHELL_INVALID 0x80070057u
#define NTW_SHELL_MISSING 0x80070002u
typedef int (*ntw_shell_exists)(void *user, const char *path);
typedef int (*ntw_shell_mkdir)(void *user, const char *path);
int ntw_shell_argv(const uint16_t *cmd, uint16_t *words, uint32_t word_cap, uint32_t *offsets,
                   int max_args, int *argc, uint32_t *error);
int ntw_shell_folder(uint32_t csidl, const char *root, ntw_shell_exists exists, ntw_shell_mkdir mkdir,
                     void *user, uint16_t *out, uint32_t chars, uint32_t *hr);
int ntw_shell_known(const uint8_t guid[16], uint32_t flags, const char *root, ntw_shell_exists exists,
                    ntw_shell_mkdir mkdir, void *user, uint16_t *out, uint32_t chars, uint32_t *hr);
#endif
