/* SPDX-License-Identifier: GPL-2.0-only
 * Synchronous console ReadFile/WriteFile for the loader's three standard handles.
 * Compared with Microsoft WriteFile and Wine kernel32 file I/O at
 * df15af3652511150490934682202d45af892f887. NULL byte-count without OVERLAPPED
 * fails. No Wine body is copied. Overlapped I/O is rejected.
 */
#ifndef NTW_FILEIO_H
#define NTW_FILEIO_H
#include <stdint.h>
#define NTW_STD_INPUT 0xfffffff6u
#define NTW_STD_OUTPUT 0xfffffff5u
#define NTW_STD_ERROR 0xfffffff4u
#define NTW_FILE_TYPE_UNKNOWN 0u
#define NTW_FILE_TYPE_CHAR 2u
typedef int (*ntw_file_transfer)(void *user, int fd, void *buffer, uint32_t bytes, int writing);
void ntw_file_set_transfer(ntw_file_transfer transfer, void *user);
uint32_t ntw_file_get_std(uint32_t kind);
int ntw_file_set_std(uint32_t kind, uint32_t handle);
int ntw_file_write(uint32_t handle, const void *buffer, uint32_t bytes, uint32_t *written, const void *overlapped, uint32_t *error);
int ntw_file_read(uint32_t handle, void *buffer, uint32_t bytes, uint32_t *read_count, const void *overlapped, uint32_t *error);
uint32_t ntw_file_type(uint32_t handle, uint32_t *error);
#endif
