/* SPDX-License-Identifier: GPL-2.0-only
 * Pagefile-backed CreateFileMapping / MapViewOfFile / UnmapViewOfFile.
 * Compared with Microsoft CreateFileMappingW. A bad handle, size, alignment,
 * or protection fails. Named duplicates return the existing mapping and
 * last-error 183. A live file handle maps that file; a zero size uses its
 * length. No Wine body is copied.
 */
#ifndef NTW_FILEMAP_H
#define NTW_FILEMAP_H
#include <stdint.h>
#define NTW_MAP_INVALID_FILE 0xffffffffu
#define NTW_MAP_PAGE_READONLY 0x02u
#define NTW_MAP_PAGE_READWRITE 0x04u
#define NTW_MAP_PAGE_WRITECOPY 0x08u
#define NTW_MAP_PAGE_EXECUTE_READ 0x20u
#define NTW_MAP_PAGE_EXECUTE_READWRITE 0x40u
#define NTW_MAP_PAGE_EXECUTE_WRITECOPY 0x80u
#define NTW_MAP_SEC_COMMIT 0x8000000u
#define NTW_MAP_SEC_RESERVE 0x4000000u
#define NTW_MAP_SEC_NOCACHE 0x10000000u
#define NTW_MAP_READ 0x4u
#define NTW_MAP_WRITE 0x2u
#define NTW_MAP_COPY 0x1u
#define NTW_MAP_EXECUTE 0x20u
#define NTW_ERR_INVALID 87u
#define NTW_ERR_HANDLE 6u
#define NTW_ERR_ACCESS 5u
#define NTW_ERR_EXISTS 183u
#define NTW_ERR_NOMEM 8u
#define NTW_ERR_ADDRESS 487u
typedef void *(*ntw_map_place)(void *user, void *addr, uint32_t length, int prot, int flags);
typedef int (*ntw_map_remove)(void *user, void *addr, uint32_t length);
typedef int (*ntw_map_protect)(void *user, void *addr, uint32_t length, int prot);
void ntw_filemap_set_ops(ntw_map_place place, ntw_map_remove remove, ntw_map_protect protect, void *user);
void ntw_filemap_reset(void);
uint32_t ntw_filemap_create(uint32_t file, uint32_t protect, uint32_t size_high, uint32_t size_low,
                            const uint16_t *name, uint32_t *error);
uintptr_t ntw_filemap_view(uint32_t mapping, uint32_t access, uint32_t offset_high, uint32_t offset_low,
                          uint32_t bytes, uint32_t *error);
int ntw_filemap_unmap(uintptr_t address, uint32_t *error);
int ntw_filemap_close(uint32_t handle, uint32_t *error);
int ntw_filemap_duplicate(uint32_t source, int close_source, uint32_t *out, uint32_t *error);
int ntw_filemap_query(uintptr_t address, uint32_t *base, uint32_t *allocation, uint32_t *allocation_protect,
                      uint32_t *region, uint32_t *state, uint32_t *protect);
#endif
