/* SPDX-License-Identifier: GPL-2.0-only
 * I/O completion ports. A posted packet returns with the same byte count,
 * completion key, and overlapped pointer. An empty wait times out.
 * Wine completion.c was not copied.
 */
#ifndef NTW_IOCP_H
#define NTW_IOCP_H
#include <stdint.h>
typedef void (*ntw_iocp_pause)(void);
void ntw_iocp_set_pause(ntw_iocp_pause pause);
int ntw_iocp_create(uint32_t file, uint32_t existing, uint32_t key, uint32_t threads,
                    int (*valid_file)(uint32_t file), uint32_t *handle, uint32_t *error);
int ntw_iocp_post(uint32_t port, uint32_t bytes, uint32_t key, uint32_t overlapped, uint32_t *error);
int ntw_iocp_get(uint32_t port, uint32_t *bytes, uint32_t *key, uint32_t *overlapped, uint32_t timeout,
                 uint32_t *error);
int ntw_iocp_owns(uint32_t handle);
int ntw_iocp_close(uint32_t handle, uint32_t *error);
#endif
