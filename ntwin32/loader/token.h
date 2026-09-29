/* SPDX-License-Identifier: GPL-2.0-only
 * OpenProcessToken and GetTokenInformation. Missing and short buffers fail.
 * This is not a security authority and does not grant privileges.
 */
#ifndef NTW_TOKEN_H
#define NTW_TOKEN_H
#include <stdint.h>
int ntw_token_owns(uint32_t handle);
int ntw_token_open(uint32_t access, uint32_t *handle, uint32_t *error);
int ntw_token_info(uint32_t handle, uint32_t klass, void *buffer, uint32_t bytes, uint32_t *needed, uint32_t *error);
int ntw_token_close(uint32_t handle, uint32_t *error);
#endif
