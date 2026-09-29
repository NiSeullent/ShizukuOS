/* SPDX-License-Identifier: GPL-2.0-only
 * Stored process shutdown priority. The OS shutdown order is not changed.
 */
#ifndef NTW_SHUTDOWN_H
#define NTW_SHUTDOWN_H
#include <stdint.h>
int ntw_shutdown_set(uint32_t level, uint32_t flags, uint32_t *error);
int ntw_shutdown_get(uint32_t *level, uint32_t *flags, uint32_t *error);
#endif
