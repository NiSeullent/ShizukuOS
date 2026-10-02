/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PZ98_STORE_H
#define PZ98_STORE_H
#include <stdint.h>
#include "core.h"
/* Verified write with a same-directory backup and rollback, not a filesystem
 * transaction. Interrupted publication recovers under an exclusive file lock.
 * Error is the actual Win32 failure; a failed rollback retains the .bak file. */
int pz98_store_write(const char *,const void *,uint32_t,const void *,uint32_t);
int pz98_store_preferences(const char *,pz98_preferences *);
#endif
