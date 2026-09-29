/* SPDX-License-Identifier: GPL-2.0-only
 * USER32 delay-load subset Chromium calls. Missing classes and windows fail.
 * This is not a desktop compositor.
 */
#ifndef NTW_USER32_H
#define NTW_USER32_H
#include <stdint.h>
void ntw_user_bind(uint32_t *last_error);
void ntw_user_set_log(void (*fn)(const char *text));
uint32_t ntw_user_export(const char *name);
int ntw_user_owns(uint32_t handle);
#endif
