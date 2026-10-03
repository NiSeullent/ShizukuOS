/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_ELEVATE_PROMPT_H
#define SHZ_ELEVATE_PROMPT_H
#include <windows.h>
int shz_password_prompt(const char *,const char *,unsigned char *,unsigned);
/* Returns accepted UTF-8 byte count (>=8) or 0. *outcome receives one of
 * SHZ_PROMPT_* (flow.h): accepted, canceled, expired after timeout_ms, or
 * unavailable. Every non-accepted outcome leaves the output buffer zeroed. */
int shz_password_prompt_ex(const char *,const char *,unsigned char *,unsigned,unsigned,int *);
#endif
