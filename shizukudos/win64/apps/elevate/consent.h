/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_ELEVATE_CONSENT_H
#define SHZ_ELEVATE_CONSENT_H
#include "../../../abi/shz_auth.h"
#define SHZ_ELEVATE_CONSENT_BYTES 1024u
/* The selected executable and its separate argument string are both literal.
 * Never use argv[0] from the command string as the executable's identity. */
int shz_elevate_consent(uint32_t, const shz_auth_request *, char *, size_t);
#endif
