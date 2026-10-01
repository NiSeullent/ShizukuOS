/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_DOMAIN_H
#define SHZ_WIN98_DOMAIN_H
#include "../src/domain.h"
int win98_domain_create(shz_info_t *,const shz_caps_t *);
int win98_handle_exit(domain_t *,uint32_t);
/* Read bounded diagnostics only while this domain's VMCS is current and paused. */
void win98_observe_exit(domain_t *,uint32_t);
int win98_ready(domain_t *,uint64_t);
void win98_housekeeping(void);
#endif
