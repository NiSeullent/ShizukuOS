/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_DOMAIN_H
#define SHZ_WIN98_DOMAIN_H
#include "../src/domain.h"
#define WIN98_PERSISTENCE_HOOKS 1
int win98_domain_create(shz_info_t *,const shz_caps_t *);
int win98_handle_exit(domain_t *,uint32_t);
/* Read bounded diagnostics only while this domain's VMCS is current and paused. */
void win98_observe_exit(domain_t *,uint32_t);
int win98_ready(domain_t *,uint64_t);
void win98_housekeeping(void);
/* Scheduler-only: after checked VMCS load, immediately around vmx_enter.
 * Immutable VMCS/CPU binding stays retained; this releases execution only. */
int win98_execution_begin(domain_t *);
int win98_execution_end(domain_t *);
/* Readonly, called with the current paused Win98 VMCS after execution_end. */
int win98_native_gop_epoch_word(domain_t *,uint64_t,uint64_t,uint32_t *);
#endif
