/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_TLS_REMOTE_H
#define NTW_TLS_REMOTE_H
#include "tls_runtime.h"

/* Caller holds the logical loader lock. The target is an admitted, live
 * loader-owned thread whose exit trampoline retires its TDB under that lock.
 * New module code/exports are unpublished until every slot is initialized.
 * replace is atomic: a failed call must leave the expected value unchanged.
 */
typedef struct ntw_tls_remote_io {
    void *context;
    uint32_t owner;
    int (*read)(void *,uint32_t,void **);
    int (*replace)(void *,uint32_t,void *,void *);
} ntw_tls_remote_io;

/* Uses a separately prepared extension plan; never rebuild an existing plan.
 * Published thread state can later detach normally on the actual target via
 * ntw_tls_detach. Failed remote clear retains ownership/storage for retry.
 */
int ntw_tls_remote_attach(ntw_tls_plan *,ntw_tls_thread *,const ntw_tls_remote_io *,const char **);
int ntw_tls_remote_detach(ntw_tls_thread *,const ntw_tls_remote_io *,const char **);

#ifdef _WIN32
typedef struct ntw_tls_native_target {
    uint32_t owner,tib,vector;
    int admitted;
} ntw_tls_native_target;
/* Capture on the actual target before entering application code; no arbitrary
 * target/TDB discovery. Registry admission/retirement and all uses are locked.
 * The loader must block unregistered ingress, abrupt thread termination and
 * fiber/vector replacement until it implements their lifetime contracts.
 */
int ntw_tls_capture_current_target(ntw_tls_native_target *,const char **);
int ntw_tls_native_remote_io(ntw_tls_native_target *,ntw_tls_remote_io *,const char **);
void ntw_tls_retire_target(ntw_tls_native_target *);
#endif
#endif
