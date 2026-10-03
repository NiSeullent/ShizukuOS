/* SPDX-License-Identifier: GPL-2.0-only
 * NTWRAP9X W64 derived owner identity (native-window lane, clone prototype behind NTWV_W64_DERIVED_OWNER).
 *
 * The caller of a W64 SEND is identified by the VWIN32-filled DIOCParams (VMHandle, tagProcess), never by the
 * application's message: VWIN32 writes those fields before the VxD's W32_DEVICEIOCONTROL handler runs. The VxD
 * issues a nonzero 31-bit token per (system VM, tagProcess, channel generation) and overwrites capability_id of
 * every outgoing W64 request with SHZ_W64_OWNER_CAP_DERIVED|token. Tokens come from a monotonic counter and are
 * never reissued (exhaustion fails closed); DIOC_CLOSEHANDLE of the owner, a channel generation change and a
 * channel reset retire them, so a recycled tagProcess gets a fresh identity. K64 binds the creating request's
 * capability into the slot (subsys64 owner_cap), so a different Win98 process presenting a spoofed pid or
 * capability_id is refused by shz_w64_gui_subject_authorized().
 *
 * Handle lifetime (batch 5): VWIN32 sends DIOC_OPEN (code 0) per CreateFile and DIOC_CLOSEHANDLE (code -1) per
 * CloseHandle, both with the caller's tagProcess. The VxD keeps a per-process count of live NTWRAP9X handles; an
 * identity is derivable only while that count is nonzero, and only the LAST close retires it (a second handle, e.g. a
 * PMA client, closing no longer drops the W64 identity). A close with no recorded open retires the process
 * (fail closed); an open the table cannot record leaves the process without a derivable identity (W64 denied,
 * the handle itself still opens so PMA/account semantics are unchanged). The count table is guarded by the bound
 * interrupt-disable lock (uniprocessor VMM), never by the W64 admission token, because opens/closes are not admitted.
 *
 * Locking: derive/stamp/reset run under bridge.c's W64 admission token. Departure may arrive while that token is
 * held elsewhere; it is then queued in a bounded lock-free list and applied before the next derive. If that list
 * overflows, every identity is retired (fail closed: existing views become DENIED, nothing is granted). */
#ifndef NTWV_W64_OWNER_H
#define NTWV_W64_OWNER_H
#include <stdint.h>
#include "../../shizukudos/abi/shz_abi.h"
#include "../../shizukudos/abi/shz_w64_gui.h"

#ifndef NTWV_ERROR_ACCESS_DENIED
#define NTWV_ERROR_ACCESS_DENIED 5u
#endif
#define NTWV_W64_OWNER_SLOTS 16u
#define NTWV_W64_OWNER_DEFERRED 8u
#define NTWV_W64_OWNER_HANDLE_PROCS 32u

/* Installed by native.c at init from Get_Sys_VM_Handle; host tests set a model value. 0 = unbound => deny all. */
void ntwv_w64_owner_bind_system_vm(uint32_t system_vm);
/* Installed by native.c at init (ntwv_irq_enter/leave); host tests supply a model. Unbound => opens are not recorded. */
void ntwv_w64_owner_bind_lock(uintptr_t (*enter)(void *opaque), void (*leave)(void *opaque, uintptr_t saved));
/* Any context, after a successful DIOC_OPEN: count one live handle of (system VM, tagProcess). 0 when recorded;
 * NTWV_ERROR_ACCESS_DENIED (not the bound system VM / tag 0 / no lock) or NTWV_ERROR_BUSY (table full) otherwise. */
uint32_t ntwv_w64_owner_handle_open(uint32_t vm, uint32_t process);
/* Any context, on DIOC_CLOSEHANDLE: drop one handle; the last one (or an unrecorded close) retires the identity. */
void ntwv_w64_owner_handle_close(uint32_t process);
/* Live recorded handles of process (diagnostics / derive precondition). */
uint32_t ntwv_w64_owner_handles(uint32_t process);
/* Locked (W64 admission held). 0 and *capability on success; else an NTWV_ERROR_* code and no capability. */
uint32_t ntwv_w64_owner_derive(uint32_t vm, uint32_t process, uint32_t channel_generation, uint32_t *capability);
/* Locked. Overwrite the app-supplied identity: stamp=1 -> derived capability, stamp=0 (trusted in-VxD endpoint
 * send) -> clear the DERIVED bit so only a stamped request can ever carry it. */
void ntwv_w64_owner_stamp(shz_msg_hdr_t *header, int stamp, uint32_t capability);
/* Locked. Channel teardown: retire every identity (the counter is preserved, so no token is reissued). */
void ntwv_w64_owner_reset_locked(void);
/* Any context: queue retirement of tagProcess (last DIOC_CLOSEHANDLE / process departure). */
void ntwv_w64_owner_departed(uint32_t process);
/* Locked. 1 while cap is the derived identity of a live (not retired) owner. */
int ntwv_w64_owner_cap_live(uint32_t capability);
/* Diagnostics (host tests): live identities, tokens issued. */
uint32_t ntwv_w64_owner_live(void);
uint32_t ntwv_w64_owner_issued(void);
#endif
