/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 WIN64 native GUI frame-pull service (abi/shz_w64_gui.h, draft v1). Called only from the subsys64
 * service thread. The subject is resolved by subsys64 from its OWN slot table (kernel-created process, slot
 * generation, creator capability id, live channel generation); the request pid only selects that slot. */
#ifndef K64_W64_GUI_SERVICE_H
#define K64_W64_GUI_SERVICE_H
#include "proc_internal.h"
#include "gfx.h"
#include "../abi/shz_w64_gui.h"

typedef struct {
    uint32_t pid;                   /* slot pid (kernel-assigned) */
    uint32_t slot_gen;              /* subsys64 slot generation: the wire process_generation */
    process_t *proc;                /* live process, NULL once reaped */
    uint32_t channel_gen;           /* current channel generation */
    uint32_t owner_cap;             /* capability_id of the CREATE_PROCESS request that made the slot */
    uint32_t request_cap;           /* capability_id of this request */
    int channel_attested;           /* Supervisor SHZ_HC_CHANNEL_ATTESTED W64_DERIVED_OWNER for channel_gen */
} w64_gui_subject_t;

/* 1 when GUI opcodes are served and SHZ_W64_CAP_GUI is advertised. Supervisor profile: only while the Supervisor
 * attests (SHZ_HC_CHANNEL_ATTESTED) that the Win98 VxD stamps a derived owner on every user send for the current
 * channel generation (.codex/handoff/w98w64-wire-b5.md); never anonymously. */
int w64_gui_enabled(void);
/* subsys64.c: Supervisor attestation of SHZ_CHAN_ATTEST_W64_DERIVED_OWNER for the live channel generation
 * re-queried at every call (no positive cache; revoked after a positive answer never reverts to legacy).
 * Always 0 in the standalone loopback profile. */
int subsys64_channel_attested(void);
/* Handles one GUI opcode. `subject` is NULL when no slot matches the selector. Returns an SHZ status; on SHZ_OK
 * *reply_len bytes of `reply` (capacity SHZ_MSG_MAX_INLINE) are the exact reply payload. */
int32_t w64_gui_handle(uint32_t opcode, const uint8_t *payload, uint32_t length, const w64_gui_subject_t *subject,
                       uint8_t *reply, uint16_t *reply_len);
/* Slot release/reap: revoke the view and snapshot bound to that slot generation. */
void w64_gui_revoke(uint32_t pid, uint32_t slot_gen);
/* Channel attestation revoked (attester exited/failed/restarted): revoke every view, held frame and snapshot. */
void w64_gui_revoke_all(void);
/* Software hosted display backend (no scanout): lets the existing WM run when no display device exists so W64
 * windows render into their own client surfaces for frame pull. Registered by gfx_fb.c (core-integration handoff). */
extern const gfx_backend_t gfx_backend_w64_hosted;
#endif
