/* SPDX-License-Identifier: GPL-2.0-only -- original implementation.
 * NTWRAP9X.VXD native endpoint owner: raw SEND allowlist extension for the C6 typed broker requests
 * (SHZ_OP_W64_AUTH_LOGIN/REGISTER/CONFIRM_ELEVATION, shizukudos/abi/shz_w64_owner.h) and credential hygiene.
 *
 * Header-only (static inline): included by bridge.c after shz_ipc.h/shz_w64_owner.h, so the existing VxD object list
 * (build.py, tests/test_vxd.py) is unchanged. The frozen contract header is consumed unchanged; it deliberately keeps
 * the auth opcodes out of shz_w64_endpoint_op_allowed, and this VxD-local predicate is that separate change.
 *
 * Contract for a native endpoint (NTW32) auth SEND (NTWV_IOCTL_W64_SEND, no new IOCTL):
 *   input_bytes == 64 + sizeof(shz_w64_auth_req_t) == 248 exactly (no pool data, nothing trailing);
 *   header: opcode 0x20A..0x20C, flags 0, status 0, buffer_offset/length 0, payload_length 184,
 *           capability_id 0 or the caller's own OPEN owner_id (anything else is ACCESS_DENIED); the VxD stamps
 *           capability_id/src/dst/generation itself;
 *   payload: shz_w64_auth_req_check() must accept it with the stamped owner (else INVALID_PARAMETER);
 *   at most one auth request outstanding per owner (second one BUSY until its reply is RECVed or the owner departs).
 * The reply arrives on the caller's own mailbox only (capability_id echo): flags REPLY, same opcode/request_id,
 * payload either a valid 24-byte shz_w64_auth_reply_t or empty with a non-OK status. A malformed Core reply to an
 * accepted request is delivered sanitized (status SHZ_E_PROTO, no payload), never dropped and never forwarded raw.
 */
#ifndef NTWV_W64_OWNER_H
#define NTWV_W64_OWNER_H
#ifndef SHZ_W64_OWNER_H
#error "include shizukudos/abi/shz_w64_owner.h (with the VxD SHZ_IPC_MEMCPY/MEMSET) before w64_owner.h"
#endif
#include "bridge.h"

#define NTWV_W64_AUTH_FRAME_BYTES ((uint32_t)(sizeof(shz_msg_hdr_t) + sizeof(shz_w64_auth_req_t)))
_Static_assert(sizeof(shz_msg_hdr_t) + sizeof(shz_w64_auth_req_t) == 248u, "auth SEND frame size");
_Static_assert(sizeof(shz_msg_hdr_t) + sizeof(shz_w64_auth_req_t) <= NTWV_W64_SEND_MAX, "auth frame fits one SEND");

/* Non-elidable scrub for buffers that held credentials (or may have). */
SHZ_IPC_INLINE void ntwv_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

/* The agreed raw SEND allowlist for a native endpoint owner: the frozen endpoint list (GUI disabled) plus the three
 * typed broker requests with flags exactly 0. SHUTDOWN, OWNER_CONTROL, events, PMA 0x300..0x3ff stay refused. */
SHZ_IPC_INLINE int ntwv_w64_owner_op_allowed(uint32_t opcode, uint16_t flags)
{
    if (shz_w64_auth_op(opcode))
        return flags == 0;
    return shz_w64_endpoint_op_allowed(opcode, flags, 0);
}

/* Strict inline admission of an auth SEND before anything is forwarded. `h` is the application header copy,
 * `payload` the copied inline bytes, `in_bytes` the DIOC input length, `owner` the VxD-derived owner id and
 * `scratch` a VxD-owned bounded copy that is wiped here on every path. Returns 0 or an NTWV_ERROR_*. */
SHZ_IPC_INLINE uint32_t ntwv_w64_auth_admit(const shz_msg_hdr_t *h, const uint8_t *payload, uint32_t in_bytes,
                                           uint32_t owner, shz_w64_auth_req_t *scratch)
{
    shz_msg_hdr_t stamped;
    int rc;
    if (!shz_w64_auth_op(h->opcode) || h->flags != 0)
        return NTWV_ERROR_ACCESS_DENIED;
    /* The application may not name another owner or the privileged authority. 0 or its own id only. */
    if (!shz_w64_owner_id_valid(owner) || (h->capability_id != SHZ_W64_OWNER_NONE && h->capability_id != owner))
        return NTWV_ERROR_ACCESS_DENIED;
    if (in_bytes != NTWV_W64_AUTH_FRAME_BYTES || h->payload_length != sizeof *scratch || h->status != 0 ||
        h->buffer_offset || h->buffer_length)
        return NTWV_ERROR_INVALID_PARAMETER;
    ntwv_copy(&stamped, h, sizeof stamped);
    stamped.capability_id = owner;
    rc = shz_w64_auth_req_check(&stamped, payload, scratch);
    ntwv_wipe(scratch, sizeof *scratch);
    if (rc == SHZ_E_DENIED)
        return NTWV_ERROR_ACCESS_DENIED;
    return rc == SHZ_OK ? 0u : NTWV_ERROR_INVALID_PARAMETER;
}

/* Strict check of a Core auth reply (header already validated for domain/generation/flags by the pump). */
SHZ_IPC_INLINE int ntwv_w64_auth_reply_ok(const shz_msg_hdr_t *h, const uint8_t *payload)
{
    shz_w64_auth_reply_t r;
    if (h->flags != SHZ_MSGF_REPLY || !shz_w64_auth_op(h->opcode))
        return 0;
    if (h->payload_length == 0)
        return h->status != SHZ_OK;           /* generic refusal (e.g. owner not admitted) */
    if (h->payload_length != sizeof r)
        return 0;
    ntwv_copy(&r, payload, sizeof r);
    if (r.size != sizeof r || r.status != h->status || r.reserved)
        return 0;
    return h->status == SHZ_OK || (!r.auth_epoch && !r.subject_flags);
}

/* Replace a malformed auth reply frame in place by a terminal SHZ_E_PROTO reply without payload. */
SHZ_IPC_INLINE void ntwv_w64_auth_reply_sanitize(uint8_t *frame)
{
    shz_msg_hdr_t h;
    ntwv_copy(&h, frame, sizeof h);
    ntwv_wipe(frame + sizeof h, SHZ_MSG_SLOT_SIZE - sizeof h);
    h.status = SHZ_E_PROTO;
    h.payload_length = 0;
    h.payload_offset = 0;
    h.message_size = (uint32_t)sizeof h;
    h.checksum = 0;
    ntwv_copy(frame, &h, sizeof h);
    h.checksum = shz_msg_checksum((const shz_msg_hdr_t *)frame);
    ntwv_copy(frame, &h, sizeof h);
}
#endif
