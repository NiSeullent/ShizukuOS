/* SPDX-License-Identifier: GPL-2.0-only
 * NTW64 authenticated-broker client (see ntw64_auth.h). Stock Win98 imports only (SetLastError/GetLastError). */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include "ntw64.h"

static void ntw_copy(void *d, const void *s, size_t n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; }
static void ntw_zero(void *d, int c, size_t n) { uint8_t *a = d; while (n--) *a++ = (uint8_t)c; }
#define SHZ_IPC_MEMCPY(d, s, n) ntw_copy((d), (s), (n))
#define SHZ_IPC_MEMSET(d, c, n) ntw_zero((d), (c), (n))
#include "../../shizukudos/abi/shz_ipc.h"
#include "../../shizukudos/abi/shz_w64_owner.h"
#define NTW64_AUTH_INTERNAL
#include "ntw64_auth.h"

static void finish(ntw64_auth_result_t *out, const ntw64_auth_result_t *r)
{
    if (out) *out = *r;
}

static NTW64_AUTH_STATUS done(ntw64_auth_result_t *out, ntw64_auth_result_t *r, NTW64_AUTH_STATUS st, DWORD error)
{
    r->size = NTW64_AUTH_RESULT_SIZE;
    r->status = (uint32_t)st;
    if (st != NTW64_AUTH_OK) {
        r->subject_flags = 0;
        r->auth_epoch = 0;
        r->storage_state = NTW64_AUTH_STORAGE_UNKNOWN;
    }
    finish(out, r);
    SetLastError(error);
    return st;
}

static DWORD error_of(uint32_t opcode, int32_t st)
{
    switch (st) {
    case SHZ_E_DENIED: return opcode == SHZ_OP_W64_AUTH_LOGIN ? ERROR_LOGON_FAILURE : ERROR_ACCESS_DENIED;
    case SHZ_E_INVALID: case SHZ_E_RANGE: case SHZ_E_PROTO: return ERROR_INVALID_PARAMETER;
    case SHZ_E_BUSY: case SHZ_E_QUEUE_FULL: return ERROR_BUSY;
    case SHZ_E_UNSUPPORTED: return ERROR_NOT_SUPPORTED;
    case SHZ_E_NOENT: return ERROR_FILE_NOT_FOUND;
    case SHZ_E_STALE: return ERROR_REVISION_MISMATCH;
    default: return ERROR_GEN_FAILURE;
    }
}

/* Strict reply check; 1 when it is a well-formed answer to `opcode`. Fills *rep (zeroed unless status OK). */
static int reply_ok(uint32_t opcode, const shz_msg_hdr_t *h, const uint8_t *payload, shz_w64_auth_reply_t *rep)
{
    ntw_zero(rep, 0, sizeof *rep);
    if (h->magic != SHZ_MSG_MAGIC || h->abi_major != SHZ_ABI_MAJOR || h->header_size != sizeof *h ||
        h->message_size != (uint32_t)h->header_size + h->payload_length || h->payload_length > SHZ_MSG_MAX_INLINE ||
        (h->payload_length && h->payload_offset != h->header_size) || h->flags != SHZ_MSGF_REPLY ||
        h->opcode != opcode || h->buffer_length || h->buffer_offset || !shz_w64_owner_id_valid(h->capability_id))
        return 0;
    {
        const uint32_t owner = ntw64_priv_owner();
        if (owner && h->capability_id != owner)
            return 0;                               /* owner echo must match the VxD-stamped owner */
    }
    if (h->status > 0 || h->status < SHZ_E_DENIED)
        return 0;
    if (h->payload_length == 0)
        return h->status != SHZ_OK;                 /* success must carry the reply struct */
    if (h->payload_length != sizeof *rep)
        return 0;
    ntw_copy(rep, payload, sizeof *rep);
    if (rep->size != sizeof *rep || rep->status != h->status || rep->reserved)
        return 0;
    if (h->status != SHZ_OK)
        return rep->auth_epoch == 0 && rep->subject_flags == 0;
    return opcode == SHZ_OP_W64_AUTH_REGISTER || rep->auth_epoch != 0;
}

static NTW64_AUTH_STATUS transact(uint32_t opcode, const char *user, const void *secret, DWORD secret_len,
                                  DWORD roles, ntw64_auth_result_t *out)
{
    shz_w64_auth_req_t req;                         /* owned local frame: the only copy of the credentials */
    shz_msg_hdr_t h;
    uint8_t payload[SHZ_MSG_MAX_INLINE];
    shz_w64_auth_reply_t rep;
    ntw64_auth_result_t r;
    uint32_t i, ulen = 0;
    int sent = 0, got;
    NTW64_AUTH_STATUS st;
    DWORD err;

    ntw_zero(&r, 0, sizeof r);
    ntw_zero(&req, 0, sizeof req);
    ntw_zero(&rep, 0, sizeof rep);
    if (!user || !secret || !secret_len || secret_len > NTW64_AUTH_SECRET_MAX || (opcode != SHZ_OP_W64_AUTH_REGISTER && roles))
        return done(out, &r, NTW64_AUTH_INVALID_PARAMETER, ERROR_INVALID_PARAMETER);
    while (user[ulen] && ulen <= NTW64_AUTH_USER_MAX) ++ulen;
    if (!ulen || ulen > NTW64_AUTH_USER_MAX)
        return done(out, &r, NTW64_AUTH_INVALID_PARAMETER, ERROR_INVALID_PARAMETER);

    req.size = sizeof req;
    req.version = SHZ_W64_AUTH_VERSION;
    req.user_len = ulen;
    req.secret_len = secret_len;
    req.roles = roles;
    for (i = 0; i < ulen; ++i) req.user[i] = user[i];
    ntw_copy(req.secret, secret, secret_len);
    /* Same checker Core runs (owner is checked there; use a structurally valid placeholder only for this local
     * pre-flight, it is not sent). */
    {
        shz_msg_hdr_t pre;
        shz_w64_auth_req_t scratch;
        int rc;
        ntw_zero(&pre, 0, sizeof pre);
        pre.opcode = opcode;
        pre.payload_length = sizeof req;
        pre.capability_id = shz_w64_owner_make(0, 1);
        rc = shz_w64_auth_req_check(&pre, &req, &scratch);
        ntw64_priv_wipe(&scratch, sizeof scratch);
        if (rc != SHZ_OK) {
            ntw64_priv_wipe(&req, sizeof req);
            return done(out, &r, NTW64_AUTH_INVALID_PARAMETER, ERROR_INVALID_PARAMETER);
        }
    }

    ntw_zero(&h, 0, sizeof h);
    got = ntw64_priv_call(opcode, &req, (uint16_t)sizeof req, &h, payload, &sent);
    err = GetLastError();
    ntw64_priv_wipe(&req, sizeof req);              /* credentials are gone on every path from here on */

    if (!got) {
        if (sent) {
            st = NTW64_AUTH_UNCERTAIN;
            err = NTW64_ERROR_TIMEOUT;
        } else if (err == ERROR_BUSY) {
            st = NTW64_AUTH_BUSY;
        } else {
            st = NTW64_AUTH_UNAVAILABLE;
        }
        ntw64_priv_wipe(payload, sizeof payload);
        return done(out, &r, st, err);
    }
    if (!reply_ok(opcode, &h, payload, &rep) || !ntw64_priv_bind_owner(h.capability_id)) {
        ntw64_priv_wipe(payload, sizeof payload);
        return done(out, &r, NTW64_AUTH_PROTOCOL, ERROR_GEN_FAILURE);
    }
    r.shz_status = h.status;
    ntw64_priv_wipe(payload, sizeof payload);
    if (h.status != SHZ_OK)
        return done(out, &r, h.status == SHZ_E_DENIED ? NTW64_AUTH_DENIED : NTW64_AUTH_REFUSED, error_of(opcode, h.status));
    r.subject_flags = rep.subject_flags;
    r.auth_epoch = rep.auth_epoch;
    /* Durability comes from the reply, never assumed: only an explicit absence of the volatile flag is durable. */
    /* Subject bit 0 means SANDBOX, not SHZ_AUTH_VOLATILE. The current wire reply
     * carries no storage flag, so neither ordinary nor sandbox subjects prove durability. */
    r.storage_state = NTW64_AUTH_STORAGE_UNKNOWN;
    return done(out, &r, NTW64_AUTH_OK, 0);
}

BOOL WINAPI Ntw64AuthLogin(const char *user, const void *secret, DWORD secret_len, ntw64_auth_result_t *result)
{
    return transact(SHZ_OP_W64_AUTH_LOGIN, user, secret, secret_len, 0, result) == NTW64_AUTH_OK;
}

BOOL WINAPI Ntw64AuthRegister(const char *user, const void *secret, DWORD secret_len, DWORD roles,
                              ntw64_auth_result_t *result)
{
    return transact(SHZ_OP_W64_AUTH_REGISTER, user, secret, secret_len, roles, result) == NTW64_AUTH_OK;
}

BOOL WINAPI Ntw64AuthElevateConfirm(const char *user, const void *secret, DWORD secret_len, ntw64_auth_result_t *result)
{
    return transact(SHZ_OP_W64_AUTH_CONFIRM_ELEVATION, user, secret, secret_len, 0, result) == NTW64_AUTH_OK;
}
