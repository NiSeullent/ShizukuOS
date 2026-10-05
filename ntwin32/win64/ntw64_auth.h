/* SPDX-License-Identifier: GPL-2.0-only
 * NTW64 authenticated-broker client: serialized login, register and elevation-confirm for a native Win98 caller,
 * carried over the existing NTW64 transport (opcodes 0x20A/0x20B/0x20C of shizukudos/abi/shz_w64_owner.h).
 *
 * The caller never supplies an owner, capability or privilege: the VxD stamps the endpoint owner id and Kernel64
 * decides. Success is reported only after the reply passed strict validation (header magic/ABI/size/flags/opcode/
 * request id/buffer fields, owner echo, payload size/status/reserved). Credentials are copied once into an owned
 * frame; the frame, the shared transport frame and all stack temporaries are wiped on every path. Nothing is
 * logged. Not thread-safe; a concurrent or re-entered call fails with NTW64_AUTH_BUSY.
 *
 * NTW64_AUTH_UNCERTAIN: the request was handed to the VxD but no valid answer arrived (timeout, transport error).
 * The outcome is UNKNOWN: treat the session as NOT logged in / NOT registered / NOT elevated, and do not repeat
 * the request until a later call stops returning NTW64_AUTH_PENDING (a late reply was drained). */
#ifndef NTW64_AUTH_H
#define NTW64_AUTH_H
#include <stdint.h>

typedef enum ntw64_auth_status {
    NTW64_AUTH_OK = 0,
    NTW64_AUTH_INVALID_PARAMETER = 1,   /* rejected locally before anything was sent          -> ERROR_INVALID_PARAMETER (87) */
    NTW64_AUTH_DENIED = 2,              /* Core refused (bad credentials / policy)            -> login: ERROR_LOGON_FAILURE (1326), else ERROR_ACCESS_DENIED (5) */
    NTW64_AUTH_REFUSED = 3,             /* Core: invalid/unsupported/busy/other status        -> mapped from the SHZ status (87/50/170/31) */
    NTW64_AUTH_UNAVAILABLE = 4,         /* VxD or channel unavailable, nothing sent           -> the transport's error (2/50/55/1306) */
    NTW64_AUTH_BUSY = 5,                /* re-entered or ring busy, nothing sent              -> ERROR_BUSY (170) */
    NTW64_AUTH_PENDING = 6,             /* an earlier credential request is unresolved        -> ERROR_BUSY (170) */
    NTW64_AUTH_UNCERTAIN = 7,           /* sent, no valid answer; outcome unknown (see above) -> ERROR_TIMEOUT (1460) */
    NTW64_AUTH_PROTOCOL = 8             /* an answer arrived but failed validation; unknown   -> ERROR_GEN_FAILURE (31) */
} NTW64_AUTH_STATUS;

#define NTW64_AUTH_RESULT_SIZE 32u
#define NTW64_AUTH_STORAGE_UNKNOWN 0u
#define NTW64_AUTH_STORAGE_VOLATILE 1u
#define NTW64_AUTH_STORAGE_DURABLE 2u
#define NTW64_AUTH_USER_MAX 31u         /* characters, no NUL */
#define NTW64_AUTH_SECRET_MAX 128u      /* bytes */

typedef struct ntw64_auth_result {
    uint32_t size;                      /* NTW64_AUTH_RESULT_SIZE; set by the caller or ignored, always written back */
    uint32_t status;                    /* NTW64_AUTH_STATUS */
    int32_t shz_status;                 /* Core's status when an answer was validated, else 0 */
    uint32_t subject_flags;             /* broker subject flags, success only */
    uint64_t auth_epoch;                /* broker login epoch, success only (never zero for login/confirm) */
    uint32_t storage_state;             /* NTW64_AUTH_STORAGE_*; current broker reply does not convey storage state */
    uint32_t reserved;
} ntw64_auth_result_t;

#ifdef _WIN32
#include <windows.h>
/* user: ANSI/OEM text, 1..31 characters, no embedded NUL. secret: 1..128 bytes (not necessarily text). roles for
 * register: forwarded verbatim to the broker, which validates them. All return TRUE only for NTW64_AUTH_OK;
 * otherwise FALSE with SetLastError per the table above. `result` may be NULL; it is always filled when given. */
BOOL WINAPI Ntw64AuthLogin(const char *user, const void *secret, DWORD secret_len, ntw64_auth_result_t *result);
BOOL WINAPI Ntw64AuthRegister(const char *user, const void *secret, DWORD secret_len, DWORD roles,
                              ntw64_auth_result_t *result);
BOOL WINAPI Ntw64AuthElevateConfirm(const char *user, const void *secret, DWORD secret_len, ntw64_auth_result_t *result);
#endif

/* ---- internal, provided by ntw64.c, consumed by ntw64_auth.c only (not exported) ---- */
#ifdef NTW64_AUTH_INTERNAL
#include "../../shizukudos/abi/shz_abi.h"
void ntw64_priv_wipe(void *d, size_t n);
int ntw64_priv_call(uint32_t opcode, const void *payload, uint16_t len, shz_msg_hdr_t *reply, uint8_t *reply_payload,
                    int *sent);
uint32_t ntw64_priv_owner(void);
int ntw64_priv_bind_owner(uint32_t id);
uint32_t ntw64_priv_channel_generation(void);
#endif
#endif
