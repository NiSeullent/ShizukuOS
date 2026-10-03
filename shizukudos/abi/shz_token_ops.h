/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_TOKEN_OPS_H
#define SHZ_TOKEN_OPS_H
#include <stdint.h>

/* New operation: old backends reject it instead of silently discarding access.
 * a2 = source handle; a3 = access32 | type8<<32 | level8<<40; a4 = output.
 * Upper16 bits are reserved and must be zero. Legacy op5 remains type8|level8<<8.
 * Both operations require TOKEN_DUPLICATE on the source handle. Legacy op5 keeps
 * the source handle grant. Ex with access 0 keeps the source handle grant; a
 * nonzero request (incl. MAXIMUM_ALLOWED) is authorized against the token
 * object's trusted policy below, as DuplicateTokenEx checks the token DACL,
 * for the effective caller (thread impersonation context, if any). */
#define SHZ_TOKEN_OP_DUPLICATE_EX 0x100u
#define SHZ_TOKEN_ALL_ACCESS 0x000f01ffu
#define SHZ_TOKEN_QUERY 0x0008u
#define SHZ_TOKEN_DUPLICATE 0x0002u
#define SHZ_TOKEN_IMPERSONATE 0x0004u
#define SHZ_TOKEN_ADJUST_PRIVILEGES 0x0020u
#define SHZ_TOKEN_ADJUST_DEFAULT 0x0080u
#define SHZ_TOKEN_ADJUST_SESSIONID 0x0100u
#define SHZ_TOKEN_READ_CONTROL 0x00020000u
#define SHZ_TOKEN_WRITE_DAC 0x00040000u
#define SHZ_TOKEN_MAXIMUM_ALLOWED 0x02000000u
#define SHZ_TOKEN_SYSTEM_AUTH_ID 0x3e7u
/* Rights the generic-write mapping and standard write/delete rights add; a
 * mandatory NO_WRITE_UP label withholds them from lower-integrity subjects. */
#define SHZ_TOKEN_WRITE_UP_RIGHTS 0x000d01e0u

/* Kernel-owned subject of a token (auth LUID, session, integrity label).
 * Callers must fill it from kernel token objects/account binding only, never
 * from caller-supplied SIDs, masks or descriptors. */
typedef struct shz_token_subject {
    uint64_t auth_id;
    uint32_t session, integrity_rid;
} shz_token_subject;

/* Trusted object policy standing in for the default token DACL Windows
 * assigns (owner user + SYSTEM: GENERIC_ALL) plus its mandatory label
 * (NO_WRITE_UP). A different logon subject or session gets no rights; the
 * SYSTEM logon is admitted like the owner. Each right is still enforced at its
 * own use site (e.g. integrity can only be lowered, session needs TCB). */
static inline uint32_t shz_token_object_rights(const shz_token_subject *caller, const shz_token_subject *token)
{
    uint32_t rights;
    if (!caller || !token) return 0;
    if (caller->auth_id != token->auth_id && caller->auth_id != SHZ_TOKEN_SYSTEM_AUTH_ID) return 0;
    if (caller->auth_id != SHZ_TOKEN_SYSTEM_AUTH_ID && caller->session != token->session) return 0;
    rights = SHZ_TOKEN_ALL_ACCESS;
    if (caller->integrity_rid < token->integrity_rid) rights &= ~SHZ_TOKEN_WRITE_UP_RIGHTS;
    return rights;
}

/* Effective caller rights on a token object. The thread impersonation token,
 * when present, is the caller context: it must be an impersonation token
 * (type 2) at SecurityImpersonation(2) or SecurityDelegation(3); Anonymous(0)
 * and Identification(1) cannot authorize object access, so they get nothing.
 * Until stored security descriptors are evaluated, an impersonating thread
 * receives the intersection of its impersonated subject's rights and its
 * primary subject's rights: it never regains primary-only rights (lower label,
 * other subject) and never gains rights the primary lacks. All subjects must
 * be snapshotted from kernel token objects. Returns 0 rights on denial. */
static inline uint32_t shz_token_effective_rights(const shz_token_subject *primary, const shz_token_subject *imp,
                                                  uint32_t imp_type, uint32_t imp_level,
                                                  const shz_token_subject *token)
{
    uint32_t rights;
    if (!primary || !token) return 0;
    rights = shz_token_object_rights(primary, token);
    if (!imp) return rights;
    if (imp_type != 2 || imp_level < 2 || imp_level > 3) return 0;
    return rights & shz_token_object_rights(imp, token);
}

/* Token generic mapping; maximum is a caller-supplied authorization ceiling.
 * This is handle admission, not an object DACL or account authority. */
static inline int shz_token_map_access(uint32_t desired, uint32_t maximum, uint32_t *out)
{
    uint32_t mapped = desired & ~0xf2000000u;
    if (desired & 0x80000000u) mapped |= 0x00020008u;
    if (desired & 0x40000000u) mapped |= 0x000200e0u;
    if (desired & 0x20000000u) mapped |= 0x00020000u;
    if (desired & 0x10000000u) mapped |= SHZ_TOKEN_ALL_ACCESS;
    if (desired & 0x02000000u) mapped |= maximum;
    if (mapped & ~SHZ_TOKEN_ALL_ACCESS || mapped & ~maximum) return 0;
    *out = mapped;
    return 1;
}

/* DuplicateTokenEx new-handle access: 0 keeps the source handle grant;
 * otherwise generic/MAXIMUM_ALLOWED map against the object's authorized
 * rights and every requested bit must be authorized. Empty result denies. */
static inline int shz_token_duplicate_access(uint32_t desired, uint32_t source_granted,
                                             uint32_t object_rights, uint32_t *out)
{
    uint32_t mapped;
    if (!desired) { *out = source_granted; return 1; }
    if (!shz_token_map_access(desired, object_rights, &mapped) || !mapped) return 0;
    *out = mapped;
    return 1;
}

static inline uint64_t shz_token_duplicate_pack(uint32_t access, uint32_t type, uint32_t level)
{
    return (uint64_t)access | ((uint64_t)type << 32) | ((uint64_t)level << 40);
}
#endif
