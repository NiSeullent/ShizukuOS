/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll: helpers the registry layer needs (RtlFreeUnicodeString, RtlFormatCurrentUserKeyPath, RtlGetLastNtStatus).
 * The registry system calls themselves (NtCreateKey ...) are generated stubs, see win64/build.py.
 */
#include "nt.h"
#include "ntdll_int.h"
#include "../include/ntreg.h"
#include "../../abi/shz_auth.h"
#include <string.h>

/* Frees a string whose buffer was allocated from the process heap (RtlFormatCurrentUserKeyPath, ...). */
VOID NTAPI RtlFreeUnicodeString(SHZ_UNICODE_STRING *s)
{
    if (s->Buffer) RtlFreeHeap(ShzProcessHeap(), 0, s->Buffer);
    s->Buffer = 0;
    s->Length = s->MaximumLength = 0;
}

/* The private token query is the same snapshot used by advapi32 TokenUser.
 * Only STATUS_NO_TOKEN permits using the primary token instead of the thread.
 * Registry authorization currently uses the immutable primary subject, so a
 * different authentication ID, session or integrity cannot be impersonated
 * through this frontend. */
static NTSTATUS current_user_token(shz_token_info *out)
{
    HANDLE thread = 0, process = 0;
    shz_token_info primary = {0};
    NTSTATUS st, close_status;
    st = NtOpenThreadToken(CURRENT_THREAD, TOKEN_QUERY, TRUE, &thread);
    if (st != STATUS_SUCCESS && st != STATUS_NO_TOKEN) return st;
    if (st == STATUS_SUCCESS) {
        st = NtShzToken(SHZ_TOK_QUERY, (ULONG_PTR)thread, (ULONG_PTR)out, sizeof *out);
        close_status = NtClose(thread);
        if (st) return st;
        if (close_status) return close_status;
        if (out->type != 2) return STATUS_BAD_TOKEN_TYPE;
        if (out->imp_level < 2 || out->imp_level > 3) return STATUS_ACCESS_DENIED;
    }
    st = NtOpenProcessToken(CURRENT_PROCESS, TOKEN_QUERY, &process);
    if (st) return st;
    st = NtShzToken(SHZ_TOK_QUERY, (ULONG_PTR)process, (ULONG_PTR)&primary, sizeof primary);
    close_status = NtClose(process);
    if (st) return st;
    if (close_status) return close_status;
    if (primary.type != 1) return STATUS_BAD_TOKEN_TYPE;
    if (thread && (out->auth_id != primary.auth_id || out->session != primary.session ||
                   out->integrity_rid != primary.integrity_rid)) return STATUS_ACCESS_DENIED;
    if (!thread) *out = primary;
    return STATUS_SUCCESS;
}

static ULONG append_decimal(WCHAR *out, ULONG64 value)
{
    WCHAR digits[20];
    ULONG n = 0, i;
    do { digits[n++] = (WCHAR)('0' + value % 10); value /= 10; } while (value);
    for (i = 0; i < n; ++i) out[i] = digits[n - 1 - i];
    return n;
}

/* Validate the embedded SID before reading it: it must be wholly inside the
 * queried TokenUser record. All SID authorities are formatted as decimal.
 * A maximum SID needs fewer than 200 characters including the registry prefix. */
static NTSTATUS format_user_sid(SHZ_UNICODE_STRING *out, const TOKEN_USER *user, SIZE_T bytes)
{
    static const WCHAR prefix[] = L"\\Registry\\User\\";
    const SIZE_T base = (SIZE_T)user;
    const BYTE *sid;
    SIZE_T offset, available;
    ULONG n = sizeof prefix / sizeof(WCHAR) - 1, i, sub;
    ULONG64 authority = 0;
    WCHAR text[200], *buffer;
    if (!user || bytes < sizeof *user || bytes > sizeof *user + SECURITY_MAX_SID_SIZE + sizeof(ULONG_PTR) - 1)
        return STATUS_INVALID_SID;
    if ((SIZE_T)user->User.Sid < base || (SIZE_T)user->User.Sid - base < sizeof *user) return STATUS_INVALID_SID;
    offset = (SIZE_T)user->User.Sid - base;
    if (offset > bytes || bytes - offset < 8) return STATUS_INVALID_SID;
    available = bytes - offset;
    sid = (const BYTE *)user->User.Sid;
    if (sid[0] != SID_REVISION || sid[1] > SID_MAX_SUB_AUTHORITIES || available < 8u + 4u * sid[1])
        return STATUS_INVALID_SID;
    memcpy(text, prefix, n * sizeof(WCHAR));
    text[n++] = 'S'; text[n++] = '-';
    n += append_decimal(text + n, sid[0]); text[n++] = '-';
    for (i = 0; i < 6; ++i) authority = (authority << 8) | sid[2 + i];
    n += append_decimal(text + n, authority);
    for (i = 0; i < sid[1]; ++i) {
        memcpy(&sub, sid + 8 + 4 * i, sizeof sub);
        text[n++] = '-'; n += append_decimal(text + n, sub);
    }
    text[n] = 0;
    buffer = RtlAllocateHeap(ShzProcessHeap(), 0, (n + 1) * sizeof(WCHAR));
    if (!buffer) return STATUS_NO_MEMORY;
    memcpy(buffer, text, (n + 1) * sizeof(WCHAR));
    out->Buffer = buffer;
    out->Length = (USHORT)(n * sizeof(WCHAR));
    out->MaximumLength = (USHORT)((n + 1) * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

/* \Registry\User\<actual TokenUser SID>. No SID or path is cached. The caller
 * frees the successful result with RtlFreeUnicodeString. Unknown identities and
 * token/authority/heap failures never select the legacy RID1001 hive. */
NTSTATUS NTAPI RtlFormatCurrentUserKeyPath(SHZ_UNICODE_STRING *out)
{
    typedef struct { BYTE revision, count; SID_IDENTIFIER_AUTHORITY authority; ULONG sub[5]; } user_sid;
    struct { TOKEN_USER user; user_sid sid; } record = {0};
    shz_token_info token = {0};
    ULONG uid;
    NTSTATUS st;
    if (!out) return STATUS_INVALID_PARAMETER;
    out->Buffer = 0; out->Length = out->MaximumLength = 0;
    st = current_user_token(&token);
    if (st) return st;
    uid = (ULONG)(token.auth_id >> 32);
    if (!uid && token.auth_id == 0x4e7) {
        shz_auth_reply reply = {0};
        st = NtShzToken(SHZ_AUTH_QUERY, 0, sizeof reply, (ULONG_PTR)&reply);
        if (st) return st;
        if (reply.version != SHZ_AUTH_VERSION || reply.reserved || reply.accounts) return STATUS_ACCESS_DENIED;
        uid = 1001;                         /* actual pre-enrollment legacy token */
    }
    if (uid < 1000 || uid - 1000 >= SHZ_ACCOUNT_LIMIT) return STATUS_ACCESS_DENIED;
    record.user.User.Sid = &record.sid;
    record.sid.revision = SID_REVISION; record.sid.count = 5;
    record.sid.authority.Value[5] = 5;
    record.sid.sub[0] = 21; record.sid.sub[1] = 2210311251u;
    record.sid.sub[2] = 3305482031u; record.sid.sub[3] = 1094512843u; record.sid.sub[4] = uid;
    return format_user_sid(out, &record.user, sizeof record);
}

NTSTATUS NTAPI RtlGetLastNtStatus(void) { return shz_last_status(); }
