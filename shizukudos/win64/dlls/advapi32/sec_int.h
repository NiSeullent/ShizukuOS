/* SPDX-License-Identifier: GPL-2.0-only
 * advapi32 internal: helpers shared by security.c (ACL/SD/SDDL), token.c (tokens, privileges, AccessCheck, account lookup)
 * and objsec.c (object security). */
#ifndef SHZ_ADVAPI32_SEC_INT_H
#define SHZ_ADVAPI32_SEC_INT_H

typedef struct { SECURITY_DESCRIPTOR_CONTROL control; PSID owner, group; PACL dacl, sacl; } sec_parts_t;

void sec_parts(PSECURITY_DESCRIPTOR psd, sec_parts_t *o);                  /* absolute or self-relative */
DWORD sec_build_relative(const sec_parts_t *p, void *out, DWORD cap);     /* returns the size; writes when cap suffices */
DWORD sec_acl_used(const ACL *acl);                                        /* 0 = malformed */
BOOL sec_add_simple_ace(PACL acl, BYTE type, BYTE flags, DWORD mask, PSID sid, DWORD start);
BOOL sec_unsupported(const char *fn, const char *what, DWORD err);       /* sets err, reports it under SHZ_K32TRACE, FALSE */
PSID sec_sid_for_name(LPCWSTR name);                                       /* LocalAlloc'd SID of an account name, or NULL */
/* The identity of the single Kernel64 user (ntreg.h SHZ_USER_SID_A) and its token's groups. */
PSID sec_user_sid(void);                                                   /* static storage */
PSID sec_primary_group_sid(void);                                          /* the user's domain + 513 ("None") */
BOOL sec_default_sd(PSECURITY_DESCRIPTOR *out, DWORD *len);               /* LocalAlloc'd: owner/group = user, DACL user+SYSTEM GA */
#endif
