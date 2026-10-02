/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_ACCOUNT_H
#define SHZ_ACCOUNT_H
#include <stddef.h>
#include <stdint.h>
#define SHZ_ACCOUNT_LIMIT 16
#define SHZ_KDF_ROUNDS 600000u
#define SHZ_ROLE_ADMIN 1u
#define SHZ_SUBJECT_SANDBOX 1u
#define SHZ_AUTH_DENIED (-1)
#define SHZ_AUTH_INVALID (-2)
#define SHZ_AUTH_FULL (-3)
#define SHZ_AUTH_LOCKED (-4)
#define SHZ_AUTH_ENTROPY (-5)
typedef struct { uint32_t uid,session,integrity,roles,flags,reserved; uint64_t auth_id; } shz_subject;
typedef int (*shz_entropy)(void *,void *,size_t);
typedef struct {char name[32];uint32_t uid,roles,failures;uint64_t locked_until;uint8_t salt[32],digest[32];} shz_account;
typedef struct {shz_account accounts[SHZ_ACCOUNT_LIMIT];uint32_t count,next_session;shz_entropy entropy;void *entropy_ctx;} shz_accounts;
void shz_accounts_init(shz_accounts *,shz_entropy,void *);
int shz_account_register(shz_accounts *,const shz_subject *,int,const char *,const void *,size_t,uint32_t);
int shz_account_login(shz_accounts *,const char *,const void *,size_t,uint64_t,shz_subject *);
int shz_account_elevate(shz_accounts *,const char *,const void *,size_t,uint64_t,shz_subject *);
int shz_subject_access(const shz_subject *,const shz_subject *);
int shz_subject_path(const shz_subject *,const char *,int);
#endif
