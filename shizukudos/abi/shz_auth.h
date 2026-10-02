/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_AUTH_ABI_H
#define SHZ_AUTH_ABI_H
#include <stdint.h>
#include "../accounts/account.h"
#define SHZ_AUTH_VERSION 1u
#define SHZ_AUTH_QUERY 0x200u
#define SHZ_AUTH_REGISTER 0x201u
#define SHZ_AUTH_LOGIN_LAUNCH 0x202u
#define SHZ_AUTH_ELEVATE_LAUNCH 0x203u
#define SHZ_AUTH_SANDBOX_LAUNCH 0x204u
#define SHZ_AUTH_VOLATILE 1u
typedef struct {uint32_t version,roles,password_bytes,reserved;char user[32];uint8_t password[128];char image[260],command[512];} shz_auth_request;
typedef struct {uint32_t version,flags,accounts,reserved;shz_subject subject;uint64_t child_pid;} shz_auth_reply;
#endif
