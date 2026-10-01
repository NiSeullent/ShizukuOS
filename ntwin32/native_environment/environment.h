/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_ENVIRONMENT_H
#define NTW_ENVIRONMENT_H
#include <stddef.h>
#include <stdint.h>
enum { ENV_VERIFIER=1, ENV_SECURE=2, ENV_DESKTOP=1, ENV_OWNED_FIXTURE=2 };
typedef struct { uint32_t scope, nt_global_flags, process_flags; } env_model;
typedef struct { uint8_t digest[32]; uint32_t bytes, verifier_rva, secure_rva; } env_profile;
typedef struct { uint32_t eax,eip,eflags; } env_context;
int env_decode(const uint8_t *,size_t,uint32_t *,uint32_t *);
int env_model_make(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,env_model *);
int env_emulate(const env_model *,uint32_t,uint32_t,uint32_t,uint32_t,const uint8_t *,size_t,env_context *);
int env_pe_gate(const uint8_t *,size_t,const env_profile *,uint32_t *);
typedef struct { uint32_t state[8]; uint64_t bytes; uint8_t block[64]; size_t used; } env_sha;
void env_sha_init(env_sha *);
void env_sha_update(env_sha *,const uint8_t *,size_t);
void env_sha_final(env_sha *,uint8_t[32]);
#endif
