/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_RPC_OBSERVER_H
#define NTW_RPC_OBSERVER_H
#include <stddef.h>
#include <stdint.h>
#define RPC_THREADS 256u
#define RPC_WINDOW 32u
#define RPC_DR_MASK 0x000f000fu
#define RPC_STATUS_MASK 0x0000e00fu
#define RPC_RF 0x00010000u
enum { RPC_PASS=0, RPC_ENTRY=1, RPC_STORE=2, RPC_UNSAFE=-1 };
enum { R_EAX,R_EBX,R_ECX,R_EDX,R_ESI,R_EDI,R_EBP,R_ESP,R_EIP,R_FLAGS,
       R_CS,R_SS,R_DS,R_ES,R_FS,R_GS,R_DR0,R_DR1,R_DR2,R_DR3,R_DR6,R_DR7,R_COUNT };
typedef struct { uint32_t v[R_COUNT]; } rpc_context;
typedef struct {
    uint8_t sha256[32]; uint32_t file_bytes,image_bytes,pe_offset,preferred_base;
    uint32_t timestamp,size_headers,sections,characteristics;
    uint32_t entry_rva,store_rva,state_rva,flag_rva;
    uint8_t code[2][RPC_WINDOW],length[2],relocations[2][RPC_WINDOW];
} rpc_profile;
typedef struct {
    uint32_t id; uintptr_t handle; rpc_context original;
    uint32_t hits[2]; unsigned used,armed;
} rpc_thread;
typedef struct {
    rpc_thread threads[RPC_THREADS]; const rpc_profile *profile; uint32_t base;
    uint32_t created,exit_threads,process_retired,arms,restores,hits[2],generations;
    unsigned incomplete,unsafe,counter_overflow;
} rpc_runtime;
typedef struct {
    void *opaque;
    int (*read_context)(void *,uintptr_t,rpc_context *);
    int (*write_debug)(void *,uintptr_t,const rpc_context *);
    int (*write_resume)(void *,uintptr_t,const rpc_context *);
    int (*read_memory)(void *,uint32_t,void *,uint32_t);
} rpc_ops;
int rpc_file_gate(const uint8_t *,size_t,const rpc_profile *);
int rpc_expected_code(const rpc_profile *,unsigned,uint32_t,uint8_t[RPC_WINDOW]);
int rpc_context_equal(const rpc_context *,const rpc_context *);
int rpc_add_thread(rpc_runtime *,uint32_t,uintptr_t,const rpc_ops *);
int rpc_bind_module(rpc_runtime *,const rpc_profile *,uint32_t,const rpc_ops *);
int rpc_unbind_module(rpc_runtime *,const rpc_ops *);
int rpc_retire_thread(rpc_runtime *,uint32_t);
void rpc_retire_process(rpc_runtime *);
int rpc_observe(rpc_runtime *,uint32_t,uint32_t,unsigned,uint32_t,const rpc_ops *,rpc_context *);
int rpc_complete(const rpc_runtime *);
void rpc_gap(rpc_runtime *);
#endif
