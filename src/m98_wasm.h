/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_WASM_H
#define M98_WASM_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Standalone numeric C embedding. This is not the browser WebAssembly API. */
enum { M98_WASM_OK=0, M98_WASM_ARGUMENT=-1, M98_WASM_THREAD=-2,
 M98_WASM_BUSY=-3, M98_WASM_LIMIT=-4, M98_WASM_STALE=-5,
 M98_WASM_VALIDATE=-6, M98_WASM_LINK=-7, M98_WASM_TRAP=-8,
 M98_WASM_TYPE=-9, M98_WASM_RANGE=-10, M98_WASM_PLATFORM=-11 };
enum { M98_WASM_I32=0, M98_WASM_I64=1, M98_WASM_F32=2, M98_WASM_F64=3 };
typedef struct { uint32_t kind; uint64_t bits; } m98_wasm_value;
typedef struct { uint32_t memory_bytes, stack_bytes, instruction_limit,
 linear_memory_pages; } m98_wasm_options;
typedef int (*m98_wasm_import_fn)(void *, const m98_wasm_value *, uint32_t,
 m98_wasm_value *); /* Nonzero return raises an actual Wasm exception. */
typedef struct { const char *module_name,*name,*signature;
 m98_wasm_import_fn callback; void *user; } m98_wasm_import;
/* Signatures use WAMR numeric letters: (iIfF)i, with at most 8 args / 1 result. */
typedef struct { uint32_t used_bytes, peak_bytes, denied_allocations,
 modules,instances; char diagnostic[160]; } m98_wasm_info;
int m98_wasm_open(const m98_wasm_options *,const m98_wasm_import *,uint32_t,uint32_t *);
int m98_wasm_close(uint32_t);
int m98_wasm_load(uint32_t,const void *,uint32_t,uint32_t *);
int m98_wasm_unload(uint32_t,uint32_t);
int m98_wasm_instantiate(uint32_t,uint32_t,uint32_t *);
int m98_wasm_instance_close(uint32_t,uint32_t);
int m98_wasm_call(uint32_t,uint32_t,const char *,const m98_wasm_value *,uint32_t,
 m98_wasm_value *,uint32_t);
int m98_wasm_memory_size(uint32_t,uint32_t,uint32_t,uint32_t *);
int m98_wasm_memory_grow(uint32_t,uint32_t,uint32_t,uint32_t,int32_t *);
int m98_wasm_memory_read(uint32_t,uint32_t,uint32_t,uint32_t,void *,uint32_t);
int m98_wasm_memory_write(uint32_t,uint32_t,uint32_t,uint32_t,const void *,uint32_t);
int m98_wasm_inspect(uint32_t,m98_wasm_info *);
#ifdef __cplusplus
}
#endif
#endif
