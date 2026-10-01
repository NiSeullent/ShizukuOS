/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_WASM_QJS_H
#define M98_WASM_QJS_H
#include "quickjs.h"
#include "m98_wasm.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct m98_wasm_qjs m98_wasm_qjs;
/* Attach before untrusted code in a fresh, trusted context. The host owns the
 * context/runtime, their JS execution budgets, and imported callbacks/userdata.
 * One native store and OS thread. No global WebAssembly object is installed.
 * Both output values remain unchanged on failure; a JS exception may be pending. */
int m98_wasm_qjs_attach(JSContext *,const m98_wasm_options *,
 const m98_wasm_import *,uint32_t,m98_wasm_qjs **,JSValue *private_api);
/* Detach on the owner thread BEFORE freeing its context/runtime. All retained
 * JS module/instance/API objects become stale, but remain safe to finalize.
 * On failure the host pointer remains unchanged. */
int m98_wasm_qjs_detach(m98_wasm_qjs **);
int m98_wasm_qjs_inspect(m98_wasm_qjs *,m98_wasm_info *);
#ifdef __cplusplus
}
#endif
#endif
