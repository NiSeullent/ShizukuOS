/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_DELAY_RUNTIME_H
#define NTW_DELAY_RUNTIME_H
#include "../native_loader/pe.h"
#ifdef __cplusplus
extern "C" {
#endif

#define NTW_DELAY_MODULES 64u
#define NTW_DELAY_NAMES 131072u
#define NTW_DELAY_MAGIC 0x444c5932u

/* Operations must return real retained handles and callable PE32 addresses.
 * enter/leave serialize resolution and disposal. open/find may not recursively
 * enter this context. The caller owns validated, writable mapping pages.
 */
typedef struct ntw_delay_ops {
 void *opaque;
 int (*enter)(void *);
 void (*leave)(void *);
 uint32_t (*open)(void *,const char *);
 uint32_t (*find)(void *,uint32_t,const char *,uint16_t);
 int (*close)(void *,uint32_t);
} ntw_delay_ops;
typedef struct ntw_delay_module {
 uint32_t descriptor_rva,handle_rva,name,handle,published;
 uint8_t descriptor[32];
} ntw_delay_module;
typedef struct ntw_delay_entry {
 uint32_t slot_rva,initial,address,name;
 uint16_t ordinal,module;
} ntw_delay_entry;
typedef struct ntw_delay_context {
 uint32_t magic,state,module_count,entry_count,names_used,busy;
 uint8_t *mapped;
 uint32_t mapped_bytes,loaded_base;
 ntw_delay_ops ops;
 ntw_delay_module module[NTW_DELAY_MODULES];
 ntw_delay_entry entry[NP_IMPORTS];
 char names[NTW_DELAY_NAMES];
} ntw_delay_context;

/* ctx must initially be zeroed. Original file bytes are never modified.
 * No DLL is opened, and no mapping slot is written, before complete validation.
 * Supported: RVA descriptors, named/ordinal slots, no bound or unload tables.
 */
int ntw_delay_init(ntw_delay_context *,const np_image *,uint8_t *,uint32_t,uint32_t,
                   const ntw_delay_ops *,const char **);
/* Resolve exactly one linker-owned IAT slot. Failed lookup leaves both the IAT
 * and HMODULE slot unchanged; cleanup failure retains ownership for disposal.
 * The result is a function address, not evidence of the function's semantics.
 */
int ntw_delay_resolve(ntw_delay_context *,uint32_t,uint32_t,uint32_t *,const char **);
/* Requires quiescent=1: caller has joined all target threads and callbacks.
 * Restores slots before releasing DLL references. Close failures can be retried;
 * the poisoned/closing context cannot resolve new calls.
 */
int ntw_delay_dispose(ntw_delay_context *,int,const char **);
#ifdef __cplusplus
}
#endif
#endif
