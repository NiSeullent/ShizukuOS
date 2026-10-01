/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_RESOURCE_WIN32_ADAPTER_H
#define NTW_RESOURCE_WIN32_ADAPTER_H
#include "resources.h"
#if defined(__i386__)
#define NRA_CALL __attribute__((stdcall))
#else
#define NRA_CALL
#endif
#define NRA_MODULES 8u
#define NRA_QUERY_UNITS 32767u
#define NRA_VERIFY_BYTES (64u*1024u*1024u)
#define NRA_ERROR_INVALID_HANDLE 6u
#define NRA_ERROR_BAD_EXE_FORMAT 193u
#define NRA_ERROR_INVALID_PARAMETER 87u
#define NRA_ERROR_CALL_NOT_IMPLEMENTED 120u
#define NRA_ERROR_RESOURCE_DATA_NOT_FOUND 1812u
#define NRA_ERROR_RESOURCE_TYPE_NOT_FOUND 1813u
#define NRA_ERROR_RESOURCE_NAME_NOT_FOUND 1814u
#define NRA_ERROR_RESOURCE_LANG_NOT_FOUND 1815u

typedef const uint8_t *(*nra_read)(void *,const void *,uint32_t);
typedef void (*nra_error)(void *,uint32_t);
typedef struct nra_module {
    const nr_resources *resources;
    const uint8_t *mapped;
    uint32_t bytes,active;
    uint32_t found[NR_LEAVES/32],loaded[NR_LEAVES/32];
} nra_module;
typedef struct nra_adapter {
    const struct nra_adapter *self;
    nra_read read;
    nra_error error;
    void *opaque;
    const void *root;
    nra_module module[NRA_MODULES];
} nra_adapter;

/* Explicit caller-owned mapping registry, patterned on native.c by_handle:
 * identity is the actual mapped PE base, never an invented module number.
 * No registration changes the real native loader, its admission, or its hooks.
 * read returns the SAME address after proving the entire range readable; this
 * trusted callback covers caller query strings and borrowed mapped-image data.
 * It must preserve the caller thread's LastError on EVERY return, including
 * refused ranges; save/restore around any OS readability-query helper. The
 * adapter's error callback selects errors for failed resource operations.
 * error sets the caller thread's actual Win32 last error (or a host test slot).
 * The manager serializes every call, registration/unregistration and binding;
 * it retains originals, contexts and mappings through all borrowed uses. It may
 * reuse storage only after every borrowed handle/pointer is discarded (no ABA
 * detection). No DLL entry, TLS or other target callback is invoked here.
 */
int nra_init(nra_adapter *,nra_read,nra_error,void *);
int nra_register(nra_adapter *,const nr_resources *,const void *,uint32_t,int);
int nra_unregister(nra_adapter *,const void *);
int nra_bind(nra_adapter *); /* one explicit process facade, caller serialized */
void nra_unbind(nra_adapter *);

/* Exact counted-key entry for internal consumers, preserving PE 31-bit IDs and
 * arbitrary counted UTF16. This is not the Win32 string/fallback interface. */
void *nra_find_counted(nra_adapter *,const void *,const nr_key *,const nr_key *,uint16_t);
void *nra_load(nra_adapter *,const void *,const void *);
void *nra_lock(nra_adapter *,const void *);
uint32_t nra_sizeof(nra_adapter *,const void *,const void *);
int nra_free(nra_adapter *,const void *);

/* Win32 ABI-compatible facade; prefixes keep it out of global Kernel32 names.
 * NULL module uses the explicitly registered root. MAKEINTRESOURCE/#decimal
 * are WORD IDs; A/W ASCII names use case-insensitive comparison, as the pinned
 * Wine PE path does. Non-ASCII ACP/folding is explicit unsupported work.
 * Exact nonneutral Ex matches work. Special/neutral and FindResource selection
 * succeeds only for a sole matching language variant; ambiguous language sets,
 * missing exact-language fallback and MUI return CALL_NOT_IMPLEMENTED.
 * Full Win98 language behavior remains pending actual native comparison.
 * Successful calls preserve last error. HRSRC and loaded data handles are
 * separate identities. Load returns mapped+rva, never original raw file data.
 * Lock accepts only previously loaded identities. FreeResource returns FALSE
 * and releases nothing for a valid PE data handle; repeated calls are harmless.
 */
void *NRA_CALL nra_FindResourceExA(void *,const char *,const char *,uint16_t);
void *NRA_CALL nra_FindResourceExW(void *,const uint16_t *,const uint16_t *,uint16_t);
void *NRA_CALL nra_FindResourceA(void *,const char *,const char *);
void *NRA_CALL nra_FindResourceW(void *,const uint16_t *,const uint16_t *);
void *NRA_CALL nra_LoadResource(void *,void *);
void *NRA_CALL nra_LockResource(void *);
uint32_t NRA_CALL nra_SizeofResource(void *,void *);
int NRA_CALL nra_FreeResource(void *);

typedef struct nra_api {
    void *(NRA_CALL *find_ex_a)(void *,const char *,const char *,uint16_t);
    void *(NRA_CALL *find_ex_w)(void *,const uint16_t *,const uint16_t *,uint16_t);
    void *(NRA_CALL *find_a)(void *,const char *,const char *);
    void *(NRA_CALL *find_w)(void *,const uint16_t *,const uint16_t *);
    void *(NRA_CALL *load)(void *,void *);
    void *(NRA_CALL *lock)(void *);
    uint32_t (NRA_CALL *size)(void *,void *);
    int (NRA_CALL *free_resource)(void *);
} nra_api;
#endif
