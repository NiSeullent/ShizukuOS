/* SPDX-License-Identifier: GPL-2.0-only */
/* NT native registry subset required by Chromium chrome_elf.dll
 * (chrome/chrome_elf/nt_registry) mapped onto the real Windows 98 ANSI
 * registry. Original implementation following the documented NT contracts
 * (ZwCreateKey/ZwOpenKeyEx/ZwQueryValueKey/ZwSetValueKey/ZwDeleteKey,
 * RtlInitUnicodeString, RtlFreeUnicodeString); informed by ReactOS/Wine
 * public behaviour descriptions, no code copied. */
#ifndef NTW_CHROMIUM_NT_REGISTRY_H
#define NTW_CHROMIUM_NT_REGISTRY_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t ntr_status;
#define NTR_SUCCESS                 ((ntr_status)0x00000000)
#define NTR_BUFFER_OVERFLOW         ((ntr_status)0x80000005)
#define NTR_UNSUCCESSFUL            ((ntr_status)0xC0000001)
#define NTR_NOT_IMPLEMENTED         ((ntr_status)0xC0000002)
#define NTR_INVALID_INFO_CLASS      ((ntr_status)0xC0000003)
#define NTR_INVALID_HANDLE          ((ntr_status)0xC0000008)
#define NTR_INVALID_PARAMETER       ((ntr_status)0xC000000D)
#define NTR_NO_MEMORY               ((ntr_status)0xC0000017)
#define NTR_ACCESS_DENIED           ((ntr_status)0xC0000022)
#define NTR_BUFFER_TOO_SMALL        ((ntr_status)0xC0000023)
#define NTR_OBJECT_NAME_INVALID     ((ntr_status)0xC0000033)
#define NTR_OBJECT_NAME_NOT_FOUND   ((ntr_status)0xC0000034)
#define NTR_OBJECT_PATH_SYNTAX_BAD  ((ntr_status)0xC000003B)
#define NTR_INSUFFICIENT_RESOURCES  ((ntr_status)0xC000009A)
#define NTR_NOT_SUPPORTED           ((ntr_status)0xC00000BB)
#define NTR_NAME_TOO_LONG           ((ntr_status)0xC0000106)
#define NTR_CANNOT_DELETE           ((ntr_status)0xC0000121)
#define NTR_UNMAPPABLE_CHARACTER    ((ntr_status)0xC0000162)
#define NTR_KEY_DELETED             ((ntr_status)0xC000017C)

/* Exact NT user-mode layouts (x86: 8 and 24 bytes). */
typedef struct ntr_unicode_string {
    uint16_t Length;
    uint16_t MaximumLength;
    uint16_t *Buffer;
} ntr_unicode_string;

typedef struct ntr_object_attributes {
    uint32_t Length;
    void *RootDirectory;
    ntr_unicode_string *ObjectName;
    uint32_t Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} ntr_object_attributes;

#define NTR_OBJ_CASE_INSENSITIVE 0x00000040u
#define NTR_OBJ_OPENIF           0x00000080u

enum { NTR_KEY_VALUE_BASIC = 0, NTR_KEY_VALUE_FULL = 1, NTR_KEY_VALUE_PARTIAL = 2 };
enum { NTR_REG_CREATED_NEW_KEY = 1, NTR_REG_OPENED_EXISTING_KEY = 2 };

/* Backend roots: real Win98 predefined keys. */
enum { NTR_ROOT_MACHINE = 1, NTR_ROOT_USERS = 2, NTR_ROOT_CURRENT_USER = 3 };

#define NTR_PATH_MAX   512u
#define NTR_HANDLES    64u
#define NTR_ALLOCS     8u
#define NTR_DATA_MAX   0x100000u

/* Provider-local alias returned by RtlFormatCurrentUserKeyPath. Windows 98
 * has no user SIDs; this name maps only to HKEY_CURRENT_USER and is never
 * presented as an NT security identifier. */
#define NTR_CURRENT_USER_ALIAS "SHIZUKU-WIN98-CURRENT-USER"

/* Backend uses Win32 registry error numbers (0 = ERROR_SUCCESS). Each key
 * operation names a key by (root, ANSI path); the backend owns key handles. */
typedef struct ntr_backend {
    void *ctx;
    void (*lock)(void *ctx);
    void (*unlock)(void *ctx);
    long (*open)(void *ctx, unsigned root, const char *path, void **key);
    long (*create)(void *ctx, unsigned root, const char *path, void **key, int *created);
    long (*query)(void *ctx, void *key, const char *name, uint32_t *type, uint8_t *data, uint32_t *bytes);
    long (*set)(void *ctx, void *key, const char *name, uint32_t type, const uint8_t *data, uint32_t bytes);
    long (*has_subkey)(void *ctx, void *key, int *present);
    long (*remove)(void *ctx, unsigned root, const char *path);
    long (*close)(void *ctx, void *key);
    /* Strict conversions: return 0 when any character is unmappable.
     * out may be NULL to count. Lengths are in bytes (ANSI) / WCHARs. */
    int (*to_ansi)(void *ctx, const uint16_t *w, uint32_t wchars, char *out, uint32_t cap, uint32_t *used);
    int (*to_wide)(void *ctx, const char *a, uint32_t bytes, uint16_t *out, uint32_t cap, uint32_t *used);
    void *(*alloc)(void *ctx, uint32_t bytes);
    void (*release)(void *ctx, void *p);
} ntr_backend;

typedef struct ntr_slot {
    uint32_t generation;
    uint8_t live, deleted;
    unsigned root;
    uint32_t access;
    void *key;
    char path[NTR_PATH_MAX];
} ntr_slot;

typedef struct ntr_state {
    uint32_t magic;
    ntr_backend ops;
    ntr_slot slots[NTR_HANDLES];
    void *allocs[NTR_ALLOCS];
} ntr_state;

int ntr_init(ntr_state *s, const ntr_backend *ops);
/* Quiescent teardown: closes every live backend key; returns live count. */
unsigned ntr_shutdown(ntr_state *s);
unsigned ntr_live_handles(ntr_state *s);

ntr_status ntr_create_key(ntr_state *s, void **handle, uint32_t access, const ntr_object_attributes *oa,
                          uint32_t title_index, const ntr_unicode_string *class_name, uint32_t options,
                          uint32_t *disposition);
ntr_status ntr_open_key_ex(ntr_state *s, void **handle, uint32_t access, const ntr_object_attributes *oa,
                           uint32_t options);
ntr_status ntr_query_value_key(ntr_state *s, void *handle, const ntr_unicode_string *name, uint32_t info_class,
                               void *out, uint32_t length, uint32_t *result_length);
ntr_status ntr_set_value_key(ntr_state *s, void *handle, const ntr_unicode_string *name, uint32_t title_index,
                             uint32_t type, const void *data, uint32_t bytes);
ntr_status ntr_delete_key(ntr_state *s, void *handle);
ntr_status ntr_close(ntr_state *s, void *handle);
ntr_status ntr_format_current_user_key_path(ntr_state *s, ntr_unicode_string *out);
void ntr_init_unicode_string(ntr_unicode_string *dest, const uint16_t *source);
void ntr_free_unicode_string(ntr_state *s, ntr_unicode_string *str);

#ifdef __cplusplus
}
#endif
#endif
