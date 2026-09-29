/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 configuration manager (registry): internal interface between registry.c (the key/value tree) and sysreg.c
 * (the system-call layer). Nothing outside those two files includes this header.
 */
#ifndef K64_REGISTRY_H
#define K64_REGISTRY_H
#include "proc_internal.h"

/* ---- Windows registry value types (winnt.h) ---- */
#define REG_NONE 0
#define REG_SZ 1
#define REG_EXPAND_SZ 2
#define REG_BINARY 3
#define REG_DWORD 4
#define REG_MULTI_SZ 7
#define REG_QWORD 11

/* ---- key access rights (winnt.h) ---- */
#define KEY_QUERY_VALUE 0x0001u
#define KEY_SET_VALUE 0x0002u
#define KEY_CREATE_SUB_KEY 0x0004u
#define KEY_ENUMERATE_SUB_KEYS 0x0008u
#define KEY_NOTIFY 0x0010u
#define KEY_CREATE_LINK 0x0020u
#define ACC_DELETE 0x00010000u
#define ACC_READ_CONTROL 0x00020000u
#define ACC_WRITE_DAC 0x00040000u
#define ACC_WRITE_OWNER 0x00080000u
#define KEY_ALL_ACCESS_MASK 0x000F003Fu             /* STANDARD_RIGHTS_ALL without SYNCHRONIZE | all key rights */
#define KEY_READ_MASK 0x00020019u
#define KEY_WRITE_MASK 0x00020006u
#define ACC_GENERIC_READ 0x80000000u
#define ACC_GENERIC_WRITE 0x40000000u
#define ACC_GENERIC_EXECUTE 0x20000000u
#define ACC_GENERIC_ALL 0x10000000u
#define ACC_MAXIMUM_ALLOWED 0x02000000u

/* ---- create options (NtCreateKey CreateOptions) ---- */
#define REG_OPTION_VOLATILE 0x1u
#define REG_OPTION_CREATE_LINK 0x2u
#define REG_OPTION_BACKUP_RESTORE 0x4u
#define REG_OPTION_OPEN_LINK 0x8u

/* Limits (Windows: key name 255 chars, value name 16383 chars, nesting 512 levels). Kernel-heap budget is ours: the
 * whole registry may use REG_QUOTA_BYTES of the 4 MiB kernel heap and one value at most REG_MAX_VALUE_BYTES. */
#define REG_MAX_KEY_NAME 255u
#define REG_MAX_VALUE_NAME 16383u
#define REG_MAX_DEPTH 512u
#define REG_MAX_VALUE_BYTES (256u * 1024u)
#define REG_QUOTA_BYTES (1024u * 1024u)

typedef struct regval regval_t;
typedef struct regkey regkey_t;

struct regval {
    regval_t *next;
    uint32_t type, data_len;
    uint32_t name_len;                  /* UTF-16 code units, the name is not NUL terminated */
    uint32_t alloc_size;
    /* uint16_t name[name_len] follows, then (8-byte aligned) uint8_t data[data_len] */
};

enum { RK_DELETED = 1, RK_VOLATILE = 2, RK_FIXED = 4 };
struct regkey {
    regkey_t *parent, *child, *sibling;         /* children are kept sorted by upcased name */
    regval_t *values, *values_tail;             /* creation order */
    uint64_t last_write;                        /* FILETIME */
    uint32_t nsubkeys, nvalues;
    uint32_t refs;                              /* key objects (open handles) referring to this node */
    uint32_t flags;
    uint32_t name_len, class_len;               /* UTF-16 code units */
    uint32_t alloc_size;
    /* uint16_t name[name_len]; uint16_t class[class_len]; follow */
};

static inline uint16_t *regkey_name(regkey_t *k) { return (uint16_t *)(k + 1); }
static inline uint16_t *regkey_class(regkey_t *k) { return (uint16_t *)(k + 1) + k->name_len; }
static inline uint16_t *regval_name(regval_t *v) { return (uint16_t *)(v + 1); }
static inline uint8_t *regval_data(regval_t *v) { return (uint8_t *)(v + 1) + (((size_t)v->name_len * 2 + 7) & ~(size_t)7); }

/* Every function below except reg_lock/reg_unlock/reg_key_release requires the caller to hold the registry lock. */
void reg_lock(void);                            /* also seeds the default tree on first use */
void reg_unlock(void);
regkey_t *reg_root(void);
void reg_key_release(regkey_t *k);              /* locks internally: drops one handle reference */

/* Path resolution. `start` is the key the (relative) path is resolved against. On success *out is the key found or
 * created. `create` = 0 opens only (STATUS_OBJECT_NAME_NOT_FOUND if any component is missing); with create, missing
 * components are made (volatile if `options` has REG_OPTION_VOLATILE; the class string goes to the last one) and
 * *created reports whether any was. `start_can_create` says whether the caller's handle on `start` holds
 * KEY_CREATE_SUB_KEY: creating directly below `start` without it is STATUS_ACCESS_DENIED. */
int32_t reg_resolve(regkey_t *start, const uint16_t *path, uint32_t chars, int create, uint32_t options,
                    int start_can_create, const uint16_t *cls, uint32_t cls_chars, regkey_t **out, int *created);
int32_t reg_delete_key(regkey_t *k);
regval_t *reg_find_value(regkey_t *k, const uint16_t *name, uint32_t chars);
int32_t reg_set_value(regkey_t *k, const uint16_t *name, uint32_t chars, uint32_t type, const void *data, uint32_t len);
int32_t reg_delete_value(regkey_t *k, const uint16_t *name, uint32_t chars);
regkey_t *reg_nth_child(regkey_t *k, uint32_t index);
regval_t *reg_nth_value(regkey_t *k, uint32_t index);
/* Full path "\REGISTRY\MACHINE\..." of a live key; returns the number of code units (always the full length), writes at
 * most `cap`. */
uint32_t reg_key_path(regkey_t *k, uint16_t *out, uint32_t cap);
uint64_t reg_filetime_now(void);
uint32_t reg_upcase_char(uint16_t c);

#endif
