/* SPDX-License-Identifier: GPL-2.0-only
 * Microsoft FlsAlloc/Get/Set/Free contract for one thread. Compared with
 * src/m98_fls.c index reservation (index 0 unused, limit 128, ERROR_NO_MORE_ITEMS)
 * and docs.microsoft.com FlsGetValue empty-slot ERROR_SUCCESS. Not copied.
 */
#include "fls.h"
enum { NTW_FLS_OK = 0, NTW_FLS_INVALID = 87, NTW_FLS_NO_MORE = 259 };
typedef struct ntw_fls_slot {
    int active;
    ntw_fls_callback callback;
    void *value;
} ntw_fls_slot;
static ntw_fls_slot slots[NTW_FLS_LIMIT];
static uint32_t fls_error;
uint32_t ntw_fls_last_error(void) { return fls_error; }
uint32_t ntw_fls_alloc(ntw_fls_callback callback) {
    uint32_t index;
    for (index = 1; index < NTW_FLS_LIMIT; ++index) {
        if (!slots[index].active) {
            slots[index].active = 1;
            slots[index].callback = callback;
            slots[index].value = 0;
            fls_error = NTW_FLS_OK;
            return index;
        }
    }
    fls_error = NTW_FLS_NO_MORE;
    return NTW_FLS_OUT_OF_INDEXES;
}
uint32_t ntw_fls_free(uint32_t index) {
    void *value;
    ntw_fls_callback callback;
    if (!index || index >= NTW_FLS_LIMIT || !slots[index].active) {
        fls_error = NTW_FLS_INVALID;
        return 0;
    }
    value = slots[index].value;
    callback = slots[index].callback;
    slots[index].active = 0;
    slots[index].callback = 0;
    slots[index].value = 0;
    if (value && callback) callback(value);
    fls_error = NTW_FLS_OK;
    return 1;
}
void *ntw_fls_get(uint32_t index) {
    if (!index || index >= NTW_FLS_LIMIT || !slots[index].active) {
        fls_error = NTW_FLS_INVALID;
        return 0;
    }
    fls_error = NTW_FLS_OK;
    return slots[index].value;
}
uint32_t ntw_fls_set(uint32_t index, void *value) {
    if (!index || index >= NTW_FLS_LIMIT || !slots[index].active) {
        fls_error = NTW_FLS_INVALID;
        return 0;
    }
    slots[index].value = value;
    fls_error = NTW_FLS_OK;
    return 1;
}
