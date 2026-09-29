/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded synchronous VxD adapter. See REFERENCES.md for ABI facts.
 */
#include "bridge.h"

_Static_assert(sizeof(struct ntwv_dioc) == 48, "VWIN32 DIOC ABI");
_Static_assert(sizeof(struct ntwv_query) == 32, "query wire ABI");
static struct ntw_context context;
static uint32_t live, selftest;

int ntwv_initialize(const struct ntw_lock_ops *ops)
{
    ntw_handle handle;
    if (live || ntw_initialize(&context, ops) != NTW_OK)
        return 0;
    /* Real object behavior, before exposing any request interface. */
    if (ntw_event_create(&context, 0, 0, NTW_EVENT_ALL, &handle) != NTW_OK)
        goto failed;
    if (ntw_event_try_wait(&context, handle) != NTW_PENDING ||
        ntw_event_set(&context, handle, 0) != NTW_OK ||
        ntw_event_try_wait(&context, handle) != NTW_OK ||
        ntw_event_try_wait(&context, handle) != NTW_PENDING) {
        (void)ntw_close(&context, handle);
        goto failed;
    }
    if (ntw_close(&context, handle) != NTW_OK)
        goto failed;
    selftest = live = 1;
    return 1;
failed:
    (void)ntw_shutdown(&context);
    return 0;
}

int ntwv_shutdown(void)
{
    if (!live || ntw_shutdown(&context) != NTW_OK)
        return 0;
    live = selftest = 0;
    return 1;
}

struct pinned {
    uint32_t original_page, count, alias, offset;
};

static int user_range(uint32_t address, uint32_t bytes)
{
    /* This initial ABI accepts only the Win32 private arena. Shared/system,
     * low DOS mappings, overflow and zero-length requests are excluded. */
    return bytes != 0 && address >= 0x00400000u && address < 0x80000000u &&
           bytes <= 0x80000000u - address;
}

static int pin(const struct ntwv_pages *ops, uint32_t address, uint32_t bytes,
               struct pinned *range)
{
    uint32_t alias;
    range->original_page = address >> 12;
    range->offset = address & 4095u;
    range->count = (range->offset + bytes + 4095u) >> 12;
    range->alias = 0;
    if (ops->check(range->original_page, range->count, 0) != range->count)
        return 0;
    alias = ops->lock(range->original_page, range->count, NTWV_MAP_GLOBAL);
    if (!alias)
        return 0;
    /* The service contract returns a page-aligned system alias. */
    if (alias < 0x80000000u || (alias & 4095u) != 0 ||
        range->count > ((UINT32_MAX - alias) >> 12) + 1) {
        (void)ops->unlock(alias >> 12, range->count, NTWV_MAP_GLOBAL);
        return 0;
    }
    range->alias = alias;
    return 1;
}

static int writable_alias(const struct ntwv_pages *ops, const struct pinned *range)
{
    uint32_t original[2], alias[2], i;
    if (range->count > 2 ||
        !ops->ptes(range->original_page, range->count, original, 0) ||
        !ops->ptes(range->alias >> 12, range->count, alias, 0))
        return 0;
    for (i = 0; i < range->count; ++i) {
        /* Present, writable and user-accessible original; writable present
         * alias must refer to exactly the same pinned physical page. */
        if ((original[i] & 7u) != 7u || (alias[i] & 3u) != 3u ||
            (original[i] & 0xfffff000u) != (alias[i] & 0xfffff000u))
            return 0;
    }
    return 1;
}

uint32_t ntwv_dioc(const struct ntwv_dioc *request, const struct ntwv_pages *ops)
{
    struct ntwv_query reply = { NTWV_QUERY_MAGIC, sizeof(struct ntwv_query),
        1, NTW_ABI_VERSION, NTW_MAX_OBJECTS, 1, 0, 0 };
    struct pinned output, returned;
    uint32_t bytes = sizeof(reply), result = NTWV_ERROR_NOACCESS;
    uintptr_t saved;
    if (!request)
        return NTWV_ERROR_INVALID_PARAMETER;
    if (!live)
        return NTWV_ERROR_NOT_READY;
    if (request->code == 0)
        return 0; /* DIOC_OPEN/GETVERSION handshake; no user buffer access. */
    if (request->code == UINT32_MAX)
        return 1; /* DIOC_CLOSEHANDLE: documented VXD_SUCCESS. */
    if (request->code != NTWV_IOCTL_QUERY)
        return NTWV_ERROR_NOT_SUPPORTED;
    if (request->input || request->input_bytes || request->overlapped)
        return NTWV_ERROR_INVALID_PARAMETER;
    if (request->output_bytes < bytes)
        return NTWV_ERROR_INSUFFICIENT_BUFFER;
    if (!user_range(request->output, bytes) || !user_range(request->returned, 4) ||
        (request->output < request->returned + 4 && request->returned < request->output + bytes))
        return NTWV_ERROR_INVALID_PARAMETER;
    if (!ops || !ops->check || !ops->lock || !ops->unlock || !ops->ptes ||
        !ops->enter || !ops->leave || !ops->write)
        return NTWV_ERROR_NOT_SUPPORTED;
    if (!pin(ops, request->output, bytes, &output))
        return NTWV_ERROR_NOACCESS;
    if (!pin(ops, request->returned, 4, &returned)) {
        (void)ops->unlock(output.alias >> 12, output.count, NTWV_MAP_GLOBAL);
        return NTWV_ERROR_NOACCESS;
    }
    /* Win98 uniprocessor, synchronous callback only. Both aliases are pinned
     * before disabling IRQs. No blocking calls, user pointers or allocations
     * occur inside the bounded PTE-validation / 36-byte-copy interval. */
    saved = ops->enter(0);
    if (writable_alias(ops, &output) && writable_alias(ops, &returned)) {
        reply.initialized = live;
        reply.selftest = selftest;
        ops->write(output.alias + output.offset, &reply, bytes);
        ops->write(returned.alias + returned.offset, &bytes, 4);
        result = 0;
    }
    ops->leave(0, saved);
    if (!ops->unlock(returned.alias >> 12, returned.count, NTWV_MAP_GLOBAL))
        result = NTWV_ERROR_NOACCESS;
    if (!ops->unlock(output.alias >> 12, output.count, NTWV_MAP_GLOBAL))
        result = NTWV_ERROR_NOACCESS;
    return result;
}
