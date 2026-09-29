/* SPDX-License-Identifier: GPL-2.0-only
 * Original adapter. Registration order follows ReactOS
 * sdk/lib/rtl/vectoreh.c RtlpAddVectoredHandler at
 * 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8: a nonzero First argument inserts
 * at the head and zero appends. Remove reports success when the entry was
 * found, including while a dispatch still holds it. A NULL handler returns
 * an error; the pinned ReactOS routine does not check that pointer.
 * No Wine vectoreh body is copied. There is no native SEH or trap entry.
 */
#include "k32veh.h"
#define NTW_COOKIE_MAX 128u
typedef struct ntw_cookie {
    ntw_vectored_handler function;
    uint32_t state;
    ntwe_handle handle;
} ntw_cookie;
static ntwe_registry registry;
static ntw_cookie cookies[NTW_COOKIE_MAX];
static unsigned char lock_byte;
static int ready;
static unsigned char node_storage[NTWE_MAX_HANDLERS][128];
static unsigned char node_used[NTWE_MAX_HANDLERS];
static void enter_lock(void *user) {
    unsigned char previous;
    (void)user;
    do {
        previous = 1;
        __asm__ __volatile__("lock xchgb %0, %1" : "+r"(previous), "+m"(lock_byte) : : "memory");
    } while (previous);
}
static void leave_lock(void *user) {
    (void)user;
    __asm__ __volatile__("movb $0, %0" : "=m"(lock_byte) : : "memory");
}
static void *allocate_node(void *user, size_t bytes) {
    unsigned n;
    (void)user;
    if (bytes == 0 || bytes > sizeof(node_storage[0])) return 0;
    enter_lock(0);
    for (n = 0; n < NTWE_MAX_HANDLERS; ++n) {
        if (!node_used[n]) {
            node_used[n] = 1;
            leave_lock(0);
            return node_storage[n];
        }
    }
    leave_lock(0);
    return 0;
}
static void release_node(void *user, void *memory, size_t bytes) {
    unsigned n;
    (void)user;
    (void)bytes;
    enter_lock(0);
    for (n = 0; n < NTWE_MAX_HANDLERS; ++n) {
        if (node_storage[n] == memory) node_used[n] = 0;
    }
    leave_lock(0);
}
static int32_t thunk(ntwe_pointers *exception, void *user) {
    ntw_cookie *cookie = user;
    ntw_vectored_handler function = cookie->function;
    int32_t result = function(exception);
    if (cookie->state == 2) {
        cookie->function = 0;
        cookie->state = 0;
    }
    return result;
}
static int startup(void) {
    ntwe_ops ops;
    unsigned n;
    if (ready) return NTWE_OK;
    for (n = 0; n < NTW_COOKIE_MAX; ++n) cookies[n] = (ntw_cookie){0, 0, 0};
    for (n = 0; n < NTWE_MAX_HANDLERS; ++n) node_used[n] = 0;
    ops = (ntwe_ops){0, allocate_node, release_node, enter_lock, leave_lock};
    if (ntwe_init(&registry, &ops) != NTWE_OK) return NTWE_INVALID;
    ready = 1;
    return NTWE_OK;
}
int ntw_k32_init(void) { return startup(); }
void ntw_k32_test_reset(void) {
    if (ready) (void)ntwe_close(&registry);
    ready = 0;
    (void)startup();
}
int ntw_k32_add(uint32_t first, ntw_vectored_handler handler, void **out_handle) {
    unsigned slot;
    ntwe_handle handle = 0;
    int status;
    if (!out_handle) return NTWE_INVALID;
    if (startup() != NTWE_OK) return NTWE_INVALID;
    if (!handler) return NTWE_INVALID;
    for (slot = 0; slot < NTW_COOKIE_MAX; ++slot)
        if (!cookies[slot].state) break;
    if (slot == NTW_COOKIE_MAX) return NTWE_LIMIT;
    cookies[slot].function = handler;
    cookies[slot].state = 1;
    status = ntwe_add(&registry, NTWE_EXCEPTION, first ? 1 : 0, thunk, &cookies[slot], &handle);
    if (status != NTWE_OK) {
        cookies[slot].function = 0;
        cookies[slot].state = 0;
        return status;
    }
    cookies[slot].handle = handle;
    *out_handle = (void *)(uintptr_t)handle;
    return NTWE_OK;
}
static ntw_cookie *cookie_for(ntwe_handle handle) {
    unsigned n;
    for (n = 0; n < NTW_COOKIE_MAX; ++n)
        if (cookies[n].state && cookies[n].handle == handle) return &cookies[n];
    return 0;
}
static void clear_cookie(ntw_cookie *cookie) {
    cookie->function = 0;
    cookie->handle = 0;
    cookie->state = 0;
}
static void reclaim_dying(void) {
    unsigned n;
    for (n = 0; n < NTW_COOKIE_MAX; ++n)
        if (cookies[n].state == 2) clear_cookie(&cookies[n]);
}
int ntw_k32_remove(void *handle) {
    ntw_cookie *cookie;
    int status;
    if (!handle || startup() != NTWE_OK) return NTWE_INVALID;
    cookie = cookie_for((ntwe_handle)(uintptr_t)handle);
    status = ntwe_remove(&registry, NTWE_EXCEPTION, (ntwe_handle)(uintptr_t)handle);
    if (cookie && status == NTWE_OK) clear_cookie(cookie);
    if (cookie && status == NTWE_PENDING) cookie->state = 2;
    return status;
}
int ntw_k32_dispatch(void *record, void *context, int32_t *disposition) {
    int status;
    if (startup() != NTWE_OK) return NTWE_INVALID;
    status = ntwe_dispatch(&registry, NTWE_EXCEPTION, record, context, disposition);
    reclaim_dying();
    return status;
}
