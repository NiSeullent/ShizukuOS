/* SPDX-License-Identifier: GPL-2.0-only
 * Portable cores for M98K32CE.DLL; see k32_compat.h for the contract.
 */
#include "k32_compat.h"

#define CAS(p, o, n) __sync_bool_compare_and_swap((p), (o), (n))

typedef struct k32_waiter {
    struct k32_waiter *next, *prev;
    const volatile void *key;
    void *event;
    int exclusive;           /* SRW: wanted mode; CV: unused */
    int is_cv;
    volatile int granted;    /* SRW ownership handed over / CV notified */
} k32_waiter;

static k32_waiter *queue_head, *queue_tail;   /* guarded by k32p_lock */

static void enqueue(k32_waiter *w)
{
    w->next = 0; w->prev = queue_tail;
    if (queue_tail) queue_tail->next = w; else queue_head = w;
    queue_tail = w;
}
static void unlink_waiter(k32_waiter *w)
{
    if (w->prev) w->prev->next = w->next; else queue_head = w->next;
    if (w->next) w->next->prev = w->prev; else queue_tail = w->prev;
    w->next = w->prev = 0;
}
static int has_waiter(const volatile void *key, int is_cv)
{
    k32_waiter *w;
    for (w = queue_head; w; w = w->next) if (w->key == key && w->is_cv == is_cv) return 1;
    return 0;
}
/* Wake one already-unlinked waiter. The node may vanish once granted is
 * visible, so the event is read first. Exactly one signal per grant. */
static void grant(k32_waiter *w)
{
    void *event = w->event;
    w->granted = 1;
    __sync_synchronize();
    k32p_signal(event);
}

static int fast_try(volatile uint32_t *lock, int exclusive)
{
    uint32_t s = *lock;
    if (exclusive) return s == 0 && CAS(lock, 0u, K32_SRW_EXCLUSIVE);
    while (!(s & (K32_SRW_EXCLUSIVE | K32_SRW_WAITERS))) {
        if (s >= 0xfffffffcu) return 0;            /* shared count overflow */
        if (CAS(lock, s, s + K32_SRW_SHARED)) return 1;
        s = *lock;
    }
    return 0;
}

int k32_srw_try_acquire(volatile uint32_t *lock, int exclusive)
{
    return lock ? fast_try(lock, exclusive) : 0;
}

/* Called with k32p_lock held and the lock word showing no remaining owner. */
static void grant_next(volatile uint32_t *lock)
{
    k32_waiter *w = queue_head, *next, *batch[64];
    uint32_t state = 0;
    unsigned n = 0, i;
    while (w && (w->key != lock || w->is_cv)) w = w->next;
    if (!w) { __sync_lock_test_and_set(lock, 0u); return; }
    if (w->exclusive) {
        unlink_waiter(w);
        batch[n++] = w;
        state = K32_SRW_EXCLUSIVE;
    } else {
        /* Consecutive shared waiters of this lock, stopping at the next
         * exclusive waiter so writers are not starved. */
        while (w && n < 64) {
            next = w->next;
            if (w->key == lock && !w->is_cv) {
                if (w->exclusive) break;
                unlink_waiter(w);
                batch[n++] = w;
                state += K32_SRW_SHARED;
            }
            w = next;
        }
    }
    if (has_waiter(lock, 0)) state |= K32_SRW_WAITERS;
    __sync_lock_test_and_set(lock, state);
    __sync_synchronize();
    for (i = 0; i < n; i++) grant(batch[i]);
}

void k32_srw_acquire(volatile uint32_t *lock, int exclusive)
{
    k32_waiter self;
    void *event;
    uint32_t s;
    if (!lock || fast_try(lock, exclusive)) return;
    event = k32p_thread_event();
    k32p_lock();
    for (;;) {
        s = *lock;
        if (!(s & K32_SRW_WAITERS)) {
            if (exclusive ? s == 0 : !(s & K32_SRW_EXCLUSIVE)) {
                if (!exclusive && s >= 0xfffffffcu) { k32p_unlock(); k32p_yield(); k32p_lock(); continue; }
                if (CAS(lock, s, exclusive ? K32_SRW_EXCLUSIVE : s + K32_SRW_SHARED)) { k32p_unlock(); return; }
                continue;
            }
            if (!event) break;
            if (!CAS(lock, s, s | K32_SRW_WAITERS)) continue;
        } else if (!event) break;
        self.key = lock; self.event = event; self.exclusive = exclusive;
        self.is_cv = 0; self.granted = 0;
        enqueue(&self);
        k32p_unlock();
        /* Every grant is followed by exactly one signal; consume it even
         * if granted is already visible so no stale signal remains. */
        do { (void)k32p_wait(event, K32_INFINITE); } while (!self.granted);
        return;
    }
    /* No per-thread event could be created: poll without queueing. The
     * lock is still only taken through the same atomic transitions. */
    k32p_unlock();
    for (;;) {
        k32p_yield();
        k32p_lock();
        s = *lock;
        if (!(s & K32_SRW_WAITERS) && (exclusive ? s == 0 : !(s & K32_SRW_EXCLUSIVE)) &&
            s < 0xfffffffcu &&
            CAS(lock, s, exclusive ? K32_SRW_EXCLUSIVE : s + K32_SRW_SHARED)) { k32p_unlock(); return; }
        k32p_unlock();
    }
}

void k32_srw_release(volatile uint32_t *lock, int exclusive)
{
    uint32_t s;
    if (!lock) return;
    if (exclusive) {
        if (CAS(lock, K32_SRW_EXCLUSIVE, 0u)) return;
        k32p_lock();
        grant_next(lock);              /* state is EXCLUSIVE|WAITERS */
        k32p_unlock();
        return;
    }
    for (;;) {
        s = *lock;
        if (s & K32_SRW_WAITERS) break;
        if (s < K32_SRW_SHARED) return;                 /* not shared-owned: undefined, ignore */
        if (CAS(lock, s, s - K32_SRW_SHARED)) return;
    }
    k32p_lock();
    for (;;) {
        s = *lock;
        if (s < K32_SRW_SHARED) break;
        if (CAS(lock, s, s - K32_SRW_SHARED)) {
            s -= K32_SRW_SHARED;
            if ((s & ~K32_SRW_WAITERS) == 0 && (s & K32_SRW_WAITERS)) grant_next(lock);
            break;
        }
    }
    k32p_unlock();
}

int k32_cv_sleep(volatile uint32_t *cv, void *lock, int shared, uint32_t ms,
                 k32_lock_fn release, k32_lock_fn acquire)
{
    k32_waiter self;
    void *event = k32p_thread_event();
    int r, result;
    if (!event) return 2;
    self.key = cv; self.event = event; self.exclusive = 0; self.is_cv = 1; self.granted = 0;
    k32p_lock();
    enqueue(&self);
    k32p_unlock();
    release(lock, shared);
    r = k32p_wait(event, ms);
    if (r == 0) result = 0;
    else {
        k32p_lock();
        if (!self.granted) { unlink_waiter(&self); result = r == 1 ? 1 : 3; }
        else {
            /* Notified concurrently with timeout: the waker already signalled
             * under the queue lock; consume that signal. */
            (void)k32p_wait(event, K32_INFINITE);
            result = 0;
        }
        k32p_unlock();
    }
    acquire(lock, shared);
    return result;
}

void k32_cv_wake(volatile uint32_t *cv, int all)
{
    k32_waiter *w, *next;
    if (!cv) return;
    k32p_lock();
    for (w = queue_head; w; w = next) {
        next = w->next;
        if (w->key == cv && w->is_cv) {
            unlink_waiter(w);
            grant(w);
            if (!all) break;
        }
    }
    k32p_unlock();
}

unsigned k32_queue_depth(void)
{
    unsigned n = 0;
    k32_waiter *w;
    k32p_lock();
    for (w = queue_head; w; w = w->next) n++;
    k32p_unlock();
    return n;
}

/* ---- Version conditions ---------------------------------------------- */
uint64_t k32_ver_set_condition_mask(uint64_t mask, uint32_t type, uint8_t condition)
{
    unsigned shift;
    if (!type || !condition) return mask;
    condition &= 7;
    if (type & K32_VER_PRODUCT) shift = 7;
    else if (type & K32_VER_SUITE) shift = 6;
    else if (type & K32_VER_SPMAJOR) shift = 5;
    else if (type & K32_VER_SPMINOR) shift = 4;
    else if (type & K32_VER_PLATFORM) shift = 3;
    else if (type & K32_VER_BUILD) shift = 2;
    else if (type & K32_VER_MAJOR) shift = 1;
    else if (type & K32_VER_MINOR) shift = 0;
    else return mask;
    return mask | ((uint64_t)condition << (shift * 3));
}

static int compare(uint32_t have, uint32_t want, unsigned condition)
{
    switch (condition) {
    case K32_VER_EQUAL: return have == want ? K32_VERIFY_OK : K32_VERIFY_MISMATCH;
    case K32_VER_GREATER: return have > want ? K32_VERIFY_OK : K32_VERIFY_MISMATCH;
    case K32_VER_GREATER_EQUAL: return have >= want ? K32_VERIFY_OK : K32_VERIFY_MISMATCH;
    case K32_VER_LESS: return have < want ? K32_VERIFY_OK : K32_VERIFY_MISMATCH;
    case K32_VER_LESS_EQUAL: return have <= want ? K32_VERIFY_OK : K32_VERIFY_MISMATCH;
    default: return K32_VERIFY_BADARG;
    }
}
#define COND(c, shift) ((unsigned)(((c) >> ((shift) * 3)) & 7))

int k32_verify_version(const k32_osver *have, const k32_osver *want,
                       uint32_t type, uint64_t c)
{
    int status;
    if (!have || !want || !type || !c || (type & ~0xffu)) return K32_VERIFY_BADARG;
    if (type & K32_VER_PRODUCT) {
        status = compare(have->product, want->product, COND(c, 7));
        if (status) return status;
    }
    if (type & K32_VER_SUITE) {
        unsigned how = COND(c, 6);
        if (how == K32_VER_AND) { if ((have->suite & want->suite) != want->suite) return K32_VERIFY_MISMATCH; }
        else if (how == K32_VER_OR) { if (want->suite && !(have->suite & want->suite)) return K32_VERIFY_MISMATCH; }
        else return K32_VERIFY_BADARG;
    }
    if (type & K32_VER_PLATFORM) {
        status = compare(have->platform, want->platform, COND(c, 3));
        if (status) return status;
    }
    if (type & K32_VER_BUILD) {
        status = compare(have->build, want->build, COND(c, 2));
        if (status) return status;
    }
    if (type & (K32_VER_MAJOR | K32_VER_MINOR | K32_VER_SPMAJOR | K32_VER_SPMINOR)) {
        /* Hierarchical compare: the condition of the most significant field
         * present governs; a lower field is consulted only on equality. */
        unsigned condition = (type & K32_VER_MAJOR) ? COND(c, 1) : (type & K32_VER_MINOR) ? COND(c, 0)
                           : (type & K32_VER_SPMAJOR) ? COND(c, 5) : COND(c, 4);
        int next = 1;
        if (condition < K32_VER_EQUAL || condition > K32_VER_LESS_EQUAL) return K32_VERIFY_BADARG;
        status = K32_VERIFY_OK;
        if (type & K32_VER_MAJOR) { status = compare(have->major, want->major, condition); next = have->major == want->major; }
        if (next && (type & K32_VER_MINOR)) { status = compare(have->minor, want->minor, condition); next = have->minor == want->minor; }
        if (next && (type & K32_VER_SPMAJOR)) { status = compare(have->sp_major, want->sp_major, condition); next = have->sp_major == want->sp_major; }
        if (next && (type & K32_VER_SPMINOR)) status = compare(have->sp_minor, want->sp_minor, condition);
        if (status) return status;
    }
    return K32_VERIFY_OK;
}

/* ---- Pointer encoding: rotate-xor, inverse pair keyed by a per-process
 * cookie, as Windows does with its process cookie. -------------------- */
static uint32_t rotr(uint32_t v, unsigned n) { n &= 31; return n ? (v >> n) | (v << (32 - n)) : v; }
static uint32_t rotl(uint32_t v, unsigned n) { n &= 31; return n ? (v << n) | (v >> (32 - n)) : v; }
uint32_t k32_encode(uint32_t value, uint32_t cookie) { return rotr(value ^ cookie, cookie & 31); }
uint32_t k32_decode(uint32_t value, uint32_t cookie) { return rotl(value, cookie & 31) ^ cookie; }

/* ---- Vectored exception handler list ----------------------------------- */
typedef struct k32_veh_node { void *handler; int prev, next; unsigned refs, state; } k32_veh_node;
static k32_veh_node veh_pool[K32_VEH_MAX];
static int veh_head = -1, veh_tail = -1;
static unsigned veh_live;

static void veh_unlink(int i)
{
    k32_veh_node *n = &veh_pool[i];
    if (n->prev >= 0) veh_pool[n->prev].next = n->next; else veh_head = n->next;
    if (n->next >= 0) veh_pool[n->next].prev = n->prev; else veh_tail = n->prev;
    n->handler = 0; n->prev = n->next = -1; n->state = 0; n->refs = 0;
}
void *k32_veh_add(int first, void *handler)
{
    unsigned i;
    if (!handler) return 0;
    k32p_lock();
    for (i = 0; i < K32_VEH_MAX && veh_pool[i].state; i++) {}
    if (i == K32_VEH_MAX) { k32p_unlock(); return 0; }
    veh_pool[i].handler = handler; veh_pool[i].state = 1; veh_pool[i].refs = 0;
    if (first) {
        veh_pool[i].prev = -1; veh_pool[i].next = veh_head;
        if (veh_head >= 0) veh_pool[veh_head].prev = (int)i; else veh_tail = (int)i;
        veh_head = (int)i;
    } else {
        veh_pool[i].next = -1; veh_pool[i].prev = veh_tail;
        if (veh_tail >= 0) veh_pool[veh_tail].next = (int)i; else veh_head = (int)i;
        veh_tail = (int)i;
    }
    veh_live++;
    k32p_unlock();
    return &veh_pool[i];
}
int k32_veh_remove(void *handle)
{
    uintptr_t a = (uintptr_t)handle, b = (uintptr_t)veh_pool;
    int i, ok = 0;
    if (a < b || a >= b + sizeof(veh_pool) || (a - b) % sizeof(veh_pool[0])) return 0;
    i = (int)((a - b) / sizeof(veh_pool[0]));
    k32p_lock();
    if (veh_pool[i].state == 1) {
        ok = 1; veh_live--;
        if (veh_pool[i].refs) veh_pool[i].state = 2; else veh_unlink(i);
    }
    k32p_unlock();
    return ok;
}
long k32_veh_dispatch(void *pointers, k32_veh_invoke invoke)
{
    int i, next;
    long r = 0;
    if (!invoke) return 0;
    k32p_lock();
    for (i = veh_head; i >= 0; i = next) {
        if (veh_pool[i].state == 1) {
            void *h = veh_pool[i].handler;
            veh_pool[i].refs++;
            k32p_unlock();
            r = invoke(h, pointers);
            k32p_lock();
            veh_pool[i].refs--;
        }
        next = veh_pool[i].next;
        if (veh_pool[i].state == 2 && !veh_pool[i].refs) veh_unlink(i);
        if (r == -1) break;
    }
    k32p_unlock();
    return r == -1 ? -1 : 0;
}
unsigned k32_veh_count(void) { unsigned n; k32p_lock(); n = veh_live; k32p_unlock(); return n; }

/* ---- Bounded frame-pointer walk ---------------------------------------- */
unsigned k32_walk_frames(uintptr_t fp, uintptr_t low, uintptr_t high, unsigned skip,
                         unsigned count, void **out, uint32_t *hash)
{
    unsigned index = 0, n = 0;
    uint32_t sum = 0;
    const uintptr_t word = sizeof(uintptr_t);
    if (!out || !count || high <= low || high - low < 2 * word) { if (hash) *hash = 0; return 0; }
    while (n < count) {
        uintptr_t next, ret;
        if (fp < low || fp > high - 2 * word || (fp & (word - 1))) break;
        next = ((const uintptr_t *)fp)[0];
        ret = ((const uintptr_t *)fp)[1];
        if (!ret) break;
        if (index++ >= skip) { out[n++] = (void *)ret; sum += (uint32_t)ret; }
        if (next <= fp) break;
        fp = next;
    }
    if (hash) *hash = sum;
    return n;
}

/* ---- Logical processor information ------------------------------------- */
static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
int k32_logical_processor_info(uint32_t mask, uint8_t *buffer, uint32_t *length)
{
    unsigned bits = 0, i, e = 0;
    uint32_t need;
    if (!length || !mask) return K32_LPI_BADARG;
    for (i = 0; i < 32; i++) if (mask & (1u << i)) bits++;
    need = (bits + 2) * K32_LPI_ENTRY;
    if (!buffer || *length < need) { *length = need; return K32_LPI_SHORT; }
    for (i = 0; i < need; i++) buffer[i] = 0;
    for (i = 0; i < 32; i++) if (mask & (1u << i)) {          /* RelationProcessorCore, Flags 0 */
        put32(buffer + e * K32_LPI_ENTRY, 1u << i); put32(buffer + e * K32_LPI_ENTRY + 4, 0); e++;
    }
    put32(buffer + e * K32_LPI_ENTRY, mask); put32(buffer + e * K32_LPI_ENTRY + 4, 3); e++;  /* package */
    put32(buffer + e * K32_LPI_ENTRY, mask); put32(buffer + e * K32_LPI_ENTRY + 4, 1); e++;  /* NUMA node 0 */
    *length = need;
    return K32_LPI_OK;
}

/* ---- Computer name formats --------------------------------------------- */
int k32_compose_computer_name(unsigned format, const char *netbios, const char *dns_host,
                              const char *dns_domain, char *out, unsigned cap, unsigned *need)
{
    const char *a, *b = 0;
    unsigned la = 0, lb = 0, total;
    if (format > 7 || !netbios || !need) return -1;
    format &= 3;                                   /* Physical* == logical on a non-cluster Win98 */
    if (format == 0) a = netbios;
    else if (format == 2) a = dns_domain ? dns_domain : "";
    else {
        a = dns_host && *dns_host ? dns_host : netbios;  /* MSTCP host name defaults to computer name */
        if (format == 3 && dns_domain && *dns_domain) b = dns_domain;
    }
    while (a[la]) la++;
    if (b) while (b[lb]) lb++;
    total = la + (b ? 1 + lb : 0);
    *need = total + 1;
    if (!out || cap < total + 1) return -2;
    for (unsigned i = 0; i < la; i++) out[i] = a[i];
    if (b) { out[la] = '.'; for (unsigned i = 0; i < lb; i++) out[la + 1 + i] = b[i]; }
    out[total] = 0;
    return (int)total;
}

/* ---- NTWPE32-mapped image registry ------------------------------------- */
typedef struct k32_image { uintptr_t base; uint32_t size; char path[K32_IMAGE_PATH]; } k32_image;
static k32_image images[K32_IMAGE_MAX];
static int ci_equal(const char *a, const char *b)
{
    for (;; a++, b++) {
        unsigned x = (unsigned char)*a, y = (unsigned char)*b;
        if (x >= 'a' && x <= 'z') x -= 32;
        if (y >= 'a' && y <= 'z') y -= 32;
        if (x != y) return 0;
        if (!x) return 1;
    }
}
int k32_image_register(uintptr_t base, uint32_t size, const char *path)
{
    unsigned i, n = 0, slot = K32_IMAGE_MAX;
    if (!base || !size || !path || base + size < base || (uint64_t)base + size > 0x100000000ull) return 0;  /* x86 address space */
    while (path[n]) if (++n >= K32_IMAGE_PATH) return 0;
    if (!n) return 0;
    k32p_lock();
    for (i = 0; i < K32_IMAGE_MAX; i++) {
        if (!images[i].base) { if (slot == K32_IMAGE_MAX) slot = i; continue; }
        if (base < images[i].base + images[i].size && images[i].base < base + size) { k32p_unlock(); return 0; }
    }
    if (slot == K32_IMAGE_MAX) { k32p_unlock(); return 0; }
    images[slot].size = size;
    for (i = 0; i <= n; i++) images[slot].path[i] = path[i];
    images[slot].base = base;
    k32p_unlock();
    return 1;
}
int k32_image_unregister(uintptr_t base)
{
    unsigned i; int ok = 0;
    k32p_lock();
    for (i = 0; i < K32_IMAGE_MAX; i++) if (base && images[i].base == base) { images[i].base = 0; images[i].size = 0; images[i].path[0] = 0; ok = 1; }
    k32p_unlock();
    return ok;
}
int k32_image_find(uintptr_t address, uintptr_t *base, uint32_t *size, char *path, unsigned cap)
{
    unsigned i, n;
    k32p_lock();
    for (i = 0; i < K32_IMAGE_MAX; i++)
        if (images[i].base && address >= images[i].base && address - images[i].base < images[i].size) {
            if (base) *base = images[i].base;
            if (size) *size = images[i].size;
            if (path && cap) {
                for (n = 0; images[i].path[n] && n + 1 < cap; n++) path[n] = images[i].path[n];
                path[n] = 0;
                if (images[i].path[n]) { k32p_unlock(); return -1; }   /* truncated */
            }
            k32p_unlock();
            return 1;
        }
    k32p_unlock();
    return 0;
}
int k32_image_by_name(const char *name, uintptr_t *base)
{
    unsigned i;
    if (!name || !*name) return 0;
    k32p_lock();
    for (i = 0; i < K32_IMAGE_MAX; i++) {
        const char *p = images[i].path, *leaf = p;
        if (!images[i].base) continue;
        for (; *p; p++) if (*p == '\\' || *p == '/' || *p == ':') leaf = p + 1;
        if (ci_equal(name, images[i].path) || ci_equal(name, leaf)) { if (base) *base = images[i].base; k32p_unlock(); return 1; }
    }
    k32p_unlock();
    return 0;
}
unsigned k32_image_list(uintptr_t *bases, unsigned cap)
{
    unsigned i, n = 0;
    k32p_lock();
    for (i = 0; i < K32_IMAGE_MAX; i++) if (images[i].base) { if (bases && n < cap) bases[n] = images[i].base; n++; }
    k32p_unlock();
    return n;
}
