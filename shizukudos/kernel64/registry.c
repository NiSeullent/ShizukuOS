/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 configuration manager: the in-memory registry (key/value tree).
 *
 * What it is
 *   A tree of keys under one root, "\REGISTRY", with the two hive roots "MACHINE" and "USER" below it. Every key owns an
 *   ordered list of values. Names are UTF-16 and compared case-insensitively (see reg_upcase_char); key and value names
 *   keep the case they were created with. Sub-keys are enumerated in upcased-name order, values in creation order.
 *   Value types are opaque 32-bit numbers with binary payloads (REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD,
 *   REG_MULTI_SZ, REG_QWORD ... nothing here interprets them); the payload is stored byte-exact, no terminator is
 *   added or removed.
 *
 * What it is not (deliberate, documented limits)
 *   - Volatile only: everything lives in the kernel heap and is gone at reboot. There is no hive file. The
 *     REG_OPTION_VOLATILE flag is still tracked so the Windows rule holds that a stable key cannot be created below a
 *     volatile one (STATUS_CHILD_MUST_BE_VOLATILE).
 *   - Security is ignored: keys have no security descriptor, every caller is the single administrator and is granted any
 *     access it asks for. The access mask stored in the handle IS enforced for the operation classes (KEY_QUERY_VALUE,
 *     KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, DELETE), because that is per-handle NT behaviour.
 *   - No symbolic links, no hive load/unload, no change notification, no transactions.
 *   - Bounded: at most REG_QUOTA_BYTES of kernel heap in total, values up to REG_MAX_VALUE_BYTES.
 *
 * Concurrency: one kernel mutex serialises every tree access (the kernel is preemptible; the tree is small and the
 * operations short). Key objects (open handles) hold a reference on their node; a deleted key stays allocated but
 * unreachable until its last handle is closed, and operations through such a handle fail with STATUS_KEY_DELETED.
 *
 * Default tree (only what the runtime itself needs; see seed_defaults):
 *   MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion   version values that match the PEB the loader reports
 *                                                          (10.0, build 22631: a PROFILE value, not a verified build)
 *   MACHINE\SOFTWARE\Classes                               what advapi32 maps HKEY_CLASSES_ROOT to (a simplification:
 *                                                          Windows merges HKLM and HKCU class data)
 *   MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName  the computer name the loader puts in COMPUTERNAME
 *   MACHINE\SYSTEM\CurrentControlSet\Hardware Profiles\Current   HKEY_CURRENT_CONFIG target (empty)
 *   USER\.DEFAULT and USER\<SHZ_USER_SID>                  the single user of the system (HKEY_CURRENT_USER target)
 */
#include "registry.h"

/* The one interactive identity of the system (documented constant, see also advapi32's GetUserNameW). */
#define SHZ_USER_SID "S-1-5-21-2210311251-3305482031-1094512843-1001"

static kmutex_t reg_mutex;                      /* zero-initialised == unlocked */
static regkey_t *g_root;
static uint32_t g_bytes;                        /* heap charged to the registry */
static int g_seeded;

static void seed_defaults(void);

void reg_lock(void)
{
    mutex_lock(&reg_mutex);
    if (!g_root)
        seed_defaults();
}

void reg_unlock(void) { mutex_unlock(&reg_mutex); }
regkey_t *reg_root(void) { return g_root; }

/* FILETIME for LastWriteTime. The wall clock (a hypercall) is read once; afterwards time advances with the scheduler tick
 * (TICK_US), so a registry write costs no hypercall. Resolution is one tick. Always called with the registry lock held. */
uint64_t reg_filetime_now(void)
{
    static uint64_t base_ft, base_tick;
    static int have_base;
    if (!have_base) {
        hcreg_t secs = 0;
        shz_hcall(SHZ_HC_WALLTIME, 0, 0, &secs);
        base_ft = (secs + 11644473600ull) * 10000000ull + (shz_time_ns() % 1000000000ull) / 100;
        base_tick = ticks_now();
        have_base = 1;
    }
    return base_ft + (ticks_now() - base_tick) * (TICK_US * 10ull);          /* one tick = TICK_US microseconds = TICK_US * 10 x 100 ns */
}

/* ---------------------------------------------------------------- names */
/* Case folding: ASCII, Latin-1, Greek and Cyrillic basic letters. Anything else compares by exact code unit. */
uint32_t reg_upcase_char(uint16_t c)
{
    if (c < 0x80) return c >= 'a' && c <= 'z' ? (uint32_t)c - 32 : c;
    if (c >= 0xe0 && c <= 0xfe && c != 0xf7) return (uint32_t)c - 32;
    if (c == 0xff) return 0x178;
    if (c >= 0x3b1 && c <= 0x3c9 && c != 0x3c2) return (uint32_t)c - 32;
    if (c >= 0x430 && c <= 0x44f) return (uint32_t)c - 32;
    if (c >= 0x450 && c <= 0x45f) return (uint32_t)c - 80;
    return c;
}

static int name_cmp(const uint16_t *a, uint32_t an, const uint16_t *b, uint32_t bn)
{
    const uint32_t n = an < bn ? an : bn;
    uint32_t i;
    for (i = 0; i < n; ++i) {
        const uint32_t x = reg_upcase_char(a[i]), y = reg_upcase_char(b[i]);
        if (x != y) return x < y ? -1 : 1;
    }
    return an == bn ? 0 : an < bn ? -1 : 1;
}

/* ---------------------------------------------------------------- allocation with quota */
static void *reg_alloc(uint32_t size, uint32_t credit)
{
    void *p;
    if (g_seeded && (uint64_t)g_bytes - credit + size > REG_QUOTA_BYTES) return 0;
    p = kzalloc(size);
    if (p) g_bytes += size;
    return p;
}

static void reg_free(void *p, uint32_t size)
{
    kfree(p);
    g_bytes -= size;
}

static regkey_t *key_alloc(const uint16_t *name, uint32_t nchars, const uint16_t *cls, uint32_t cchars, uint32_t flags)
{
    const uint32_t size = (uint32_t)sizeof(regkey_t) + (nchars + cchars) * 2;
    regkey_t *k = reg_alloc(size, 0);
    if (!k) return 0;
    k->alloc_size = size;
    k->name_len = nchars;
    k->class_len = cchars;
    k->flags = flags;
    k->last_write = reg_filetime_now();
    memcpy(regkey_name(k), name, nchars * 2);
    if (cchars) memcpy(regkey_class(k), cls, cchars * 2);
    return k;
}

/* ---------------------------------------------------------------- change notification */
typedef struct regnotify regnotify_t;
struct regnotify {
    regnotify_t *next;
    regkey_t *key;
    kobject_t *key_obj;                 /* the key object the registration was made on (not referenced) */
    kobject_t *event;                   /* referenced; may be NULL when only the IO_STATUS_BLOCK is polled */
    process_t *proc;
    uint64_t iosb;                      /* user address of an IO_STATUS_BLOCK, or 0 */
    uint32_t filter;
    int subtree;
};
static regnotify_t *g_notify;
static uint32_t g_notify_count;

/* Registry lock held. Completes and frees `n` (already unlinked). */
static void notify_complete(regnotify_t *n, int32_t status)
{
    if (n->iosb) {
        const uint64_t iosb[2] = { (uint64_t)(int64_t)status, 0 };
        copy_to_user(n->proc, n->iosb, iosb, sizeof iosb);
    }
    if (n->event) {
        ob_signal_event(n->event);
        ob_deref(n->event);             /* an event object: never takes the registry lock */
    }
    kfree(n);
    --g_notify_count;
}

int32_t reg_notify_add(regkey_t *k, kobject_t *key_obj, kobject_t *event, process_t *p, uint64_t iosb_va, uint32_t filter, int subtree)
{
    regnotify_t *n;
    if (k->flags & RK_DELETED) return STATUS_KEY_DELETED;
    if (g_notify_count >= REG_NOTIFY_MAX_REGISTRATIONS) return STATUS_NO_MEMORY;
    n = kzalloc(sizeof *n);
    if (!n) return STATUS_NO_MEMORY;
    n->key = k;
    n->key_obj = key_obj;
    n->event = event;
    if (event) ob_ref(event);
    n->proc = p;
    n->iosb = iosb_va;
    n->filter = filter;
    n->subtree = subtree;
    n->next = g_notify;
    g_notify = n;
    ++g_notify_count;
    return STATUS_SUCCESS;
}

/* Something in `changed` happened (`what` is one REG_NOTIFY_CHANGE_* bit): complete every matching registration on the key
 * itself and every sub-tree registration on one of its ancestors. */
static void notify_fire(regkey_t *changed, uint32_t what)
{
    regnotify_t **pp = &g_notify;
    while (*pp) {
        regnotify_t *n = *pp;
        int match = 0;
        if (n->filter & what) {
            if (n->key == changed) match = 1;
            else if (n->subtree) {
                regkey_t *a;
                for (a = changed->parent; a; a = a->parent)
                    if (a == n->key) { match = 1; break; }
            }
        }
        if (match) { *pp = n->next; notify_complete(n, STATUS_SUCCESS); }
        else pp = &n->next;
    }
}

/* Completes every registration made on key `k` (the key is going away) or on key object `obj` (the object is destroyed). */
static void notify_drop(regkey_t *k, kobject_t *obj, int32_t status)
{
    regnotify_t **pp = &g_notify;
    while (*pp) {
        regnotify_t *n = *pp;
        if ((k && n->key == k) || (obj && n->key_obj == obj)) { *pp = n->next; notify_complete(n, status); }
        else pp = &n->next;
    }
}

/* ---------------------------------------------------------------- tree */
static regkey_t *find_child(regkey_t *k, const uint16_t *name, uint32_t chars)
{
    regkey_t *c;
    for (c = k->child; c; c = c->sibling) {
        const int r = name_cmp(regkey_name(c), c->name_len, name, chars);
        if (r == 0) return c;
        if (r > 0) break;                        /* sorted: past the insertion point */
    }
    return 0;
}

static void link_child(regkey_t *parent, regkey_t *c)
{
    regkey_t **pp = &parent->child;
    while (*pp && name_cmp(regkey_name(*pp), (*pp)->name_len, regkey_name(c), c->name_len) < 0)
        pp = &(*pp)->sibling;
    c->sibling = *pp;
    *pp = c;
    c->parent = parent;
    ++parent->nsubkeys;
    parent->last_write = reg_filetime_now();
    if (g_seeded) notify_fire(parent, REG_NOTIFY_CHANGE_NAME);
}

static uint32_t key_depth(regkey_t *k)
{
    uint32_t d = 0;
    for (; k && k->parent; k = k->parent) ++d;
    return d;
}

int32_t reg_resolve(regkey_t *start, const uint16_t *path, uint32_t chars, int create, uint32_t options,
                    int start_can_create, const uint16_t *cls, uint32_t cls_chars, regkey_t **out, int *created)
{
    regkey_t *k = start;
    uint32_t i, depth;
    int made = 0;
    if (start->flags & RK_DELETED) return STATUS_KEY_DELETED;
    if (chars && path[chars - 1] == '\\') --chars;        /* one trailing separator is tolerated */
    /* validate every component before touching the tree, so a bad path never leaves half its keys behind */
    for (i = 0; i < chars; ) {
        uint32_t s = i;
        while (i < chars && path[i] != '\\') ++i;
        if (i == s) return STATUS_OBJECT_NAME_INVALID;     /* empty component ("a\\b") */
        if (i - s > REG_MAX_KEY_NAME) return STATUS_INVALID_PARAMETER;
        if (i < chars) ++i;
    }
    depth = key_depth(start);
    for (i = 0; i < chars; ) {
        const uint32_t s = i;
        regkey_t *child;
        uint32_t len;
        while (i < chars && path[i] != '\\') ++i;
        len = i - s;
        child = find_child(k, path + s, len);
        if (!child) {
            const int last = i >= chars;
            uint32_t flags = options & REG_OPTION_VOLATILE ? RK_VOLATILE : 0;
            if (!create) return STATUS_OBJECT_NAME_NOT_FOUND;
            if (k == g_root && g_seeded) return STATUS_ACCESS_DENIED;     /* \REGISTRY only holds the hive roots */
            if (k == start && !start_can_create) return STATUS_ACCESS_DENIED;
            if ((k->flags & RK_VOLATILE) && !(flags & RK_VOLATILE)) return STATUS_CHILD_MUST_BE_VOLATILE;
            if (depth + 1 > REG_MAX_DEPTH) return STATUS_INVALID_PARAMETER;
            child = key_alloc(path + s, len, last ? cls : 0, last ? cls_chars : 0, flags);
            if (!child) return STATUS_NO_MEMORY;
            link_child(k, child);
            made = 1;
        }
        k = child;
        ++depth;
        if (i < chars) ++i;
    }
    *out = k;
    if (created) *created = made;
    return STATUS_SUCCESS;
}

regkey_t *reg_nth_child(regkey_t *k, uint32_t index)
{
    regkey_t *c;
    for (c = k->child; c && index; c = c->sibling) --index;
    return c;
}

regval_t *reg_nth_value(regkey_t *k, uint32_t index)
{
    regval_t *v;
    for (v = k->values; v && index; v = v->next) --index;
    return v;
}

static void free_values(regkey_t *k)
{
    regval_t *v = k->values;
    while (v) {
        regval_t *n = v->next;
        reg_free(v, v->alloc_size);
        v = n;
    }
    k->values = k->values_tail = 0;
    k->nvalues = 0;
}

static void key_free_now(regkey_t *k)
{
    free_values(k);
    reg_free(k, k->alloc_size);
}

int32_t reg_delete_key(regkey_t *k)
{
    regkey_t **pp;
    if (k->flags & RK_DELETED) return STATUS_KEY_DELETED;
    if ((k->flags & RK_FIXED) || k->child) return STATUS_CANNOT_DELETE;   /* hive roots; keys with sub-keys */
    notify_fire(k->parent, REG_NOTIFY_CHANGE_NAME);            /* watchers of the parent (and sub-tree watchers above it) */
    notify_drop(k, 0, STATUS_SUCCESS);                        /* watchers of the deleted key itself complete */
    for (pp = &k->parent->child; *pp; pp = &(*pp)->sibling)
        if (*pp == k) { *pp = k->sibling; break; }
    --k->parent->nsubkeys;
    k->parent->last_write = reg_filetime_now();
    k->parent = 0;
    k->sibling = 0;
    k->flags |= RK_DELETED;
    free_values(k);
    if (k->refs == 0) key_free_now(k);
    return STATUS_SUCCESS;
}

void reg_key_release(regkey_t *k)
{
    reg_lock();
    KASSERT(k->refs > 0);
    if (--k->refs == 0 && (k->flags & RK_DELETED))
        key_free_now(k);
    reg_unlock();
}

void reg_key_object_free(kobject_t *o)
{
    regkey_t *k = o->u.key.node;
    o->u.key.node = 0;
    reg_lock();
    notify_drop(0, o, STATUS_NOTIFY_CLEANUP);                 /* the handle is gone: its pending notifications complete */
    if (k) {
        KASSERT(k->refs > 0);
        if (--k->refs == 0 && (k->flags & RK_DELETED))
            key_free_now(k);
    }
    reg_unlock();
}

uint32_t reg_key_path(regkey_t *k, uint16_t *out, uint32_t cap)
{
    uint32_t total = 0, pos;
    regkey_t *c;
    for (c = k; c; c = c->parent) total += 1 + c->name_len;      /* "\" + name */
    pos = total;
    for (c = k; c; c = c->parent) {
        pos -= c->name_len;
        if (pos < cap) {
            uint32_t i;
            for (i = 0; i < c->name_len && pos + i < cap; ++i) out[pos + i] = regkey_name(c)[i];
        }
        --pos;
        if (pos < cap) out[pos] = '\\';
    }
    return total;
}

/* ---------------------------------------------------------------- values */
regval_t *reg_find_value(regkey_t *k, const uint16_t *name, uint32_t chars)
{
    regval_t *v;
    for (v = k->values; v; v = v->next)
        if (name_cmp(regval_name(v), v->name_len, name, chars) == 0) return v;
    return 0;
}

int32_t reg_set_value(regkey_t *k, const uint16_t *name, uint32_t chars, uint32_t type, const void *data, uint32_t len)
{
    regval_t *v, *nv, **pp;
    uint32_t size, credit = 0;
    if (k->flags & RK_DELETED) return STATUS_KEY_DELETED;
    if (chars > REG_MAX_VALUE_NAME) return STATUS_INVALID_PARAMETER;
    if (len > REG_MAX_VALUE_BYTES) return STATUS_INSUFFICIENT_RESOURCES;
    v = reg_find_value(k, name, chars);
    if (v && v->data_len == len) {                                       /* same size: overwrite in place */
        v->type = type;
        if (len) memcpy(regval_data(v), data, len);
        k->last_write = reg_filetime_now();
        notify_fire(k, REG_NOTIFY_CHANGE_LAST_SET);
        return STATUS_SUCCESS;
    }
    if (v) { name = regval_name(v); chars = v->name_len; credit = v->alloc_size; }   /* an existing value keeps its name */
    size = (uint32_t)sizeof(regval_t) + ((chars * 2 + 7) & ~7u) + len;
    nv = reg_alloc(size, credit);
    if (!nv) return STATUS_NO_MEMORY;
    nv->alloc_size = size;
    nv->name_len = chars;
    nv->type = type;
    nv->data_len = len;
    memcpy(regval_name(nv), name, chars * 2);
    if (len) memcpy(regval_data(nv), data, len);
    if (v) {                                                             /* replace, keeping the creation-order slot */
        for (pp = &k->values; *pp != v; pp = &(*pp)->next) { }
        nv->next = v->next;
        *pp = nv;
        if (k->values_tail == v) k->values_tail = nv;
        reg_free(v, v->alloc_size);
    } else {
        if (k->values_tail) k->values_tail->next = nv; else k->values = nv;
        k->values_tail = nv;
        ++k->nvalues;
    }
    k->last_write = reg_filetime_now();
    notify_fire(k, REG_NOTIFY_CHANGE_LAST_SET);
    return STATUS_SUCCESS;
}

int32_t reg_delete_value(regkey_t *k, const uint16_t *name, uint32_t chars)
{
    regval_t *v, *prev = 0;
    if (k->flags & RK_DELETED) return STATUS_KEY_DELETED;
    for (v = k->values; v; prev = v, v = v->next)
        if (name_cmp(regval_name(v), v->name_len, name, chars) == 0) break;
    if (!v) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (prev) prev->next = v->next; else k->values = v->next;
    if (k->values_tail == v) k->values_tail = prev;
    --k->nvalues;
    reg_free(v, v->alloc_size);
    k->last_write = reg_filetime_now();
    notify_fire(k, REG_NOTIFY_CHANGE_LAST_SET);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- default tree */
static uint32_t ascii_to_w(uint16_t *dst, const char *s)
{
    uint32_t n = 0;
    while (s[n]) { dst[n] = (uint8_t)s[n]; ++n; }
    return n;
}

static regkey_t *seed_key(regkey_t *parent, const char *path)
{
    regkey_t *k = parent;
    uint16_t w[128];
    uint32_t n = ascii_to_w(w, path);
    regkey_t *made = 0;
    KASSERT(n < 128 && reg_resolve(k, w, n, 1, 0, 1, 0, 0, &made, 0) == STATUS_SUCCESS);
    return made;
}

static void seed_value(regkey_t *k, const char *name, uint32_t type, const void *data, uint32_t len)
{
    uint16_t w[64];
    const uint32_t n = ascii_to_w(w, name);
    KASSERT(n < 64 && reg_set_value(k, w, n, type, data, len) == STATUS_SUCCESS);
}

static void seed_sz(regkey_t *k, const char *name, const char *value)
{
    uint16_t w[96];
    const uint32_t n = ascii_to_w(w, value);
    w[n] = 0;
    KASSERT(n < 95);
    seed_value(k, name, REG_SZ, w, (n + 1) * 2);
}

static void seed_dword(regkey_t *k, const char *name, uint32_t v) { seed_value(k, name, REG_DWORD, &v, 4); }

static void seed_defaults(void)
{
    static const uint16_t root_name[] = { 'R', 'E', 'G', 'I', 'S', 'T', 'R', 'Y' };
    regkey_t *machine, *user, *k;
    g_root = key_alloc(root_name, 8, 0, 0, RK_FIXED);
    KASSERT(g_root);
    machine = seed_key(g_root, "MACHINE");
    user = seed_key(g_root, "USER");
    KASSERT(machine && user);
    machine->flags |= RK_FIXED;
    user->flags |= RK_FIXED;

    /* Version values: same profile the loader writes into the PEB (kernel64/ldr.c: 10.0, build 22631). */
    k = seed_key(machine, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    seed_dword(k, "CurrentMajorVersionNumber", 10);
    seed_dword(k, "CurrentMinorVersionNumber", 0);
    seed_sz(k, "CurrentBuild", "22631");
    seed_sz(k, "CurrentBuildNumber", "22631");
    seed_sz(k, "ProductName", "Shizuku Kernel64 (Windows 10.0 profile)");
    seed_sz(k, "SystemRoot", "C:\\SHZ");
    seed_sz(k, "ShzProfile", "win11-amd64 profile value (10.0 build 22631); not a verified Windows build");
    seed_key(machine, "SOFTWARE\\Classes");
    k = seed_key(machine, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName");
    seed_sz(k, "ComputerName", "SHZ-K64");                                  /* == COMPUTERNAME in the loader's environment */
    k = seed_key(machine, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName");
    seed_sz(k, "ComputerName", "SHZ-K64");
    seed_key(machine, "SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current");

    seed_key(user, ".DEFAULT");
    k = seed_key(user, SHZ_USER_SID);
    seed_key(k, "Environment");
    seed_key(k, "Software");
    g_seeded = 1;                                                           /* the quota applies from here on */
}
