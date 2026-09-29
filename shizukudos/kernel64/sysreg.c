/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 registry system calls (NtCreateKey ... NtQueryObject), the user-facing side of registry.c.
 *
 * Structures and status codes follow the Windows x64 native API: OBJECT_ATTRIBUTES / UNICODE_STRING as in ntsys users,
 * KEY_*_INFORMATION and KEY_VALUE_*_INFORMATION with their documented field order. Where a buffer is too small the
 * behaviour is the documented one: STATUS_BUFFER_TOO_SMALL when not even the fixed part fits, STATUS_BUFFER_OVERFLOW
 * when the fixed part (and as much of the rest as fits) was written; ResultLength always reports the full size.
 *
 * Handles: an open key is a kobject of type OB_KEY in the process handle table (multiples of 4, like every other handle),
 * closed with NtClose, duplicated with NtDuplicateObject. Access rights on the handle are enforced (see registry.c for
 * what is and is not checked).
 */
#include "registry.h"

extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);

struct ustr { uint16_t length, maxlen; uint32_t pad; uint64_t buffer; };
struct objattr { uint32_t length, pad; uint64_t root, name; uint32_t attributes, pad2; uint64_t sd, sqos; };

#define ACCESS_SYSTEM_SECURITY_BIT 0x01000000u
#define KEY_WOW64_BITS 0x00000300u
#define REG_CREATED_NEW_KEY 1u
#define REG_OPENED_EXISTING_KEY 2u

/* ---------------------------------------------------------------- user buffers */
/* A UTF-16 string copied out of user memory: short ones live in the struct, long ones on the kernel heap. */
typedef struct { uint16_t small[64]; uint16_t *p; uint32_t chars; } ubuf_t;

static void ubuf_free(ubuf_t *b)
{
    if (b->p != b->small) kfree(b->p);
    b->p = b->small;
    b->chars = 0;
}

/* Reads the UNICODE_STRING at `uva` (0 = empty string). `max_chars` bounds the length. */
static int32_t ubuf_read(process_t *pr, uint64_t uva, uint32_t max_chars, ubuf_t *b)
{
    struct ustr u;
    b->p = b->small;
    b->chars = 0;
    if (!uva) return STATUS_SUCCESS;
    if (copy_from_user(pr, &u, uva, sizeof u)) return STATUS_ACCESS_VIOLATION;
    if (u.length & 1) return STATUS_OBJECT_NAME_INVALID;
    if (u.length / 2 > max_chars) return STATUS_INVALID_PARAMETER;
    if (!u.length) return STATUS_SUCCESS;
    if (u.length / 2 > 64) {
        b->p = kmalloc(u.length);
        if (!b->p) { b->p = b->small; return STATUS_NO_MEMORY; }
    }
    if (copy_from_user(pr, b->p, u.buffer, u.length)) { ubuf_free(b); return STATUS_ACCESS_VIOLATION; }
    b->chars = u.length / 2;
    return STATUS_SUCCESS;
}

/* Clipped writer into the caller's information buffer. */
/* fixed: size of the fixed part of the record; a buffer smaller than that receives nothing (STATUS_BUFFER_TOO_SMALL). */
typedef struct { process_t *p; uint64_t base; uint32_t cap; int bad; uint32_t fixed; } outbuf_t;

static void put(outbuf_t *o, uint32_t off, const void *src, uint32_t n)
{
    if (o->cap < o->fixed || off >= o->cap) return;
    if (n > o->cap - off) n = o->cap - off;
    if (n && copy_to_user(o->p, o->base + off, src, n)) o->bad = 1;
}

static void put32(outbuf_t *o, uint32_t off, uint32_t v) { put(o, off, &v, 4); }
static void put64(outbuf_t *o, uint32_t off, uint64_t v) { put(o, off, &v, 8); }

static int32_t finish(process_t *pr, outbuf_t *o, uint64_t pres, uint32_t need, uint32_t fixed)
{
    if (pres && copy_to_user(pr, pres, &need, 4)) return STATUS_ACCESS_VIOLATION;
    if (o->bad) return STATUS_ACCESS_VIOLATION;
    if (o->cap < fixed) return STATUS_BUFFER_TOO_SMALL;
    return need > o->cap ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- access and handles */
static uint32_t map_access(uint32_t a)
{
    if (a & ACC_MAXIMUM_ALLOWED) a |= KEY_ALL_ACCESS_MASK;
    if (a & ACC_GENERIC_READ) a |= KEY_READ_MASK;
    if (a & ACC_GENERIC_WRITE) a |= KEY_WRITE_MASK;
    if (a & ACC_GENERIC_EXECUTE) a |= KEY_READ_MASK;
    if (a & ACC_GENERIC_ALL) a |= KEY_ALL_ACCESS_MASK;
    return a & (KEY_ALL_ACCESS_MASK | ACCESS_SYSTEM_SECURITY_BIT | KEY_WOW64_BITS);
}

/* Registry lock held. Makes a key object for `node` (taking a node reference) and inserts it into the handle table.
 * The lock is dropped and NOT reacquired. On success *h holds the handle value. */
static int32_t new_key_handle(process_t *pr, regkey_t *node, uint32_t access, uint32_t *h)
{
    int32_t st;
    kobject_t *o = ob_create(OB_KEY, 0);
    if (!o) { reg_unlock(); return STATUS_NO_MEMORY; }
    o->u.key.node = node;
    ++node->refs;
    reg_unlock();
    st = handle_insert(pr, o, access, h);
    ob_deref(o);                                        /* the handle owns the object now (or it is freed on failure) */
    return st;
}

/* Resolves `h` to a referenced key object; checks the handle's granted access for `need` (0 = nothing required). */
static int32_t key_of(process_t *pr, uint64_t h, uint32_t need, kobject_t **o, uint32_t *access_out)
{
    uint32_t granted = 0;
    const int32_t st = handle_ref(pr, h, OB_KEY, o, &granted);
    if (st) return st;
    if ((granted & need) != need) { ob_deref(*o); *o = 0; return STATUS_ACCESS_DENIED; }
    if (access_out) *access_out = granted;
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- NtCreateKey / NtOpenKey */
static int32_t open_create(process_t *pr, uint64_t phandle, uint32_t desired, uint64_t oa_va, int create, uint32_t options,
                           uint64_t class_va, uint64_t pdisp)
{
    struct objattr oa;
    ubuf_t name, cls;
    kobject_t *root_obj = 0;
    uint32_t root_access = 0, h = 0, access = map_access(desired);
    const uint16_t *path;
    uint32_t chars;
    regkey_t *start, *node = 0;
    int32_t st;
    int created = 0;

    if (options & ~(REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK | REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK))
        return STATUS_INVALID_PARAMETER;
    if (create && (options & REG_OPTION_CREATE_LINK)) return STATUS_NOT_SUPPORTED;      /* no symbolic links */
    if (copy_from_user(pr, &oa, oa_va, sizeof oa) || oa.length < sizeof oa) return STATUS_ACCESS_VIOLATION;
    st = ubuf_read(pr, oa.name, 32767, &name);
    if (st) return st;
    st = STATUS_SUCCESS;
    cls.p = cls.small; cls.chars = 0;
    if (create && class_va) {
        st = ubuf_read(pr, class_va, REG_MAX_VALUE_NAME, &cls);
        if (st) { ubuf_free(&name); return st; }
    }
    path = name.p;
    chars = name.chars;
    if (oa.root) {
        st = key_of(pr, oa.root, 0, &root_obj, &root_access);
        if (st) goto out;
        if (chars && path[0] == '\\') { st = STATUS_OBJECT_PATH_SYNTAX_BAD; goto out; }
    } else {
        /* absolute name: "\REGISTRY[\...]" (the object-manager prefix), resolved from the registry root */
        uint32_t i = 1;
        static const uint16_t reg[8] = { 'R', 'E', 'G', 'I', 'S', 'T', 'R', 'Y' };
        int ok;
        if (!chars || path[0] != '\\') { st = STATUS_OBJECT_PATH_SYNTAX_BAD; goto out; }
        while (i < chars && path[i] != '\\') ++i;
        {
            uint32_t k;
            ok = i - 1 == 8;
            for (k = 0; ok && k < 8; ++k) {
                const uint32_t c = reg_upcase_char(path[1 + k]);
                if (c != reg[k]) ok = 0;
            }
        }
        if (!ok) { st = i < chars ? STATUS_OBJECT_PATH_NOT_FOUND : STATUS_OBJECT_NAME_NOT_FOUND; goto out; }
        path += i < chars ? i + 1 : i;
        chars -= i < chars ? i + 1 : i;
    }
    reg_lock();
    start = root_obj ? root_obj->u.key.node : reg_root();
    if (start->flags & RK_DELETED) { reg_unlock(); st = STATUS_KEY_DELETED; goto out; }
    st = reg_resolve(start, path, chars, 0, 0, 1, 0, 0, &node, 0);
    if (st == STATUS_SUCCESS) {
        created = 0;
    } else if (create && st == STATUS_OBJECT_NAME_NOT_FOUND) {
        st = reg_resolve(start, path, chars, 1, options, !root_obj || (root_access & KEY_CREATE_SUB_KEY) != 0, cls.p, cls.chars,
                         &node, &created);
    }
    if (st) { reg_unlock(); goto out; }
    st = new_key_handle(pr, node, access, &h);          /* drops the registry lock */
    if (st) goto out;
    {
        const uint64_t hv = h;
        if (copy_to_user(pr, phandle, &hv, 8)) { handle_close(pr, h); st = STATUS_ACCESS_VIOLATION; goto out; }
    }
    if (create && pdisp) {
        const uint32_t d = created ? REG_CREATED_NEW_KEY : REG_OPENED_EXISTING_KEY;
        if (copy_to_user(pr, pdisp, &d, 4)) { handle_close(pr, h); st = STATUS_ACCESS_VIOLATION; goto out; }
    }
    st = STATUS_SUCCESS;
out:
    if (root_obj) ob_deref(root_obj);
    ubuf_free(&name);
    ubuf_free(&cls);
    return st;
}

/* ---------------------------------------------------------------- information records */
/* Key information classes 0..4 (basic, node, full, name, cached). Class 3 is the full path of the key and only NtQueryKey
 * offers it. Requires the registry lock. */
static int32_t fill_key_info(process_t *pr, regkey_t *k, uint32_t cls, uint64_t buf, uint32_t len, uint64_t pres)
{
    outbuf_t o = { pr, buf, len, 0, 0 };
    const uint32_t nbytes = k->name_len * 2;
    uint32_t need, fixed;
    switch (cls) {
    case 0: {                                           /* KEY_BASIC_INFORMATION: time(8) title(4) namelen(4) name */
        o.fixed = fixed = 16;
        need = fixed + nbytes;
        put64(&o, 0, k->last_write);
        put32(&o, 8, 0);
        put32(&o, 12, nbytes);
        put(&o, 16, regkey_name(k), nbytes);
        break;
    }
    case 1: {                                           /* KEY_NODE_INFORMATION: ... classoff classlen namelen name class */
        const uint32_t cbytes = k->class_len * 2, coff = (24 + nbytes + 3) & ~3u;
        o.fixed = fixed = 24;
        need = cbytes ? coff + cbytes : 24 + nbytes;
        put64(&o, 0, k->last_write);
        put32(&o, 8, 0);
        put32(&o, 12, cbytes ? coff : 0xffffffffu);
        put32(&o, 16, cbytes);
        put32(&o, 20, nbytes);
        put(&o, 24, regkey_name(k), nbytes);
        if (cbytes) put(&o, coff, regkey_class(k), cbytes);
        break;
    }
    case 2: {                                           /* KEY_FULL_INFORMATION */
        regkey_t *c;
        regval_t *v;
        uint32_t max_name = 0, max_class = 0, max_vname = 0, max_vdata = 0;
        const uint32_t cbytes = k->class_len * 2;
        for (c = k->child; c; c = c->sibling) {
            if (c->name_len * 2 > max_name) max_name = c->name_len * 2;
            if (c->class_len * 2 > max_class) max_class = c->class_len * 2;
        }
        for (v = k->values; v; v = v->next) {
            if (v->name_len * 2 > max_vname) max_vname = v->name_len * 2;
            if (v->data_len > max_vdata) max_vdata = v->data_len;
        }
        o.fixed = fixed = 44;
        need = fixed + cbytes;
        put64(&o, 0, k->last_write);
        put32(&o, 8, 0);
        put32(&o, 12, cbytes ? 44 : 0xffffffffu);       /* ClassOffset */
        put32(&o, 16, cbytes);
        put32(&o, 20, k->nsubkeys);
        put32(&o, 24, max_name);                        /* the four Max* fields are in bytes, like the Windows structure */
        put32(&o, 28, max_class);
        put32(&o, 32, k->nvalues);
        put32(&o, 36, max_vname);
        put32(&o, 40, max_vdata);
        if (cbytes) put(&o, 44, regkey_class(k), cbytes);
        break;
    }
    case 3: {                                           /* KEY_NAME_INFORMATION: namelen(4) name (the full path) */
        const uint32_t pchars = reg_key_path(k, 0, 0);
        uint16_t *path = kmalloc(pchars * 2);
        if (!path) return STATUS_NO_MEMORY;
        reg_key_path(k, path, pchars);
        o.fixed = fixed = 4;
        need = 4 + pchars * 2;
        put32(&o, 0, pchars * 2);
        put(&o, 4, path, pchars * 2);
        kfree(path);
        break;
    }
    case 4: {                                           /* KEY_CACHED_INFORMATION */
        regkey_t *c;
        regval_t *v;
        uint32_t max_name = 0, max_vname = 0, max_vdata = 0;
        for (c = k->child; c; c = c->sibling) if (c->name_len * 2 > max_name) max_name = c->name_len * 2;
        for (v = k->values; v; v = v->next) {
            if (v->name_len * 2 > max_vname) max_vname = v->name_len * 2;
            if (v->data_len > max_vdata) max_vdata = v->data_len;
        }
        o.fixed = fixed = 36;
        need = fixed;
        put64(&o, 0, k->last_write);
        put32(&o, 8, 0);
        put32(&o, 12, k->nsubkeys);
        put32(&o, 16, max_name);
        put32(&o, 20, k->nvalues);
        put32(&o, 24, max_vname);
        put32(&o, 28, max_vdata);
        put32(&o, 32, k->name_len * 2);
        break;
    }
    default: return STATUS_INVALID_INFO_CLASS;
    }
    return finish(pr, &o, pres, need, fixed);
}

/* Value classes: 0 basic, 1 full, 2 partial. Requires the registry lock. */
static int32_t fill_value_info(process_t *pr, regval_t *v, uint32_t cls, uint64_t buf, uint32_t len, uint64_t pres)
{
    outbuf_t o = { pr, buf, len, 0, 0 };
    const uint32_t nbytes = v->name_len * 2;
    uint32_t need, fixed;
    switch (cls) {
    case 0:                                             /* KEY_VALUE_BASIC_INFORMATION: title type namelen name */
        o.fixed = fixed = 12;
        need = fixed + nbytes;
        put32(&o, 0, 0);
        put32(&o, 4, v->type);
        put32(&o, 8, nbytes);
        put(&o, 12, regval_name(v), nbytes);
        break;
    case 1: {                                           /* KEY_VALUE_FULL_INFORMATION: title type dataoff datalen namelen name data */
        const uint32_t doff = (20 + nbytes + 3) & ~3u;
        o.fixed = fixed = 20;
        need = doff + v->data_len;
        put32(&o, 0, 0);
        put32(&o, 4, v->type);
        put32(&o, 8, doff);
        put32(&o, 12, v->data_len);
        put32(&o, 16, nbytes);
        put(&o, 20, regval_name(v), nbytes);
        put(&o, doff, regval_data(v), v->data_len);
        break;
    }
    case 2:                                             /* KEY_VALUE_PARTIAL_INFORMATION: title type datalen data */
        o.fixed = fixed = 12;
        need = fixed + v->data_len;
        put32(&o, 0, 0);
        put32(&o, 4, v->type);
        put32(&o, 8, v->data_len);
        put(&o, 12, regval_data(v), v->data_len);
        break;
    default: return STATUS_INVALID_INFO_CLASS;
    }
    return finish(pr, &o, pres, need, fixed);
}

/* ---------------------------------------------------------------- value and key operations */
static int32_t query_value(process_t *pr, uint64_t h, uint64_t vname, uint32_t cls, uint64_t buf, uint32_t len, uint64_t pres)
{
    kobject_t *ko;
    ubuf_t name;
    regkey_t *k;
    regval_t *v;
    int32_t st = key_of(pr, h, KEY_QUERY_VALUE, &ko, 0);
    if (st) return st;
    st = ubuf_read(pr, vname, REG_MAX_VALUE_NAME, &name);
    if (st) { ob_deref(ko); return st; }
    reg_lock();
    k = ko->u.key.node;
    if (k->flags & RK_DELETED) st = STATUS_KEY_DELETED;
    else if (!(v = reg_find_value(k, name.p, name.chars))) st = STATUS_OBJECT_NAME_NOT_FOUND;
    else st = fill_value_info(pr, v, cls, buf, len, pres);
    reg_unlock();
    ubuf_free(&name);
    ob_deref(ko);
    return st;
}

static int32_t set_value(process_t *pr, uint64_t h, uint64_t vname, uint32_t type, uint64_t data_va, uint32_t size)
{
    kobject_t *ko;
    ubuf_t name;
    uint8_t *tmp = 0;
    int32_t st = key_of(pr, h, KEY_SET_VALUE, &ko, 0);
    if (st) return st;
    st = ubuf_read(pr, vname, REG_MAX_VALUE_NAME, &name);
    if (st) { ob_deref(ko); return st; }
    if (size > REG_MAX_VALUE_BYTES) st = STATUS_INSUFFICIENT_RESOURCES;
    else if (size) {
        tmp = kmalloc(size);
        if (!tmp) st = STATUS_NO_MEMORY;
        else if (copy_from_user(pr, tmp, data_va, size)) st = STATUS_ACCESS_VIOLATION;
    }
    if (!st) {
        reg_lock();
        st = reg_set_value(ko->u.key.node, name.p, name.chars, type, tmp, size);
        reg_unlock();
    }
    kfree(tmp);
    ubuf_free(&name);
    ob_deref(ko);
    return st;
}

static int32_t delete_value(process_t *pr, uint64_t h, uint64_t vname)
{
    kobject_t *ko;
    ubuf_t name;
    int32_t st = key_of(pr, h, KEY_SET_VALUE, &ko, 0);
    if (st) return st;
    st = ubuf_read(pr, vname, REG_MAX_VALUE_NAME, &name);
    if (!st) {
        reg_lock();
        st = reg_delete_value(ko->u.key.node, name.p, name.chars);
        reg_unlock();
        ubuf_free(&name);
    }
    ob_deref(ko);
    return st;
}

static int32_t delete_key(process_t *pr, uint64_t h)
{
    kobject_t *ko;
    int32_t st = key_of(pr, h, ACC_DELETE, &ko, 0);
    if (st) return st;
    reg_lock();
    st = reg_delete_key(ko->u.key.node);
    reg_unlock();
    ob_deref(ko);
    return st;
}

static int32_t enum_key(process_t *pr, uint64_t h, uint32_t index, uint32_t cls, uint64_t buf, uint32_t len, uint64_t pres)
{
    kobject_t *ko;
    regkey_t *k, *c;
    int32_t st;
    if (cls > 1) return STATUS_INVALID_INFO_CLASS;
    st = key_of(pr, h, KEY_ENUMERATE_SUB_KEYS, &ko, 0);
    if (st) return st;
    reg_lock();
    k = ko->u.key.node;
    if (k->flags & RK_DELETED) st = STATUS_KEY_DELETED;
    else if (!(c = reg_nth_child(k, index))) st = STATUS_NO_MORE_ENTRIES;
    else st = fill_key_info(pr, c, cls, buf, len, pres);
    reg_unlock();
    ob_deref(ko);
    return st;
}

static int32_t enum_value(process_t *pr, uint64_t h, uint32_t index, uint32_t cls, uint64_t buf, uint32_t len, uint64_t pres)
{
    kobject_t *ko;
    regkey_t *k;
    regval_t *v;
    int32_t st = key_of(pr, h, KEY_QUERY_VALUE, &ko, 0);
    if (st) return st;
    reg_lock();
    k = ko->u.key.node;
    if (k->flags & RK_DELETED) st = STATUS_KEY_DELETED;
    else if (!(v = reg_nth_value(k, index))) st = STATUS_NO_MORE_ENTRIES;
    else st = fill_value_info(pr, v, cls, buf, len, pres);
    reg_unlock();
    ob_deref(ko);
    return st;
}

static int32_t query_key(process_t *pr, uint64_t h, uint32_t cls, uint64_t buf, uint32_t len, uint64_t pres)
{
    kobject_t *ko;
    regkey_t *k;
    int32_t st;
    if (cls > 4) return STATUS_INVALID_INFO_CLASS;
    st = key_of(pr, h, cls == 3 ? 0 : KEY_QUERY_VALUE, &ko, 0);
    if (st) return st;
    reg_lock();
    k = ko->u.key.node;
    st = (k->flags & RK_DELETED) ? STATUS_KEY_DELETED : fill_key_info(pr, k, cls, buf, len, pres);
    reg_unlock();
    ob_deref(ko);
    return st;
}

/* ---------------------------------------------------------------- NtQueryObject */
static const char *object_type_name(uint32_t type)
{
    switch (type) {
    case OB_EVENT: return "Event";
    case OB_MUTANT: return "Mutant";
    case OB_SEMAPHORE: return "Semaphore";
    case OB_THREAD: return "Thread";
    case OB_PROCESS: return "Process";
    case OB_FILE: return "File";
    case OB_TIMER: return "Timer";
    case OB_DIRECTORY: return "Directory";
    case OB_KEY: return "Key";
    default: return 0;
    }
}

static int32_t query_object(process_t *pr, uint64_t h, uint32_t cls, uint64_t buf, uint32_t len, uint64_t pres)
{
    kobject_t *o = 0;
    uint32_t access = 0, k;
    const char *tn;
    uint16_t twide[16];
    uint32_t tchars = 0;
    outbuf_t ob = { pr, buf, len, 0, 0 };
    int32_t st;
    if (h == CURRENT_PROCESS_HANDLE) { o = pr->object; ob_ref(o); access = 0x1fffff; }
    else if (h == CURRENT_THREAD_HANDLE) { o = thread_current()->object; ob_ref(o); access = 0x1fffff; }
    else {
        st = handle_ref(pr, h, 0, &o, &access);
        if (st) return st;
    }
    tn = object_type_name(o->type);
    if (!tn) { ob_deref(o); return STATUS_NOT_SUPPORTED; }
    while (tn[tchars]) { twide[tchars] = (uint8_t)tn[tchars]; ++tchars; }
    switch (cls) {
    case 0: {                                           /* OBJECT_BASIC_INFORMATION (0x38 bytes) */
        uint32_t handles = 0;
        for (k = 0; k < MAX_HANDLES; ++k) if (pr->handles[k].obj == o) ++handles;
        st = STATUS_SUCCESS;
        put32(&ob, 0, 0);                               /* Attributes */
        put32(&ob, 4, access);                          /* GrantedAccess of this handle */
        put32(&ob, 8, handles);                         /* HandleCount: handles of the CALLING process only */
        put32(&ob, 12, o->refs);                        /* PointerCount: kernel references */
        {
            const uint32_t z[3] = { 0, 0, 0 }, ti = 0x68 + (tchars + 1) * 2;
            put(&ob, 16, z, 8);                         /* pool charges */
            put(&ob, 24, z, 12);                        /* Reserved[3] */
            put32(&ob, 36, 16);                         /* NameInfoSize: the UNICODE_STRING header (the name itself is class 1) */
            put32(&ob, 40, ti);                         /* TypeInfoSize */
            put32(&ob, 44, 0);                          /* SecurityDescriptorSize */
            put64(&ob, 48, 0);                          /* CreationTime: not tracked */
        }
        if (ob.bad) st = STATUS_ACCESS_VIOLATION;
        else if (len < 0x38) st = STATUS_INFO_LENGTH_MISMATCH;
        if (pres) { const uint32_t n = 0x38; if (copy_to_user(pr, pres, &n, 4)) st = STATUS_ACCESS_VIOLATION; }
        break;
    }
    case 1: {                                           /* OBJECT_NAME_INFORMATION: UNICODE_STRING, then the characters */
        uint32_t pchars = 0, need;
        struct ustr us;
        uint16_t *path = 0;
        st = STATUS_SUCCESS;
        if (o->type == OB_KEY) {
            regkey_t *kn = o->u.key.node;
            reg_lock();
            if (kn->flags & RK_DELETED) st = STATUS_KEY_DELETED;
            else {
                pchars = reg_key_path(kn, 0, 0);
                path = kmalloc(pchars * 2 + 2);
                if (!path) st = STATUS_NO_MEMORY; else reg_key_path(kn, path, pchars);
            }
            reg_unlock();
        } else if (o->name[0]) {
            st = STATUS_NOT_SUPPORTED;                  /* named kernel objects live in a namespace we do not report */
        } else if (o->type == OB_FILE) {
            st = STATUS_NOT_SUPPORTED;                  /* files: device paths are not modelled */
        }
        if (st) { kfree(path); break; }
        need = 16 + (pchars ? pchars * 2 + 2 : 0);
        us.length = (uint16_t)(pchars * 2);
        us.maxlen = (uint16_t)(pchars ? pchars * 2 + 2 : 0);
        us.pad = 0;
        us.buffer = pchars ? buf + 16 : 0;
        if (pres && copy_to_user(pr, pres, &need, 4)) st = STATUS_ACCESS_VIOLATION;
        else if (len < need) st = STATUS_INFO_LENGTH_MISMATCH;
        else if (copy_to_user(pr, buf, &us, sizeof us) ||
                 (pchars && (copy_to_user(pr, buf + 16, path, pchars * 2) || copy_to_user(pr, buf + 16 + pchars * 2, "\0\0", 2))))
            st = STATUS_ACCESS_VIOLATION;
        kfree(path);
        break;
    }
    case 2: {                                           /* OBJECT_TYPE_INFORMATION: only TypeName is populated (0x68 bytes + name) */
        const uint32_t need = 0x68 + (tchars + 1) * 2;
        struct ustr us;
        uint8_t zero[0x68 - 16];
        memset(zero, 0, sizeof zero);
        us.length = (uint16_t)(tchars * 2);
        us.maxlen = (uint16_t)(tchars * 2 + 2);
        us.pad = 0;
        us.buffer = buf + 0x68;
        st = STATUS_SUCCESS;
        if (pres && copy_to_user(pr, pres, &need, 4)) st = STATUS_ACCESS_VIOLATION;
        else if (len < need) st = STATUS_INFO_LENGTH_MISMATCH;
        else if (copy_to_user(pr, buf, &us, sizeof us) || copy_to_user(pr, buf + 16, zero, sizeof zero) ||
                 copy_to_user(pr, buf + 0x68, twide, tchars * 2) || copy_to_user(pr, buf + 0x68 + tchars * 2, "\0\0", 2))
            st = STATUS_ACCESS_VIOLATION;
        break;
    }
    default:
        st = STATUS_INVALID_INFO_CLASS;                 /* ObjectAllTypes/ObjectHandleFlag... are not provided */
    }
    ob_deref(o);
    return st;
}

/* ---------------------------------------------------------------- NtNotifyChangeKey */
/* NtNotifyChangeKey(KeyHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, CompletionFilter, WatchTree, Buffer, BufferSize,
 * Asynchronous). Only the asynchronous form exists: the call registers and returns STATUS_PENDING; the event is signaled and
 * the IO_STATUS_BLOCK completed once, when a change matching the filter happens (or the key object is closed). The blocking
 * form is built by advapi32 from an event and a wait. APCs and the change-data buffer are not supported. */
static int32_t notify_change(process_t *pr, struct regs *r, uint64_t h, uint64_t ev_h, uint64_t apc)
{
    const uint64_t iosb = (uint64_t)stack_arg(pr, r, 5), buffer = (uint64_t)stack_arg(pr, r, 8);
    const uint32_t filter = (uint32_t)stack_arg(pr, r, 6), buflen = (uint32_t)stack_arg(pr, r, 9);
    const int subtree = (stack_arg(pr, r, 7) & 0xff) != 0, async = (stack_arg(pr, r, 10) & 0xff) != 0;
    kobject_t *ko, *ev = 0;
    int32_t st;
    if (apc || buffer || buflen) return STATUS_NOT_SUPPORTED;
    if (!async) return STATUS_NOT_SUPPORTED;
    if (!filter || (filter & ~(REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_LAST_SET |
                               REG_NOTIFY_CHANGE_SECURITY | REG_NOTIFY_THREAD_AGNOSTIC)))
        return STATUS_INVALID_PARAMETER;
    st = key_of(pr, h, KEY_NOTIFY, &ko, 0);
    if (st) return st;
    if (ev_h) {
        st = handle_ref(pr, ev_h, OB_EVENT, &ev, 0);
        if (st) { ob_deref(ko); return st; }
        ob_reset_event(ev);                             /* like every asynchronous operation: the event starts non-signaled */
    }
    if (iosb) {
        const uint64_t pending[2] = { (uint64_t)(int64_t)STATUS_PENDING, 0 };
        if (copy_to_user(pr, iosb, pending, sizeof pending)) st = STATUS_ACCESS_VIOLATION;
    }
    if (!st) {
        reg_lock();
        st = ko->u.key.node ? reg_notify_add(ko->u.key.node, ko, ev, pr, iosb, filter & ~REG_NOTIFY_THREAD_AGNOSTIC, subtree)
                            : STATUS_INVALID_HANDLE;
        reg_unlock();
    }
    if (ev) ob_deref(ev);                               /* the registration holds its own reference */
    ob_deref(ko);
    return st ? st : STATUS_PENDING;
}

/* ---------------------------------------------------------------- dispatch */
int32_t sys_ext_registry(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    switch (num) {
    case SYS_NtOpenKey:                                 /* (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) */
        return open_create(cur, a1, (uint32_t)a2, a3, 0, 0, 0, 0);
    case SYS_NtOpenKeyEx:                               /* (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG OpenOptions) */
        if ((uint32_t)a4 & ~(REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK)) return STATUS_INVALID_PARAMETER;
        return open_create(cur, a1, (uint32_t)a2, a3, 0, (uint32_t)a4, 0, 0);
    case SYS_NtCreateKey:                               /* (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG TitleIndex, PUNICODE_STRING Class, ULONG Options, PULONG Disposition) */
        return open_create(cur, a1, (uint32_t)a2, a3, 1, (uint32_t)stack_arg(cur, r, 6), (uint64_t)stack_arg(cur, r, 5),
                           (uint64_t)stack_arg(cur, r, 7));
    case SYS_NtQueryValueKey:                           /* (HANDLE, PUNICODE_STRING, CLASS, PVOID, ULONG, PULONG) */
        return query_value(cur, a1, a2, (uint32_t)a3, a4, (uint32_t)stack_arg(cur, r, 5), (uint64_t)stack_arg(cur, r, 6));
    case SYS_NtSetValueKey:                             /* (HANDLE, PUNICODE_STRING, ULONG TitleIndex, ULONG Type, PVOID, ULONG) */
        return set_value(cur, a1, a2, (uint32_t)a4, (uint64_t)stack_arg(cur, r, 5), (uint32_t)stack_arg(cur, r, 6));
    case SYS_NtDeleteKey: return delete_key(cur, a1);
    case SYS_NtDeleteValueKey: return delete_value(cur, a1, a2);
    case SYS_NtEnumerateKey:                            /* (HANDLE, ULONG Index, CLASS, PVOID, ULONG, PULONG) */
        return enum_key(cur, a1, (uint32_t)a2, (uint32_t)a3, a4, (uint32_t)stack_arg(cur, r, 5), (uint64_t)stack_arg(cur, r, 6));
    case SYS_NtEnumerateValueKey:
        return enum_value(cur, a1, (uint32_t)a2, (uint32_t)a3, a4, (uint32_t)stack_arg(cur, r, 5), (uint64_t)stack_arg(cur, r, 6));
    case SYS_NtQueryKey:                                /* (HANDLE, CLASS, PVOID, ULONG, PULONG) */
        return query_key(cur, a1, (uint32_t)a2, a3, (uint32_t)a4, (uint64_t)stack_arg(cur, r, 5));
    case SYS_NtFlushKey: {                              /* nothing to flush: the registry is memory-only; validates the handle */
        kobject_t *ko;
        const int32_t st = key_of(cur, a1, 0, &ko, 0);
        if (st) return st;
        ob_deref(ko);
        return STATUS_SUCCESS;
    }
    case SYS_NtNotifyChangeKey: return notify_change(cur, r, a1, a2, a3);
    case SYS_NtQueryObject:                             /* (HANDLE, CLASS, PVOID, ULONG, PULONG) */
        return query_object(cur, a1, (uint32_t)a2, a3, (uint32_t)a4, (uint64_t)stack_arg(cur, r, 5));
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}
