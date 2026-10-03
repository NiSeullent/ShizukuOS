/* SPDX-License-Identifier: GPL-2.0-only */
/* NT registry subset for chrome_elf.dll on the real Win98 ANSI registry.
 * Original code; see nt_registry.h and NT_REGISTRY_README.md. */
#include "nt_registry.h"

#define NTR_MAGIC 0x4E545231u
#define HANDLE_TAG 0x4E000000u
#define KEY_QUERY_VALUE 0x0001u
#define KEY_SET_VALUE 0x0002u
#define KEY_WOW64_64KEY 0x0100u
#define KEY_WOW64_32KEY 0x0200u
#define KEY_SPECIFIC 0x003Fu
#define NT_DELETE 0x00010000u
#define STANDARD_RIGHTS 0x001F0000u
#define KEY_READ 0x00020019u
#define KEY_WRITE 0x00020006u
#define KEY_ALL 0x000F003Fu
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_EXECUTE 0x20000000u
#define GENERIC_ALL 0x10000000u
#define MAXIMUM_ALLOWED 0x02000000u
#define OBJ_INHERIT 0x00000002u
#define REG_SZ 1u
#define REG_EXPAND_SZ 2u
#define REG_MULTI_SZ 7u
#define ERR_FILE_NOT_FOUND 2L
#define ERR_PATH_NOT_FOUND 3L
#define ERR_ACCESS_DENIED 5L
#define ERR_INVALID_HANDLE 6L
#define ERR_NOT_ENOUGH_MEMORY 8L
#define ERR_OUTOFMEMORY 14L
#define ERR_INVALID_PARAMETER 87L
#define ERR_MORE_DATA 234L
#define ERR_BADKEY 1010L

static ntr_status map_error(long e)
{
    switch (e) {
    case 0: return NTR_SUCCESS;
    case ERR_FILE_NOT_FOUND: case ERR_PATH_NOT_FOUND: return NTR_OBJECT_NAME_NOT_FOUND;
    case ERR_ACCESS_DENIED: return NTR_ACCESS_DENIED;
    case ERR_INVALID_HANDLE: case ERR_BADKEY: return NTR_INVALID_HANDLE;
    case ERR_NOT_ENOUGH_MEMORY: case ERR_OUTOFMEMORY: return NTR_INSUFFICIENT_RESOURCES;
    case ERR_INVALID_PARAMETER: return NTR_INVALID_PARAMETER;
    default: return NTR_UNSUCCESSFUL;
    }
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void copy_bytes(void *d, const void *s, uint32_t n)
{
    uint8_t *dp = (uint8_t *)d; const uint8_t *sp = (const uint8_t *)s;
    while (n--) *dp++ = *sp++;
}

static int valid_state(const ntr_state *s) { return s && s->magic == NTR_MAGIC; }

int ntr_init(ntr_state *s, const ntr_backend *ops)
{
    unsigned i;
    if (!s) return 0;
    s->magic = 0;
    if (!ops || !ops->lock || !ops->unlock || !ops->open || !ops->create || !ops->query || !ops->set ||
        !ops->has_subkey || !ops->remove || !ops->close || !ops->to_ansi || !ops->to_wide ||
        !ops->alloc || !ops->release)
        return 0;
    s->ops = *ops;
    for (i = 0; i < NTR_HANDLES; i++) {
        s->slots[i].generation = 1; s->slots[i].live = 0; s->slots[i].deleted = 0;
        s->slots[i].key = 0; s->slots[i].path[0] = 0;
    }
    for (i = 0; i < NTR_ALLOCS; i++) s->allocs[i] = 0;
    s->magic = NTR_MAGIC;
    return 1;
}

static void retire(ntr_slot *slot)
{
    slot->live = 0; slot->deleted = 0; slot->key = 0; slot->path[0] = 0;
    slot->generation = (slot->generation + 1u) & 0x3FFFu;
    if (!slot->generation) slot->generation = 1;
}

unsigned ntr_live_handles(ntr_state *s)
{
    unsigned i, n = 0;
    if (!valid_state(s)) return 0;
    s->ops.lock(s->ops.ctx);
    for (i = 0; i < NTR_HANDLES; i++) n += s->slots[i].live;
    s->ops.unlock(s->ops.ctx);
    return n;
}

unsigned ntr_shutdown(ntr_state *s)
{
    unsigned i, n = 0;
    if (!valid_state(s)) return 0;
    s->ops.lock(s->ops.ctx);
    for (i = 0; i < NTR_HANDLES; i++)
        if (s->slots[i].live) { s->ops.close(s->ops.ctx, s->slots[i].key); retire(&s->slots[i]); n++; }
    for (i = 0; i < NTR_ALLOCS; i++)
        if (s->allocs[i]) { s->ops.release(s->ops.ctx, s->allocs[i]); s->allocs[i] = 0; }
    s->ops.unlock(s->ops.ctx);
    s->magic = 0;
    return n;
}

static void *encode(unsigned index, uint32_t generation)
{
    return (void *)(uintptr_t)(HANDLE_TAG | ((generation & 0x3FFFu) << 10) | ((uint32_t)(index + 1u) << 2));
}

static ntr_slot *decode(ntr_state *s, void *handle)
{
    uintptr_t v = (uintptr_t)handle;
    uint32_t index, generation;
    if ((v & 0xFF000003u) != HANDLE_TAG || (v >> 24) != (HANDLE_TAG >> 24)) return 0;
    index = (uint32_t)((v >> 2) & 0xFFu);
    generation = (uint32_t)((v >> 10) & 0x3FFFu);
    if (!index || index > NTR_HANDLES) return 0;
    if (!s->slots[index - 1].live || s->slots[index - 1].generation != generation) return 0;
    return &s->slots[index - 1];
}

static int map_access(uint32_t in, uint32_t *out)
{
    uint32_t a = in;
    if ((a & KEY_WOW64_32KEY) && (a & KEY_WOW64_64KEY)) return 0;
    a &= ~(KEY_WOW64_32KEY | KEY_WOW64_64KEY);  /* Win98 has a single x86 view */
    if (a & GENERIC_READ) a = (a & ~GENERIC_READ) | KEY_READ;
    if (a & GENERIC_WRITE) a = (a & ~GENERIC_WRITE) | KEY_WRITE;
    if (a & GENERIC_EXECUTE) a = (a & ~GENERIC_EXECUTE) | KEY_READ;
    if (a & GENERIC_ALL) a = (a & ~GENERIC_ALL) | KEY_ALL;
    if (a & MAXIMUM_ALLOWED) a = (a & ~MAXIMUM_ALLOWED) | KEY_ALL; /* no registry ACLs on Win98 */
    if (a & ~(KEY_SPECIFIC | STANDARD_RIGHTS)) return 0;
    *out = a;
    return 1;
}

static int valid_unicode(const ntr_unicode_string *u)
{
    if (!u || (u->Length & 1u) || (u->MaximumLength & 1u) || u->Length > u->MaximumLength) return 0;
    if (u->Length && !u->Buffer) return 0;
    return 1;
}

static int wide_equal_ascii(const uint16_t *w, uint32_t n, const char *lit)
{
    uint32_t i;
    for (i = 0; i < n; i++) {
        uint16_t c = w[i]; char l = lit[i];
        if (!l) return 0;
        if (c >= 'a' && c <= 'z') c = (uint16_t)(c - 32);
        if (l >= 'a' && l <= 'z') l = (char)(l - 32);
        if (c != (uint16_t)(unsigned char)l) return 0;
    }
    return lit[n] == 0;
}

/* Appends wide components [w, w+n) separated by '\\' to path, converting each
 * component strictly. Splitting happens on UTF-16 so DBCS trail bytes equal
 * to 0x5C can never be misparsed. *parent receives the byte length of the
 * path before the final component (or -1 when nothing was appended). */
static ntr_status append_components(ntr_state *s, char *path, const uint16_t *w, uint32_t n, long *parent)
{
    uint32_t len = 0, start = 0, i;
    while (path[len]) len++;
    if (!n) return NTR_SUCCESS;
    for (i = 0; i <= n; i++) {
        if (i == n || w[i] == '\\') {
            uint32_t used = 0, comp = i - start, need;
            long before = (long)len;
            if (!comp) return NTR_OBJECT_NAME_INVALID;
            if (len) {
                if (len + 1u >= NTR_PATH_MAX) return NTR_NAME_TOO_LONG;
                path[len++] = '\\';
            }
            if (!s->ops.to_ansi(s->ops.ctx, w + start, comp, 0, 0, &need)) return NTR_UNMAPPABLE_CHARACTER;
            if (need > 255u || len + need >= NTR_PATH_MAX) return NTR_NAME_TOO_LONG;
            if (!s->ops.to_ansi(s->ops.ctx, w + start, comp, path + len, NTR_PATH_MAX - 1u - len, &used) ||
                used != need)
                return NTR_UNMAPPABLE_CHARACTER;
            len += used;
            path[len] = 0;
            *parent = before;
            start = i + 1u;
        }
    }
    return NTR_SUCCESS;
}

static ntr_status resolve_name(ntr_state *s, const ntr_object_attributes *oa, unsigned *root, char *path, long *parent)
{
    const ntr_unicode_string *u;
    const uint16_t *w;
    uint32_t n, i, comp_start[4], comp_len[4], count = 0, start, rest;
    if (!oa || oa->Length != (uint32_t)sizeof(ntr_object_attributes)) return NTR_INVALID_PARAMETER;
    if (oa->Attributes & OBJ_INHERIT) return NTR_NOT_SUPPORTED;
    if (oa->Attributes & ~(NTR_OBJ_CASE_INSENSITIVE | NTR_OBJ_OPENIF)) return NTR_INVALID_PARAMETER;
    if (oa->SecurityDescriptor) return NTR_NOT_SUPPORTED; /* Win98 registry has no ACLs */
    u = oa->ObjectName;
    if (u && !valid_unicode(u)) return NTR_INVALID_PARAMETER;
    w = u ? u->Buffer : 0;
    n = u ? u->Length / 2u : 0;
    path[0] = 0;
    *parent = -1;
    if (oa->RootDirectory) {
        ntr_slot *base = decode(s, oa->RootDirectory);
        if (!base) return NTR_INVALID_HANDLE;
        if (base->deleted) return NTR_KEY_DELETED;
        if (n && w[0] == '\\') return NTR_OBJECT_PATH_SYNTAX_BAD;
        *root = base->root;
        copy_bytes(path, base->path, (uint32_t)sizeof(base->path));
        return append_components(s, path, w, n, parent);
    }
    if (!n || w[0] != '\\') return NTR_OBJECT_PATH_SYNTAX_BAD;
    if (n > 1u && w[n - 1u] == '\\') return NTR_OBJECT_NAME_INVALID;
    start = 1;
    for (i = 1; i <= n && count < 4; i++)
        if (i == n || w[i] == '\\') {
            comp_start[count] = start; comp_len[count] = i - start; count++; start = i + 1u;
        }
    if (!count || !wide_equal_ascii(w + comp_start[0], comp_len[0], "REGISTRY")) return NTR_OBJECT_NAME_NOT_FOUND;
    if (count < 2) return NTR_NOT_SUPPORTED; /* the bare \\Registry directory is not a Win98 key */
    if (wide_equal_ascii(w + comp_start[1], comp_len[1], "MACHINE")) {
        *root = NTR_ROOT_MACHINE; rest = 2;
    } else if (wide_equal_ascii(w + comp_start[1], comp_len[1], "USER")) {
        if (count >= 3 && wide_equal_ascii(w + comp_start[2], comp_len[2], NTR_CURRENT_USER_ALIAS)) {
            *root = NTR_ROOT_CURRENT_USER; rest = 3;
        } else {
            *root = NTR_ROOT_USERS; rest = 2;
        }
    } else {
        return NTR_OBJECT_NAME_NOT_FOUND;
    }
    if (count <= rest) return NTR_SUCCESS;
    return append_components(s, path, w + comp_start[rest], n - comp_start[rest], parent);
}

static int alloc_slot(ntr_state *s)
{
    unsigned i;
    for (i = 0; i < NTR_HANDLES; i++) if (!s->slots[i].live) return (int)i;
    return -1;
}

static ntr_status publish(ntr_state *s, int index, unsigned root, const char *path, uint32_t access, void *key,
                          void **handle)
{
    ntr_slot *slot = &s->slots[index];
    slot->live = 1; slot->deleted = 0; slot->root = root; slot->access = access; slot->key = key;
    copy_bytes(slot->path, path, NTR_PATH_MAX);
    *handle = encode((unsigned)index, slot->generation);
    return NTR_SUCCESS;
}

ntr_status ntr_open_key_ex(ntr_state *s, void **handle, uint32_t access, const ntr_object_attributes *oa,
                           uint32_t options)
{
    char path[NTR_PATH_MAX];
    unsigned root = 0;
    long parent;
    uint32_t granted;
    void *key = 0;
    ntr_status st;
    int index;
    if (!valid_state(s)) return NTR_UNSUCCESSFUL;
    if (!handle) return NTR_INVALID_PARAMETER;
    *handle = 0;
    if (options) return NTR_NOT_SUPPORTED; /* backup/restore and link opens */
    if (!map_access(access, &granted)) return NTR_INVALID_PARAMETER;
    s->ops.lock(s->ops.ctx);
    st = resolve_name(s, oa, &root, path, &parent);
    if (st == NTR_SUCCESS) {
        index = alloc_slot(s);
        if (index < 0) st = NTR_INSUFFICIENT_RESOURCES;
        else {
            st = map_error(s->ops.open(s->ops.ctx, root, path, &key));
            if (st == NTR_SUCCESS) st = publish(s, index, root, path, granted, key, handle);
        }
    }
    s->ops.unlock(s->ops.ctx);
    return st;
}

ntr_status ntr_create_key(ntr_state *s, void **handle, uint32_t access, const ntr_object_attributes *oa,
                          uint32_t title_index, const ntr_unicode_string *class_name, uint32_t options,
                          uint32_t *disposition)
{
    char path[NTR_PATH_MAX];
    unsigned root = 0;
    long parent;
    uint32_t granted;
    void *key = 0, *probe = 0;
    int created = 0, index;
    ntr_status st;
    (void)title_index; /* ignored by NT as well */
    if (!valid_state(s)) return NTR_UNSUCCESSFUL;
    if (!handle) return NTR_INVALID_PARAMETER;
    *handle = 0;
    if (options) return NTR_NOT_SUPPORTED; /* volatile/link/backup keys absent on Win98 */
    if (class_name && (!valid_unicode(class_name) || class_name->Length)) return NTR_NOT_SUPPORTED;
    if (!map_access(access, &granted)) return NTR_INVALID_PARAMETER;
    s->ops.lock(s->ops.ctx);
    st = resolve_name(s, oa, &root, path, &parent);
    if (st == NTR_SUCCESS) {
        index = alloc_slot(s);
        if (index < 0) st = NTR_INSUFFICIENT_RESOURCES;
        else if (parent < 0) {
            /* Predefined root itself: it always exists. */
            st = map_error(s->ops.open(s->ops.ctx, root, path, &key));
            created = 0;
        } else {
            /* NT creates exactly one level; Win98 RegCreateKeyEx would create
             * missing intermediates, so the parent must already exist. */
            char saved = path[parent];
            path[parent] = 0;
            st = map_error(s->ops.open(s->ops.ctx, root, path, &probe));
            path[parent] = saved;
            if (st == NTR_SUCCESS) {
                s->ops.close(s->ops.ctx, probe);
                st = map_error(s->ops.create(s->ops.ctx, root, path, &key, &created));
            }
        }
        if (st == NTR_SUCCESS) {
            st = publish(s, index, root, path, granted, key, handle);
            if (disposition) *disposition = created ? NTR_REG_CREATED_NEW_KEY : NTR_REG_OPENED_EXISTING_KEY;
        }
    }
    s->ops.unlock(s->ops.ctx);
    return st;
}

static int is_string_type(uint32_t type) { return type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ; }

static ntr_status value_name(ntr_state *s, const ntr_unicode_string *name, char *out)
{
    uint32_t need = 0, used = 0, n;
    if (!name || !valid_unicode(name)) return NTR_INVALID_PARAMETER;
    n = name->Length / 2u;
    out[0] = 0;
    if (!n) return NTR_SUCCESS;
    if (!s->ops.to_ansi(s->ops.ctx, name->Buffer, n, 0, 0, &need)) return NTR_UNMAPPABLE_CHARACTER;
    if (need > 255u) return NTR_NAME_TOO_LONG;
    if (!s->ops.to_ansi(s->ops.ctx, name->Buffer, n, out, 255u, &used) || used != need) return NTR_UNMAPPABLE_CHARACTER;
    out[used] = 0;
    return NTR_SUCCESS;
}

static ntr_slot *usable(ntr_state *s, void *handle, uint32_t right, ntr_status *st)
{
    ntr_slot *slot = decode(s, handle);
    if (!slot) { *st = NTR_INVALID_HANDLE; return 0; }
    if (slot->deleted) { *st = NTR_KEY_DELETED; return 0; }
    if ((slot->access & right) != right) { *st = NTR_ACCESS_DENIED; return 0; }
    *st = NTR_SUCCESS;
    return slot;
}

ntr_status ntr_query_value_key(ntr_state *s, void *handle, const ntr_unicode_string *name, uint32_t info_class,
                               void *out, uint32_t length, uint32_t *result_length)
{
    char vname[256];
    ntr_slot *slot;
    ntr_status st;
    uint32_t type = 0, raw = 0, data_bytes, name_bytes, fixed, required, data_offset, wide = 0, tries;
    uint8_t *buffer = 0, *o = (uint8_t *)out;
    long e = 0;
    if (!valid_state(s)) return NTR_UNSUCCESSFUL;
    if (!result_length || (length && !out)) return NTR_INVALID_PARAMETER;
    if (info_class != NTR_KEY_VALUE_BASIC && info_class != NTR_KEY_VALUE_FULL && info_class != NTR_KEY_VALUE_PARTIAL)
        return NTR_INVALID_INFO_CLASS;
    s->ops.lock(s->ops.ctx);
    slot = usable(s, handle, KEY_QUERY_VALUE, &st);
    if (slot) st = value_name(s, name, vname);
    for (tries = 0; st == NTR_SUCCESS && tries < 3; tries++) {
        raw = 0;
        e = s->ops.query(s->ops.ctx, slot->key, vname, &type, 0, &raw);
        if (e) { st = map_error(e); break; }
        if (raw > NTR_DATA_MAX) { st = NTR_INSUFFICIENT_RESOURCES; break; }
        if (buffer) s->ops.release(s->ops.ctx, buffer);
        buffer = (uint8_t *)s->ops.alloc(s->ops.ctx, raw ? raw : 1u);
        if (!buffer) { st = NTR_INSUFFICIENT_RESOURCES; break; }
        e = s->ops.query(s->ops.ctx, slot->key, vname, &type, buffer, &raw);
        if (e != ERR_MORE_DATA) { st = map_error(e); break; }
    }
    if (st == NTR_SUCCESS && e == ERR_MORE_DATA) st = NTR_UNSUCCESSFUL; /* value kept growing */
    if (st == NTR_SUCCESS) {
        if (is_string_type(type)) {
            if (raw && !s->ops.to_wide(s->ops.ctx, (const char *)buffer, raw, 0, 0, &wide)) st = NTR_UNMAPPABLE_CHARACTER;
            data_bytes = wide * 2u;
        } else {
            data_bytes = raw;
        }
    }
    if (st == NTR_SUCCESS) {
        name_bytes = name->Length;
        if (info_class == NTR_KEY_VALUE_BASIC) { fixed = 12u; data_offset = 0; required = 12u + name_bytes; }
        else if (info_class == NTR_KEY_VALUE_FULL) {
            fixed = 20u; data_offset = (20u + name_bytes + 3u) & ~3u; required = data_offset + data_bytes;
        } else { fixed = 12u; data_offset = 12u; required = 12u + data_bytes; }
        *result_length = required;
        if (length < fixed) st = NTR_BUFFER_TOO_SMALL;
        else {
            put32(o, 0); /* TitleIndex */
            put32(o + 4, type);
            if (info_class == NTR_KEY_VALUE_BASIC) put32(o + 8, name_bytes);
            else if (info_class == NTR_KEY_VALUE_FULL) {
                put32(o + 8, data_offset); put32(o + 12, data_bytes); put32(o + 16, name_bytes);
            } else put32(o + 8, data_bytes);
            if (length < required) st = NTR_BUFFER_OVERFLOW;
            else {
                if (info_class != NTR_KEY_VALUE_PARTIAL && name_bytes) copy_bytes(o + fixed, name->Buffer, name_bytes);
                if (info_class == NTR_KEY_VALUE_FULL)
                    for (wide = 20u + name_bytes; wide < data_offset; wide++) o[wide] = 0;
                if (info_class != NTR_KEY_VALUE_BASIC && data_bytes) {
                    if (is_string_type(type)) {
                        uint32_t used = 0;
                        uint16_t *tmp = (uint16_t *)s->ops.alloc(s->ops.ctx, data_bytes);
                        if (!tmp) st = NTR_INSUFFICIENT_RESOURCES;
                        else {
                            if (!s->ops.to_wide(s->ops.ctx, (const char *)buffer, raw, tmp, data_bytes / 2u, &used) ||
                                used * 2u != data_bytes)
                                st = NTR_UNMAPPABLE_CHARACTER;
                            else copy_bytes(o + data_offset, tmp, data_bytes);
                            s->ops.release(s->ops.ctx, tmp);
                        }
                    } else {
                        copy_bytes(o + data_offset, buffer, data_bytes);
                    }
                }
            }
        }
    }
    if (buffer) s->ops.release(s->ops.ctx, buffer);
    s->ops.unlock(s->ops.ctx);
    return st;
}

ntr_status ntr_set_value_key(ntr_state *s, void *handle, const ntr_unicode_string *name, uint32_t title_index,
                             uint32_t type, const void *data, uint32_t bytes)
{
    char vname[256];
    ntr_slot *slot;
    ntr_status st;
    char *ansi = 0;
    uint32_t need = 0, used = 0;
    (void)title_index;
    if (!valid_state(s)) return NTR_UNSUCCESSFUL;
    if (bytes && !data) return NTR_INVALID_PARAMETER;
    if (bytes > NTR_DATA_MAX) return NTR_INSUFFICIENT_RESOURCES;
    if (is_string_type(type) && (bytes & 1u)) return NTR_INVALID_PARAMETER;
    s->ops.lock(s->ops.ctx);
    slot = usable(s, handle, KEY_SET_VALUE, &st);
    if (slot) st = value_name(s, name, vname);
    if (st == NTR_SUCCESS) {
        if (is_string_type(type) && bytes) {
            /* Copy the caller's UTF-16 once so validation and conversion see
             * the same bytes even if another thread mutates its buffer. */
            uint16_t *wide = (uint16_t *)s->ops.alloc(s->ops.ctx, bytes);
            if (!wide) st = NTR_INSUFFICIENT_RESOURCES;
            else {
                copy_bytes(wide, data, bytes);
                if (!s->ops.to_ansi(s->ops.ctx, wide, bytes / 2u, 0, 0, &need)) st = NTR_UNMAPPABLE_CHARACTER;
                else if (!(ansi = (char *)s->ops.alloc(s->ops.ctx, need ? need : 1u))) st = NTR_INSUFFICIENT_RESOURCES;
                else if (!s->ops.to_ansi(s->ops.ctx, wide, bytes / 2u, ansi, need, &used) || used != need)
                    st = NTR_UNMAPPABLE_CHARACTER;
                s->ops.release(s->ops.ctx, wide);
            }
            if (st == NTR_SUCCESS)
                st = map_error(s->ops.set(s->ops.ctx, slot->key, vname, type, (const uint8_t *)ansi, used));
        } else {
            st = map_error(s->ops.set(s->ops.ctx, slot->key, vname, type, (const uint8_t *)data, bytes));
        }
    }
    if (ansi) s->ops.release(s->ops.ctx, ansi);
    s->ops.unlock(s->ops.ctx);
    return st;
}

static int same_path(const ntr_slot *a, unsigned root, const char *path)
{
    unsigned i;
    if (a->root != root) return 0;
    for (i = 0; i < NTR_PATH_MAX; i++) {
        char x = a->path[i], y = path[i];
        if (x >= 'a' && x <= 'z') x = (char)(x - 32);
        if (y >= 'a' && y <= 'z') y = (char)(y - 32);
        if (x != y) return 0;
        if (!x) return 1;
    }
    return 0;
}

ntr_status ntr_delete_key(ntr_state *s, void *handle)
{
    ntr_slot *slot;
    ntr_status st;
    int present = 1;
    unsigned i;
    if (!valid_state(s)) return NTR_UNSUCCESSFUL;
    s->ops.lock(s->ops.ctx);
    slot = usable(s, handle, NT_DELETE, &st);
    if (slot && !slot->path[0]) st = NTR_CANNOT_DELETE; /* predefined roots */
    if (st == NTR_SUCCESS) st = map_error(s->ops.has_subkey(s->ops.ctx, slot->key, &present));
    /* Win98 RegDeleteKey deletes recursively; NT refuses keys with children. */
    if (st == NTR_SUCCESS && present) st = NTR_CANNOT_DELETE;
    if (st == NTR_SUCCESS) st = map_error(s->ops.remove(s->ops.ctx, slot->root, slot->path));
    if (st == NTR_SUCCESS) {
        unsigned root = slot->root;
        char path[NTR_PATH_MAX];
        copy_bytes(path, slot->path, NTR_PATH_MAX);
        for (i = 0; i < NTR_HANDLES; i++)
            if (s->slots[i].live && same_path(&s->slots[i], root, path)) s->slots[i].deleted = 1;
    }
    s->ops.unlock(s->ops.ctx);
    return st;
}

ntr_status ntr_close(ntr_state *s, void *handle)
{
    ntr_slot *slot;
    ntr_status st = NTR_SUCCESS;
    if (!valid_state(s)) return NTR_UNSUCCESSFUL;
    s->ops.lock(s->ops.ctx);
    slot = decode(s, handle);
    if (!slot) st = NTR_INVALID_HANDLE; /* non-registry handles are not owned here */
    else {
        long e = s->ops.close(s->ops.ctx, slot->key);
        retire(slot);
        if (e) st = map_error(e);
    }
    s->ops.unlock(s->ops.ctx);
    return st;
}

ntr_status ntr_format_current_user_key_path(ntr_state *s, ntr_unicode_string *out)
{
    static const char prefix[] = "\\REGISTRY\\USER\\" NTR_CURRENT_USER_ALIAS;
    uint32_t n = (uint32_t)sizeof(prefix) - 1u, i;
    uint16_t *buffer;
    ntr_status st = NTR_INSUFFICIENT_RESOURCES;
    if (!valid_state(s)) return NTR_UNSUCCESSFUL;
    if (!out) return NTR_INVALID_PARAMETER;
    s->ops.lock(s->ops.ctx);
    for (i = 0; i < NTR_ALLOCS; i++) if (!s->allocs[i]) break;
    if (i < NTR_ALLOCS && (buffer = (uint16_t *)s->ops.alloc(s->ops.ctx, (n + 1u) * 2u)) != 0) {
        uint32_t k;
        for (k = 0; k < n; k++) buffer[k] = (uint16_t)(unsigned char)prefix[k];
        buffer[n] = 0;
        s->allocs[i] = buffer;
        out->Buffer = buffer; out->Length = (uint16_t)(n * 2u); out->MaximumLength = (uint16_t)((n + 1u) * 2u);
        st = NTR_SUCCESS;
    }
    s->ops.unlock(s->ops.ctx);
    return st;
}

void ntr_init_unicode_string(ntr_unicode_string *dest, const uint16_t *source)
{
    uint32_t n = 0;
    if (!dest) return;
    dest->Buffer = (uint16_t *)source;
    if (!source) { dest->Length = dest->MaximumLength = 0; return; }
    while (source[n] && n < 0x7FFEu) n++;
    if (n * 2u > 0xFFFCu) n = 0xFFFCu / 2u;
    dest->Length = (uint16_t)(n * 2u);
    dest->MaximumLength = (uint16_t)(n * 2u + 2u);
}

void ntr_free_unicode_string(ntr_state *s, ntr_unicode_string *str)
{
    unsigned i;
    if (!str) return;
    if (valid_state(s) && str->Buffer) {
        s->ops.lock(s->ops.ctx);
        /* Only buffers this provider allocated are released; unknown buffers
         * are never passed to a heap they may not belong to. */
        for (i = 0; i < NTR_ALLOCS; i++)
            if (s->allocs[i] == (void *)str->Buffer) {
                s->ops.release(s->ops.ctx, s->allocs[i]); s->allocs[i] = 0; break;
            }
        s->ops.unlock(s->ops.ctx);
    }
    str->Buffer = 0; str->Length = str->MaximumLength = 0;
}
