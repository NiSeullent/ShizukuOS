/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the registry and native-service surface a driver calls beyond
 * ntdrv_zw.c -- RtlQueryRegistryValues (every RTL_QUERY_REGISTRY_* flag, the DIRECT rules,
 * defaults, REG_MULTI_SZ expansion, DELETE), RtlWrite/Delete/Check/CreateRegistryKey, the
 * key/value information classes for ZwQueryValueKey / ZwEnumerateValueKey / ZwEnumerateKey /
 * ZwQueryKey, ZwDeleteKey/ZwDeleteValueKey/ZwFlushKey, object-manager directories and symbolic
 * links, ZwOpenFile/ZwQueryInformationFile, ZwQuerySystemInformation (basic, processor, module
 * list, time of day), ZwLoadDriver/ZwUnloadDriver from kernel mode and ZwPowerInformation. All
 * of it works on the real configuration manager (registry.c) and the real loader records.
 */
#include "ntdrv.h"
#include "registry.h"
#include "fs.h"

struct objattr { uint32_t Length, pad; uint64_t RootDirectory; UNICODE_STRING *ObjectName; uint32_t Attributes, pad2; void *sd, *sqos; };
#define STATUS_NAME_TOO_LONG ((int32_t)0xC0000106)
#define STATUS_INVALID_DEVICE_REQUEST_ ((int32_t)0xC0000010)
#define NT_SUCCESS(s) ((int32_t)(s) >= 0)

extern NTSTATUS NTAPI ZwOpenKey(void *handle_out, uint32_t access, struct objattr *oa);
extern NTSTATUS NTAPI ZwCreateKey(void *handle_out, uint32_t access, struct objattr *oa, uint32_t ti, void *cls, uint32_t opt, uint32_t *disp);
extern NTSTATUS NTAPI ZwSetValueKey(uint64_t handle, UNICODE_STRING *name, uint32_t ti, uint32_t type, void *data, uint32_t len);
extern NTSTATUS NTAPI ZwClose(uint64_t handle);
extern NTSTATUS NTAPI ZwCreateFile(void *handle_out, uint32_t access, struct objattr *oa, IO_STATUS_BLOCK *iosb, LARGE_INTEGER *alloc,
                                   uint32_t attrs, uint32_t share, uint32_t disp, uint32_t opts, void *ea, uint32_t ealen);
extern int32_t ntdrv_load_service_path(const uint16_t *w, unsigned chars);      /* ntdrv_io.c: NtLoadDriver's kernel core */
extern int32_t ntdrv_unload_service_path(const uint16_t *w, unsigned chars);
extern uint64_t ntdrv_wcslen(const WCHAR *);

/* ================================================================ information records (kernel buffers) */
typedef struct { uint8_t *buf; uint32_t len, need; } kout_t;
static void kput(kout_t *o, uint32_t off, const void *src, uint32_t n)
{
    if (!n) return;
    if (off >= o->len) return;
    memcpy(o->buf + off, src, off + n <= o->len ? n : o->len - off);
}
static void kput32(kout_t *o, uint32_t off, uint32_t v) { kput(o, off, &v, 4); }
static void kput64(kout_t *o, uint32_t off, uint64_t v) { kput(o, off, &v, 8); }
/* Windows: STATUS_BUFFER_TOO_SMALL when even the fixed part does not fit (nothing written), STATUS_BUFFER_OVERFLOW when the
 * fixed part fits but the variable part is cut; ResultLength always carries the full size. */
static int32_t kfinish(kout_t *o, uint32_t *reslen, uint32_t need, uint32_t fixed)
{
    if (reslen) *reslen = need;
    if (o->len < fixed) return STATUS_BUFFER_TOO_SMALL;
    if (o->len < need) return STATUS_BUFFER_OVERFLOW;
    return STATUS_SUCCESS;
}

static int32_t fill_key_info(regkey_t *k, uint32_t cls, void *buf, uint32_t len, uint32_t *reslen)
{
    kout_t o = { buf, len, 0 };
    const uint32_t nbytes = k->name_len * 2;
    uint32_t need, fixed;
    switch (cls) {
    case 0:                                             /* KEY_BASIC_INFORMATION */
        fixed = 16; need = fixed + nbytes;
        if (len >= fixed) { kput64(&o, 0, k->last_write); kput32(&o, 8, 0); kput32(&o, 12, nbytes); kput(&o, 16, regkey_name(k), nbytes); }
        break;
    case 1: {                                           /* KEY_NODE_INFORMATION */
        const uint32_t cbytes = k->class_len * 2, coff = (24 + nbytes + 3) & ~3u;
        fixed = 24; need = cbytes ? coff + cbytes : 24 + nbytes;
        if (len >= fixed) {
            kput64(&o, 0, k->last_write); kput32(&o, 8, 0); kput32(&o, 12, cbytes ? coff : 0xffffffffu); kput32(&o, 16, cbytes); kput32(&o, 20, nbytes);
            kput(&o, 24, regkey_name(k), nbytes);
            if (cbytes) kput(&o, coff, regkey_class(k), cbytes);
        }
        break; }
    case 2: {                                           /* KEY_FULL_INFORMATION */
        regkey_t *c; regval_t *v;
        uint32_t max_name = 0, max_class = 0, max_vname = 0, max_vdata = 0;
        const uint32_t cbytes = k->class_len * 2;
        for (c = k->child; c; c = c->sibling) { if (c->name_len * 2 > max_name) max_name = c->name_len * 2; if (c->class_len * 2 > max_class) max_class = c->class_len * 2; }
        for (v = k->values; v; v = v->next) { if (v->name_len * 2 > max_vname) max_vname = v->name_len * 2; if (v->data_len > max_vdata) max_vdata = v->data_len; }
        fixed = 44; need = fixed + cbytes;
        if (len >= fixed) {
            kput64(&o, 0, k->last_write); kput32(&o, 8, 0); kput32(&o, 12, cbytes ? 44 : 0xffffffffu); kput32(&o, 16, cbytes); kput32(&o, 20, k->nsubkeys);
            kput32(&o, 24, max_name); kput32(&o, 28, max_class); kput32(&o, 32, k->nvalues); kput32(&o, 36, max_vname); kput32(&o, 40, max_vdata);
            if (cbytes) kput(&o, 44, regkey_class(k), cbytes);
        }
        break; }
    case 3: {                                           /* KEY_NAME_INFORMATION: full path */
        const uint32_t pchars = reg_key_path(k, 0, 0);
        uint16_t *path = kmalloc(pchars * 2);
        if (!path) return STATUS_NO_MEMORY;
        reg_key_path(k, path, pchars);
        fixed = 4; need = 4 + pchars * 2;
        if (len >= fixed) { kput32(&o, 0, pchars * 2); kput(&o, 4, path, pchars * 2); }
        kfree(path);
        break; }
    case 4: {                                           /* KEY_CACHED_INFORMATION */
        regkey_t *c; regval_t *v;
        uint32_t max_name = 0, max_vname = 0, max_vdata = 0;
        for (c = k->child; c; c = c->sibling) if (c->name_len * 2 > max_name) max_name = c->name_len * 2;
        for (v = k->values; v; v = v->next) { if (v->name_len * 2 > max_vname) max_vname = v->name_len * 2; if (v->data_len > max_vdata) max_vdata = v->data_len; }
        fixed = need = 36;
        if (len >= fixed) {
            kput64(&o, 0, k->last_write); kput32(&o, 8, 0); kput32(&o, 12, k->nsubkeys); kput32(&o, 16, max_name); kput32(&o, 20, k->nvalues);
            kput32(&o, 24, max_vname); kput32(&o, 28, max_vdata); kput32(&o, 32, k->name_len * 2);
        }
        break; }
    default: return STATUS_INVALID_INFO_CLASS;
    }
    return kfinish(&o, reslen, need, fixed);
}

static int32_t fill_value_info(regval_t *v, uint32_t cls, void *buf, uint32_t len, uint32_t *reslen)
{
    kout_t o = { buf, len, 0 };
    const uint32_t nbytes = v->name_len * 2;
    uint32_t need, fixed;
    switch (cls) {
    case 0:                                             /* KEY_VALUE_BASIC_INFORMATION */
        fixed = 12; need = fixed + nbytes;
        if (len >= fixed) { kput32(&o, 0, 0); kput32(&o, 4, v->type); kput32(&o, 8, nbytes); kput(&o, 12, regval_name(v), nbytes); }
        break;
    case 1: {                                           /* KEY_VALUE_FULL_INFORMATION */
        const uint32_t doff = (20 + nbytes + 3) & ~3u;
        fixed = 20; need = doff + v->data_len;
        if (len >= fixed) {
            kput32(&o, 0, 0); kput32(&o, 4, v->type); kput32(&o, 8, doff); kput32(&o, 12, v->data_len); kput32(&o, 16, nbytes);
            kput(&o, 20, regval_name(v), nbytes); kput(&o, doff, regval_data(v), v->data_len);
        }
        break; }
    case 2:                                             /* KEY_VALUE_PARTIAL_INFORMATION */
        fixed = 12; need = fixed + v->data_len;
        if (len >= fixed) { kput32(&o, 0, 0); kput32(&o, 4, v->type); kput32(&o, 8, v->data_len); kput(&o, 12, regval_data(v), v->data_len); }
        break;
    case 3:                                             /* KEY_VALUE_FULL_INFORMATION_ALIGN64 */
    case 4: {                                           /* KEY_VALUE_PARTIAL_INFORMATION_ALIGN64: type(0) datalen(4) data(8) */
        if (cls == 3) return fill_value_info(v, 1, buf, len, reslen);
        fixed = 8; need = fixed + v->data_len;
        if (len >= fixed) { kput32(&o, 0, v->type); kput32(&o, 4, v->data_len); kput(&o, 8, regval_data(v), v->data_len); }
        break; }
    default: return STATUS_INVALID_INFO_CLASS;
    }
    return kfinish(&o, reslen, need, fixed);
}

/* ================================================================ Zw key queries */
NTSTATUS NTAPI ZwQueryValueKey(uint64_t handle, UNICODE_STRING *name, uint32_t cls, void *buf, uint32_t len, uint32_t *reslen)
{
    regkey_t *node = ntdrv_kh_get(handle, KH_KEY);
    regval_t *v;
    NTSTATUS st;
    if (!node) return STATUS_INVALID_HANDLE;
    reg_lock();
    v = reg_find_value(node, name->Buffer, name->Length / 2);
    if (!v) { reg_unlock(); return STATUS_OBJECT_NAME_NOT_FOUND; }
    st = fill_value_info(v, cls, buf, len, reslen);
    reg_unlock();
    return st;
}
NTSTATUS NTAPI ZwEnumerateValueKey(uint64_t handle, uint32_t index, uint32_t cls, void *buf, uint32_t len, uint32_t *reslen)
{
    regkey_t *node = ntdrv_kh_get(handle, KH_KEY);
    regval_t *v;
    NTSTATUS st;
    if (!node) return STATUS_INVALID_HANDLE;
    reg_lock();
    v = reg_nth_value(node, index);
    if (!v) { reg_unlock(); return STATUS_NO_MORE_ENTRIES; }
    st = fill_value_info(v, cls, buf, len, reslen);
    reg_unlock();
    return st;
}
NTSTATUS NTAPI ZwEnumerateKey(uint64_t handle, uint32_t index, uint32_t cls, void *buf, uint32_t len, uint32_t *reslen)
{
    regkey_t *node = ntdrv_kh_get(handle, KH_KEY), *c;
    NTSTATUS st;
    if (!node) return STATUS_INVALID_HANDLE;
    reg_lock();
    c = reg_nth_child(node, index);
    if (!c) { reg_unlock(); return STATUS_NO_MORE_ENTRIES; }
    st = fill_key_info(c, cls, buf, len, reslen);
    reg_unlock();
    return st;
}
NTSTATUS NTAPI ZwQueryKey(uint64_t handle, uint32_t cls, void *buf, uint32_t len, uint32_t *reslen)
{
    regkey_t *node = ntdrv_kh_get(handle, KH_KEY);
    NTSTATUS st;
    if (!node) return STATUS_INVALID_HANDLE;
    reg_lock();
    st = fill_key_info(node, cls, buf, len, reslen);
    reg_unlock();
    return st;
}
NTSTATUS NTAPI ZwDeleteKey(uint64_t handle)
{
    regkey_t *node = ntdrv_kh_get(handle, KH_KEY);
    NTSTATUS st;
    if (!node) return STATUS_INVALID_HANDLE;
    reg_lock();
    st = reg_delete_key(node);
    reg_unlock();
    return st;
}
NTSTATUS NTAPI ZwDeleteValueKey(uint64_t handle, UNICODE_STRING *name)
{
    regkey_t *node = ntdrv_kh_get(handle, KH_KEY);
    NTSTATUS st;
    if (!node) return STATUS_INVALID_HANDLE;
    reg_lock();
    st = reg_delete_value(node, name->Buffer, name->Length / 2);
    reg_unlock();
    return st;
}
NTSTATUS NTAPI ZwFlushKey(uint64_t handle) { return ntdrv_kh_get(handle, KH_KEY) ? STATUS_SUCCESS : STATUS_INVALID_HANDLE; }   /* the hive is memory-resident */

/* ================================================================ Rtl registry helpers */
#define RTL_REGISTRY_ABSOLUTE 0
#define RTL_REGISTRY_SERVICES 1
#define RTL_REGISTRY_CONTROL 2
#define RTL_REGISTRY_WINDOWS_NT 3
#define RTL_REGISTRY_DEVICEMAP 4
#define RTL_REGISTRY_USER 5
#define RTL_REGISTRY_HANDLE 0x40000000u
#define RTL_REGISTRY_OPTIONAL 0x80000000u
#define RTL_QUERY_REGISTRY_SUBKEY 0x01
#define RTL_QUERY_REGISTRY_TOPKEY 0x02
#define RTL_QUERY_REGISTRY_REQUIRED 0x04
#define RTL_QUERY_REGISTRY_NOVALUE 0x08
#define RTL_QUERY_REGISTRY_NOEXPAND 0x10
#define RTL_QUERY_REGISTRY_DIRECT 0x20
#define RTL_QUERY_REGISTRY_DELETE 0x40
#define RTL_QUERY_REGISTRY_TYPECHECK 0x100

static const WCHAR *rel_prefix(uint32_t rel)
{
    switch (rel & 0x3fffffffu) {
    case RTL_REGISTRY_ABSOLUTE: return u"";
    case RTL_REGISTRY_SERVICES: return u"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
    case RTL_REGISTRY_CONTROL: return u"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\";
    case RTL_REGISTRY_WINDOWS_NT: return u"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\";
    case RTL_REGISTRY_DEVICEMAP: return u"\\Registry\\Machine\\Hardware\\DeviceMap\\";
    case RTL_REGISTRY_USER: return u"\\Registry\\User\\.Default\\";
    default: return 0;
    }
}
/* Open (or create) the key RelativeTo/Path names; with RTL_REGISTRY_HANDLE the path is the handle itself. */
static NTSTATUS rtl_open_key(uint32_t rel, const WCHAR *path, int create, uint64_t *handle, int *owned)
{
    const WCHAR *pfx;
    uint64_t np, nq;
    WCHAR *full;
    UNICODE_STRING u;
    struct objattr oa;
    NTSTATUS st;
    if (rel & RTL_REGISTRY_HANDLE) { *handle = (uint64_t)path; *owned = 0; return STATUS_SUCCESS; }
    pfx = rel_prefix(rel);
    if (!pfx) return STATUS_INVALID_PARAMETER;
    np = ntdrv_wcslen(pfx); nq = path ? ntdrv_wcslen(path) : 0;
    if ((np + nq) * 2 > 0xfffe) return STATUS_NAME_TOO_LONG;
    full = kmalloc((np + nq + 1) * 2);
    if (!full) return STATUS_NO_MEMORY;
    memcpy(full, pfx, np * 2); if (nq) memcpy(full + np, path, nq * 2); full[np + nq] = 0;
    u.Buffer = full; u.Length = (uint16_t)((np + nq) * 2); u.MaximumLength = (uint16_t)(u.Length + 2);
    memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &u; oa.Attributes = 0x40;
    st = create ? ZwCreateKey(handle, 0xf003f, &oa, 0, 0, 0, 0) : ZwOpenKey(handle, 0x20019, &oa);
    kfree(full);
    *owned = 1;
    return st;
}

/* RTL_QUERY_REGISTRY_TABLE (x64 0x38): QueryRoutine(0) Flags(8) Name(0x10) EntryContext(0x18) DefaultType(0x20) DefaultData(0x28) DefaultLength(0x30) */
typedef struct {
    NTSTATUS (NTAPI *QueryRoutine)(WCHAR *name, uint32_t type, void *data, uint32_t len, void *ctx, void *entry_ctx);
    uint32_t Flags; uint32_t _p0;
    WCHAR *Name;
    void *EntryContext;
    uint32_t DefaultType; uint32_t _p1;
    void *DefaultData;
    uint32_t DefaultLength; uint32_t _p2;
} RTL_QUERY_REGISTRY_TABLE;
_Static_assert(sizeof(RTL_QUERY_REGISTRY_TABLE) == 0x38, "RTL_QUERY_REGISTRY_TABLE");

/* The DIRECT rules (documented under RtlQueryRegistryValues, and what ntoskrnl does): string types fill a UNICODE_STRING
 * (allocating when Buffer is NULL); a value of at most 4 bytes is copied as is; otherwise EntryContext starts with a
 * LONG: negative = -(buffer size) and the data is copied raw, non-negative = the buffer receives {Length, Type, data}
 * (REG_BINARY: data only). */
static NTSTATUS query_direct(uint32_t type, const void *data, uint32_t len, void *ctx)
{
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        UNICODE_STRING *u = ctx;
        uint16_t actual = len > 0xffff ? 0xffff : (uint16_t)len;
        if (!u->Buffer) { u->Buffer = kmalloc(actual ? actual : 2); if (!u->Buffer) return STATUS_NO_MEMORY; u->MaximumLength = actual; }
        else if (actual > u->MaximumLength) return STATUS_BUFFER_TOO_SMALL;
        memcpy(u->Buffer, data, actual);
        u->Length = (uint16_t)(actual >= 2 ? actual - 2 : 0);
        return STATUS_SUCCESS;
    }
    if (len <= 4) { if (ctx != data && len) memcpy(ctx, data, len); return STATUS_SUCCESS; }
    {
        int32_t *l = ctx;
        if (*l < 0) {
            if ((uint32_t)(-*l) < len) return STATUS_BUFFER_TOO_SMALL;
            memcpy(ctx, data, len);
        } else if (type != REG_BINARY) {
            if ((uint32_t)*l < 8 + len) return STATUS_BUFFER_TOO_SMALL;
            l[0] = (int32_t)len; l[1] = (int32_t)type;
            memcpy(l + 2, data, len);
        } else memcpy(ctx, data, len);
    }
    return STATUS_SUCCESS;
}

/* Deliver one value (or the table default) to the entry: expansion of REG_MULTI_SZ into REG_SZ calls unless NOEXPAND,
 * REG_EXPAND_SZ passed through as REG_SZ (there is no environment to expand against), DIRECT or the query routine. */
static NTSTATUS deliver(RTL_QUERY_REGISTRY_TABLE *t, WCHAR *name, uint32_t type, void *data, uint32_t len, void *ctx, int absent)
{
    NTSTATUS st = STATUS_SUCCESS;
    if (absent || (len == 0 && type == t->DefaultType)) {
        if (t->DefaultType == REG_NONE) return (t->Flags & RTL_QUERY_REGISTRY_REQUIRED) ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_SUCCESS;
        name = t->Name; type = t->DefaultType; data = t->DefaultData; len = t->DefaultLength;
        if (!len && data) {
            const WCHAR *p = data;
            if (type == REG_SZ || type == REG_EXPAND_SZ) { while (*p++) {} len = (uint32_t)((const uint8_t *)p - (const uint8_t *)data); }
            else if (type == REG_MULTI_SZ) { while (*p) { while (*p++) {} } len = (uint32_t)((const uint8_t *)p - (const uint8_t *)data) + 2; }
        }
    }
    if ((t->Flags & RTL_QUERY_REGISTRY_TYPECHECK) && t->DefaultType != REG_NONE && type != t->DefaultType) return STATUS_OBJECT_TYPE_MISMATCH;
    if (!(t->Flags & RTL_QUERY_REGISTRY_NOEXPAND)) {
        if (type == REG_MULTI_SZ) {
            WCHAR *p = data, *end = (WCHAR *)((uint8_t *)data + len);
            if (t->Flags & RTL_QUERY_REGISTRY_DIRECT && !(t->Flags & RTL_QUERY_REGISTRY_NOEXPAND)) return STATUS_INVALID_PARAMETER;
            while (p < end && *p) {
                WCHAR *s = p; uint32_t slen;
                while (p < end && *p) ++p;
                if (p < end) ++p;
                slen = (uint32_t)((uint8_t *)p - (uint8_t *)s);
                st = t->QueryRoutine(name, REG_SZ, s, slen, ctx, t->EntryContext);
                if (st == STATUS_BUFFER_TOO_SMALL) st = STATUS_SUCCESS;
                if (!NT_SUCCESS(st)) return st;
            }
            return st;
        }
        if (type == REG_EXPAND_SZ) type = REG_SZ;
    }
    if (t->Flags & RTL_QUERY_REGISTRY_DIRECT) return query_direct(type, data, len, t->EntryContext);
    st = t->QueryRoutine(name, type, data, len, ctx, t->EntryContext);
    return st == STATUS_BUFFER_TOO_SMALL ? STATUS_SUCCESS : st;
}

/* Reads a value by name into a fresh buffer: type, data and len; STATUS_OBJECT_NAME_NOT_FOUND when absent. Multi-strings get
 * an extra terminating NUL, as ntoskrnl appends before calling the routine. */
static NTSTATUS read_value(uint64_t key, const WCHAR *name, uint32_t *type, void **data, uint32_t *len)
{
    regkey_t *node = ntdrv_kh_get(key, KH_KEY);
    regval_t *v;
    uint8_t *buf;
    if (!node) return STATUS_INVALID_HANDLE;
    reg_lock();
    v = reg_find_value(node, name, (uint32_t)ntdrv_wcslen(name));
    if (!v) { reg_unlock(); return STATUS_OBJECT_NAME_NOT_FOUND; }
    buf = kmalloc(v->data_len + 4);
    if (!buf) { reg_unlock(); return STATUS_NO_MEMORY; }
    memcpy(buf, regval_data(v), v->data_len);
    *type = v->type; *len = v->data_len;
    if (v->type == REG_MULTI_SZ) { buf[v->data_len] = buf[v->data_len + 1] = 0; *len += 2; }
    reg_unlock();
    *data = buf;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlQueryRegistryValues(uint32_t rel, const WCHAR *path, RTL_QUERY_REGISTRY_TABLE *t, void *ctx, void *env)
{
    uint64_t top, cur;
    int owned, cur_owned = 0;
    NTSTATUS st;
    (void)env;
    st = rtl_open_key(rel, path, 0, &top, &owned);
    if (!NT_SUCCESS(st)) return st;
    cur = top;
    for (; t->QueryRoutine || (t->Flags & (RTL_QUERY_REGISTRY_SUBKEY | RTL_QUERY_REGISTRY_DIRECT)); ++t) {
        if ((t->Flags & RTL_QUERY_REGISTRY_DIRECT) && (!t->Name || (t->Flags & RTL_QUERY_REGISTRY_SUBKEY) || t->QueryRoutine)) { st = STATUS_INVALID_PARAMETER; break; }
        if (t->Flags & (RTL_QUERY_REGISTRY_TOPKEY | RTL_QUERY_REGISTRY_SUBKEY)) {
            if (cur != top) { if (cur_owned) ZwClose(cur); cur = top; cur_owned = 0; }
        }
        if (t->Flags & RTL_QUERY_REGISTRY_SUBKEY) {
            UNICODE_STRING u; struct objattr oa; uint64_t sub;
            if (!t->Name) { st = STATUS_INVALID_PARAMETER; break; }
            u.Buffer = t->Name; u.Length = (uint16_t)(ntdrv_wcslen(t->Name) * 2); u.MaximumLength = (uint16_t)(u.Length + 2);
            memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &u; oa.RootDirectory = top; oa.Attributes = 0x40;
            st = ZwOpenKey(&sub, 0x2000000, &oa);
            if (!NT_SUCCESS(st)) break;
            cur = sub; cur_owned = 1;
            if (!t->QueryRoutine) continue;
            goto enumerate;
        }
        if (t->Name) {
            uint32_t type = REG_NONE, len = 0; void *data = 0;
            st = read_value(cur, t->Name, &type, &data, &len);
            if (st == STATUS_OBJECT_NAME_NOT_FOUND) st = deliver(t, t->Name, REG_NONE, 0, 0, ctx, 1);
            else if (NT_SUCCESS(st)) {
                st = deliver(t, t->Name, type, data, len, ctx, 0);
                if (NT_SUCCESS(st) && (t->Flags & RTL_QUERY_REGISTRY_DELETE)) {
                    UNICODE_STRING u; u.Buffer = t->Name; u.Length = (uint16_t)(ntdrv_wcslen(t->Name) * 2); u.MaximumLength = u.Length;
                    ZwDeleteValueKey(cur, &u);
                }
            }
            kfree(data);
            if (!NT_SUCCESS(st)) break;
            continue;
        }
        if (t->Flags & RTL_QUERY_REGISTRY_NOVALUE) {
            st = t->QueryRoutine(0, REG_NONE, 0, 0, ctx, t->EntryContext);
            if (!NT_SUCCESS(st)) break;
            continue;
        }
enumerate:
        {   /* every value of the current key */
            uint32_t index = 0, delivered = 0;
            regkey_t *node = ntdrv_kh_get(cur, KH_KEY);
            if (!node) { st = STATUS_INVALID_HANDLE; break; }
            for (;;) {
                regval_t *v; uint8_t *data; uint32_t type, len, nlen; WCHAR *name;
                reg_lock();
                v = reg_nth_value(node, index);
                if (!v) { reg_unlock(); break; }
                nlen = v->name_len;
                name = kmalloc((nlen + 1) * 2); data = kmalloc(v->data_len + 4);
                if (!name || !data) { reg_unlock(); kfree(name); kfree(data); st = STATUS_NO_MEMORY; break; }
                memcpy(name, regval_name(v), nlen * 2); name[nlen] = 0;
                memcpy(data, regval_data(v), v->data_len); type = v->type; len = v->data_len;
                if (type == REG_MULTI_SZ) { data[len] = data[len + 1] = 0; len += 2; }
                reg_unlock();
                st = deliver(t, name, type, data, len, ctx, 0);
                if (NT_SUCCESS(st) && (t->Flags & RTL_QUERY_REGISTRY_DELETE)) {
                    UNICODE_STRING u; u.Buffer = name; u.Length = (uint16_t)(nlen * 2); u.MaximumLength = u.Length;
                    if (NT_SUCCESS(ZwDeleteValueKey(cur, &u))) --index;
                }
                kfree(name); kfree(data);
                ++delivered;
                if (!NT_SUCCESS(st)) break;
                ++index;
            }
            if (NT_SUCCESS(st) && !delivered && (t->Flags & RTL_QUERY_REGISTRY_REQUIRED)) st = STATUS_OBJECT_NAME_NOT_FOUND;
            if (!NT_SUCCESS(st)) break;
        }
    }
    if (cur != top && cur_owned) ZwClose(cur);
    if (owned) ZwClose(top);
    return st;
}
NTSTATUS NTAPI RtlWriteRegistryValue(uint32_t rel, const WCHAR *path, const WCHAR *name, uint32_t type, void *data, uint32_t len)
{
    uint64_t h; int owned; UNICODE_STRING u; NTSTATUS st;
    st = rtl_open_key(rel, path, 1, &h, &owned);
    if (!NT_SUCCESS(st)) return st;
    u.Buffer = (WCHAR *)name; u.Length = (uint16_t)(ntdrv_wcslen(name) * 2); u.MaximumLength = (uint16_t)(u.Length + 2);
    st = ZwSetValueKey(h, &u, 0, type, data, len);
    if (owned) ZwClose(h);
    return st;
}
NTSTATUS NTAPI RtlDeleteRegistryValue(uint32_t rel, const WCHAR *path, const WCHAR *name)
{
    uint64_t h; int owned; UNICODE_STRING u; NTSTATUS st;
    st = rtl_open_key(rel, path, 0, &h, &owned);
    if (!NT_SUCCESS(st)) return st;
    u.Buffer = (WCHAR *)name; u.Length = (uint16_t)(ntdrv_wcslen(name) * 2); u.MaximumLength = (uint16_t)(u.Length + 2);
    st = ZwDeleteValueKey(h, &u);
    if (owned) ZwClose(h);
    return st;
}
NTSTATUS NTAPI RtlCheckRegistryKey(uint32_t rel, const WCHAR *path)
{
    uint64_t h; int owned; NTSTATUS st = rtl_open_key(rel, path, 0, &h, &owned);
    if (NT_SUCCESS(st) && owned) ZwClose(h);
    return st;
}
NTSTATUS NTAPI RtlCreateRegistryKey(uint32_t rel, const WCHAR *path)
{
    uint64_t h; int owned; NTSTATUS st = rtl_open_key(rel, path, 1, &h, &owned);
    if (NT_SUCCESS(st) && owned) ZwClose(h);
    return st;
}
/* Key path helper for other providers: open or create "\Registry\..." given as an ASCII path. */
NTSTATUS ntdrv_open_key_ascii(const char *path, int create, uint64_t *handle)
{
    WCHAR w[300]; UNICODE_STRING u; struct objattr oa;
    unsigned n = (unsigned)ntdrv_ascii_to_wide(path, w, 300);
    u.Buffer = w; u.Length = (uint16_t)(n * 2); u.MaximumLength = (uint16_t)(n * 2 + 2);
    memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &u; oa.Attributes = 0x40;
    return create ? ZwCreateKey(handle, 0xf003f, &oa, 0, 0, 0, 0) : ZwOpenKey(handle, 0x20019, &oa);
}
NTSTATUS ntdrv_set_value_ascii(uint64_t key, const char *name, uint32_t type, const void *data, uint32_t len)
{
    WCHAR w[64]; UNICODE_STRING u;
    unsigned n = (unsigned)ntdrv_ascii_to_wide(name, w, 64);
    u.Buffer = w; u.Length = (uint16_t)(n * 2); u.MaximumLength = (uint16_t)(n * 2 + 2);
    return ZwSetValueKey(key, &u, 0, type, (void *)data, len);
}

/* ================================================================ object directories and symbolic links */
/* The object manager namespace of this host is: \Device (ntdrv_io.c), \?? and \DosDevices (symbolic links), \Registry,
 * \Callback (ntdrv_ex.c) and the directories drivers create here. A directory is a name; its handle is a KH_DIR. */
typedef struct objdir { struct objdir *next; char name[96]; int permanent; } objdir_t;
static objdir_t *objdirs;
NTSTATUS NTAPI ZwCreateDirectoryObject(uint64_t *handle, uint32_t access, struct objattr *oa)
{
    objdir_t *d;
    char name[96];
    (void)access;
    if (!oa || !oa->ObjectName) return STATUS_INVALID_PARAMETER;
    ntdrv_wide_to_ascii(oa->ObjectName->Buffer, oa->ObjectName->Length / 2, name, sizeof name);
    for (d = objdirs; d; d = d->next)
        if (!strcmp(d->name, name)) {
            if (!(oa->Attributes & 0x80)) return STATUS_OBJECT_NAME_COLLISION;         /* OBJ_OPENIF absent */
            *handle = ntdrv_kh_alloc(KH_DIR, d);
            return *handle ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
        }
    d = kzalloc(sizeof *d);
    if (!d) return STATUS_INSUFFICIENT_RESOURCES;
    memcpy(d->name, name, sizeof name);
    d->permanent = (oa->Attributes & 0x10) != 0;                                        /* OBJ_PERMANENT */
    d->next = objdirs; objdirs = d;
    *handle = ntdrv_kh_alloc(KH_DIR, d);
    return *handle ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}
NTSTATUS NTAPI ZwOpenDirectoryObject(uint64_t *handle, uint32_t access, struct objattr *oa)
{
    objdir_t *d; char name[96];
    (void)access;
    if (!oa || !oa->ObjectName) return STATUS_INVALID_PARAMETER;
    ntdrv_wide_to_ascii(oa->ObjectName->Buffer, oa->ObjectName->Length / 2, name, sizeof name);
    for (d = objdirs; d; d = d->next)
        if (!strcmp(d->name, name)) { *handle = ntdrv_kh_alloc(KH_DIR, d); return *handle ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES; }
    return STATUS_OBJECT_NAME_NOT_FOUND;
}
NTSTATUS NTAPI ZwMakeTemporaryObject(uint64_t handle)
{
    objdir_t *d = ntdrv_kh_get(handle, KH_DIR);
    if (d) { d->permanent = 0; return STATUS_SUCCESS; }
    if (ntdrv_kh_get(handle, KH_KEY) || ntdrv_kh_get(handle, KH_FILE) || ntdrv_kh_get(handle, KH_EVENT) || ntdrv_kh_get(handle, KH_SECTION)) return STATUS_SUCCESS;
    return STATUS_INVALID_HANDLE;
}
NTSTATUS NTAPI ZwMakePermanentObject(uint64_t handle)
{
    objdir_t *d = ntdrv_kh_get(handle, KH_DIR);
    if (d) { d->permanent = 1; return STATUS_SUCCESS; }
    return ntdrv_kh_get(handle, KH_KEY) ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
}
int ntdrv_objdir_exists(const char *name) { objdir_t *d; for (d = objdirs; d; d = d->next) if (!strcmp(d->name, name)) return 1; return 0; }

/* ================================================================ Zw files */
#define FILE_OPEN 1
NTSTATUS NTAPI ZwOpenFile(void *handle_out, uint32_t access, struct objattr *oa, IO_STATUS_BLOCK *iosb, uint32_t share, uint32_t opts)
{ return ZwCreateFile(handle_out, access, oa, iosb, 0, 0, share, FILE_OPEN, opts, 0, 0); }
struct kfile { fsnode_t *node; uint64_t pos; int write; };
NTSTATUS NTAPI ZwQueryInformationFile(uint64_t handle, IO_STATUS_BLOCK *iosb, void *buf, uint32_t len, uint32_t cls)
{
    struct kfile *f = ntdrv_kh_get(handle, KH_FILE);
    uint32_t need;
    if (!f) return STATUS_INVALID_HANDLE;
    switch (cls) {
    case 4: {                                           /* FileBasicInformation: 4 times + attributes */
        uint8_t b[0x28]; uint64_t t = (uint64_t)reg_filetime_now();
        need = sizeof b;
        if (len < need) return STATUS_INFO_LENGTH_MISMATCH;
        memcpy(b, &t, 8); memcpy(b + 8, &t, 8); memcpy(b + 16, &t, 8); memcpy(b + 24, &t, 8);
        *(uint32_t *)(b + 32) = f->node->is_dir ? 0x10 : 0x80; *(uint32_t *)(b + 36) = 0;
        memcpy(buf, b, need);
        break; }
    case 5: {                                           /* FileStandardInformation: AllocationSize EndOfFile NumberOfLinks DeletePending Directory */
        uint8_t b[0x18]; uint64_t sz = f->node->size, alloc = (sz + 511) & ~511ull;
        need = sizeof b;
        if (len < need) return STATUS_INFO_LENGTH_MISMATCH;
        memcpy(b, &alloc, 8); memcpy(b + 8, &sz, 8); *(uint32_t *)(b + 16) = 1; b[20] = 0; b[21] = f->node->is_dir ? 1 : 0; b[22] = b[23] = 0;
        memcpy(buf, b, need);
        break; }
    case 14:                                            /* FilePositionInformation */
        need = 8;
        if (len < need) return STATUS_INFO_LENGTH_MISMATCH;
        memcpy(buf, &f->pos, 8);
        break;
    default: return STATUS_INVALID_INFO_CLASS;
    }
    if (iosb) { iosb->Status = STATUS_SUCCESS; iosb->Information = need; }
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI ZwSetInformationFile(uint64_t handle, IO_STATUS_BLOCK *iosb, void *buf, uint32_t len, uint32_t cls)
{
    struct kfile *f = ntdrv_kh_get(handle, KH_FILE);
    if (!f) return STATUS_INVALID_HANDLE;
    if (cls == 14 && len >= 8) { memcpy(&f->pos, buf, 8); if (iosb) { iosb->Status = 0; iosb->Information = 0; } return STATUS_SUCCESS; }
    return STATUS_INVALID_INFO_CLASS;
}

/* ================================================================ ZwQuerySystemInformation */
extern uint64_t mem_ram_top(void);
extern void ntdrv_for_each_driver(void (*fn)(ntdrv_driver_t *, void *), void *ctx);   /* ntdrv_ldr.c */
struct modctx { uint8_t *buf; uint32_t len, n; };
static void mod_cb(ntdrv_driver_t *d, void *c)
{
    struct modctx *m = c;
    uint32_t off = 8 + m->n * 0x128;
    m->n++;
    if (off + 0x128 > m->len) return;
    {   /* RTL_PROCESS_MODULE_INFORMATION (0x128): Section MappedBase ImageBase ImageSize Flags LoadOrderIndex InitOrderIndex
         * LoadCount OffsetToFileName FullPathName[256] */
        uint8_t *e = m->buf + off; unsigned i, j = 0;
        static const char pfx[] = "\\SystemRoot\\SYS64\\DRIVERS\\";
        memset(e, 0, 0x128);
        *(uint64_t *)(e + 8) = d->image_base; *(uint64_t *)(e + 16) = d->image_base;
        *(uint32_t *)(e + 24) = (uint32_t)d->image_size;
        *(uint16_t *)(e + 32) = (uint16_t)(m->n); *(uint16_t *)(e + 34) = (uint16_t)(m->n); *(uint16_t *)(e + 36) = 1;
        for (i = 0; pfx[i]; ++i) e[40 + j++] = (uint8_t)pfx[i];
        *(uint16_t *)(e + 38) = (uint16_t)j;
        for (i = 0; d->name[i] && j < 250; ++i) e[40 + j++] = (uint8_t)d->name[i];
        for (i = 0; ".sys"[i] && j < 255; ++i) e[40 + j++] = (uint8_t)".sys"[i];
    }
}
NTSTATUS NTAPI ZwQuerySystemInformation(uint32_t cls, void *buf, uint32_t len, uint32_t *reslen)
{
    switch (cls) {
    case 0: {                                           /* SystemBasicInformation (0x40) */
        uint8_t b[0x40]; uint64_t pages = mem_ram_top() / 4096, lo = 0x10000, hi = 0x7ffffffeffff;
        memset(b, 0, sizeof b);
        *(uint32_t *)(b + 4) = 0x2000000; *(uint32_t *)(b + 8) = 4096; *(uint32_t *)(b + 12) = (uint32_t)pages;
        *(uint32_t *)(b + 16) = 1; *(uint32_t *)(b + 20) = (uint32_t)pages; *(uint32_t *)(b + 24) = (uint32_t)pages;
        memcpy(b + 32, &lo, 8); memcpy(b + 40, &hi, 8);
        *(uint64_t *)(b + 48) = 1; *(uint32_t *)(b + 56) = 4096; b[60] = 1;
        if (reslen) *reslen = sizeof b;
        if (len < sizeof b) return STATUS_INFO_LENGTH_MISMATCH;
        memcpy(buf, b, sizeof b);
        return STATUS_SUCCESS; }
    case 1: {                                           /* SystemProcessorInformation (0xc) */
        uint8_t b[12]; uint32_t a, bb, c, d;
        __asm__ volatile("cpuid" : "=a"(a), "=b"(bb), "=c"(c), "=d"(d) : "a"(1), "c"(0));
        *(uint16_t *)b = 9; *(uint16_t *)(b + 2) = (uint16_t)(((a >> 8) & 0xf) << 8 | ((a >> 4) & 0xf));   /* PROCESSOR_ARCHITECTURE_AMD64, level */
        *(uint16_t *)(b + 4) = (uint16_t)((((a >> 4) & 0xf) << 8) | (a & 0xf)); *(uint16_t *)(b + 6) = 0; *(uint32_t *)(b + 8) = d;
        if (reslen) *reslen = sizeof b;
        if (len < sizeof b) return STATUS_INFO_LENGTH_MISMATCH;
        memcpy(buf, b, sizeof b);
        return STATUS_SUCCESS; }
    case 3: {                                           /* SystemTimeOfDayInformation (0x30) */
        extern int64_t ntdrv_100ns_now(void);
        uint8_t b[0x30]; int64_t now = ntdrv_100ns_now(), boot = now - (int64_t)(shz_time_ns() / 100);
        memset(b, 0, sizeof b);
        memcpy(b, &boot, 8); memcpy(b + 8, &now, 8);
        if (reslen) *reslen = sizeof b;
        if (len < 0x20) return STATUS_INFO_LENGTH_MISMATCH;
        memcpy(buf, b, len < sizeof b ? len : sizeof b);
        return STATUS_SUCCESS; }
    case 11: {                                          /* SystemModuleInformation: RTL_PROCESS_MODULES (ntoskrnl first, then loaded drivers) */
        struct modctx m = { buf, len, 0 };
        uint8_t *e;
        unsigned i;
        static const char nt[] = "\\SystemRoot\\SYS64\\ntoskrnl.exe";
        m.n = 1;
        if (len >= 8 + 0x128) {
            e = m.buf + 8; memset(e, 0, 0x128);
            *(uint64_t *)(e + 8) = K64_VIRT_BASE; *(uint64_t *)(e + 16) = K64_VIRT_BASE; *(uint32_t *)(e + 24) = 0x400000;
            *(uint16_t *)(e + 36) = 1; *(uint16_t *)(e + 38) = 18;
            for (i = 0; nt[i]; ++i) e[40 + i] = (uint8_t)nt[i];
        }
        ntdrv_for_each_driver(mod_cb, &m);
        if (reslen) *reslen = 8 + m.n * 0x128;
        if (len < 8 + m.n * 0x128) return STATUS_INFO_LENGTH_MISMATCH;
        *(uint32_t *)buf = m.n;
        return STATUS_SUCCESS; }
    default:
        if (reslen) *reslen = 0;
        return STATUS_INVALID_INFO_CLASS;
    }
}

/* ================================================================ ZwLoadDriver / ZwUnloadDriver (kernel callers) */
NTSTATUS NTAPI ZwLoadDriver(UNICODE_STRING *regpath)
{
    if (!regpath || !regpath->Buffer) return STATUS_INVALID_PARAMETER;
    return ntdrv_load_service_path(regpath->Buffer, regpath->Length / 2);
}
NTSTATUS NTAPI ZwUnloadDriver(UNICODE_STRING *regpath)
{
    if (!regpath || !regpath->Buffer) return STATUS_INVALID_PARAMETER;
    return ntdrv_unload_service_path(regpath->Buffer, regpath->Length / 2);
}

/* ================================================================ ZwPowerInformation */
/* SystemPowerCapabilities (4): a machine with no sleep states (S1-S4 absent), S5 present, no battery, no lid;
 * the record is what a driver deciding on power policy gets from a desktop without ACPI sleep support. */
NTSTATUS NTAPI ZwPowerInformation(uint32_t level, void *in, uint32_t inlen, void *out, uint32_t outlen)
{
    (void)in; (void)inlen;
    switch (level) {
    case 4: {                                           /* SYSTEM_POWER_CAPABILITIES (0x4c): PowerButtonPresent(0) SleepButtonPresent(1)
                                                         * LidPresent(2) SystemS1..S5(3..7) HiberFilePresent(8) FullWake(9) VideoDimPresent(10)
                                                         * ApmPresent(11) UpsPresent(12) ThermalControl(13) ProcessorThrottle(14) ProcessorMin/
                                                         * MaxThrottle(15,16) FastSystemS4(17) Hiberboot(18) WakeAlarmPresent(19) AoAc(20)
                                                         * DiskSpinDown(21) HiberFileType(22) AoAcConnectivitySupported(23) spare(24..29)
                                                         * SystemBatteriesPresent(30) BatteriesAreShortTerm(31) BatteryScale[3](32..43)
                                                         * AcOnLineWake(44) SoftLidWake(45) RtcWake(46) MinDeviceWakeState(47) DefaultLowLatencyWake(48) */
        uint8_t b[0x4c];
        if (!out || outlen < sizeof b) return STATUS_BUFFER_TOO_SMALL;
        memset(b, 0, sizeof b);
        b[0] = 1;                                       /* a power button */
        b[7] = 1;                                       /* S5 (soft off) is the only system sleep state */
        b[15] = 100; b[16] = 100;                       /* no processor throttling: min = max = 100 % */
        memcpy(out, b, sizeof b);
        return STATUS_SUCCESS; }
    case 11: {                                          /* ProcessorInformation: one PROCESSOR_POWER_INFORMATION (0x18) */
        uint8_t b[0x18];
        if (!out || outlen < sizeof b) return STATUS_BUFFER_TOO_SMALL;
        memset(b, 0, sizeof b);
        *(uint32_t *)(b + 4) = 1000; *(uint32_t *)(b + 8) = 1000; *(uint32_t *)(b + 12) = 1000;   /* MaxMhz CurrentMhz MhzLimit: nominal */
        memcpy(out, b, sizeof b);
        return STATUS_SUCCESS; }
    default: return STATUS_INVALID_INFO_CLASS;
    }
}
