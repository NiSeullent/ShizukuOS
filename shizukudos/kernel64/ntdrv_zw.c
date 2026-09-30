/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the Zw registry/file interface a driver calls, plus the
 * kernel-mode handle table those handles live in. Registry access goes through the real
 * configuration manager (registry.c); files go through the real in-memory file system
 * (fs.c). A driver opening its Services\...\Parameters key and reading a value gets the same
 * data any other component would.
 */
#include "ntdrv.h"
#include "registry.h"
#include "fs.h"

/* ---------------------------------------------------------------- kernel handle table */
#define KH_MAX 256
static struct { int kind; void *ptr; } kh_tab[KH_MAX];
static kmutex_t kh_lock;
static int kh_inited;

static void kh_ensure(void) { if (!kh_inited) { mutex_init(&kh_lock); kh_inited = 1; } }

uint64_t ntdrv_kh_alloc(int kind, void *ptr)
{
    unsigned i;
    uint64_t h = 0;
    kh_ensure();
    mutex_lock(&kh_lock);
    for (i = 0; i < KH_MAX; ++i)
        if (!kh_tab[i].kind) { kh_tab[i].kind = kind; kh_tab[i].ptr = ptr; h = ((uint64_t)(i + 1) << 2) | 0x80000000ull; break; }
    mutex_unlock(&kh_lock);
    return h;
}
static int kh_index(uint64_t handle) { return (handle & 0x80000000ull) ? (int)((handle & 0x7fffffff) >> 2) - 1 : -1; }
void *ntdrv_kh_get(uint64_t handle, int kind)
{
    int i = kh_index(handle);
    if (i < 0 || i >= KH_MAX) return 0;
    if (kh_tab[i].kind != kind) return 0;
    return kh_tab[i].ptr;
}
int ntdrv_kh_free(uint64_t handle)
{
    int i = kh_index(handle);
    if (i < 0 || i >= KH_MAX || !kh_tab[i].kind) return -1;
    kh_ensure();
    mutex_lock(&kh_lock);
    { int kind = kh_tab[i].kind; void *ptr = kh_tab[i].ptr;
      kh_tab[i].kind = KH_NONE; kh_tab[i].ptr = 0;
      mutex_unlock(&kh_lock);
      if (kind == KH_KEY) reg_key_release((regkey_t *)ptr);
      else if (kind == KH_FILE) kfree(ptr); }
    return 0;
}

/* ---------------------------------------------------------------- OBJECT_ATTRIBUTES */
struct objattr { uint32_t Length, pad; uint64_t RootDirectory; UNICODE_STRING *ObjectName; uint32_t Attributes, pad2; void *sd, *sqos; };

/* Strip the "\REGISTRY" object-manager prefix; return the remaining path in *out (pointer into
 * the original buffer) and its length in *chars, matching sysreg.c's resolution. */
static int reg_strip(const WCHAR *path, unsigned n, const WCHAR **out, unsigned *chars)
{
    static const WCHAR reg[8] = { 'R', 'E', 'G', 'I', 'S', 'T', 'R', 'Y' };
    unsigned i = 1, k;
    int ok;
    if (!n || path[0] != '\\') return -1;
    while (i < n && path[i] != '\\') ++i;
    ok = (i - 1 == 8);
    for (k = 0; ok && k < 8; ++k) if (reg_upcase_char(path[1 + k]) != reg[k]) ok = 0;
    if (!ok) return -1;
    *out = path + (i < n ? i + 1 : i);
    *chars = n - (i < n ? i + 1 : i);
    return 0;
}

static regkey_t *resolve_key(struct objattr *oa, int create, int32_t *st_out)
{
    UNICODE_STRING u;
    const WCHAR *rel;
    unsigned chars;
    regkey_t *start, *node = 0;
    int32_t st;
    if (!oa->ObjectName) { *st_out = STATUS_INVALID_PARAMETER; return 0; }
    u = *oa->ObjectName;
    reg_lock();
    if (oa->RootDirectory) {
        start = ntdrv_kh_get(oa->RootDirectory, KH_KEY);
        rel = u.Buffer; chars = u.Length / 2;
        if (!start) { reg_unlock(); *st_out = STATUS_INVALID_HANDLE; return 0; }
        if (chars && rel[0] == '\\') { reg_unlock(); *st_out = STATUS_OBJECT_PATH_SYNTAX_BAD; return 0; }
    } else {
        if (reg_strip(u.Buffer, u.Length / 2, &rel, &chars)) { reg_unlock(); *st_out = STATUS_OBJECT_PATH_NOT_FOUND; return 0; }
        start = reg_root();
    }
    st = reg_resolve(start, rel, chars, 0, 0, 1, 0, 0, &node, 0);
    if (st == STATUS_OBJECT_NAME_NOT_FOUND && create)
        st = reg_resolve(start, rel, chars, 1, 0, 1, 0, 0, &node, 0);
    if (st) { reg_unlock(); *st_out = st; return 0; }
    ++node->refs;
    reg_unlock();
    *st_out = STATUS_SUCCESS;
    return node;
}

NTSTATUS NTAPI ZwOpenKey(void *handle_out, uint32_t access, struct objattr *oa)
{
    int32_t st;
    regkey_t *node = resolve_key(oa, 0, &st);
    (void)access;
    if (!node) return st;
    *(uint64_t *)handle_out = ntdrv_kh_alloc(KH_KEY, node);
    if (!*(uint64_t *)handle_out) { reg_key_release(node); return STATUS_INSUFFICIENT_RESOURCES; }
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI ZwCreateKey(void *handle_out, uint32_t access, struct objattr *oa, uint32_t ti, void *cls, uint32_t opt, uint32_t *disp)
{
    int32_t st;
    regkey_t *node;
    (void)access; (void)ti; (void)cls; (void)opt;
    node = resolve_key(oa, 1, &st);
    if (!node) return st;
    if (disp) *disp = 1;                       /* REG_OPENED_EXISTING_KEY / created: reported as opened */
    *(uint64_t *)handle_out = ntdrv_kh_alloc(KH_KEY, node);
    if (!*(uint64_t *)handle_out) { reg_key_release(node); return STATUS_INSUFFICIENT_RESOURCES; }
    return STATUS_SUCCESS;
}

struct kv_partial { uint32_t TitleIndex, Type, DataLength; uint8_t Data[]; };
NTSTATUS NTAPI ZwQueryValueKey(uint64_t handle, UNICODE_STRING *name, uint32_t cls, void *buf, uint32_t len, uint32_t *reslen)
{
    regkey_t *node = ntdrv_kh_get(handle, KH_KEY);
    regval_t *v;
    NTSTATUS st = STATUS_SUCCESS;
    if (!node) return STATUS_INVALID_HANDLE;
    reg_lock();
    v = reg_find_value(node, name->Buffer, name->Length / 2);
    if (!v) { reg_unlock(); return STATUS_OBJECT_NAME_NOT_FOUND; }
    if (cls == 2) {                            /* KeyValuePartialInformation */
        uint32_t need = 12 + v->data_len;
        if (reslen) *reslen = need;
        if (len < 12) { reg_unlock(); return STATUS_BUFFER_TOO_SMALL; }
        { struct kv_partial *p = buf; uint32_t copy = len - 12 < v->data_len ? len - 12 : v->data_len;
          p->TitleIndex = 0; p->Type = v->type; p->DataLength = v->data_len;
          memcpy(p->Data, regval_data(v), copy);
          if (copy < v->data_len) st = STATUS_BUFFER_OVERFLOW; }
    } else { reg_unlock(); return STATUS_INVALID_INFO_CLASS; }
    reg_unlock();
    return st;
}
NTSTATUS NTAPI ZwSetValueKey(uint64_t handle, UNICODE_STRING *name, uint32_t ti, uint32_t type, void *data, uint32_t len)
{
    regkey_t *node = ntdrv_kh_get(handle, KH_KEY);
    int32_t st;
    (void)ti;
    if (!node) return STATUS_INVALID_HANDLE;
    reg_lock();
    st = reg_set_value(node, name->Buffer, name->Length / 2, type, data, len);
    reg_unlock();
    return st;
}

/* ---------------------------------------------------------------- Zw files */
struct kfile { fsnode_t *node; uint64_t pos; int write; };
NTSTATUS NTAPI ZwClose(uint64_t handle)
{
    if (kh_index(handle) < 0) return STATUS_SUCCESS;            /* tolerate pseudo handles */
    return ntdrv_kh_free(handle) == 0 ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
}
NTSTATUS NTAPI ZwCreateFile(void *handle_out, uint32_t access, struct objattr *oa, IO_STATUS_BLOCK *iosb,
                            LARGE_INTEGER *alloc, uint32_t attrs, uint32_t share, uint32_t disp, uint32_t opts,
                            void *ea, uint32_t ealen)
{
    char path[300];
    fsnode_t *n;
    struct kfile *f;
    int created = 0;
    (void)alloc; (void)attrs; (void)share; (void)opts; (void)ea; (void)ealen;
    if (!oa->ObjectName) return STATUS_INVALID_PARAMETER;
    ntdrv_wide_to_ascii(oa->ObjectName->Buffer, oa->ObjectName->Length / 2, path, sizeof path);
    n = fs_lookup(path);
    if (!n && (disp == 2 || disp == 3 || disp == 5)) n = fs_create(path, 0, &created);   /* CREATE/OPEN_IF/OVERWRITE_IF */
    if (!n) { if (iosb) { iosb->Status = STATUS_OBJECT_NAME_NOT_FOUND; iosb->Information = 0; } return STATUS_OBJECT_NAME_NOT_FOUND; }
    f = kzalloc(sizeof *f);
    if (!f) return STATUS_NO_MEMORY;
    f->node = n; f->write = (access & (0x40000000u | 2u)) != 0;   /* GENERIC_WRITE | FILE_WRITE_DATA */
    *(uint64_t *)handle_out = ntdrv_kh_alloc(KH_FILE, f);
    if (!*(uint64_t *)handle_out) { kfree(f); return STATUS_INSUFFICIENT_RESOURCES; }
    if (iosb) { iosb->Status = STATUS_SUCCESS; iosb->Information = created ? 2 : 1; }
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI ZwReadFile(uint64_t handle, void *event, void *apc, void *apcctx, IO_STATUS_BLOCK *iosb,
                          void *buf, uint32_t len, LARGE_INTEGER *off, uint32_t *key)
{
    struct kfile *f = ntdrv_kh_get(handle, KH_FILE);
    uint64_t got = 0, at;
    (void)event; (void)apc; (void)apcctx; (void)key;
    if (!f) return STATUS_INVALID_HANDLE;
    at = off ? (uint64_t)off->QuadPart : f->pos;
    fs_read(f->node, at, buf, len, &got);
    f->pos = at + got;
    if (iosb) { iosb->Status = got ? STATUS_SUCCESS : STATUS_END_OF_FILE; iosb->Information = got; }
    return got ? STATUS_SUCCESS : STATUS_END_OF_FILE;
}
NTSTATUS NTAPI ZwWriteFile(uint64_t handle, void *event, void *apc, void *apcctx, IO_STATUS_BLOCK *iosb,
                           void *buf, uint32_t len, LARGE_INTEGER *off, uint32_t *key)
{
    struct kfile *f = ntdrv_kh_get(handle, KH_FILE);
    uint64_t at;
    int rc;
    (void)event; (void)apc; (void)apcctx; (void)key;
    if (!f) return STATUS_INVALID_HANDLE;
    at = off ? (uint64_t)off->QuadPart : f->pos;
    rc = fs_write(f->node, at, buf, len);
    if (rc) { if (iosb) { iosb->Status = STATUS_DISK_FULL; iosb->Information = 0; } return STATUS_DISK_FULL; }
    f->pos = at + len;
    if (iosb) { iosb->Status = STATUS_SUCCESS; iosb->Information = len; }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- minimal Ob */
NTSTATUS NTAPI ObReferenceObjectByHandle(uint64_t h, uint32_t access, void *type, uint8_t mode, void **obj, void *info)
{
    void *p;
    (void)access; (void)type; (void)mode; (void)info;
    p = ntdrv_kh_get(h, KH_THREAD);
    if (!p) p = ntdrv_kh_get(h, KH_EVENT);
    if (!p) return STATUS_INVALID_HANDLE;
    if (obj) *obj = p;
    return STATUS_SUCCESS;
}
void NTAPI ObDereferenceObject(void *o) { (void)o; }
void NTAPI ObfDereferenceObject(void *o) { (void)o; }
LONG NTAPI ObfReferenceObject(void *o) { (void)o; return 1; }

/* ---------------------------------------------------------------- ZwEnumerateKey / ZwQueryInformationFile */
/* KEY_BASIC_INFORMATION (0x10 + name): LastWriteTime, TitleIndex, NameLength, Name[].
 * KEY_NODE_INFORMATION (0x18 + name): LastWriteTime, TitleIndex, ClassOffset, ClassLength, NameLength, Name[].
 * KEY_FULL_INFORMATION (0x2c + class): LastWriteTime, TitleIndex, ClassOffset, ClassLength, SubKeys, MaxNameLen,
 * MaxClassLen, Values, MaxValueNameLen, MaxValueDataLen, Class[]. */
NTSTATUS NTAPI ZwEnumerateKey(uint64_t handle, uint32_t index, uint32_t cls, void *buf, uint32_t len, uint32_t *reslen)
{
    regkey_t *node = ntdrv_kh_get(handle, KH_KEY), *child;
    uint8_t tmp[0x30];
    uint32_t fixed, need, i;
    const void *var;
    uint32_t varlen;
    NTSTATUS st = STATUS_SUCCESS;
    if (!node) return STATUS_INVALID_HANDLE;
    reg_lock();
    child = reg_nth_child(node, index);
    if (!child) { reg_unlock(); return STATUS_NO_MORE_ENTRIES; }
    memset(tmp, 0, sizeof tmp);
    memcpy(tmp, &child->last_write, 8);
    var = regkey_name(child); varlen = child->name_len * 2;
    switch (cls) {
    case 0: fixed = 0x10; memcpy(tmp + 0xc, &varlen, 4); break;
    case 1: fixed = 0x18; {   /* the key's class string is not returned: ClassOffset -1 and ClassLength 0 say so */
        uint32_t cl = 0, co = 0xffffffffu;
        memcpy(tmp + 0xc, &co, 4); memcpy(tmp + 0x10, &cl, 4); memcpy(tmp + 0x14, &varlen, 4);
    } break;
    case 2: {
        uint32_t cl = child->class_len * 2, co = cl ? 0x2c : 0xffffffffu, maxname = 0, maxclass = 0, maxvname = 0, maxvdata = 0;
        regkey_t *c; regval_t *v;
        for (i = 0; (c = reg_nth_child(child, i)) != 0; ++i) { if (c->name_len * 2 > maxname) maxname = c->name_len * 2; if (c->class_len * 2 > maxclass) maxclass = c->class_len * 2; }
        for (i = 0; (v = reg_nth_value(child, i)) != 0; ++i) { if (v->name_len * 2 > maxvname) maxvname = v->name_len * 2; if (v->data_len > maxvdata) maxvdata = v->data_len; }
        fixed = 0x2c;
        memcpy(tmp + 0xc, &co, 4); memcpy(tmp + 0x10, &cl, 4); memcpy(tmp + 0x14, &child->nsubkeys, 4); memcpy(tmp + 0x18, &maxname, 4);
        memcpy(tmp + 0x1c, &maxclass, 4); memcpy(tmp + 0x20, &child->nvalues, 4); memcpy(tmp + 0x24, &maxvname, 4); memcpy(tmp + 0x28, &maxvdata, 4);
        var = regkey_class(child); varlen = cl;
        break;
    }
    default: reg_unlock(); return STATUS_INVALID_INFO_CLASS;
    }
    need = fixed + varlen;
    if (reslen) *reslen = need;
    if (len < fixed) { reg_unlock(); return STATUS_BUFFER_TOO_SMALL; }
    memcpy(buf, tmp, fixed);
    if (len < need) { memcpy((uint8_t *)buf + fixed, var, len - fixed); st = STATUS_BUFFER_OVERFLOW; }
    else memcpy((uint8_t *)buf + fixed, var, varlen);
    reg_unlock();
    return st;
}

/* FILE_STANDARD_INFORMATION (class 5, 0x18): AllocationSize, EndOfFile, NumberOfLinks, DeletePending, Directory.
 * FILE_BASIC_INFORMATION (class 4, 0x28): four FILETIMEs and FileAttributes. */
NTSTATUS NTAPI ZwQueryInformationFile(uint64_t handle, IO_STATUS_BLOCK *iosb, void *buf, uint32_t len, uint32_t cls)
{
    struct kfile *f = ntdrv_kh_get(handle, KH_FILE);
    NTSTATUS st = STATUS_SUCCESS;
    uint32_t n = 0;
    if (!f) return STATUS_INVALID_HANDLE;
    if (cls == 5) {
        struct { uint64_t alloc, eof; uint32_t links; uint8_t del, dir, pad[2]; } s;
        memset(&s, 0, sizeof s);
        s.alloc = s.eof = f->node->size; s.links = 1; s.del = f->node->delete_pending != 0; s.dir = f->node->is_dir != 0;
        n = sizeof s;
        if (len < n) st = STATUS_INFO_LENGTH_MISMATCH; else memcpy(buf, &s, n);
    } else if (cls == 4) {
        struct { int64_t t[4]; uint32_t attrs, pad; } b;
        memset(&b, 0, sizeof b);
        b.attrs = f->node->attrs ? f->node->attrs : (f->node->is_dir ? 0x10 : 0x80);
        n = sizeof b;
        if (len < n) st = STATUS_INFO_LENGTH_MISMATCH; else memcpy(buf, &b, n);
    } else st = STATUS_INVALID_INFO_CLASS;
    if (iosb) { iosb->Status = st; iosb->Information = st ? 0 : n; }
    return st;
}
