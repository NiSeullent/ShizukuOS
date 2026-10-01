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

extern const char *ntdrv_device_name(DEVICE_OBJECT *dev);
struct kfile;
static void kfile_close(struct kfile *f);

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
      else if (kind == KH_FILE) kfile_close(ptr); }
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

/* ZwQueryValueKey (every information class), ZwEnumerate*Key, ZwQueryKey, ZwDelete*: ntdrv_reg.c. */
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
/* A kernel file handle is either a file-system node or an open device (a FILE_OBJECT on a DEVICE_OBJECT, opened with
 * IRP_MJ_CREATE and closed with IRP_MJ_CLEANUP/IRP_MJ_CLOSE, reads/writes/IOCTLs travelling as IRPs). */
struct kfile { fsnode_t *node; uint64_t pos; int write; DEVICE_OBJECT *dev; FILE_OBJECT fo; };
static void kfile_close(struct kfile *f)
{
    if (f->dev) ntdrv_open_close_device(f->dev, 1);
    kfree(f);
}
NTSTATUS NTAPI ZwClose(uint64_t handle)
{
    int i = kh_index(handle);
    if (i < 0) return STATUS_SUCCESS;                           /* tolerate pseudo handles */
    if (i < KH_MAX && kh_tab[i].kind == KH_FILE) {
        struct kfile *f = kh_tab[i].ptr;
        kh_ensure(); mutex_lock(&kh_lock); kh_tab[i].kind = KH_NONE; kh_tab[i].ptr = 0; mutex_unlock(&kh_lock);
        kfile_close(f);
        return STATUS_SUCCESS;
    }
    return ntdrv_kh_free(handle) == 0 ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
}
/* Open a device object for a kernel caller: IRP_MJ_CREATE through its stack; *fo_out is the FILE_OBJECT (kept in the
 * kfile record, valid until the handle closes). Used by ZwCreateFile on "\Device\..." / "\??\..." names and by
 * IoGetDeviceObjectPointer. */
int32_t ntdrv_device_open_file(DEVICE_OBJECT *dev, uint32_t access, FILE_OBJECT **fo_out)
{
    struct kfile *f = kzalloc(sizeof *f);
    DEVICE_OBJECT *top;
    int32_t st;
    if (!f) return STATUS_INSUFFICIENT_RESOURCES;
    top = dev; while (top->AttachedDevice) top = top->AttachedDevice;
    f->dev = top; f->write = (access & (0x40000000u | 2u)) != 0;
    f->fo.Type = 5; f->fo.Size = sizeof(FILE_OBJECT); f->fo.DeviceObject = top;
    f->fo.ReadAccess = (access & (0x80000000u | 1u)) != 0; f->fo.WriteAccess = f->write;
    st = ntdrv_open_close_device(top, 0);
    if (st && st != STATUS_PENDING) { kfree(f); return st; }
    if (fo_out) *fo_out = &f->fo;
    { uint64_t h = ntdrv_kh_alloc(KH_FILE, f); if (!h) { ntdrv_open_close_device(top, 1); kfree(f); return STATUS_INSUFFICIENT_RESOURCES; } }
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI ZwCreateFile(void *handle_out, uint32_t access, struct objattr *oa, IO_STATUS_BLOCK *iosb,
                            LARGE_INTEGER *alloc, uint32_t attrs, uint32_t share, uint32_t disp, uint32_t opts,
                            void *ea, uint32_t ealen)
{
    char path[300];
    fsnode_t *n;
    struct kfile *f;
    int created = 0;
    DEVICE_OBJECT *dev = 0;
    (void)alloc; (void)attrs; (void)share; (void)opts; (void)ea; (void)ealen;
    if (!oa->ObjectName) return STATUS_INVALID_PARAMETER;
    ntdrv_wide_to_ascii(oa->ObjectName->Buffer, oa->ObjectName->Length / 2, path, sizeof path);
    if (!strncmp(path, "\\Device\\", 8)) dev = ntdrv_find_device(path);
    else if (!strncmp(path, "\\??\\", 4) || !strncmp(path, "\\DosDevices\\", 12) || !strncmp(path, "\\Global??\\", 10)) dev = ntdrv_resolve_symlink(path);
    if (dev) {
        FILE_OBJECT *fo;
        int32_t st = ntdrv_device_open_file(dev, access, &fo);
        if (st) { if (iosb) { iosb->Status = st; iosb->Information = 0; } return st; }
        f = (struct kfile *)((uint8_t *)fo - __builtin_offsetof(struct kfile, fo));
        { unsigned i; for (i = 0; i < KH_MAX; ++i) if (kh_tab[i].kind == KH_FILE && kh_tab[i].ptr == f) { *(uint64_t *)handle_out = ((uint64_t)(i + 1) << 2) | 0x80000000ull; break; } }
        if (iosb) { iosb->Status = STATUS_SUCCESS; iosb->Information = 1; }
        return STATUS_SUCCESS;
    }
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
    if (f->dev) {
        int32_t st = ntdrv_read_write(f->dev, 0, buf, len, at, &got);
        f->pos = at + got;
        if (iosb) { iosb->Status = st; iosb->Information = got; }
        return st;
    }
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
    if (f->dev) {
        uint64_t info = 0;
        int32_t st = ntdrv_read_write(f->dev, 1, buf, len, at, &info);
        f->pos = at + info;
        if (iosb) { iosb->Status = st; iosb->Information = info; }
        return st;
    }
    rc = fs_write(f->node, at, buf, len);
    if (rc) { if (iosb) { iosb->Status = STATUS_DISK_FULL; iosb->Information = 0; } return STATUS_DISK_FULL; }
    f->pos = at + len;
    if (iosb) { iosb->Status = STATUS_SUCCESS; iosb->Information = len; }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ZwDeviceIoControlFile(uint64_t handle, void *event, void *apc, void *apcctx, IO_STATUS_BLOCK *iosb,
                                     uint32_t ioctl, void *in, uint32_t inlen, void *out, uint32_t outlen)
{
    struct kfile *f = ntdrv_kh_get(handle, KH_FILE);
    uint64_t info = 0;
    int32_t st;
    (void)event; (void)apc; (void)apcctx;
    if (!f) return STATUS_INVALID_HANDLE;
    if (!f->dev) return STATUS_INVALID_DEVICE_REQUEST;
    st = ntdrv_device_control(f->dev, ioctl, in, inlen, out, outlen, 0, &info);
    if (iosb) { iosb->Status = st; iosb->Information = info; }
    return st;
}

/* ---------------------------------------------------------------- Ob */
/* Handle -> object: the kernel handle table maps a handle to its kind; when the caller names an object type
 * (*IoFileObjectType, *PsThreadType, ...) the kinds must agree (STATUS_OBJECT_TYPE_MISMATCH otherwise). A file handle
 * yields its FILE_OBJECT; a device handle its DEVICE_OBJECT; thread/event/semaphore handles their objects. */
extern int ntdrv_object_type_kind(const void *type);
#define STATUS_OBJECT_TYPE_MISMATCH_ ((int32_t)0xC0000024)
NTSTATUS NTAPI ObReferenceObjectByHandle(uint64_t h, uint32_t access, void *type, uint8_t mode, void **obj, void *info)
{
    int i = kh_index(h), kind, want = ntdrv_object_type_kind(type);
    void *p;
    (void)access; (void)mode; (void)info;
    if (i < 0 || i >= KH_MAX || !kh_tab[i].kind) return STATUS_INVALID_HANDLE;
    kind = kh_tab[i].kind; p = kh_tab[i].ptr;
    if (want && want != kind) return STATUS_OBJECT_TYPE_MISMATCH_;
    if (kind == KH_FILE) p = &((struct kfile *)p)->fo;
    if (obj) *obj = p;
    return STATUS_SUCCESS;
}
/* Object references: device objects carry ReferenceCount; the kernel's own records (threads, events, keys) are not
 * freed by a dereference, so a reference is bookkeeping for them. */
LONG NTAPI ObfReferenceObject(void *o)
{
    int16_t t = *(int16_t *)o;
    if (t == 3) return ++((DEVICE_OBJECT *)o)->ReferenceCount;
    return 1;
}
LONG NTAPI ObfDereferenceObject(void *o)
{
    int16_t t = *(int16_t *)o;
    if (t == 3 && ((DEVICE_OBJECT *)o)->ReferenceCount > 0) return --((DEVICE_OBJECT *)o)->ReferenceCount;
    return 0;
}
void NTAPI ObDereferenceObject(void *o) { ObfDereferenceObject(o); }
void NTAPI ObReferenceObject(void *o) { ObfReferenceObject(o); }
NTSTATUS NTAPI ObOpenObjectByPointer(void *obj, uint32_t attrs, void *pas, uint32_t access, void *type, uint8_t mode, uint64_t *handle)
{
    int16_t t = *(int16_t *)obj;
    int kind = ntdrv_object_type_kind(type);
    (void)attrs; (void)pas; (void)access; (void)mode;
    if (t == 5) kind = KH_FILE;
    if (!kind) return STATUS_INVALID_PARAMETER;
    if (kind == KH_FILE) {                                      /* a FILE_OBJECT of ours sits inside its kfile record */
        struct kfile *f = (struct kfile *)((uint8_t *)obj - __builtin_offsetof(struct kfile, fo));
        unsigned i; for (i = 0; i < KH_MAX; ++i) if (kh_tab[i].kind == KH_FILE && kh_tab[i].ptr == f) { *handle = ((uint64_t)(i + 1) << 2) | 0x80000000ull; return STATUS_SUCCESS; }
        return STATUS_INVALID_PARAMETER;
    }
    *handle = ntdrv_kh_alloc(kind, obj);
    return *handle ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}
NTSTATUS NTAPI ObQueryNameString(void *obj, void *info, uint32_t len, uint32_t *reslen)
{
    /* OBJECT_NAME_INFORMATION: UNICODE_STRING then the characters; devices report "\Device\X", others an empty name. */
    int16_t t = *(int16_t *)obj;
    const char *name = t == 3 ? ntdrv_device_name(obj) : 0;
    uint32_t n = name ? (uint32_t)strlen(name) : 0, need = 16 + (n + 1) * 2;
    UNICODE_STRING *u = info;
    if (reslen) *reslen = need;
    if (len < need) return STATUS_INFO_LENGTH_MISMATCH;
    u->Buffer = (WCHAR *)(u + 1); u->Length = (uint16_t)(n * 2); u->MaximumLength = (uint16_t)((n + 1) * 2);
    if (name) ntdrv_ascii_to_wide(name, u->Buffer, n + 1); else u->Buffer[0] = 0;
    return STATUS_SUCCESS;
}
