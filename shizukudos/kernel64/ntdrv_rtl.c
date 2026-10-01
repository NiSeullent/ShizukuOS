/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the Rtl string/memory library, the debug print path (DbgPrint /
 * DbgPrintEx to the kernel console), the Ps system-thread API and the Hal bus/port access a
 * driver uses. Every entry is NTAPI (Microsoft x64). String routines follow the counted
 * UNICODE_STRING/ANSI_STRING contract; nothing truncates silently past MaximumLength.
 */
#include "ntdrv.h"
#include "pci.h"

/* ---------------------------------------------------------------- shared string helpers */
int ntdrv_ascii_to_wide(const char *s, WCHAR *out, unsigned cap)
{
    unsigned n = 0;
    while (s[n] && n + 1 < cap) { out[n] = (uint8_t)s[n]; ++n; }
    out[n] = 0;
    return (int)n;
}
int ntdrv_wide_to_ascii(const WCHAR *s, unsigned chars, char *out, unsigned cap)
{
    unsigned n = 0;
    while (n < chars && n + 1 < cap) { out[n] = s[n] < 0x80 ? (char)s[n] : '?'; ++n; }
    out[n] = 0;
    return (int)n;
}
static unsigned wlen(const WCHAR *s) { unsigned n = 0; while (s[n]) ++n; return n; }

/* ---------------------------------------------------------------- Rtl memory */
void NTAPI RtlCopyMemory(void *d, const void *s, uint64_t n) { memcpy(d, s, n); }
void NTAPI RtlMoveMemory(void *d, const void *s, uint64_t n) { memmove(d, s, n); }
void NTAPI RtlZeroMemory(void *d, uint64_t n) { memset(d, 0, n); }
void NTAPI RtlFillMemory(void *d, uint64_t n, uint8_t v) { memset(d, v, n); }
void NTAPI RtlSecureZeroMemory(void *d, uint64_t n) { volatile uint8_t *p = d; while (n--) *p++ = 0; }
uint64_t NTAPI RtlCompareMemory(const void *a, const void *b, uint64_t n)
{
    const uint8_t *x = a, *y = b; uint64_t i = 0;
    while (i < n && x[i] == y[i]) ++i;
    return i;
}
LONG NTAPI RtlCompareMemoryUlong(void *src, uint64_t len, uint32_t val)
{
    const uint32_t *p = src; uint64_t i, cnt = len / 4;
    for (i = 0; i < cnt && p[i] == val; ++i) {}
    return (LONG)(i * 4);
}
/* ntoskrnl also exports the plain C library primitives. */
void *NTAPI ntdrv_memcpy(void *d, const void *s, uint64_t n) { return memcpy(d, s, n); }
void *NTAPI ntdrv_memset(void *d, int c, uint64_t n) { return memset(d, c, n); }
void *NTAPI ntdrv_memmove(void *d, const void *s, uint64_t n) { return memmove(d, s, n); }

/* ---------------------------------------------------------------- Rtl strings */
void NTAPI RtlInitUnicodeString(UNICODE_STRING *u, const WCHAR *s)
{
    unsigned n = s ? wlen(s) : 0;
    u->Buffer = (WCHAR *)s;
    u->Length = (uint16_t)(n * 2);
    u->MaximumLength = (uint16_t)(s ? n * 2 + 2 : 0);
}
void NTAPI RtlInitAnsiString(ANSI_STRING *a, const char *s)
{
    unsigned n = s ? (unsigned)strlen(s) : 0;
    a->Buffer = (char *)s;
    a->Length = (uint16_t)n;
    a->MaximumLength = (uint16_t)(s ? n + 1 : 0);
}
NTSTATUS NTAPI RtlUnicodeStringToAnsiString(ANSI_STRING *dst, const UNICODE_STRING *src, uint8_t alloc)
{
    unsigned chars = src->Length / 2, i;
    if (alloc) { dst->Buffer = kmalloc(chars + 1); if (!dst->Buffer) return STATUS_NO_MEMORY; dst->MaximumLength = (uint16_t)(chars + 1); }
    if (chars + 1 > dst->MaximumLength) return STATUS_BUFFER_OVERFLOW;
    for (i = 0; i < chars; ++i) dst->Buffer[i] = src->Buffer[i] < 0x80 ? (char)src->Buffer[i] : '?';
    dst->Buffer[chars] = 0;
    dst->Length = (uint16_t)chars;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlAnsiStringToUnicodeString(UNICODE_STRING *dst, const ANSI_STRING *src, uint8_t alloc)
{
    unsigned n = src->Length, i;
    if (alloc) { dst->Buffer = kmalloc((n + 1) * 2); if (!dst->Buffer) return STATUS_NO_MEMORY; dst->MaximumLength = (uint16_t)((n + 1) * 2); }
    if ((n + 1) * 2 > dst->MaximumLength) return STATUS_BUFFER_OVERFLOW;
    for (i = 0; i < n; ++i) dst->Buffer[i] = (uint8_t)src->Buffer[i];
    dst->Buffer[n] = 0;
    dst->Length = (uint16_t)(n * 2);
    return STATUS_SUCCESS;
}
void NTAPI RtlFreeUnicodeString(UNICODE_STRING *u) { if (u->Buffer) { kfree(u->Buffer); u->Buffer = 0; u->Length = u->MaximumLength = 0; } }
void NTAPI RtlFreeAnsiString(ANSI_STRING *a) { if (a->Buffer) { kfree(a->Buffer); a->Buffer = 0; a->Length = a->MaximumLength = 0; } }
NTSTATUS NTAPI RtlCopyUnicodeString(UNICODE_STRING *dst, const UNICODE_STRING *src)
{
    unsigned n = src ? src->Length : 0;
    if (n > dst->MaximumLength) n = dst->MaximumLength;
    if (src) memcpy(dst->Buffer, src->Buffer, n);
    dst->Length = (uint16_t)n;
    return STATUS_SUCCESS;
}
static int wcmp(const WCHAR *a, unsigned an, const WCHAR *b, unsigned bn, int ci)
{
    unsigned i;
    if (an != bn) return an < bn ? -1 : 1;
    for (i = 0; i < an; ++i) {
        WCHAR x = a[i], y = b[i];
        if (ci) { if (x >= 'a' && x <= 'z') x -= 32; if (y >= 'a' && y <= 'z') y -= 32; }
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}
LONG NTAPI RtlCompareUnicodeString(const UNICODE_STRING *a, const UNICODE_STRING *b, uint8_t ci)
{ return wcmp(a->Buffer, a->Length / 2, b->Buffer, b->Length / 2, ci); }
uint8_t NTAPI RtlEqualUnicodeString(const UNICODE_STRING *a, const UNICODE_STRING *b, uint8_t ci)
{ return wcmp(a->Buffer, a->Length / 2, b->Buffer, b->Length / 2, ci) == 0; }
NTSTATUS NTAPI RtlAppendUnicodeToString(UNICODE_STRING *dst, const WCHAR *s)
{
    unsigned n = s ? wlen(s) : 0, have = dst->Length / 2, i;
    if ((have + n) * 2 > dst->MaximumLength) return STATUS_BUFFER_TOO_SMALL;
    for (i = 0; i < n; ++i) dst->Buffer[have + i] = s[i];
    dst->Length = (uint16_t)((have + n) * 2);
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlAppendUnicodeStringToString(UNICODE_STRING *dst, const UNICODE_STRING *src)
{
    unsigned n = src->Length / 2, have = dst->Length / 2, i;
    if ((have + n) * 2 > dst->MaximumLength) return STATUS_BUFFER_TOO_SMALL;
    for (i = 0; i < n; ++i) dst->Buffer[have + i] = src->Buffer[i];
    dst->Length = (uint16_t)((have + n) * 2);
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlIntegerToUnicodeString(uint32_t value, uint32_t base, UNICODE_STRING *dst)
{
    WCHAR tmp[36]; int n = 0, i; uint32_t v = value;
    if (base == 0) base = 10;
    if (!v) tmp[n++] = '0';
    while (v) { uint32_t d = v % base; tmp[n++] = (WCHAR)(d < 10 ? '0' + d : 'a' + d - 10); v /= base; }
    if ((unsigned)(n * 2) > dst->MaximumLength) return STATUS_BUFFER_OVERFLOW;
    for (i = 0; i < n; ++i) dst->Buffer[i] = tmp[n - 1 - i];
    dst->Length = (uint16_t)(n * 2);
    return STATUS_SUCCESS;
}
uint32_t NTAPI RtlxUnicodeStringToAnsiSize(const UNICODE_STRING *u) { return u->Length / 2 + 1; }

typedef struct { uint32_t sz, major, minor, build, plat; WCHAR csd[128]; } RTL_OSVERSIONINFOW;
NTSTATUS NTAPI RtlGetVersion(RTL_OSVERSIONINFOW *v)
{
    v->major = 10; v->minor = 0; v->build = 22631; v->plat = 2; v->csd[0] = 0;
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- DbgPrint */
/* The formatter is the CRT's (ntdrv_crt.c: the same engine as sprintf/swprintf), so every Microsoft conversion a
 * driver's DbgPrint uses (%wZ, %ws, %I64x, %p, widths, precisions) prints the same way it does under a kernel debugger. */
extern int ntdrv_vformat(void *buf, uint64_t cap, int outwide, const void *fmt, int fmtwide, __builtin_ms_va_list ap);
static int vdbg_prefix(const char *prefix, const char *fmt, __builtin_ms_va_list ap)
{
    char buf[512];
    int n = ntdrv_vformat(buf, sizeof buf, 0, fmt, 0, ap);
    kprintf("[drv] %s%s", prefix ? prefix : "", buf);
    return n < 0 ? 0 : (n < (int)sizeof buf ? n : (int)sizeof buf - 1);
}
static int vdbg(const char *fmt, __builtin_ms_va_list ap) { return vdbg_prefix(0, fmt, ap); }
uint32_t NTAPI vDbgPrintExWithPrefix(const char *prefix, uint32_t cid, uint32_t level, const char *fmt, __builtin_ms_va_list ap)
{ (void)cid; (void)level; return (uint32_t)vdbg_prefix(prefix, fmt, ap); }
uint32_t NTAPI DbgPrint(const char *fmt, ...)
{
    __builtin_ms_va_list ap; int r;
    __builtin_ms_va_start(ap, fmt);
    r = vdbg(fmt, ap);
    __builtin_ms_va_end(ap);
    return (uint32_t)r;
}
uint32_t NTAPI DbgPrintEx(uint32_t cid, uint32_t level, const char *fmt, ...)
{
    __builtin_ms_va_list ap; int r;
    (void)cid; (void)level;
    __builtin_ms_va_start(ap, fmt);
    r = vdbg(fmt, ap);
    __builtin_ms_va_end(ap);
    return (uint32_t)r;
}
uint32_t NTAPI vDbgPrintEx(uint32_t cid, uint32_t level, const char *fmt, __builtin_ms_va_list ap)
{ (void)cid; (void)level; return (uint32_t)vdbg(fmt, ap); }
void NTAPI DbgBreakPoint(void) { kprintf("[drv] DbgBreakPoint\n"); }

/* ---------------------------------------------------------------- Ps system threads */
struct systhread_start { void (NTAPI *routine)(void *); void *ctx; uint64_t handle; };
static void systhread_trampoline(void *arg)
{
    struct systhread_start s = *(struct systhread_start *)arg;
    kfree(arg);
    ntdrv_gs_enter();
    s.routine(s.ctx);
    thread_exit(0);
}
NTSTATUS NTAPI PsCreateSystemThread(void *thread_handle, uint32_t access, void *oa, void *process_handle,
                                    void *client_id, void (NTAPI *start)(void *), void *ctx)
{
    struct systhread_start *s = kmalloc(sizeof *s);
    thread_t *t;
    (void)access; (void)oa; (void)process_handle; (void)client_id;
    if (!s) return STATUS_NO_MEMORY;
    s->routine = start; s->ctx = ctx;
    t = thread_create("drv-sys", systhread_trampoline, s);
    if (!t) { kfree(s); return STATUS_INSUFFICIENT_RESOURCES; }
    if (thread_handle) { uint64_t h = ntdrv_kh_alloc(KH_THREAD, t); *(uint64_t *)thread_handle = h; }
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI PsTerminateSystemThread(NTSTATUS status) { thread_exit(status); return status; }
void *NTAPI PsGetCurrentThread(void) { return thread_current(); }
uint64_t NTAPI PsGetCurrentThreadId(void) { return (uint64_t)thread_current()->id * 4; }
uint64_t NTAPI PsGetCurrentProcessId(void) { return 4; }

/* ---------------------------------------------------------------- Hal port / bus access */
uint8_t NTAPI READ_PORT_UCHAR(uint8_t *port) { return k_inb((uint16_t)(uintptr_t)port); }
uint16_t NTAPI READ_PORT_USHORT(uint16_t *port) { return k_inw((uint16_t)(uintptr_t)port); }
uint32_t NTAPI READ_PORT_ULONG(uint32_t *port) { return k_inl((uint16_t)(uintptr_t)port); }
void NTAPI WRITE_PORT_UCHAR(uint8_t *port, uint8_t v) { k_outb((uint16_t)(uintptr_t)port, v); }
void NTAPI WRITE_PORT_USHORT(uint16_t *port, uint16_t v) { k_outw((uint16_t)(uintptr_t)port, v); }
void NTAPI WRITE_PORT_ULONG(uint32_t *port, uint32_t v) { k_outl((uint16_t)(uintptr_t)port, v); }
uint8_t NTAPI READ_REGISTER_UCHAR(volatile uint8_t *r) { return *r; }
uint16_t NTAPI READ_REGISTER_USHORT(volatile uint16_t *r) { return *r; }
uint32_t NTAPI READ_REGISTER_ULONG(volatile uint32_t *r) { return *r; }
void NTAPI WRITE_REGISTER_UCHAR(volatile uint8_t *r, uint8_t v) { *r = v; }
void NTAPI WRITE_REGISTER_USHORT(volatile uint16_t *r, uint16_t v) { *r = v; }
void NTAPI WRITE_REGISTER_ULONG(volatile uint32_t *r, uint32_t v) { *r = v; }

/* HalGetBusData / HalGetBusDataByOffset: PCI configuration space (BusDataType 4 == PCIConfiguration). */
uint32_t NTAPI HalGetBusDataByOffset(uint32_t type, uint32_t bus, uint32_t slot, void *buf, uint32_t off, uint32_t len)
{
    pci_dev_t d = { .bus = (uint8_t)bus, .dev = (uint8_t)(slot & 0x1f), .fn = (uint8_t)((slot >> 5) & 7) };
    uint8_t *out = buf;
    uint32_t i;
    if (type != 4) return 0;
    if ((pci_cfg_read32(&d, 0) & 0xffff) == 0xffff) return 0;
    for (i = 0; i < len; ++i) {
        uint32_t dw = pci_cfg_read32(&d, (off + i) & ~3u);
        out[i] = (uint8_t)(dw >> (((off + i) & 3) * 8));
    }
    return len;
}
uint32_t NTAPI HalGetBusData(uint32_t type, uint32_t bus, uint32_t slot, void *buf, uint32_t len)
{ return HalGetBusDataByOffset(type, bus, slot, buf, 0, len); }
uint32_t NTAPI HalSetBusDataByOffset(uint32_t type, uint32_t bus, uint32_t slot, void *buf, uint32_t off, uint32_t len)
{
    pci_dev_t d = { .bus = (uint8_t)bus, .dev = (uint8_t)(slot & 0x1f), .fn = (uint8_t)((slot >> 5) & 7) };
    const uint8_t *in = buf;
    uint32_t i;
    if (type != 4) return 0;
    for (i = 0; i < len; ++i) {
        uint32_t dw = pci_cfg_read32(&d, (off + i) & ~3u), sh = ((off + i) & 3) * 8;
        dw = (dw & ~(0xffu << sh)) | ((uint32_t)in[i] << sh);
        pci_cfg_write32(&d, (off + i) & ~3u, dw);
    }
    return len;
}

/* ---------------------------------------------------------------- wide C string exports (ntoskrnl exports these) */

/* ---------------------------------------------------------------- more Rtl string routines */

/* ---------------------------------------------------------------- RtlQueryRegistryValues */
/* RTL_QUERY_REGISTRY_TABLE (0x38). The table is walked until an entry with neither QueryRoutine nor Name. RelativeTo
 * selects the base key (RTL_REGISTRY_ABSOLUTE/SERVICES/CONTROL/WINDOWS_NT/DEVICEMAP/USER, or a handle with
 * RTL_REGISTRY_HANDLE). Per entry: SUBKEY descends (a missing subkey fails the call), TOPKEY returns to the base, a named
 * value is looked up (REQUIRED makes its absence an error, else the Default* fields stand in; a zero DefaultLength on a
 * string default means "measure it"), DIRECT stores it at EntryContext, otherwise QueryRoutine(Name, Type, Data, Length,
 * Context, EntryContext) is called; a REG_MULTI_SZ is delivered one REG_SZ at a time unless NOEXPAND; REG_EXPAND_SZ is
 * expanded ("%SystemRoot%"/"%windir%" = C:\SHZ, other variables stay literal: there is no environment here) and delivered
 * as REG_SZ unless NOEXPAND; a NULL Name with a QueryRoutine enumerates every value (NOVALUE: one call, REG_NONE); DELETE
 * removes the value after it was delivered. The registry lock is held only while a key or value is looked up and
 * copied: the value data goes to the routine from a private copy and the current key is pinned, so a QueryRoutine may call
 * any registry API (Zw*, IoOpenDeviceRegistryKey, RtlQueryRegistryValues itself), as on Windows. */
typedef struct {
    NTSTATUS (NTAPI *QueryRoutine)(const WCHAR *, uint32_t, void *, uint32_t, void *, void *);
    uint32_t Flags, _p0;
    const WCHAR *Name;
    void *EntryContext;
    uint32_t DefaultType, _p1;
    void *DefaultData;
    uint32_t DefaultLength, _p2;
} rtl_query_table_t;
_Static_assert(sizeof(rtl_query_table_t) == 0x38, "query table");
#define RTL_QUERY_REGISTRY_SUBKEY 0x1
#define RTL_QUERY_REGISTRY_TOPKEY 0x2
#define RTL_QUERY_REGISTRY_REQUIRED 0x4
#define RTL_QUERY_REGISTRY_NOVALUE 0x8
#define RTL_QUERY_REGISTRY_NOEXPAND 0x10
#define RTL_QUERY_REGISTRY_DIRECT 0x20
#define RTL_QUERY_REGISTRY_DELETE 0x40
#define RTL_REGISTRY_HANDLE 0x40000000u
#define RTL_REGISTRY_OPTIONAL 0x80000000u
#define REG_NONE_T 0
#define QR_PATH_MAX 400


/* the byte length of a default given as a string type with DefaultLength == 0 */


/* %SystemRoot% / %windir% -> C:\SHZ, in place into `out` (capacity `cap` bytes); returns the byte length including the
 * terminator. A variable that is not known stays as written. */



/* value `name` of key k copied out under the lock: *type, *len and a kmalloc'd copy (0 when the value is absent) */


