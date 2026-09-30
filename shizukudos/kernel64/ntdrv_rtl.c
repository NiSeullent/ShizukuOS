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
static void emit(char *buf, unsigned *n, unsigned cap, char c) { if (*n + 1 < cap) buf[(*n)++] = c; }
static void emit_str(char *buf, unsigned *n, unsigned cap, const char *s) { while (*s) emit(buf, n, cap, *s++); }
static void emit_uint(char *buf, unsigned *n, unsigned cap, uint64_t v, unsigned base, int upper, int width, int zero)
{
    char t[24]; int k = 0; const char *d = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    if (!v) t[k++] = '0';
    while (v) { t[k++] = d[v % base]; v /= base; }
    while (k < width) t[k++] = zero ? '0' : ' ';
    while (k) emit(buf, n, cap, t[--k]);
}
static int NTAPI vdbg(const char *fmt, __builtin_ms_va_list ap)
{
    char buf[256];
    unsigned n = 0;
    const char *f = fmt;
    while (*f) {
        if (*f != '%') { emit(buf, &n, sizeof buf, *f++); continue; }
        ++f;
        {
            int zero = 0, width = 0, longs = 0;
            if (*f == '0') { zero = 1; ++f; }
            while (*f >= '0' && *f <= '9') { width = width * 10 + (*f - '0'); ++f; }
            while (*f == 'l') { ++longs; ++f; }
            if (*f == 'w') ++f;                    /* %ws / %wZ */
            switch (*f) {
            case 's': emit_str(buf, &n, sizeof buf, __builtin_va_arg(ap, const char *)); break;
            case 'd': case 'i': { long v = longs ? __builtin_va_arg(ap, long) : __builtin_va_arg(ap, int);
                                  if (v < 0) { emit(buf, &n, sizeof buf, '-'); v = -v; }
                                  emit_uint(buf, &n, sizeof buf, (uint64_t)v, 10, 0, width, zero); break; }
            case 'u': emit_uint(buf, &n, sizeof buf, longs ? __builtin_va_arg(ap, unsigned long) : __builtin_va_arg(ap, unsigned), 10, 0, width, zero); break;
            case 'x': emit_uint(buf, &n, sizeof buf, longs ? __builtin_va_arg(ap, unsigned long) : __builtin_va_arg(ap, unsigned), 16, 0, width, zero); break;
            case 'X': emit_uint(buf, &n, sizeof buf, longs ? __builtin_va_arg(ap, unsigned long) : __builtin_va_arg(ap, unsigned), 16, 1, width, zero); break;
            case 'p': emit_str(buf, &n, sizeof buf, "0x"); emit_uint(buf, &n, sizeof buf, (uint64_t)__builtin_va_arg(ap, void *), 16, 0, 0, 0); break;
            case 'c': emit(buf, &n, sizeof buf, (char)__builtin_va_arg(ap, int)); break;
            case 'Z': { const void *pv = __builtin_va_arg(ap, void *); const ANSI_STRING *a = pv;
                        unsigned i; for (i = 0; i < a->Length; ++i) emit(buf, &n, sizeof buf, a->Buffer[i]); break; }
            case '%': emit(buf, &n, sizeof buf, '%'); break;
            case 0: continue;
            default: emit(buf, &n, sizeof buf, '%'); emit(buf, &n, sizeof buf, *f); break;
            }
            ++f;
        }
    }
    buf[n] = 0;
    kprintf("[drv] %s", buf);
    return (int)n;
}
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
uint64_t NTAPI ntdrv_wcslen(const WCHAR *s) { uint64_t n = 0; while (s[n]) ++n; return n; }
WCHAR *NTAPI ntdrv_wcscpy(WCHAR *d, const WCHAR *s) { WCHAR *r = d; while ((*d++ = *s++) != 0) {} return r; }
WCHAR *NTAPI ntdrv_wcscat(WCHAR *d, const WCHAR *s) { WCHAR *r = d; while (*d) ++d; while ((*d++ = *s++) != 0) {} return r; }
WCHAR *NTAPI ntdrv_wcsncpy(WCHAR *d, const WCHAR *s, uint64_t n)
{
    WCHAR *r = d;
    while (n && *s) { *d++ = *s++; --n; }
    while (n--) *d++ = 0;                                       /* C semantics: pad with NULs */
    return r;
}
WCHAR *NTAPI ntdrv_wcsncat(WCHAR *d, const WCHAR *s, uint64_t n)
{
    WCHAR *r = d;
    while (*d) ++d;
    while (n-- && *s) *d++ = *s++;
    *d = 0;
    return r;
}
int NTAPI ntdrv_wcsncmp(const WCHAR *a, const WCHAR *b, uint64_t n)
{
    for (; n; --n, ++a, ++b) {
        if (*a != *b) return *a < *b ? -1 : 1;
        if (!*a) return 0;
    }
    return 0;
}

/* ---------------------------------------------------------------- more Rtl string routines */
void NTAPI RtlInitString(ANSI_STRING *a, const char *s) { RtlInitAnsiString(a, s); }
LONG NTAPI RtlCompareString(const ANSI_STRING *a, const ANSI_STRING *b, uint8_t ci)
{
    unsigned n = a->Length < b->Length ? a->Length : b->Length, i;
    for (i = 0; i < n; ++i) {
        unsigned char ca = (unsigned char)a->Buffer[i], cb = (unsigned char)b->Buffer[i];
        if (ci) { if (ca >= 'a' && ca <= 'z') ca -= 32; if (cb >= 'a' && cb <= 'z') cb -= 32; }
        if (ca != cb) return (LONG)ca - (LONG)cb;
    }
    return (LONG)a->Length - (LONG)b->Length;
}
NTSTATUS NTAPI RtlUpcaseUnicodeString(UNICODE_STRING *dst, const UNICODE_STRING *src, uint8_t alloc)
{
    unsigned i, n = src->Length / 2;
    if (alloc) {
        dst->Buffer = kmalloc(src->Length ? src->Length : 2);
        if (!dst->Buffer) return STATUS_NO_MEMORY;
        dst->MaximumLength = src->Length;
    } else if (dst->MaximumLength < src->Length) return STATUS_BUFFER_OVERFLOW;
    for (i = 0; i < n; ++i) dst->Buffer[i] = (WCHAR)reg_upcase_char(src->Buffer[i]);
    dst->Length = src->Length;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI RtlUnicodeStringToInteger(const UNICODE_STRING *s, uint32_t base, uint32_t *value)
{
    unsigned i = 0, n = s->Length / 2;
    int neg = 0;
    uint32_t v = 0;
    const WCHAR *p = s->Buffer;
    if (!value) return STATUS_ACCESS_VIOLATION;
    while (i < n && (p[i] == ' ' || p[i] == '\t' || p[i] == '\n' || p[i] == '\r')) ++i;
    if (i < n && (p[i] == '+' || p[i] == '-')) { neg = p[i] == '-'; ++i; }
    if (!base) {
        base = 10;
        if (i + 1 < n && p[i] == '0') {
            WCHAR c = p[i + 1];
            if (c == 'x' || c == 'X') { base = 16; i += 2; }
            else if (c == 'o' || c == 'O') { base = 8; i += 2; }
            else if (c == 'b' || c == 'B') { base = 2; i += 2; }
        }
    } else if (base != 2 && base != 8 && base != 10 && base != 16) return STATUS_INVALID_PARAMETER;
    for (; i < n; ++i) {
        WCHAR c = p[i];
        uint32_t d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        if (d >= base) break;
        v = v * base + d;
    }
    *value = neg ? (uint32_t)(-(int32_t)v) : v;
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- RtlQueryRegistryValues */
/* RTL_QUERY_REGISTRY_TABLE (0x38). The table is walked until an entry with neither QueryRoutine nor Name. RelativeTo
 * selects the base key (RTL_REGISTRY_ABSOLUTE/SERVICES/CONTROL/WINDOWS_NT/DEVICEMAP/USER, or a handle with
 * RTL_REGISTRY_HANDLE). Per entry: SUBKEY descends, TOPKEY returns to the base, a named value is looked up (REQUIRED
 * makes its absence an error, else the Default* fields stand in), DIRECT stores it at EntryContext, otherwise
 * QueryRoutine(Name, Type, Data, Length, Context, EntryContext) is called; a REG_MULTI_SZ is delivered one REG_SZ at a
 * time unless NOEXPAND; a NULL Name with a QueryRoutine enumerates every value (or NOVALUE: one call, REG_NONE).
 * REG_EXPAND_SZ values are delivered as they are (no environment to expand here). Windows semantics per wdm.h. */
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
#define RTL_REGISTRY_HANDLE 0x40000000u
#define RTL_REGISTRY_OPTIONAL 0x80000000u
#define REG_NONE_T 0

static int32_t rtl_direct(uint32_t type, const void *data, uint32_t len, void *ctx)
{
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        UNICODE_STRING *u = ctx;
        uint32_t n = len;
        if (!u->Buffer) {
            u->Buffer = kmalloc(n ? n : 2);
            if (!u->Buffer) return STATUS_NO_MEMORY;
            u->MaximumLength = (uint16_t)n;
        } else if (n > u->MaximumLength) n = u->MaximumLength;
        memcpy(u->Buffer, data, n);
        u->Length = (uint16_t)n;
        if (n >= 2 && u->Buffer[n / 2 - 1] == 0) u->Length = (uint16_t)(n - 2);   /* the terminator is not counted */
        return STATUS_SUCCESS;
    }
    if (len <= 4) {                                              /* fits a ULONG: copied to it */
        memcpy(ctx, data, len);
        return STATUS_SUCCESS;
    }
    {   /* longer: EntryContext points at a ULONG length followed by the buffer; a negative length means the buffer
         * starts at EntryContext itself and holds -length bytes */
        int32_t *hdr = ctx;
        if (*hdr < 0) { uint32_t cap = (uint32_t)(-*hdr); if (len > cap) return STATUS_BUFFER_TOO_SMALL; memcpy(ctx, data, len); }
        else { if (len > (uint32_t)*hdr) return STATUS_BUFFER_TOO_SMALL; *hdr = (int32_t)len; memcpy(hdr + 1, data, len); }
        return STATUS_SUCCESS;
    }
}

static int32_t rtl_deliver(rtl_query_table_t *t, const WCHAR *name, uint32_t type, const void *data, uint32_t len, void *ctx)
{
    if (type == REG_MULTI_SZ && !(t->Flags & RTL_QUERY_REGISTRY_NOEXPAND)) {
        const WCHAR *p = data, *end = (const WCHAR *)((const uint8_t *)data + len);
        int32_t st = STATUS_SUCCESS;
        void *ectx = t->EntryContext;
        while (p < end && *p) {
            const WCHAR *q = p;
            while (q < end && *q) ++q;
            if (q < end) ++q;                                    /* include the terminator, as Windows does */
            if (t->Flags & RTL_QUERY_REGISTRY_DIRECT) { st = rtl_direct(REG_SZ, p, (uint32_t)((q - p) * 2), ectx); ectx = (uint8_t *)ectx + sizeof(UNICODE_STRING); }
            else if (t->QueryRoutine) st = t->QueryRoutine(name, REG_SZ, (void *)p, (uint32_t)((q - p) * 2), ctx, t->EntryContext);
            if (st == STATUS_BUFFER_TOO_SMALL) st = STATUS_SUCCESS;
            if (st) return st;
            p = q;
        }
        return st;
    }
    if (t->Flags & RTL_QUERY_REGISTRY_DIRECT) return rtl_direct(type, data, len, t->EntryContext);
    if (!t->QueryRoutine) return STATUS_INVALID_PARAMETER;
    return t->QueryRoutine(name, type, (void *)data, len, ctx, t->EntryContext);
}

static const char *rtl_prefix(uint32_t rel)
{
    switch (rel & 0xff) {
    case 0: return "";                                                              /* ABSOLUTE: \Registry\... */
    case 1: return "Machine\\System\\CurrentControlSet\\Services\\";
    case 2: return "Machine\\System\\CurrentControlSet\\Control\\";
    case 3: return "Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\";
    case 4: return "Machine\\Hardware\\DeviceMap\\";
    case 5: return "User\\";
    default: return 0;
    }
}

NTSTATUS NTAPI RtlQueryRegistryValues(uint32_t rel, const WCHAR *path, rtl_query_table_t *table, void *ctx, void *env)
{
    uint16_t full[400];
    unsigned n = 0, i;
    regkey_t *base = 0, *cur;
    int32_t st;
    (void)env;
    reg_lock();
    if (rel & RTL_REGISTRY_HANDLE) {
        base = ntdrv_kh_get((uint64_t)path, KH_KEY);
        if (!base) { reg_unlock(); return STATUS_INVALID_HANDLE; }
    } else {
        const char *pfx = rtl_prefix(rel);
        if (!pfx || !path) { reg_unlock(); return STATUS_INVALID_PARAMETER; }
        for (i = 0; pfx[i]; ++i) full[n++] = (uint16_t)pfx[i];
        if ((rel & 0xff) == 0) {                                 /* "\Registry\Machine\..." -> strip the object-manager root */
            unsigned k = 0;
            if (path[0] == '\\') { ++k; while (path[k] && path[k] != '\\') ++k; if (path[k]) ++k; }
            path += k;
        }
        for (i = 0; path[i] && n + 1 < 400; ++i) full[n++] = path[i];
        st = reg_resolve(reg_root(), full, n, 0, 0, 1, 0, 0, &base, 0);
        if (st) { reg_unlock(); return (rel & RTL_REGISTRY_OPTIONAL) ? STATUS_SUCCESS : st; }
    }
    cur = base;
    st = STATUS_SUCCESS;
    for (; table->QueryRoutine || table->Name; ++table) {
        rtl_query_table_t *t = table;
        if (t->Flags & RTL_QUERY_REGISTRY_TOPKEY) cur = base;
        if (t->Flags & RTL_QUERY_REGISTRY_SUBKEY) {
            regkey_t *sub;
            if (!t->Name) { st = STATUS_INVALID_PARAMETER; break; }
            for (n = 0; t->Name[n]; ++n) {}
            st = reg_resolve(cur, t->Name, n, 0, 0, 1, 0, 0, &sub, 0);
            if (st) { if (t->Flags & RTL_QUERY_REGISTRY_REQUIRED) break; st = STATUS_SUCCESS; continue; }
            cur = sub;
            if (!t->QueryRoutine) continue;
        }
        if (t->Name && !(t->Flags & RTL_QUERY_REGISTRY_SUBKEY)) {
            regval_t *v;
            for (n = 0; t->Name[n]; ++n) {}
            v = reg_find_value(cur, t->Name, n);
            if (v) st = rtl_deliver(t, t->Name, v->type, regval_data(v), v->data_len, ctx);
            else if (t->DefaultType != REG_NONE_T) st = rtl_deliver(t, t->Name, t->DefaultType, t->DefaultData, t->DefaultLength, ctx);
            else if (t->Flags & RTL_QUERY_REGISTRY_REQUIRED) st = STATUS_OBJECT_NAME_NOT_FOUND;
            else st = STATUS_SUCCESS;
        } else if (t->QueryRoutine) {
            if (t->Flags & RTL_QUERY_REGISTRY_NOVALUE) st = t->QueryRoutine(0, REG_NONE_T, 0, 0, ctx, t->EntryContext);
            else {
                uint32_t k;
                regval_t *v;
                for (k = 0; (v = reg_nth_value(cur, k)) != 0 && !st; ++k) {
                    uint16_t vname[128];
                    unsigned len = v->name_len < 127 ? v->name_len : 127;
                    memcpy(vname, regval_name(v), len * 2);
                    vname[len] = 0;
                    st = rtl_deliver(t, vname, v->type, regval_data(v), v->data_len, ctx);
                }
            }
        }
        if (st) break;
    }
    reg_unlock();
    return st;
}
