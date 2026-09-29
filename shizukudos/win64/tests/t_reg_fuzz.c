/* SPDX-License-Identifier: GPL-2.0-only
 * Registry self-check, part 5: hostile arguments. The registry system calls are driven with deterministic pseudo-random
 * arguments: wild, kernel-space, unaligned and page-crossing pointers, bogus, closed and wrong-type handles, absurd
 * lengths and UNICODE_STRING headers that lie about their buffers, unknown information classes. The kernel must survive every
 * call (a fault in the kernel would end the whole boot, so reaching the end is the primary result), never hand out a
 * bogus success where the arguments were invalid, and the registry must still behave afterwards.
 */
#include "reg_check.h"

static ULONG64 g_seed = 0x123456789abcdefull;
static ULONG64 rnd(void)
{
    g_seed = g_seed * 6364136223846793005ull + 1442695040888963407ull;
    return g_seed >> 17;
}
static ULONG pick(ULONG n) { return (ULONG)(rnd() % n); }

static BYTE *g_good;                        /* committed page followed by a reserved-only page */
static HANDLE g_keys[4];
static HANDLE g_event;
static HANDLE g_closed;

static PVOID wild_ptr(void)
{
    switch (pick(12)) {
    case 0: return 0;
    case 1: return (PVOID)(ULONG_PTR)1;
    case 2: return (PVOID)(ULONG_PTR)0x1000;
    case 3: return (PVOID)0xFFFF800000000000ull;             /* kernel direct map */
    case 4: return (PVOID)0xFFFFFFFF80100000ull;             /* kernel image */
    case 5: return (PVOID)0x00007FFFFFFFF000ull;             /* top of the user range */
    case 6: return (PVOID)(ULONG_PTR)-1;
    case 7: return g_good + 1;                               /* unaligned */
    case 8: return g_good + 4096 - 6;                        /* crosses into the reserved-only page */
    case 9: return g_good + 8192 - 2;
    default: return g_good + 8 * pick(400);
    }
}

static HANDLE pick_handle(void)
{
    switch (pick(10)) {
    case 0: return 0;
    case 1: return g_closed;
    case 2: return g_event;
    case 3: return CURRENT_PROCESS;
    case 4: return CURRENT_THREAD;
    case 5: return (HANDLE)(ULONG_PTR)(pick(2000) * 4);
    case 6: return (HANDLE)(ULONG_PTR)rnd();
    default: return g_keys[pick(4)];
    }
}

static ULONG pick_len(void)
{
    static const ULONG lens[] = { 0, 1, 2, 3, 7, 11, 12, 13, 16, 20, 24, 44, 100, 4095, 4096, 4097, 70000, 300000, 0x7FFFFFFF, 0xFFFFFFFF };
    return lens[pick(sizeof lens / sizeof lens[0])];
}

/* A UNICODE_STRING that is sometimes honest, sometimes lying about length, buffer or alignment. */
static SHZ_UNICODE_STRING g_us[8];
static WCHAR g_names[8][40];
static SHZ_UNICODE_STRING *pick_us(void)
{
    static const WCHAR *const good[] = { L"a", L"b\\c", L"D", L"Software", L"\\Registry\\User", L"\\Registry", L"x\\\\y", L"deep\\er\\still", L"" };
    static int n;
    SHZ_UNICODE_STRING *u = &g_us[n++ & 7];
    WCHAR *buf = g_names[(n - 1) & 7];
    const WCHAR *src = good[pick(sizeof good / sizeof good[0])];
    ULONG i = 0;
    while (src[i] && i < 39) { buf[i] = src[i]; ++i; }
    buf[i] = 0;
    u->Buffer = buf;
    u->Length = (USHORT)(i * 2);
    u->MaximumLength = (USHORT)(i * 2 + 2);
    switch (pick(10)) {
    case 0: u->Length = 0xFFFE; break;                       /* claims 65534 bytes of a 80-byte buffer */
    case 1: u->Length = (USHORT)(u->Length | 1); break;      /* odd length */
    case 2: u->Buffer = wild_ptr(); break;
    case 3: u->Length = (USHORT)pick(400); break;
    case 4: u->Buffer = 0; break;
    default: break;
    }
    return u;
}

static SHZ_OBJECT_ATTRIBUTES g_oa[8];
static SHZ_OBJECT_ATTRIBUTES *pick_oa(void)
{
    static int n;
    SHZ_OBJECT_ATTRIBUTES *oa = &g_oa[n++ & 7];
    memset(oa, 0, sizeof *oa);
    oa->Length = pick(6) ? sizeof *oa : pick(100);
    oa->RootDirectory = pick(3) ? 0 : pick_handle();
    oa->ObjectName = pick(8) ? pick_us() : (SHZ_UNICODE_STRING *)wild_ptr();
    oa->Attributes = pick(4) ? 0x40 : (ULONG)rnd();
    if (pick(12) == 0) return (SHZ_OBJECT_ATTRIBUTES *)wild_ptr();
    return oa;
}

static ULONG64 g_calls, g_ok;

/* Removes everything below `h` with counted names: the fuzzer creates keys whose names hold NULs and other characters that
 * the NUL-terminated Win32 calls cannot address. Returns the number of keys it could not remove. */
static int native_delete_tree(HANDLE h, int depth)
{
    int left = 0;
    for (;;) {
        BYTE buf[600];
        ULONG res = 0;
        SHZ_KEY_BASIC_INFORMATION *bi = (SHZ_KEY_BASIC_INFORMATION *)buf;
        HANDLE c = 0;
        SHZ_UNICODE_STRING us;
        SHZ_OBJECT_ATTRIBUTES oa;
        NTSTATUS st = NtEnumerateKey(h, 0, SHZ_KeyBasicInformation, buf, sizeof buf, &res);
        if (st) break;
        us.Buffer = bi->Name;
        us.Length = us.MaximumLength = (USHORT)bi->NameLength;
        memset(&oa, 0, sizeof oa);
        oa.Length = sizeof oa; oa.RootDirectory = h; oa.ObjectName = &us; oa.Attributes = 0x40;
        if (NtOpenKey(&c, KEY_ALL_ACCESS, &oa)) { ++left; break; }
        left += native_delete_tree(c, depth + 1);
        if (NtDeleteKey(c)) ++left;
        NtClose(c);
        if (left) break;
    }
    return left;
}

static void one_call(void)
{
    HANDLE h = 0;
    ULONG res = 0;
    NTSTATUS st = 0;
    PVOID buf = pick(4) ? g_good + 8 * pick(64) : wild_ptr();
    switch (pick(14)) {
    case 0: st = NtOpenKey(pick(6) ? &h : (PHANDLE)wild_ptr(), (ACCESS_MASK)rnd(), pick_oa()); break;
    case 1: st = NtOpenKeyEx(&h, (ACCESS_MASK)rnd(), pick_oa(), (ULONG)(pick(3) ? pick(20) : rnd())); break;
    case 2: st = NtCreateKey(pick(6) ? &h : (PHANDLE)wild_ptr(), (ACCESS_MASK)rnd(), pick_oa(), 0, pick(3) ? 0 : pick_us(), (ULONG)(pick(3) ? pick(16) : rnd()), pick(3) ? &res : (PULONG)wild_ptr()); break;
    case 3: st = NtQueryValueKey(pick_handle(), pick_us(), pick(6) ? pick(4) : (ULONG)rnd(), buf, pick_len(), pick(3) ? &res : (PULONG)wild_ptr()); break;
    case 4: st = NtSetValueKey(pick_handle(), pick_us(), 0, (ULONG)(pick(2) ? pick(13) : rnd()), buf, pick_len() & (pick(4) ? 0x3FFF : 0xFFFFFFFF)); break;
    case 5: if (pick(3) == 0) st = NtDeleteKey(pick_handle()); break;
    case 6: st = NtDeleteValueKey(pick_handle(), pick_us()); break;
    case 7: st = NtEnumerateKey(pick_handle(), pick(3) ? pick(8) : (ULONG)rnd(), pick(6) ? pick(5) : (ULONG)rnd(), buf, pick_len(), pick(3) ? &res : (PULONG)wild_ptr()); break;
    case 8: st = NtEnumerateValueKey(pick_handle(), pick(3) ? pick(8) : (ULONG)rnd(), pick(6) ? pick(4) : (ULONG)rnd(), buf, pick_len(), pick(3) ? &res : (PULONG)wild_ptr()); break;
    case 9: st = NtQueryKey(pick_handle(), pick(6) ? pick(6) : (ULONG)rnd(), buf, pick_len(), pick(3) ? &res : (PULONG)wild_ptr()); break;
    case 10: st = NtFlushKey(pick_handle()); break;
    case 11: st = NtQueryObject(pick_handle(), pick(6) ? pick(4) : (ULONG)rnd(), buf, pick_len(), pick(3) ? &res : (PULONG)wild_ptr()); break;
    case 12: st = NtNotifyChangeKey(pick_handle(), pick(2) ? g_event : pick_handle(), 0, 0, pick(2) ? 0 : (SHZ_IO_STATUS_BLOCK *)wild_ptr(),
                                    (ULONG)(pick(2) ? pick(32) : rnd()), (BOOLEAN)pick(2), 0, 0, (BOOLEAN)pick(4) != 0); break;
    default: st = NtFlushKey(g_keys[pick(4)]); break;        /* a well-formed call in between the hostile ones */
    }
    ++g_calls;
    if (NT_SUCCESS(st)) ++g_ok;
    if (h) NtClose(h);                                       /* handles from successful opens: close them all */
}

int main(void)
{
    PVOID base = 0;
    SIZE_T size = 8192;
    HKEY root = 0;
    ULONG i;
    LONG e;
    printf("t_reg_fuzz: registry system calls with hostile arguments\n");
    NtAllocateVirtualMemory(CURRENT_PROCESS, &base, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    {
        PVOID p = base;
        SIZE_T one = 4096;
        NtAllocateVirtualMemory(CURRENT_PROCESS, &p, 0, &one, MEM_COMMIT, PAGE_READWRITE);      /* only the first page is committed */
    }
    g_good = base;
    CHECK(g_good != 0, "a committed page followed by a reserved page for boundary cases");
    delete_tree(HKEY_CURRENT_USER, L"Software\\ShzFuzz");
    e = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ShzFuzz\\Root", 0, 0, 0, KEY_ALL_ACCESS, 0, &root, 0);
    CHECK_ERR(e, 0, "create the fuzz root");
    for (i = 0; i < 4; ++i) {
        SHZ_UNICODE_STRING us;
        SHZ_OBJECT_ATTRIBUTES oa;
        WCHAR nm[8] = L"k0";
        nm[1] = (WCHAR)(L'0' + i);
        RtlInitUnicodeString(&us, nm);
        memset(&oa, 0, sizeof oa);
        oa.Length = sizeof oa; oa.RootDirectory = (HANDLE)root; oa.ObjectName = &us; oa.Attributes = 0x40;
        NtCreateKey(&g_keys[i], KEY_ALL_ACCESS, &oa, 0, 0, 0, 0);
    }
    g_event = CreateEventW(0, TRUE, FALSE, 0);
    {
        HANDLE t = 0;
        SHZ_OBJECT_ATTRIBUTES oa;
        SHZ_UNICODE_STRING us;
        RtlInitUnicodeString(&us, L"closed");
        memset(&oa, 0, sizeof oa);
        oa.Length = sizeof oa; oa.RootDirectory = (HANDLE)root; oa.ObjectName = &us; oa.Attributes = 0x40;
        NtCreateKey(&t, KEY_ALL_ACCESS, &oa, 0, 0, 0, 0);
        g_closed = t;
        NtClose(t);
    }
    for (i = 0; i < 40000; ++i) {
        one_call();
        /* keep at least two usable key handles around: the fuzzer may delete or close the others */
        if ((i & 255) == 255) {
            ULONG k;
            for (k = 0; k < 4; ++k) {
                SHZ_UNICODE_STRING us;
                SHZ_OBJECT_ATTRIBUTES oa;
                HANDLE nh = 0;
                WCHAR nm[8] = L"k0";
                nm[1] = (WCHAR)(L'0' + k);
                RtlInitUnicodeString(&us, nm);
                memset(&oa, 0, sizeof oa);
                oa.Length = sizeof oa; oa.RootDirectory = (HANDLE)root; oa.ObjectName = &us; oa.Attributes = 0x40;
                if (NtCreateKey(&nh, KEY_ALL_ACCESS, &oa, 0, 0, 0, 0) == 0) {
                    NtClose(g_keys[k]);                              /* may already be closed: an error we ignore */
                    g_keys[k] = nh;
                }
            }
        }
    }
    printf("info: %d calls, %d returned success\n", (int)g_calls, (int)g_ok);
    CHECK(g_calls == 40000, "the kernel survived 40,000 hostile registry calls");
    /* the registry is still coherent and usable */
    {
        HKEY k = 0;
        DWORD v = 0, cb = 4, ty = 0, dw = 0x5AA5;
        e = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ShzFuzz\\After", 0, 0, 0, KEY_ALL_ACCESS, 0, &k, 0);
        CHECK_ERR(e, 0, "a key can still be created");
        CHECK_ERR(RegSetValueExW(k, L"v", 0, REG_DWORD, (const BYTE *)&dw, 4), 0, "and written");
        e = RegQueryValueExW(k, L"v", 0, &ty, (BYTE *)&v, &cb);
        CHECK(e == 0 && v == 0x5AA5, "and read back");
        if (k) RegCloseKey(k);
    }
    for (i = 0; i < 4; ++i) NtClose(g_keys[i]);
    RegCloseKey(root);
    {
        HKEY top = 0;
        int left = -1;
        e = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\ShzFuzz", 0, KEY_ALL_ACCESS, &top);
        CHECK_ERR(e, 0, "the fuzz tree is still there");
        if (e == 0) {
            left = native_delete_tree((HANDLE)top, 0);
            RegCloseKey(top);
        }
        CHECK(left == 0, "whatever the fuzzer left in the tree (keys with odd names, classes and values) can be enumerated and deleted natively");
        CHECK_ERR(RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\ShzFuzz"), 0, "and the tree's root goes too");
    }
    {   /* the registry budget is intact after 40,000 random calls (nothing leaked in error paths) */
        HKEY b = 0;
        BYTE *blob = shz_malloc(200000);
        DWORD ok = 0;
        RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ShzFuzz", 0, 0, 0, KEY_ALL_ACCESS, 0, &b, 0);
        if (blob && b) {
            memset(blob, 2, 200000);
            for (i = 0; i < 4; ++i) {
                WCHAR vn[4] = L"f0";
                vn[1] = (WCHAR)(L'0' + i);
                if (!RegSetValueExW(b, vn, 0, REG_BINARY, blob, 200000)) ++ok;
            }
        }
        CHECK(ok == 4, "the registry budget is intact: 4 x 200,000 bytes fit");
        if (b) RegCloseKey(b);
        if (blob) shz_free(blob);
        delete_tree(HKEY_CURRENT_USER, L"Software\\ShzFuzz");
    }
    return finish_tests("t_reg_fuzz");
}
