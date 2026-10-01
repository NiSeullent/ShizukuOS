/* SPDX-License-Identifier: GPL-2.0-only
 * Registry self-check, part 2: the native interface (NtCreateKey ... NtQueryObject) called directly. Buffer-size protocol
 * of every information class, NTSTATUS results, path syntax rules, handle rights, object queries, the handle table, and
 * cleanup of open key handles when the process exits (the next program, t_reg_stress, verifies that nothing leaked).
 */
#include "reg_check.h"

#define ST_SUCCESS ((NTSTATUS)0)
#define ST_BUFFER_OVERFLOW ((NTSTATUS)0x80000005)
#define ST_NO_MORE_ENTRIES ((NTSTATUS)0x8000001A)
#define ST_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023)
#define ST_INVALID_HANDLE ((NTSTATUS)0xC0000008)
#define ST_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#define ST_INFO_CLASS ((NTSTATUS)0xC0000003)
#define ST_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)
#define ST_PATH_NOT_FOUND ((NTSTATUS)0xC000003A)
#define ST_PATH_SYNTAX_BAD ((NTSTATUS)0xC000003B)
#define ST_NAME_INVALID ((NTSTATUS)0xC0000033)
#define ST_ACCESS_DENIED ((NTSTATUS)0xC0000022)
#define ST_TYPE_MISMATCH ((NTSTATUS)0xC0000024)
#define ST_CANNOT_DELETE ((NTSTATUS)0xC0000121)
#define ST_KEY_DELETED ((NTSTATUS)0xC000017C)
#define ST_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define ST_NO_MEMORY ((NTSTATUS)0xC0000017)

static void check_st_impl(NTSTATUS got, NTSTATUS want, const char *what, int line)
{
    if (got == want) { ++g_pass; printf("PASS: %s\n", what); }
    else { ++g_fail; printf("FAIL: %s: got %08x want %08x (line %d)\n", what, (unsigned)got, (unsigned)want, line); }
}
#define CHECK_ST(got, want, what) check_st_impl((NTSTATUS)(got), (NTSTATUS)(want), what, __LINE__)

static void oa_init(SHZ_OBJECT_ATTRIBUTES *oa, SHZ_UNICODE_STRING *us, HANDLE root, const WCHAR *name)
{
    memset(oa, 0, sizeof *oa);
    if (name) RtlInitUnicodeString(us, name); else { us->Length = us->MaximumLength = 0; us->Buffer = 0; }
    oa->Length = sizeof *oa;
    oa->RootDirectory = root;
    oa->ObjectName = us;
    oa->Attributes = 0x40;                                            /* OBJ_CASE_INSENSITIVE */
}

static NTSTATUS create_k(HANDLE *h, HANDLE root, const WCHAR *name, ACCESS_MASK acc, SHZ_UNICODE_STRING *cls, ULONG opts, ULONG *disp)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    oa_init(&oa, &us, root, name);
    return NtCreateKey(h, acc, &oa, 0, cls, opts, disp);
}

static NTSTATUS open_k(HANDLE *h, HANDLE root, const WCHAR *name, ACCESS_MASK acc)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    oa_init(&oa, &us, root, name);
    return NtOpenKey(h, acc, &oa);
}

/* absolute path of the current user's key + suffix; returns a heap string */
static WCHAR *user_path(const WCHAR *suffix)
{
    SHZ_UNICODE_STRING cu;
    WCHAR *out;
    size_t n, m = wl(suffix);
    if (RtlFormatCurrentUserKeyPath(&cu)) return 0;
    n = cu.Length / 2;
    out = shz_malloc((n + m + 1) * 2);
    memcpy(out, cu.Buffer, n * 2);
    memcpy(out + n, suffix, (m + 1) * 2);
    RtlFreeUnicodeString(&cu);
    return out;
}

static void test_paths_and_status(void)
{
    HANDLE base = 0, sub = 0, h = 0;
    ULONG disp = 0;
    NTSTATUS st;
    WCHAR *abs = user_path(L"\\Software\\ShzNative");
    if (!abs) { CHECK(0, "RtlFormatCurrentUserKeyPath"); return; }
    delete_tree(HKEY_CURRENT_USER, L"Software\\ShzNative");
    st = create_k(&base, 0, abs, KEY_ALL_ACCESS, 0, 0, &disp);
    CHECK_ST(st, ST_SUCCESS, "NtCreateKey with an absolute \\Registry\\User\\<SID>\\... path");
    CHECK(disp == 1, "disposition REG_CREATED_NEW_KEY (1)");
    st = create_k(&h, 0, abs, KEY_READ, 0, 0, &disp);
    CHECK(st == 0 && disp == 2, "the same absolute path again: REG_OPENED_EXISTING_KEY (2)");
    if (h) NtClose(h);
    /* the case of the root name does not matter, and \Registry itself opens */
    h = 0;
    st = open_k(&h, 0, L"\\REGISTRY\\machine\\SOFTWARE", KEY_READ);
    CHECK_ST(st, ST_SUCCESS, "\\REGISTRY\\machine\\SOFTWARE opens (names are case-insensitive)");
    if (h) NtClose(h);
    h = 0;
    st = open_k(&h, 0, L"\\Registry", KEY_READ);
    CHECK_ST(st, ST_SUCCESS, "\\Registry itself opens");
    if (h) { NtClose(h); h = 0; }
    st = create_k(&h, 0, L"\\Registry\\Hive", KEY_ALL_ACCESS, 0, 0, &disp);
    CHECK_ST(st, ST_ACCESS_DENIED, "no new key can be created directly below \\Registry");
    st = open_k(&h, 0, L"\\Registry\\Nothing\\Here", KEY_READ);
    CHECK_ST(st, ST_NAME_NOT_FOUND, "a missing key below \\Registry: STATUS_OBJECT_NAME_NOT_FOUND");
    st = open_k(&h, 0, L"\\Foo\\Bar", KEY_READ);
    CHECK_ST(st, ST_PATH_NOT_FOUND, "\\Foo\\Bar: STATUS_OBJECT_PATH_NOT_FOUND");
    st = open_k(&h, 0, L"\\Foo", KEY_READ);
    CHECK_ST(st, ST_NAME_NOT_FOUND, "\\Foo: STATUS_OBJECT_NAME_NOT_FOUND");
    st = open_k(&h, 0, L"Registry\\Machine", KEY_READ);
    CHECK_ST(st, ST_PATH_SYNTAX_BAD, "a name without a root handle must start with a backslash: STATUS_OBJECT_PATH_SYNTAX_BAD");
    st = open_k(&h, base, L"\\Leading", KEY_READ);
    CHECK_ST(st, ST_PATH_SYNTAX_BAD, "a name relative to a key handle must not start with a backslash: STATUS_OBJECT_PATH_SYNTAX_BAD");
    st = open_k(&h, base, L"a\\\\b", KEY_READ);
    CHECK_ST(st, ST_NAME_INVALID, "an empty path component is STATUS_OBJECT_NAME_INVALID");
    st = open_k(&h, (HANDLE)0x7770, L"x", KEY_READ);
    CHECK_ST(st, ST_INVALID_HANDLE, "a bogus root handle is STATUS_INVALID_HANDLE");
    {
        HANDLE ev = CreateEventW(0, TRUE, FALSE, 0);
        st = open_k(&h, ev, L"x", KEY_READ);
        CHECK_ST(st, ST_TYPE_MISMATCH, "an event handle as root directory is STATUS_OBJECT_TYPE_MISMATCH");
        CloseHandle(ev);
    }
    /* relative create with a class, then open relative, then options */
    {
        SHZ_UNICODE_STRING cls;
        RtlInitUnicodeString(&cls, L"NativeClass");
        st = create_k(&sub, base, L"Rel\\Deep", KEY_ALL_ACCESS, &cls, 0, &disp);
        CHECK(st == 0 && disp == 1, "relative NtCreateKey creates two levels at once (disposition 1)");
    }
    st = create_k(&h, 0, L"", KEY_ALL_ACCESS, 0, 0, &disp);
    CHECK_ST(st, ST_PATH_SYNTAX_BAD, "an empty name without a root handle has no meaning");
    st = create_k(&h, base, L"", KEY_ALL_ACCESS, 0, 0, &disp);
    CHECK(st == 0 && disp == 2, "an empty relative name opens the root key itself (disposition 2)");
    if (h) { NtClose(h); h = 0; }
    st = create_k(&h, base, L"Sym", KEY_ALL_ACCESS, 0, 2 /* REG_OPTION_CREATE_LINK */, &disp);
    CHECK(st != 0, "symbolic-link creation is not supported and says so");
    st = create_k(&h, base, L"Bad", KEY_ALL_ACCESS, 0, 0x100, &disp);
    CHECK_ST(st, ST_INVALID_PARAMETER, "unknown create options: STATUS_INVALID_PARAMETER");
    {
        HANDLE ro = 0;
        st = open_k(&ro, 0, abs, KEY_READ);
        CHECK_ST(st, 0, "open with KEY_READ");
        if (ro) {
            st = create_k(&h, ro, L"Deny", KEY_ALL_ACCESS, 0, 0, &disp);
            CHECK_ST(st, ST_ACCESS_DENIED, "creating below a handle without KEY_CREATE_SUB_KEY: STATUS_ACCESS_DENIED");
            st = create_k(&h, ro, L"Rel", KEY_READ, 0, 0, &disp);
            CHECK(st == 0 && disp == 2, "opening an existing child through a read-only handle via NtCreateKey needs no create right");
            if (h) NtClose(h);
            NtClose(ro);
        }
    }
    {
        /* NtOpenKeyEx: valid options are 0, BACKUP_RESTORE (4), OPEN_LINK (8) */
        SHZ_OBJECT_ATTRIBUTES oa;
        SHZ_UNICODE_STRING us;
        h = 0;
        oa_init(&oa, &us, base, L"Rel");
        CHECK_ST(NtOpenKeyEx(&h, KEY_READ, &oa, 0), ST_SUCCESS, "NtOpenKeyEx with options 0");
        if (h) { NtClose(h); h = 0; }
        CHECK_ST(NtOpenKeyEx(&h, KEY_READ, &oa, 4), ST_SUCCESS, "NtOpenKeyEx with REG_OPTION_BACKUP_RESTORE");
        if (h) { NtClose(h); h = 0; }
        CHECK_ST(NtOpenKeyEx(&h, KEY_READ, &oa, 0x40), ST_INVALID_PARAMETER, "NtOpenKeyEx rejects unknown options");
    }
    if (sub) NtClose(sub);
    if (base) NtClose(base);
    shz_free(abs);
}

static void test_value_classes(void)
{
    HANDLE k = 0;
    SHZ_UNICODE_STRING vn;
    static const BYTE data[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    BYTE buf[128];
    ULONG res = 0, i;
    NTSTATUS st;
    WCHAR *abs = user_path(L"\\Software\\ShzNative\\Values");
    st = create_k(&k, 0, abs, KEY_ALL_ACCESS, 0, 0, 0);
    if (st) { CHECK(0, "create the values key"); shz_free(abs); return; }
    RtlInitUnicodeString(&vn, L"v");
    CHECK_ST(NtSetValueKey(k, &vn, 0, REG_BINARY, (PVOID)data, 10), ST_SUCCESS, "NtSetValueKey");

    memset(buf, 0xEE, sizeof buf);
    st = NtQueryValueKey(k, &vn, SHZ_KeyValuePartialInformation, buf, sizeof buf, &res);
    CHECK(st == 0 && res == 22, "partial information: ResultLength = 12 + 10");
    {
        SHZ_KEY_VALUE_PARTIAL_INFORMATION *p = (void *)buf;
        CHECK(p->Type == REG_BINARY && p->DataLength == 10 && !memcmp(p->Data, data, 10), "partial information: Type, DataLength and Data");
    }
    st = NtQueryValueKey(k, &vn, SHZ_KeyValueBasicInformation, buf, sizeof buf, &res);
    {
        SHZ_KEY_VALUE_BASIC_INFORMATION *b = (void *)buf;
        CHECK(st == 0 && res == 14 && b->Type == REG_BINARY && b->NameLength == 2 && b->Name[0] == L'v', "basic information: 12 fixed bytes + the 1-character name");
    }
    st = NtQueryValueKey(k, &vn, SHZ_KeyValueFullInformation, buf, sizeof buf, &res);
    {
        SHZ_KEY_VALUE_FULL_INFORMATION *f = (void *)buf;
        CHECK(st == 0 && f->Type == REG_BINARY && f->DataLength == 10 && f->NameLength == 2 && f->Name[0] == L'v', "full information: type, lengths, name");
        CHECK(f->DataOffset >= 22 && f->DataOffset % 4 == 0 && res == f->DataOffset + 10 && !memcmp(buf + f->DataOffset, data, 10),
              "full information: the data lies after the name at a 4-byte aligned DataOffset, ResultLength ends with it");
    }
    /* buffer protocol on the partial class (needs 22 bytes) */
    memset(buf, 0xEE, sizeof buf);
    st = NtQueryValueKey(k, &vn, SHZ_KeyValuePartialInformation, buf, 8, &res);
    CHECK(st == ST_BUFFER_TOO_SMALL && res == 22, "8 bytes: STATUS_BUFFER_TOO_SMALL with ResultLength 22");
    CHECK(buf[0] == 0xEE, "and nothing was written into the too small buffer");
    memset(buf, 0xEE, sizeof buf);
    st = NtQueryValueKey(k, &vn, SHZ_KeyValuePartialInformation, buf, 12, &res);
    CHECK(st == ST_BUFFER_OVERFLOW && res == 22, "12 bytes (header only): STATUS_BUFFER_OVERFLOW, ResultLength 22");
    CHECK(*(ULONG *)(buf + 4) == REG_BINARY && *(ULONG *)(buf + 8) == 10 && buf[12] == 0xEE, "the header (Type, DataLength) is valid, no data was copied");
    memset(buf, 0xEE, sizeof buf);
    st = NtQueryValueKey(k, &vn, SHZ_KeyValuePartialInformation, buf, 15, &res);
    CHECK(st == ST_BUFFER_OVERFLOW && buf[12] == 1 && buf[13] == 2 && buf[14] == 3 && buf[15] == 0xEE, "15 bytes: overflow, the 3 data bytes that fit are copied");
    st = NtQueryValueKey(k, &vn, SHZ_KeyValuePartialInformation, buf, 22, &res);
    CHECK(st == 0 && res == 22, "22 bytes: exactly enough");
    st = NtQueryValueKey(k, &vn, 9, buf, sizeof buf, &res);
    CHECK_ST(st, ST_INFO_CLASS, "unknown value information class: STATUS_INVALID_INFO_CLASS");
    RtlInitUnicodeString(&vn, L"missing");
    CHECK_ST(NtQueryValueKey(k, &vn, SHZ_KeyValuePartialInformation, buf, sizeof buf, &res), ST_NAME_NOT_FOUND, "missing value: STATUS_OBJECT_NAME_NOT_FOUND");
    CHECK_ST(NtDeleteValueKey(k, &vn), ST_NAME_NOT_FOUND, "deleting a missing value: STATUS_OBJECT_NAME_NOT_FOUND");

    /* enumeration: classes, positions, end */
    RtlInitUnicodeString(&vn, L"second");
    NtSetValueKey(k, &vn, 0, REG_DWORD, (PVOID)"\x2a\0\0\0", 4);
    for (i = 0; i < 3; ++i) {
        st = NtEnumerateValueKey(k, i, SHZ_KeyValueFullInformation, buf, sizeof buf, &res);
        if (i < 2) CHECK_ST(st, ST_SUCCESS, "NtEnumerateValueKey returns each of the two values");
        else CHECK_ST(st, ST_NO_MORE_ENTRIES, "index 2 of 2: STATUS_NO_MORE_ENTRIES");
    }
    st = NtEnumerateValueKey(k, 0, SHZ_KeyValueBasicInformation, buf, 4, &res);
    CHECK(st == ST_BUFFER_TOO_SMALL && res >= 14, "enumerate with a 4-byte buffer: STATUS_BUFFER_TOO_SMALL and the size needed");
    /* access checks on the value calls */
    {
        HANDLE w = 0, r = 0;
        SHZ_UNICODE_STRING nm;
        RtlInitUnicodeString(&nm, L"v");
        open_k(&w, 0, abs, KEY_SET_VALUE);
        open_k(&r, 0, abs, KEY_QUERY_VALUE);
        CHECK_ST(NtQueryValueKey(w, &nm, SHZ_KeyValuePartialInformation, buf, sizeof buf, &res), ST_ACCESS_DENIED, "NtQueryValueKey needs KEY_QUERY_VALUE");
        CHECK_ST(NtEnumerateValueKey(w, 0, SHZ_KeyValueBasicInformation, buf, sizeof buf, &res), ST_ACCESS_DENIED, "NtEnumerateValueKey needs KEY_QUERY_VALUE");
        CHECK_ST(NtSetValueKey(r, &nm, 0, REG_DWORD, buf, 4), ST_ACCESS_DENIED, "NtSetValueKey needs KEY_SET_VALUE");
        CHECK_ST(NtDeleteValueKey(r, &nm), ST_ACCESS_DENIED, "NtDeleteValueKey needs KEY_SET_VALUE");
        CHECK_ST(NtDeleteKey(r), ST_ACCESS_DENIED, "NtDeleteKey needs DELETE");
        if (w) NtClose(w);
        if (r) NtClose(r);
    }
    CHECK_ST(NtQueryValueKey((HANDLE)0x7770, &vn, SHZ_KeyValuePartialInformation, buf, sizeof buf, &res), ST_INVALID_HANDLE, "bogus handle: STATUS_INVALID_HANDLE");
    NtClose(k);
    shz_free(abs);
}

static void test_key_classes(void)
{
    HANDLE k = 0, c1 = 0, c2 = 0;
    SHZ_UNICODE_STRING cls, vn;
    BYTE buf[512];
    ULONG res = 0;
    NTSTATUS st;
    WCHAR *abs = user_path(L"\\Software\\ShzNative\\Keys");
    RtlInitUnicodeString(&cls, L"KeyClass");
    st = create_k(&k, 0, abs, KEY_ALL_ACCESS, &cls, 0, 0);
    if (st) { CHECK(0, "create the keys key"); shz_free(abs); return; }
    create_k(&c1, k, L"Child1", KEY_ALL_ACCESS, 0, 0, 0);
    create_k(&c2, k, L"ChildNumberTwo", KEY_ALL_ACCESS, &cls, 0, 0);
    RtlInitUnicodeString(&vn, L"abc");
    NtSetValueKey(k, &vn, 0, REG_SZ, (PVOID)L"xy", 6);
    RtlInitUnicodeString(&vn, L"abcdef");
    NtSetValueKey(k, &vn, 0, REG_BINARY, buf, 33);

    st = NtQueryKey(k, SHZ_KeyFullInformation, buf, sizeof buf, &res);
    {
        SHZ_KEY_FULL_INFORMATION *f = (void *)buf;
        CHECK(st == 0 && f->SubKeys == 2 && f->Values == 2, "KeyFullInformation: 2 sub-keys, 2 values");
        CHECK(f->MaxNameLen == 14 * 2 && f->MaxValueNameLen == 6 * 2 && f->MaxValueDataLen == 33, "Max name/value-name lengths are in bytes, MaxValueDataLen is 33");
        CHECK(f->MaxClassLen == 8 * 2 && f->ClassLength == 8 * 2 && f->ClassOffset == 44 && res == 44 + 16 && !memcmp((BYTE *)f + f->ClassOffset, L"KeyClass", 16),
              "the class string follows the fixed part (ClassOffset 44), MaxClassLen covers the longest sub-key class");
        CHECK(f->LastWriteTime != 0, "LastWriteTime is set");
    }
    st = NtQueryKey(k, SHZ_KeyFullInformation, buf, 44, &res);
    CHECK(st == ST_BUFFER_OVERFLOW && res == 60, "44 bytes (fixed part only): STATUS_BUFFER_OVERFLOW, ResultLength 60");
    st = NtQueryKey(k, SHZ_KeyFullInformation, buf, 20, &res);
    CHECK(st == ST_BUFFER_TOO_SMALL && res == 60, "20 bytes: STATUS_BUFFER_TOO_SMALL");
    st = NtQueryKey(k, SHZ_KeyBasicInformation, buf, sizeof buf, &res);
    {
        SHZ_KEY_BASIC_INFORMATION *b = (void *)buf;
        CHECK(st == 0 && b->NameLength == 4 * 2 && !memcmp(b->Name, L"Keys", 8) && res == 16 + 8, "KeyBasicInformation names the key itself (\"Keys\")");
    }
    st = NtQueryKey(k, SHZ_KeyNodeInformation, buf, sizeof buf, &res);
    {
        SHZ_KEY_NODE_INFORMATION *n = (void *)buf;
        CHECK(st == 0 && n->NameLength == 8 && n->ClassLength == 16 && n->ClassOffset >= 24 + 8 && !memcmp((BYTE *)n + n->ClassOffset, L"KeyClass", 16),
              "KeyNodeInformation carries name and class");
    }
    st = NtQueryKey(k, SHZ_KeyCachedInformation, buf, sizeof buf, &res);
    {
        ULONG *w = (ULONG *)buf;
        CHECK(st == 0 && res == 36 && w[3] == 2 && w[5] == 2 && w[6] == 12 && w[7] == 33 && w[8] == 8, "KeyCachedInformation: 36 bytes, counts and maxima");
    }
    st = NtQueryKey(k, SHZ_KeyNameInformation, buf, sizeof buf, &res);
    {
        SHZ_KEY_NAME_INFORMATION *n = (void *)buf;
        const size_t want = wl(abs);
        CHECK(st == 0 && n->NameLength == want * 2 && res == 4 + want * 2 && weq_ci_n(n->Name, abs, want), "KeyNameInformation is the full \\Registry\\User\\<SID>\\... path");
    }
    st = NtQueryKey(k, SHZ_KeyNameInformation, buf, 4 + 10, &res);
    CHECK(st == ST_BUFFER_OVERFLOW && res > 14, "a name buffer that is too short: STATUS_BUFFER_OVERFLOW");
    CHECK_ST(NtQueryKey(k, 100, buf, sizeof buf, &res), ST_INFO_CLASS, "unknown key information class: STATUS_INVALID_INFO_CLASS");

    /* NtEnumerateKey: name order is by upcased name: Child1 < ChildNumberTwo */
    st = NtEnumerateKey(k, 0, SHZ_KeyBasicInformation, buf, sizeof buf, &res);
    {
        SHZ_KEY_BASIC_INFORMATION *b = (void *)buf;
        CHECK(st == 0 && b->NameLength == 12 && !memcmp(b->Name, L"Child1", 12), "NtEnumerateKey index 0 is \"Child1\"");
    }
    st = NtEnumerateKey(k, 1, SHZ_KeyNodeInformation, buf, sizeof buf, &res);
    {
        SHZ_KEY_NODE_INFORMATION *n = (void *)buf;
        CHECK(st == 0 && n->NameLength == 28 && !memcmp(n->Name, L"ChildNumberTwo", 28) && n->ClassLength == 16 &&
              !memcmp((BYTE *)n + n->ClassOffset, L"KeyClass", 16), "index 1 is \"ChildNumberTwo\" with its class");
    }
    CHECK_ST(NtEnumerateKey(k, 2, SHZ_KeyBasicInformation, buf, sizeof buf, &res), ST_NO_MORE_ENTRIES, "index 2 of 2: STATUS_NO_MORE_ENTRIES");
    CHECK_ST(NtEnumerateKey(k, 0, SHZ_KeyFullInformation, buf, sizeof buf, &res), ST_INFO_CLASS, "KeyFullInformation is not an enumeration class");
    st = NtEnumerateKey(k, 0, SHZ_KeyBasicInformation, buf, 10, &res);
    CHECK(st == ST_BUFFER_TOO_SMALL && res == 16 + 12, "enumerate with 10 bytes: STATUS_BUFFER_TOO_SMALL and the full size");
    st = NtEnumerateKey(k, 0, SHZ_KeyBasicInformation, buf, 16 + 4, &res);
    CHECK(st == ST_BUFFER_OVERFLOW && *(ULONG *)(buf + 12) == 12 && !memcmp(buf + 16, L"Ch", 4), "enumerate with room for 2 characters: overflow, NameLength is the full 12, 2 characters copied");

    /* delete semantics at the native level */
    CHECK_ST(NtDeleteKey(k), ST_CANNOT_DELETE, "NtDeleteKey of a key with sub-keys: STATUS_CANNOT_DELETE");
    CHECK_ST(NtDeleteKey(c1), ST_SUCCESS, "NtDeleteKey of a leaf");
    CHECK_ST(NtDeleteKey(c1), ST_KEY_DELETED, "deleting it again through the same handle: STATUS_KEY_DELETED");
    st = NtQueryKey(c1, SHZ_KeyBasicInformation, buf, sizeof buf, &res);
    CHECK_ST(st, ST_KEY_DELETED, "NtQueryKey on a deleted key: STATUS_KEY_DELETED");
    st = NtQueryKey(c1, SHZ_KeyNameInformation, buf, sizeof buf, &res);
    CHECK_ST(st, ST_KEY_DELETED, "even the name query: STATUS_KEY_DELETED");
    CHECK_ST(NtFlushKey(c1), ST_SUCCESS, "NtFlushKey only validates the handle (the registry lives in memory)");
    CHECK_ST(NtFlushKey((HANDLE)0x7770), ST_INVALID_HANDLE, "NtFlushKey of a bogus handle: STATUS_INVALID_HANDLE");
    {
        HANDLE ev = CreateEventW(0, TRUE, FALSE, 0);
        CHECK_ST(NtFlushKey(ev), ST_TYPE_MISMATCH, "NtFlushKey of an event handle: STATUS_OBJECT_TYPE_MISMATCH");
        CloseHandle(ev);
    }
    NtClose(c1);
    CHECK_ST(NtClose(c1), ST_INVALID_HANDLE, "NtClose of a closed handle: STATUS_INVALID_HANDLE");
    CHECK_ST(NtDeleteKey(c2), ST_SUCCESS, "delete the second child");
    NtClose(c2);
    CHECK_ST(NtDeleteKey(k), ST_SUCCESS, "now the parent has no sub-keys and can be deleted");
    NtClose(k);
    shz_free(abs);
}

static void test_object_queries(void)
{
    HANDLE k = 0, ev;
    BYTE buf[256];
    ULONG res = 0;
    NTSTATUS st;
    WCHAR *abs = user_path(L"\\Software\\ShzNative\\Obj");
    create_k(&k, 0, abs, KEY_ALL_ACCESS, 0, 0, 0);
    if (!k) { CHECK(0, "create the object-query key"); shz_free(abs); return; }
    st = NtQueryObject(k, SHZ_ObjectBasicInformation, buf, sizeof buf, &res);
    CHECK(st == 0 && res == 0x38 && *(ULONG *)(buf + 4) == 0xF003F, "ObjectBasicInformation: 0x38 bytes, GrantedAccess of a KEY_ALL_ACCESS handle is 0xF003F");
    CHECK(*(ULONG *)(buf + 8) >= 1 && *(ULONG *)(buf + 12) >= 1, "HandleCount and PointerCount are at least 1");
    st = NtQueryObject(k, SHZ_ObjectBasicInformation, buf, 0x20, &res);
    CHECK(st == ST_LENGTH_MISMATCH && res == 0x38, "a short buffer: STATUS_INFO_LENGTH_MISMATCH with the size needed");
    st = NtQueryObject(k, SHZ_ObjectNameInformation, buf, sizeof buf, &res);
    {
        SHZ_UNICODE_STRING *u = (void *)buf;
        const size_t want = wl(abs);
        CHECK(st == 0 && u->Length == want * 2 && u->Buffer == (WCHAR *)(buf + 16) && weq_ci_n(u->Buffer, abs, want) && u->Buffer[want] == 0,
              "ObjectNameInformation of a key is its NUL-terminated path, the string lives in the caller's buffer");
        CHECK(res == 16 + want * 2 + 2, "ResultLength = UNICODE_STRING + characters + NUL");
    }
    st = NtQueryObject(k, SHZ_ObjectNameInformation, buf, 16 + 8, &res);
    CHECK(st == ST_LENGTH_MISMATCH && res > 24, "a too short name buffer: STATUS_INFO_LENGTH_MISMATCH and the size needed");
    st = NtQueryObject(k, SHZ_ObjectTypeInformation, buf, sizeof buf, &res);
    {
        SHZ_UNICODE_STRING *u = (void *)buf;
        CHECK(st == 0 && u->Length == 6 && !memcmp(u->Buffer, L"Key", 6), "ObjectTypeInformation names the type \"Key\"");
    }
    ev = CreateEventW(0, TRUE, FALSE, 0);
    st = NtQueryObject(ev, SHZ_ObjectTypeInformation, buf, sizeof buf, &res);
    {
        SHZ_UNICODE_STRING *u = (void *)buf;
        CHECK(st == 0 && u->Length == 10 && !memcmp(u->Buffer, L"Event", 10), "an event handle reports the type \"Event\"");
    }
    st = NtQueryObject(ev, SHZ_ObjectNameInformation, buf, sizeof buf, &res);
    CHECK(st == 0 && ((SHZ_UNICODE_STRING *)buf)->Length == 0, "an unnamed event has an empty name");
    CloseHandle(ev);
    CHECK_ST(NtQueryObject((HANDLE)0x7770, SHZ_ObjectBasicInformation, buf, sizeof buf, &res), ST_INVALID_HANDLE, "NtQueryObject of a bogus handle: STATUS_INVALID_HANDLE");
    CHECK_ST(NtQueryObject(k, 77, buf, sizeof buf, &res), ST_INFO_CLASS, "unknown object information class: STATUS_INVALID_INFO_CLASS");
    {   /* granted access reflects generic mapping */
        HANDLE g = 0;
        open_k(&g, 0, abs, GENERIC_READ);
        st = NtQueryObject(g, SHZ_ObjectBasicInformation, buf, sizeof buf, &res);
        CHECK(st == 0 && *(ULONG *)(buf + 4) == 0x20019, "GENERIC_READ is mapped to KEY_READ (0x20019)");
        if (g) NtClose(g);
        g = 0;
        open_k(&g, 0, abs, MAXIMUM_ALLOWED);
        st = NtQueryObject(g, SHZ_ObjectBasicInformation, buf, sizeof buf, &res);
        CHECK(st == 0 && *(ULONG *)(buf + 4) == 0xF003F, "MAXIMUM_ALLOWED grants KEY_ALL_ACCESS");
        if (g) NtClose(g);
    }
    NtDeleteKey(k);
    NtClose(k);
    shz_free(abs);
}

static void test_handle_table(void)
{
    enum { HANDLE_POLICY = 4096, HANDLE_PROBE = HANDLE_POLICY + 64 };
    static HANDLE hs[HANDLE_PROBE];
    ULONG n = 0, i, dup = 0;
    NTSTATUS st = 0;
    WCHAR *abs = user_path(L"\\Software\\ShzNative");
    for (i = 0; i < HANDLE_PROBE; ++i) {
        st = open_k(&hs[i], 0, abs, KEY_READ);
        if (st) break;
        ++n;
    }
    CHECK(n >= HANDLE_POLICY - 96 && n <= HANDLE_POLICY && st == ST_NO_MEMORY,
          "the real per-process handle table fills up with STATUS_NO_MEMORY near the 4096-handle policy");
    for (i = 0; i < n; ++i) { ULONG j; for (j = i + 1; j < n; ++j) if (hs[i] == hs[j]) ++dup; }
    CHECK(dup == 0, "all handle values are distinct");
    for (i = 0; i < n; ++i) if (NtClose(hs[i])) ++dup;
    CHECK(dup == 0, "all of them close");
    st = open_k(&hs[0], 0, abs, KEY_READ);
    CHECK_ST(st, ST_SUCCESS, "after closing them slots are available again");
    if (!st) NtClose(hs[0]);
    shz_free(abs);
}

/* Leaves open handles behind on purpose: keys that were deleted while handles stay open, each with a 6,000 byte class, so a
 * leak at process exit would eat most of the registry's 1 MiB budget. t_reg_stress starts by checking that the budget is free. */
static void leave_handles_open(void)
{
    ULONG i, made = 0;
    static WCHAR cls[3001];
    SHZ_UNICODE_STRING cu;
    HANDLE base = 0, h;
    WCHAR *abs = user_path(L"\\Software\\ShzNative\\Leftover");
    NTSTATUS st = create_k(&base, 0, abs, KEY_ALL_ACCESS, 0, 0, 0);
    for (i = 0; i < 3000; ++i) cls[i] = L'C';
    cls[3000] = 0;
    RtlInitUnicodeString(&cu, cls);
    for (i = 0; st == 0 && i < 150; ++i) {
        WCHAR nm[8];
        nm[0] = L'L'; nm[1] = (WCHAR)(L'0' + i / 100); nm[2] = (WCHAR)(L'0' + i / 10 % 10); nm[3] = (WCHAR)(L'0' + i % 10); nm[4] = 0;
        h = 0;
        if (create_k(&h, base, nm, KEY_ALL_ACCESS, &cu, 0, 0)) break;
        if (NtDeleteKey(h)) { NtClose(h); break; }               /* deleted, but the handle keeps the node (and its class) alive */
        ++made;
    }
    CHECK(made == 150, "150 deleted-but-open keys with 6,000-byte classes are held (about 900 KB) and left open at exit");
    if (base) NtClose(base);
    shz_free(abs);
}

int main(void)
{
    printf("t_reg_native: native registry system calls\n");
    test_paths_and_status();
    test_value_classes();
    test_key_classes();
    test_object_queries();
    test_handle_table();
    leave_handles_open();
    delete_tree(HKEY_CURRENT_USER, L"Software\\ShzNative");
    return finish_tests("t_reg_native");
}
