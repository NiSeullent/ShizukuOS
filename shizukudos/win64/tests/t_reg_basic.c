/* SPDX-License-Identifier: GPL-2.0-only
 * Registry self-check, part 1: Win32 registry API semantics over the Kernel64 registry (create/open/set/query/enum/delete,
 * type round-trips, ERROR_MORE_DATA sizing, case-insensitivity, nested keys, handle close semantics, access rights,
 * RegGetValue, ANSI entry points, predefined keys and the default tree, limits and resource reclamation).
 */
#include "reg_check.h"

#define ROOT L"Software\\ShzRegTest\\Basic"

NTSTATUS NTAPI RtlGetVersion(OSVERSIONINFOW *);

static HKEY create_key(HKEY parent, const WCHAR *sub, REGSAM sam, DWORD *disp)
{
    HKEY k = 0;
    LONG e = RegCreateKeyExW(parent, sub, 0, 0, 0, sam, 0, &k, disp);
    if (e) { printf("FAIL: RegCreateKeyExW failed with %d\n", (int)e); ++g_fail; return 0; }
    return k;
}

static LONG set_dword(HKEY k, const WCHAR *name, DWORD v) { return RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE *)&v, 4); }

static void test_create_open(void)
{
    HKEY k;
    DWORD d = 0;
    LONG e;
    delete_tree(HKEY_CURRENT_USER, L"Software\\ShzRegTest");             /* leftovers of an earlier run are not an error */
    e = RegOpenKeyExW(HKEY_CURRENT_USER, ROOT, 0, KEY_READ, &k);
    CHECK_ERR(e, ERROR_FILE_NOT_FOUND, "open of a missing key returns ERROR_FILE_NOT_FOUND");
    k = create_key(HKEY_CURRENT_USER, ROOT, KEY_ALL_ACCESS, &d);
    CHECK(k != 0, "RegCreateKeyExW creates the multi-level test key");
    CHECK(d == REG_CREATED_NEW_KEY, "first create reports REG_CREATED_NEW_KEY");
    RegCloseKey(k);
    k = create_key(HKEY_CURRENT_USER, ROOT, KEY_ALL_ACCESS, &d);
    CHECK(d == REG_OPENED_EXISTING_KEY, "second create reports REG_OPENED_EXISTING_KEY");
    RegCloseKey(k);
    e = RegOpenKeyExW(HKEY_CURRENT_USER, ROOT, 0, KEY_READ, &k);
    CHECK_ERR(e, ERROR_SUCCESS, "open of the created key succeeds");
    RegCloseKey(k);
    e = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\ShzRegTest\\Basic\\Nope\\Deeper", 0, KEY_READ, &k);
    CHECK_ERR(e, ERROR_FILE_NOT_FOUND, "open of a missing deep path returns ERROR_FILE_NOT_FOUND");
    e = RegOpenKeyExW(HKEY_CURRENT_USER, L"\\Software", 0, KEY_READ, &k);
    CHECK_ERR(e, ERROR_BAD_PATHNAME, "a sub-key name starting with a backslash is ERROR_BAD_PATHNAME");
}

static const WCHAR SZ_TEXT[] = L"Hello, Shizuku";
static const WCHAR EXP_TEXT[] = L"%SystemRoot%\\SYS64";
static const WCHAR MULTI_TEXT[] = L"one\0two\0three\0";                    /* the compiler adds the second terminator */

static void test_types(void)
{
    HKEY k = create_key(HKEY_CURRENT_USER, ROOT, KEY_ALL_ACCESS, 0);
    BYTE bin[256], back[512];
    DWORD type, cb, i;
    DWORD dw = 0xDEADBEEF;
    ULONGLONG qw = 0x0123456789ABCDEFull;
    static const BYTE none[5] = { 9, 8, 7, 6, 5 };
    LONG e;
    for (i = 0; i < 256; ++i) bin[i] = (BYTE)i;
    if (!k) return;
    CHECK_ERR(RegSetValueExW(k, L"sz", 0, REG_SZ, (const BYTE *)SZ_TEXT, sizeof SZ_TEXT), 0, "set REG_SZ");
    CHECK_ERR(RegSetValueExW(k, L"expand", 0, REG_EXPAND_SZ, (const BYTE *)EXP_TEXT, sizeof EXP_TEXT), 0, "set REG_EXPAND_SZ");
    CHECK_ERR(RegSetValueExW(k, L"bin", 0, REG_BINARY, bin, sizeof bin), 0, "set REG_BINARY 256 bytes");
    CHECK_ERR(RegSetValueExW(k, L"empty_bin", 0, REG_BINARY, 0, 0), 0, "set zero-length REG_BINARY");
    CHECK_ERR(RegSetValueExW(k, L"dw", 0, REG_DWORD, (const BYTE *)&dw, 4), 0, "set REG_DWORD");
    CHECK_ERR(RegSetValueExW(k, L"qw", 0, REG_QWORD, (const BYTE *)&qw, 8), 0, "set REG_QWORD");
    CHECK_ERR(RegSetValueExW(k, L"multi", 0, REG_MULTI_SZ, (const BYTE *)MULTI_TEXT, sizeof MULTI_TEXT), 0, "set REG_MULTI_SZ");
    CHECK_ERR(RegSetValueExW(k, L"none", 0, REG_NONE, none, sizeof none), 0, "set REG_NONE with data");

    type = 0; cb = sizeof back;
    e = RegQueryValueExW(k, L"sz", 0, &type, back, &cb);
    CHECK(e == 0 && type == REG_SZ && cb == sizeof SZ_TEXT && !memcmp(back, SZ_TEXT, cb), "REG_SZ round trip (type, size incl. NUL, bytes)");
    type = 0; cb = sizeof back;
    e = RegQueryValueExW(k, L"expand", 0, &type, back, &cb);
    CHECK(e == 0 && type == REG_EXPAND_SZ && cb == sizeof EXP_TEXT && !memcmp(back, EXP_TEXT, cb),
          "REG_EXPAND_SZ round trip is not expanded by RegQueryValueEx");
    type = 0; cb = sizeof back; memset(back, 0, sizeof back);
    e = RegQueryValueExW(k, L"bin", 0, &type, back, &cb);
    CHECK(e == 0 && type == REG_BINARY && cb == 256 && !memcmp(back, bin, 256), "REG_BINARY 256-byte round trip");
    type = 99; cb = sizeof back;
    e = RegQueryValueExW(k, L"empty_bin", 0, &type, back, &cb);
    CHECK(e == 0 && type == REG_BINARY && cb == 0, "zero-length REG_BINARY reads back as size 0");
    type = 0; cb = 4; dw = 0;
    e = RegQueryValueExW(k, L"dw", 0, &type, (BYTE *)&dw, &cb);
    CHECK(e == 0 && type == REG_DWORD && cb == 4 && dw == 0xDEADBEEF, "REG_DWORD 0xDEADBEEF round trip");
    type = 0; cb = 8; qw = 0;
    e = RegQueryValueExW(k, L"qw", 0, &type, (BYTE *)&qw, &cb);
    CHECK(e == 0 && type == REG_QWORD && cb == 8 && qw == 0x0123456789ABCDEFull, "REG_QWORD 0x0123456789ABCDEF round trip");
    type = 0; cb = sizeof back;
    e = RegQueryValueExW(k, L"multi", 0, &type, back, &cb);
    CHECK(e == 0 && type == REG_MULTI_SZ && cb == sizeof MULTI_TEXT && !memcmp(back, MULTI_TEXT, cb), "REG_MULTI_SZ round trip (30 bytes)");
    type = 0; cb = sizeof back;
    e = RegQueryValueExW(k, L"none", 0, &type, back, &cb);
    CHECK(e == 0 && type == REG_NONE && cb == 5 && !memcmp(back, none, 5), "REG_NONE carries its data");
    e = RegQueryValueExW(k, L"absent", 0, &type, back, &cb);
    CHECK_ERR(e, ERROR_FILE_NOT_FOUND, "query of a missing value returns ERROR_FILE_NOT_FOUND");

    /* ERROR_MORE_DATA sizing */
    memset(back, 0xAA, sizeof back);
    cb = 10; type = 0;
    e = RegQueryValueExW(k, L"sz", 0, &type, back, &cb);
    CHECK_ERR(e, ERROR_MORE_DATA, "a too small buffer returns ERROR_MORE_DATA");
    CHECK(cb == sizeof SZ_TEXT, "ERROR_MORE_DATA reports the full size in *lpcbData");
    cb = 0; type = 0;
    e = RegQueryValueExW(k, L"sz", 0, &type, 0, &cb);
    CHECK(e == 0 && cb == sizeof SZ_TEXT && type == REG_SZ, "lpData == NULL returns the size and the type");
    cb = 0;
    e = RegQueryValueExW(k, L"sz", 0, 0, back, &cb);
    CHECK_ERR(e, ERROR_MORE_DATA, "zero-sized buffer with data present returns ERROR_MORE_DATA");
    memset(back, 0xAA, sizeof back);
    cb = 200;
    e = RegQueryValueExW(k, L"sz", 0, &type, back, &cb);
    CHECK(e == 0 && cb == sizeof SZ_TEXT && back[cb] == 0xAA && back[199] == 0xAA, "a bigger buffer gets the exact size and nothing beyond it is written");
    cb = sizeof SZ_TEXT;
    e = RegQueryValueExW(k, L"sz", 0, &type, back, &cb);
    CHECK_ERR(e, ERROR_SUCCESS, "a buffer of exactly the needed size succeeds");
    cb = 0;
    e = RegQueryValueExW(k, L"empty_bin", 0, &type, 0, &cb);
    CHECK(e == 0 && cb == 0, "size query of an empty value succeeds with 0");
    cb = 100;
    e = RegQueryValueExW(k, L"sz", (LPDWORD)&cb, &type, back, &cb);
    CHECK_ERR(e, ERROR_INVALID_PARAMETER, "a non-NULL lpReserved is ERROR_INVALID_PARAMETER");
    RegCloseKey(k);
}

static void test_case_and_default(void)
{
    HKEY k = create_key(HKEY_CURRENT_USER, ROOT L"\\Case", KEY_ALL_ACCESS, 0), k2;
    DWORD v = 0, cb, type, n1 = 0, n2 = 0, d = 0;
    BYTE buf[64];
    LONG e;
    static const WCHAR dflt[] = L"the default";
    if (!k) return;
    CHECK_ERR(set_dword(k, L"MixedCase", 1), 0, "set MixedCase");
    cb = 4;
    e = RegQueryValueExW(k, L"MIXEDCASE", 0, &type, (BYTE *)&v, &cb);
    CHECK(e == 0 && v == 1, "value names are case-insensitive (upper case lookup)");
    e = RegQueryValueExW(k, L"mixedcase", 0, &type, (BYTE *)&v, &cb);
    CHECK(e == 0 && v == 1, "value names are case-insensitive (lower case lookup)");
    RegQueryInfoKeyW(k, 0, 0, 0, 0, 0, 0, &n1, 0, 0, 0, 0);
    CHECK_ERR(set_dword(k, L"MIXEDCASE", 2), 0, "set MIXEDCASE overwrites");
    RegQueryInfoKeyW(k, 0, 0, 0, 0, 0, 0, &n2, 0, 0, 0, 0);
    CHECK(n1 == 1 && n2 == 1, "a differently-cased name does not create a second value");
    cb = 4;
    RegQueryValueExW(k, L"MixedCase", 0, &type, (BYTE *)&v, &cb);
    CHECK(v == 2, "the overwrite is visible under the original spelling");
    CHECK_ERR(RegDeleteValueW(k, L"mixedCASE"), 0, "delete by a differently-cased name");
    cb = 4;
    CHECK_ERR(RegQueryValueExW(k, L"MixedCase", 0, &type, (BYTE *)&v, &cb), ERROR_FILE_NOT_FOUND, "the value is gone after the case-insensitive delete");

    /* keys */
    k2 = create_key(k, L"CaseKey", KEY_ALL_ACCESS, &d);
    CHECK(k2 && d == REG_CREATED_NEW_KEY, "create CaseKey");
    if (k2) RegCloseKey(k2);
    k2 = create_key(k, L"CASEKEY", KEY_ALL_ACCESS, &d);
    CHECK(k2 && d == REG_OPENED_EXISTING_KEY, "key names are case-insensitive: CASEKEY opens CaseKey");
    if (k2) RegCloseKey(k2);
    CHECK_ERR(RegOpenKeyExW(HKEY_CURRENT_USER, L"software\\SHZREGTEST\\basic\\case\\casekey", 0, KEY_READ, &k2), 0, "a whole path opens with different casing");
    RegCloseKey(k2);
    RegQueryInfoKeyW(k, 0, 0, 0, &n1, 0, 0, 0, 0, 0, 0, 0);
    CHECK(n1 == 1, "still exactly one sub-key after creating it under two spellings");

    /* the default (unnamed) value */
    CHECK_ERR(RegQueryValueExW(k, NULL, 0, &type, buf, &(DWORD){ sizeof buf }), ERROR_FILE_NOT_FOUND, "no default value at first");
    CHECK_ERR(RegSetValueExW(k, NULL, 0, REG_SZ, (const BYTE *)dflt, sizeof dflt), 0, "set the default value with a NULL name");
    cb = sizeof buf;
    e = RegQueryValueExW(k, L"", 0, &type, buf, &cb);
    CHECK(e == 0 && type == REG_SZ && cb == sizeof dflt && !memcmp(buf, dflt, cb), "the empty name reads the default value");
    cb = sizeof buf;
    e = RegQueryValueExW(k, NULL, 0, &type, buf, &cb);
    CHECK(e == 0 && cb == sizeof dflt, "a NULL name reads the default value");
    {
        WCHAR name[8];
        DWORD nn = 8, t2 = 0, dc = sizeof buf;
        e = RegEnumValueW(k, 0, name, &nn, 0, &t2, buf, &dc);
        CHECK(e == 0 && nn == 0 && name[0] == 0 && t2 == REG_SZ, "the default value enumerates with an empty name");
    }
    CHECK_ERR(RegDeleteValueW(k, NULL), 0, "delete the default value with a NULL name");
    cb = sizeof buf;
    CHECK_ERR(RegQueryValueExW(k, NULL, 0, &type, buf, &cb), ERROR_FILE_NOT_FOUND, "the default value is gone");
    RegCloseKey(k);
}

static void test_nested_and_delete(void)
{
    HKEY k, a, d = 0;
    DWORD disp = 0, subs = 0, maxsub = 0;
    LONG e;
    k = create_key(HKEY_CURRENT_USER, ROOT L"\\Nest", KEY_ALL_ACCESS, 0);
    if (!k) return;
    a = create_key(k, L"A\\B\\C\\D", KEY_ALL_ACCESS, &disp);
    CHECK(a && disp == REG_CREATED_NEW_KEY, "one call creates four nested levels");
    if (a) RegCloseKey(a);
    CHECK_ERR(RegOpenKeyExW(k, L"A", 0, KEY_READ, &a), 0, "intermediate key A exists");
    CHECK_ERR(RegOpenKeyExW(a, L"B\\C\\D", 0, KEY_READ, &d), 0, "a relative multi-level path opens from A");
    RegCloseKey(d);
    e = RegQueryInfoKeyW(a, 0, 0, 0, &subs, &maxsub, 0, 0, 0, 0, 0, 0);
    CHECK(e == 0 && subs == 1 && maxsub == 1, "A has one sub-key with a name of length 1");
    RegCloseKey(a);
    e = RegDeleteKeyW(k, L"A\\B");
    CHECK_ERR(e, ERROR_ACCESS_DENIED, "deleting a key that still has sub-keys is ERROR_ACCESS_DENIED");
    CHECK_ERR(RegDeleteKeyW(k, L"A\\B\\C\\D"), 0, "delete the leaf D");
    CHECK_ERR(RegOpenKeyExW(k, L"A\\B\\C\\D", 0, KEY_READ, &d), ERROR_FILE_NOT_FOUND, "D is gone");
    CHECK_ERR(RegDeleteKeyW(k, L"A\\B\\C\\D"), ERROR_FILE_NOT_FOUND, "deleting it again is ERROR_FILE_NOT_FOUND");
    CHECK_ERR(RegDeleteKeyW(k, L"A\\B\\C"), 0, "delete C (now a leaf)");
    CHECK_ERR(RegDeleteKeyW(k, L"A\\B"), 0, "delete B");
    CHECK_ERR(RegDeleteKeyW(k, L"A"), 0, "delete A");
    RegQueryInfoKeyW(k, 0, 0, 0, &subs, 0, 0, 0, 0, 0, 0, 0);
    CHECK(subs == 0, "the parent has no sub-keys left");
    RegCloseKey(k);
    CHECK_ERR(RegDeleteKeyW(HKEY_CURRENT_USER, NULL), ERROR_INVALID_PARAMETER, "RegDeleteKeyW with a NULL sub-key is ERROR_INVALID_PARAMETER");
}

static void test_handles(void)
{
    HKEY p = create_key(HKEY_CURRENT_USER, ROOT L"\\Handles", KEY_ALL_ACCESS, 0), a, b, c, d;
    DWORD v = 0, cb, disp = 0;
    HANDLE dup = 0;
    LONG e;
    if (!p) return;
    CHECK_ERR(RegOpenKeyExW(p, NULL, 0, KEY_ALL_ACCESS, &a), 0, "a NULL sub-key opens a new handle to the same key");
    CHECK(a != 0 && a != p, "the new handle is a distinct handle value");
    CHECK_ERR(set_dword(a, L"shared", 77), 0, "write through the second handle");
    cb = 4;
    e = RegQueryValueExW(p, L"shared", 0, 0, (BYTE *)&v, &cb);
    CHECK(e == 0 && v == 77, "the first handle sees the value (both refer to one key)");
    CHECK_ERR(RegCloseKey(a), 0, "close the second handle");
    cb = 4; v = 0;
    e = RegQueryValueExW(p, L"shared", 0, 0, (BYTE *)&v, &cb);
    CHECK(e == 0 && v == 77, "the key stays usable through the remaining handle");
    CHECK_ERR(RegCloseKey(a), ERROR_INVALID_HANDLE, "closing the same handle twice is ERROR_INVALID_HANDLE");
    cb = 4;
    CHECK_ERR(RegQueryValueExW(a, L"shared", 0, 0, (BYTE *)&v, &cb), ERROR_INVALID_HANDLE, "a closed handle is invalid for queries");
    CHECK_ERR(RegCloseKey(NULL), ERROR_INVALID_HANDLE, "RegCloseKey(NULL) is ERROR_INVALID_HANDLE");
    CHECK_ERR(RegCloseKey(HKEY_LOCAL_MACHINE), 0, "closing a predefined key succeeds and does nothing");
    cb = 4;
    e = RegQueryValueExW(p, L"shared", 0, 0, (BYTE *)&v, &cb);
    CHECK(e == 0, "the predefined-key close did not disturb other handles");

    /* the key outlives its handles; the parent handle can be closed before a child handle */
    b = create_key(p, L"Child", KEY_ALL_ACCESS, 0);
    set_dword(b, L"n", 5);
    RegCloseKey(p);
    cb = 4; v = 0;
    e = RegQueryValueExW(b, L"n", 0, 0, (BYTE *)&v, &cb);
    CHECK(e == 0 && v == 5, "a child handle keeps working after its parent handle is closed");
    RegCloseKey(b);
    CHECK_ERR(RegOpenKeyExW(HKEY_CURRENT_USER, ROOT L"\\Handles\\Child", 0, KEY_READ, &b), 0, "the key persists after every handle to it was closed");
    cb = 4; v = 0;
    RegQueryValueExW(b, L"n", 0, 0, (BYTE *)&v, &cb);
    CHECK(v == 5, "its value persists too");

    /* DuplicateHandle keeps the rights (DUPLICATE_SAME_ACCESS) and the key */
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)b, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS), "DuplicateHandle of a key handle");
    RegCloseKey(b);
    cb = 4; v = 0;
    e = RegQueryValueExW((HKEY)dup, L"n", 0, 0, (BYTE *)&v, &cb);
    CHECK(e == 0 && v == 5, "the duplicated key handle still works after the original is closed");
    RegCloseKey((HKEY)dup);

    /* deleted key with an open handle: ERROR_KEY_DELETED, the name can be reused for a new, empty key */
    p = create_key(HKEY_CURRENT_USER, ROOT L"\\Handles", KEY_ALL_ACCESS, 0);
    c = create_key(p, L"Del", KEY_ALL_ACCESS, 0);
    set_dword(c, L"old", 1);
    d = create_key(p, L"Del", KEY_ALL_ACCESS, &disp);
    CHECK(disp == REG_OPENED_EXISTING_KEY, "second handle to Del");
    CHECK_ERR(RegDeleteKeyW(p, L"Del"), 0, "delete Del while two handles are open");
    cb = 4;
    CHECK_ERR(RegQueryValueExW(c, L"old", 0, 0, (BYTE *)&v, &cb), ERROR_KEY_DELETED, "query through a handle to a deleted key is ERROR_KEY_DELETED");
    CHECK_ERR(set_dword(d, L"new", 2), ERROR_KEY_DELETED, "set through a handle to a deleted key is ERROR_KEY_DELETED");
    {
        WCHAR nm[16];
        DWORD nn = 16;
        CHECK_ERR(RegEnumKeyExW(c, 0, nm, &nn, 0, 0, 0, 0), ERROR_KEY_DELETED, "enumerate through a handle to a deleted key is ERROR_KEY_DELETED");
    }
    CHECK_ERR(RegOpenKeyExW(p, L"Del", 0, KEY_READ, &a), ERROR_FILE_NOT_FOUND, "the deleted key cannot be opened");
    a = create_key(p, L"Del", KEY_ALL_ACCESS, &disp);
    CHECK(a && disp == REG_CREATED_NEW_KEY, "the name can be created again as a new key");
    cb = 4;
    CHECK_ERR(RegQueryValueExW(a, L"old", 0, 0, (BYTE *)&v, &cb), ERROR_FILE_NOT_FOUND, "the new key does not inherit the deleted key's values");
    cb = 4;
    CHECK_ERR(RegQueryValueExW(c, L"old", 0, 0, (BYTE *)&v, &cb), ERROR_KEY_DELETED, "the old handle stays deleted even though the name exists again");
    CHECK_ERR(RegCloseKey(c), 0, "closing a handle to a deleted key succeeds");
    CHECK_ERR(RegCloseKey(d), 0, "closing the other one too");
    RegCloseKey(a);
    RegCloseKey(p);
}

static void test_enumeration(void)
{
    HKEY k = create_key(HKEY_CURRENT_USER, ROOT L"\\Enum", KEY_ALL_ACCESS, 0), s;
    static const WCHAR *const names[10] = { L"E9", L"E8", L"E7", L"E6", L"E5", L"E4", L"E3", L"E2", L"E1", L"E0" };
    static const WCHAR *const vnames[5] = { L"v_dword", L"v_sz_longer_name", L"v_bin", L"v_q", L"v" };
    WCHAR name[64];
    DWORD i, j, n, seen[10] = { 0 }, cls, subs = 0, maxsub = 0, vals = 0, maxvn = 0, maxvd = 0, type, cb;
    DWORD dwv = 0x11223344;
    ULONGLONG q = 0xFFEEDDCCBBAA9988ull;
    FILETIME ft = { 0, 0 };
    BYTE data[64];
    LONG e;
    static const WCHAR szv[] = L"sz-data";
    static const BYTE binv[3] = { 1, 2, 3 };
    if (!k) return;
    for (i = 0; i < 10; ++i) { s = create_key(k, names[i], KEY_READ, 0); if (s) RegCloseKey(s); }
    set_dword(k, vnames[0], dwv);
    RegSetValueExW(k, vnames[1], 0, REG_SZ, (const BYTE *)szv, sizeof szv);
    RegSetValueExW(k, vnames[2], 0, REG_BINARY, binv, 3);
    RegSetValueExW(k, vnames[3], 0, REG_QWORD, (const BYTE *)&q, 8);
    RegSetValueExW(k, vnames[4], 0, REG_NONE, 0, 0);

    for (i = 0; i < 12; ++i) {
        n = 64;
        e = RegEnumKeyExW(k, i, name, &n, 0, 0, 0, &ft);
        if (i < 10) {
            int found = -1;
            CHECK_ERR(e, 0, "RegEnumKeyExW returns a sub-key for every index below the count");
            for (j = 0; j < 10; ++j) if (weq(name, names[j])) found = (int)j;
            CHECK(found >= 0 && n == 2 && name[2] == 0, "the enumerated name is one of the created ones, length 2, NUL terminated");
            if (found >= 0) ++seen[found];
            CHECK(ft.dwLowDateTime || ft.dwHighDateTime, "last write time is reported");
        } else {
            CHECK_ERR(e, ERROR_NO_MORE_ITEMS, "past the last sub-key the result is ERROR_NO_MORE_ITEMS");
        }
    }
    for (j = 0, n = 0; j < 10; ++j) n += seen[j] == 1;
    CHECK(n == 10, "every sub-key was enumerated exactly once");
    n = 2;
    CHECK_ERR(RegEnumKeyExW(k, 0, name, &n, 0, 0, 0, 0), ERROR_MORE_DATA, "a name buffer of 2 characters cannot hold \"E0\" plus NUL: ERROR_MORE_DATA");
    n = 3;
    CHECK_ERR(RegEnumKeyExW(k, 0, name, &n, 0, 0, 0, 0), 0, "3 characters are enough");

    /* values: order is unspecified, the set must be exact */
    {
        int seenv[5] = { 0, 0, 0, 0, 0 };
        for (i = 0; i < 6; ++i) {
            WCHAR vn[64];
            DWORD vnn = 64, ty = 0, dc = sizeof data;
            e = RegEnumValueW(k, i, vn, &vnn, 0, &ty, data, &dc);
            if (i == 5) { CHECK_ERR(e, ERROR_NO_MORE_ITEMS, "past the last value: ERROR_NO_MORE_ITEMS"); continue; }
            CHECK_ERR(e, 0, "RegEnumValueW returns each value");
            for (j = 0; j < 5; ++j) {
                if (!weq(vn, vnames[j])) continue;
                seenv[j]++;
                if (j == 0) CHECK(ty == REG_DWORD && dc == 4 && *(DWORD *)data == dwv, "enumerated REG_DWORD value and data");
                if (j == 1) CHECK(ty == REG_SZ && dc == sizeof szv && !memcmp(data, szv, dc), "enumerated REG_SZ value and data");
                if (j == 2) CHECK(ty == REG_BINARY && dc == 3 && !memcmp(data, binv, 3), "enumerated REG_BINARY value and data");
                if (j == 3) CHECK(ty == REG_QWORD && dc == 8 && !memcmp(data, &q, 8), "enumerated REG_QWORD value and data");
                if (j == 4) CHECK(ty == REG_NONE && dc == 0, "enumerated empty REG_NONE value");
                CHECK(vnn == wl(vnames[j]), "the reported name length excludes the NUL");
            }
        }
        for (j = 0, n = 0; j < 5; ++j) n += seenv[j] == 1;
        CHECK(n == 5, "each of the five values was enumerated exactly once");
    }
    {
        /* find the long-named value by enumeration, then give its name a 4-character buffer */
        for (i = 0; i < 5; ++i) {
            WCHAR vn[64];
            DWORD vnn = 64, ty, dc = sizeof data;
            e = RegEnumValueW(k, i, vn, &vnn, 0, &ty, data, &dc);
            if (e == 0 && weq(vn, L"v_sz_longer_name")) {
                vnn = 4;
                dc = sizeof data;
                e = RegEnumValueW(k, i, vn, &vnn, 0, &ty, data, &dc);
                CHECK_ERR(e, ERROR_MORE_DATA, "a 4-character value-name buffer cannot hold a 16-character name: ERROR_MORE_DATA");
                break;
            }
        }
        CHECK(i < 5, "the long-named value was found by enumeration");
    }
    {
        /* find the 64-bit value's index by enumeration, then give its data a 4-byte buffer */
        for (i = 0; i < 5; ++i) {
            WCHAR vn[64];
            DWORD vnn = 64, ty, dc = 0;
            e = RegEnumValueW(k, i, vn, &vnn, 0, &ty, 0, &dc);
            if (e == 0 && weq(vn, L"v_q")) {
                DWORD small = 4;
                vnn = 64;
                e = RegEnumValueW(k, i, vn, &vnn, 0, &ty, data, &small);
                CHECK(e == ERROR_MORE_DATA && small == 8, "a too small data buffer: ERROR_MORE_DATA and the size needed (8)");
            }
        }
    }

    /* RegQueryInfoKey: computed independently from what was created */
    e = RegQueryInfoKeyW(k, 0, 0, 0, &subs, &maxsub, 0, &vals, &maxvn, &maxvd, 0, &ft);
    CHECK_ERR(e, 0, "RegQueryInfoKeyW succeeds");
    CHECK(subs == 10 && maxsub == 2, "10 sub-keys, longest name 2 characters");
    CHECK(vals == 5 && maxvn == wl(L"v_sz_longer_name") && maxvd == sizeof szv, "5 values, longest name 16 characters, largest data 16 bytes");
    CHECK(ft.dwLowDateTime || ft.dwHighDateTime, "RegQueryInfoKeyW reports a last write time");
    {
        DWORD sd = 5;
        RegQueryInfoKeyW(k, 0, 0, 0, 0, 0, 0, 0, 0, 0, &sd, 0);
        CHECK(sd == 0, "keys have no security descriptor on this system (size 0)");
    }
    /* class names */
    s = 0;
    {
        static WCHAR cname[] = L"MyClass";
        WCHAR cbuf[32];
        DWORD cn = 32;
        DWORD disp2 = 0;
        e = RegCreateKeyExW(k, L"WithClass", 0, cname, 0, KEY_ALL_ACCESS, 0, &s, &disp2);
        CHECK(e == 0 && disp2 == REG_CREATED_NEW_KEY, "create a key with a class string");
        e = RegQueryInfoKeyW(s, cbuf, &cn, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        CHECK(e == 0 && cn == 7 && weq(cbuf, L"MyClass"), "RegQueryInfoKeyW returns the class");
        cn = 7;
        e = RegQueryInfoKeyW(s, cbuf, &cn, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        CHECK(e == ERROR_MORE_DATA && cn == 7, "class buffer without room for the NUL: ERROR_MORE_DATA and the class length");
        if (s) RegCloseKey(s);
        cls = 32;
        for (i = 0; i < 11; ++i) {
            n = 64;
            cls = 32;
            e = RegEnumKeyExW(k, i, name, &n, 0, cbuf, &cls, 0);
            if (e == 0 && weq(name, L"WithClass")) { CHECK(cls == 7 && weq(cbuf, L"MyClass"), "RegEnumKeyExW returns the class of the sub-key"); break; }
        }
        CHECK(i < 11, "the class-carrying sub-key was found by enumeration");
    }
    RegCloseKey(k);
    (void)type; (void)cb;
}

static void test_access(void)
{
    HKEY rw = create_key(HKEY_CURRENT_USER, ROOT L"\\Access", KEY_ALL_ACCESS, 0), r, w, en, c;
    DWORD v = 0, cb = 4;
    WCHAR nm[16];
    DWORD nn;
    if (!rw) return;
    set_dword(rw, L"x", 3);
    c = create_key(rw, L"Sub", KEY_READ, 0);
    RegCloseKey(c);
    CHECK_ERR(RegOpenKeyExW(HKEY_CURRENT_USER, ROOT L"\\Access", 0, KEY_READ, &r), 0, "open with KEY_READ");
    CHECK_ERR(RegQueryValueExW(r, L"x", 0, 0, (BYTE *)&v, &cb), 0, "KEY_READ allows reading values");
    CHECK_ERR(set_dword(r, L"y", 1), ERROR_ACCESS_DENIED, "KEY_READ does not allow RegSetValueEx");
    CHECK_ERR(RegDeleteValueW(r, L"x"), ERROR_ACCESS_DENIED, "KEY_READ does not allow RegDeleteValue");
    c = 0;
    CHECK_ERR(RegCreateKeyExW(r, L"NewSub", 0, 0, 0, KEY_READ, 0, &c, 0), ERROR_ACCESS_DENIED, "KEY_READ does not allow creating a sub-key");
    CHECK_ERR(RegOpenKeyExW(r, L"Sub", 0, KEY_READ, &c), 0, "KEY_READ allows opening an existing sub-key");
    RegCloseKey(c);
    nn = 16;
    CHECK_ERR(RegEnumKeyExW(r, 0, nm, &nn, 0, 0, 0, 0), 0, "KEY_READ allows enumeration");
    CHECK_ERR(RegDeleteKeyW(r, L"Sub"), 0, "RegDeleteKey works whatever rights the parent handle has (documented)");
    RegCloseKey(r);

    CHECK_ERR(RegOpenKeyExW(HKEY_CURRENT_USER, ROOT L"\\Access", 0, KEY_SET_VALUE, &w), 0, "open with KEY_SET_VALUE only");
    CHECK_ERR(set_dword(w, L"y", 1), 0, "KEY_SET_VALUE allows setting");
    cb = 4;
    CHECK_ERR(RegQueryValueExW(w, L"x", 0, 0, (BYTE *)&v, &cb), ERROR_ACCESS_DENIED, "KEY_SET_VALUE does not allow querying");
    nn = 16;
    CHECK_ERR(RegEnumKeyExW(w, 0, nm, &nn, 0, 0, 0, 0), ERROR_ACCESS_DENIED, "KEY_SET_VALUE does not allow enumerating sub-keys");
    CHECK_ERR(RegQueryInfoKeyW(w, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), ERROR_ACCESS_DENIED, "KEY_SET_VALUE does not allow RegQueryInfoKey");
    RegCloseKey(w);

    CHECK_ERR(RegOpenKeyExW(HKEY_CURRENT_USER, ROOT L"\\Access", 0, KEY_ENUMERATE_SUB_KEYS, &en), 0, "open with KEY_ENUMERATE_SUB_KEYS only");
    cb = 4;
    CHECK_ERR(RegQueryValueExW(en, L"x", 0, 0, (BYTE *)&v, &cb), ERROR_ACCESS_DENIED, "KEY_ENUMERATE_SUB_KEYS does not allow querying values");
    nn = 16;
    CHECK_ERR(RegEnumKeyExW(en, 0, nm, &nn, 0, 0, 0, 0), ERROR_NO_MORE_ITEMS, "enumeration works (no sub-keys left after the delete)");
    RegCloseKey(en);

    CHECK_ERR(RegOpenKeyExW(HKEY_CURRENT_USER, ROOT L"\\Access", 0, MAXIMUM_ALLOWED, &w), 0, "MAXIMUM_ALLOWED opens");
    CHECK_ERR(set_dword(w, L"z", 9), 0, "MAXIMUM_ALLOWED grants write access");
    RegCloseKey(w);
    CHECK_ERR(RegOpenKeyExW(HKEY_CURRENT_USER, ROOT L"\\Access", 0, GENERIC_READ, &r), 0, "GENERIC_READ opens");
    cb = 4;
    CHECK_ERR(RegQueryValueExW(r, L"x", 0, 0, (BYTE *)&v, &cb), 0, "GENERIC_READ maps to KEY_READ rights");
    CHECK_ERR(set_dword(r, L"y", 1), ERROR_ACCESS_DENIED, "GENERIC_READ does not allow writing");
    RegCloseKey(r);
    RegCloseKey(rw);
}

static void test_getvalue(void)
{
    HKEY k = create_key(HKEY_CURRENT_USER, ROOT L"\\GetValue", KEY_ALL_ACCESS, 0);
    DWORD type, cb, dw;
    BYTE buf[128];
    WCHAR wbuf[64];
    LONG e;
    static const BYTE b4[4] = { 1, 2, 3, 4 };
    static const WCHAR expand_src[] = L"pre-%SHZ_REGTEST_VAR%-post";
    static const WCHAR expand_res[] = L"pre-expanded-value-post";
    static const WCHAR unterm[2] = { L'a', L'b' };                 /* stored without a terminator */
    if (!k) return;
    set_dword(k, L"dw", 0xCAFEBABE);
    RegSetValueExW(k, L"sz", 0, REG_SZ, (const BYTE *)SZ_TEXT, sizeof SZ_TEXT);
    RegSetValueExW(k, L"b4", 0, REG_BINARY, b4, 4);
    RegSetValueExW(k, L"b3", 0, REG_BINARY, b4, 3);
    RegSetValueExW(k, L"exp", 0, REG_EXPAND_SZ, (const BYTE *)expand_src, sizeof expand_src);
    RegSetValueExW(k, L"unterm", 0, REG_SZ, (const BYTE *)unterm, sizeof unterm);
    RegCloseKey(k);
    SetEnvironmentVariableW(L"SHZ_REGTEST_VAR", L"expanded-value");

    cb = 4; dw = 0;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"dw", RRF_RT_REG_DWORD, &type, &dw, &cb);
    CHECK(e == 0 && type == REG_DWORD && cb == 4 && dw == 0xCAFEBABE, "RegGetValueW with a sub-key path reads a DWORD");
    cb = 4; dw = 0;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"dw", RRF_RT_ANY, &type, &dw, &cb);
    CHECK(e == 0 && type == REG_DWORD && dw == 0xCAFEBABE, "RRF_RT_ANY accepts any type");
    cb = sizeof buf;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"dw", RRF_RT_REG_SZ, &type, buf, &cb);
    CHECK_ERR(e, ERROR_UNSUPPORTED_TYPE, "a type outside the RRF_RT_* mask is ERROR_UNSUPPORTED_TYPE");
    memset(buf, 0xAA, sizeof buf); cb = sizeof buf;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"dw", RRF_RT_REG_SZ | RRF_ZEROONFAILURE, &type, buf, &cb);
    {
        DWORD i, zero = 1;
        for (i = 0; i < sizeof buf; ++i) if (buf[i]) zero = 0;
        CHECK(e == ERROR_UNSUPPORTED_TYPE && zero, "RRF_ZEROONFAILURE zeroes the caller's buffer on failure");
    }
    cb = 0;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"sz", RRF_RT_REG_SZ, &type, 0, &cb);
    CHECK(e == 0 && type == REG_SZ && cb == sizeof SZ_TEXT, "RegGetValueW size query (pvData == NULL)");
    cb = 6;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"sz", RRF_RT_REG_SZ, &type, buf, &cb);
    CHECK(e == ERROR_MORE_DATA && cb == sizeof SZ_TEXT, "RegGetValueW too small buffer: ERROR_MORE_DATA and the needed size");
    cb = 4; memset(buf, 0, sizeof buf);
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"b4", RRF_RT_DWORD, &type, buf, &cb);
    CHECK(e == 0 && type == REG_BINARY && cb == 4 && !memcmp(buf, b4, 4), "RRF_RT_DWORD accepts a 4-byte REG_BINARY");
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"nothere", RRF_RT_ANY, &type, buf, &cb);
    CHECK_ERR(e, ERROR_FILE_NOT_FOUND, "RegGetValueW of a missing value: ERROR_FILE_NOT_FOUND");
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\NoSuchKey", L"dw", RRF_RT_ANY, &type, buf, &cb);
    CHECK_ERR(e, ERROR_FILE_NOT_FOUND, "RegGetValueW of a missing sub-key: ERROR_FILE_NOT_FOUND");
    cb = sizeof buf;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"dw", 0, &type, buf, &cb);
    CHECK_ERR(e, ERROR_UNSUPPORTED_TYPE, "with no RRF_RT_* type allowed no value type qualifies: ERROR_UNSUPPORTED_TYPE");

    /* REG_EXPAND_SZ: expanded and reported as REG_SZ unless RRF_NOEXPAND */
    cb = sizeof wbuf; type = 0;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"exp", RRF_RT_REG_SZ, &type, wbuf, &cb);
    CHECK(e == 0 && type == REG_SZ && cb == sizeof expand_res && weq(wbuf, expand_res), "REG_EXPAND_SZ is expanded and delivered as REG_SZ");
    cb = sizeof wbuf; type = 0;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"exp", RRF_RT_ANY, &type, wbuf, &cb);
    CHECK(e == 0 && type == REG_SZ && weq(wbuf, expand_res), "RRF_RT_ANY expands as well");
    cb = sizeof wbuf; type = 0;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"exp", RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, &type, wbuf, &cb);
    CHECK(e == 0 && type == REG_EXPAND_SZ && cb == sizeof expand_src && weq(wbuf, expand_src), "RRF_NOEXPAND returns the raw REG_EXPAND_SZ");
    cb = 0;
    e = RegGetValueW(HKEY_CURRENT_USER, ROOT L"\\GetValue", L"exp", RRF_RT_REG_SZ, &type, 0, &cb);
    CHECK(e == 0 && cb == sizeof expand_res, "the size query of an expandable value reports the expanded size");

    /* RegQueryValueEx on a value stored without terminator returns the raw 4 bytes: no terminator is invented */
    {
        HKEY h;
        RegOpenKeyExW(HKEY_CURRENT_USER, ROOT L"\\GetValue", 0, KEY_READ, &h);
        cb = sizeof wbuf;
        e = RegQueryValueExW(h, L"unterm", 0, &type, (BYTE *)wbuf, &cb);
        CHECK(e == 0 && cb == 4, "RegQueryValueExW returns the stored 4 bytes as they are");
        RegCloseKey(h);
    }
}

static void test_ansi(void)
{
    HKEY k = 0, k2 = 0;
    DWORD disp = 0, cb, type, n;
    char buf[64];
    WCHAR wbuf[64];
    LONG e;
    static const char text[] = "ansi-value";                      /* 10 characters + NUL = 11 bytes */
    static const WCHAR wtext[] = L"ansi-value";
    static const char multi[] = "one\0two\0three\0";              /* 15 bytes with the final terminator */
    e = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\ShzRegTest\\Basic\\Ansi", 0, 0, 0, KEY_ALL_ACCESS, 0, &k, &disp);
    CHECK(e == 0 && disp == REG_CREATED_NEW_KEY, "RegCreateKeyExA creates a key");
    if (!k) return;
    CHECK_ERR(RegSetValueExA(k, "s", 0, REG_SZ, (const BYTE *)text, sizeof text), 0, "RegSetValueExA REG_SZ");
    cb = sizeof wbuf;
    e = RegQueryValueExW(k, L"s", 0, &type, (BYTE *)wbuf, &cb);
    CHECK(e == 0 && type == REG_SZ && cb == sizeof wtext && weq(wbuf, wtext), "the ANSI-written string is stored as Unicode (22 bytes)");
    cb = sizeof buf;
    e = RegQueryValueExA(k, "S", 0, &type, (BYTE *)buf, &cb);
    CHECK(e == 0 && type == REG_SZ && cb == sizeof text && !memcmp(buf, text, cb), "RegQueryValueExA returns the ANSI string (11 bytes)");
    cb = 0;
    e = RegQueryValueExA(k, "s", 0, &type, 0, &cb);
    CHECK(e == 0 && cb == sizeof text, "RegQueryValueExA size query is in ANSI bytes");
    cb = 5;
    e = RegQueryValueExA(k, "s", 0, &type, (BYTE *)buf, &cb);
    CHECK(e == ERROR_MORE_DATA && cb == sizeof text, "RegQueryValueExA too small: ERROR_MORE_DATA and the ANSI size");
    CHECK_ERR(RegSetValueExA(k, "m", 0, REG_MULTI_SZ, (const BYTE *)multi, sizeof multi), 0, "RegSetValueExA REG_MULTI_SZ");
    cb = sizeof wbuf;
    e = RegQueryValueExW(k, L"m", 0, &type, (BYTE *)wbuf, &cb);
    CHECK(e == 0 && type == REG_MULTI_SZ && cb == sizeof MULTI_TEXT && !memcmp(wbuf, MULTI_TEXT, cb), "the ANSI multi-string is stored as the Unicode multi-string");
    cb = sizeof buf;
    e = RegQueryValueExA(k, "m", 0, &type, (BYTE *)buf, &cb);
    CHECK(e == 0 && cb == sizeof multi && !memcmp(buf, multi, cb), "RegQueryValueExA returns the ANSI multi-string");
    {
        DWORD dv = 0x01020304;
        CHECK_ERR(RegSetValueExA(k, "d", 0, REG_DWORD, (const BYTE *)&dv, 4), 0, "RegSetValueExA REG_DWORD");
        dv = 0; cb = 4;
        e = RegQueryValueExA(k, "d", 0, &type, (BYTE *)&dv, &cb);
        CHECK(e == 0 && dv == 0x01020304 && type == REG_DWORD, "RegQueryValueExA leaves a DWORD alone");
    }
    e = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\ShzRegTest\\Basic\\Ansi", 0, KEY_READ, &k2);
    CHECK_ERR(e, 0, "RegOpenKeyExA");
    if (k2) RegCloseKey(k2);
    CHECK_ERR(RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\ShzRegTest\\Basic\\Nope", 0, KEY_READ, &k2), ERROR_FILE_NOT_FOUND, "RegOpenKeyExA of a missing key");
    k2 = 0;
    RegCreateKeyExA(k, "SubA", 0, 0, 0, KEY_READ, 0, &k2, 0);
    if (k2) RegCloseKey(k2);
    n = sizeof buf;
    e = RegEnumKeyExA(k, 0, buf, &n, 0, 0, 0, 0);
    CHECK(e == 0 && n == 4 && strcmp(buf, "SubA") == 0, "RegEnumKeyExA");
    {
        int seen_s = 0, seen_m = 0, seen_d = 0, i;
        for (i = 0; i < 3; ++i) {
            char vn[16];
            DWORD vnn = 16, ty, dc = sizeof buf;
            e = RegEnumValueA(k, (DWORD)i, vn, &vnn, 0, &ty, (BYTE *)buf, &dc);
            if (e) break;
            if (vn[0] == 's' && vnn == 1) { seen_s = ty == REG_SZ && dc == sizeof text; }
            if (vn[0] == 'm' && vnn == 1) { seen_m = ty == REG_MULTI_SZ && dc == sizeof multi; }
            if (vn[0] == 'd' && vnn == 1) { seen_d = ty == REG_DWORD && dc == 4; }
        }
        CHECK(seen_s && seen_m && seen_d, "RegEnumValueA returns the three values with ANSI-sized data");
    }
    CHECK_ERR(RegDeleteValueA(k, "s"), 0, "RegDeleteValueA");
    CHECK_ERR(RegDeleteValueA(k, "s"), ERROR_FILE_NOT_FOUND, "RegDeleteValueA of a missing value");
    CHECK_ERR(RegDeleteKeyA(k, "SubA"), 0, "RegDeleteKeyA");
    RegCloseKey(k);
}

/* ---------------------------------------------------------------- predefined keys and the default tree */
static void test_predefined(void)
{
    HKEY k;
    DWORD type, cb, dw, b;
    WCHAR wbuf[128], wdigits[16];
    OSVERSIONINFOW vi;
    LONG e;
    char digits[16];
    int nd = 0, i;

    memset(&vi, 0, sizeof vi);
    vi.dwOSVersionInfoSize = sizeof vi;
    /* the un-manifested GetVersionExW reports 6.2 by design; RtlGetVersion returns the version the loader put in the PEB */
    CHECK(RtlGetVersion(&vi) == 0 && vi.dwMajorVersion >= 10, "RtlGetVersion works (the reference for the registry version values)");
    e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &k);
    CHECK_ERR(e, 0, "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion exists");
    if (e == 0) {
        cb = 4; dw = 0;
        e = RegQueryValueExW(k, L"CurrentMajorVersionNumber", 0, &type, (BYTE *)&dw, &cb);
        CHECK(e == 0 && type == REG_DWORD && dw == vi.dwMajorVersion, "CurrentMajorVersionNumber matches the version the process reports");
        cb = 4; dw = 99;
        e = RegQueryValueExW(k, L"CurrentMinorVersionNumber", 0, &type, (BYTE *)&dw, &cb);
        CHECK(e == 0 && type == REG_DWORD && dw == vi.dwMinorVersion, "CurrentMinorVersionNumber matches the version the process reports");
        b = vi.dwBuildNumber;                                          /* the decimal string is computed here, independently */
        do { digits[nd++] = (char)('0' + b % 10); b /= 10; } while (b);
        for (i = 0; i < nd; ++i) wdigits[i] = (WCHAR)digits[nd - 1 - i];
        wdigits[nd] = 0;
        cb = sizeof wbuf;
        e = RegQueryValueExW(k, L"CurrentBuildNumber", 0, &type, (BYTE *)wbuf, &cb);
        CHECK(e == 0 && type == REG_SZ && weq(wbuf, wdigits), "CurrentBuildNumber is the decimal build number the process reports");
        cb = sizeof wbuf;
        e = RegQueryValueExW(k, L"CurrentBuild", 0, &type, (BYTE *)wbuf, &cb);
        CHECK(e == 0 && type == REG_SZ && weq(wbuf, wdigits), "CurrentBuild equals it");
        cb = sizeof wbuf;
        e = RegQueryValueExW(k, L"ShzProfile", 0, &type, (BYTE *)wbuf, &cb);
        CHECK(e == 0 && type == REG_SZ && cb > 2, "the profile-value marker is present");
        RegCloseKey(k);
    }
    {
        WCHAR env[64];
        const DWORD en = GetEnvironmentVariableW(L"COMPUTERNAME", env, 64);
        cb = sizeof wbuf;
        e = RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", L"ComputerName",
                         RRF_RT_REG_SZ, &type, wbuf, &cb);
        CHECK(en > 0 && e == 0 && weq(wbuf, env), "ActiveComputerName equals the COMPUTERNAME environment variable");
    }
    {   /* the views agree: HKCU is HKU\<SID> for the SID RtlFormatCurrentUserKeyPath reports; HKCR is HKLM\Software\Classes */
        SHZ_UNICODE_STRING cu;
        SHZ_OBJECT_ATTRIBUTES oa;
        HANDLE nh = 0;
        NTSTATUS st;
        const NTSTATUS fst = RtlFormatCurrentUserKeyPath(&cu);
        CHECK(fst == 0 && cu.Length > 0, "RtlFormatCurrentUserKeyPath succeeds");
        if (fst == 0) {
            static const WCHAR prefix[] = L"\\Registry\\User\\";
            const DWORD pn = sizeof prefix / 2 - 1;
            CHECK(cu.Length / 2 > pn && !memcmp(cu.Buffer, prefix, pn * 2), "it returns \\Registry\\User\\<SID>");
            memset(&oa, 0, sizeof oa);
            oa.Length = sizeof oa;
            oa.ObjectName = &cu;
            oa.Attributes = 0x40;
            st = NtOpenKey(&nh, KEY_READ, &oa);
            CHECK(st == 0, "that path opens with NtOpenKey: the kernel's user key and ntdll's SID agree");
            if (st == 0) {
                HKEY hu, kv;
                WCHAR path[256];
                const WCHAR *sid = cu.Buffer + pn;
                static const WCHAR tail[] = L"\\" ROOT L"\\Views";
                DWORD n = (DWORD)wl(sid);
                kv = create_key(HKEY_CURRENT_USER, ROOT L"\\Views", KEY_ALL_ACCESS, 0);
                set_dword(kv, L"marker", 0x5A5A);
                RegCloseKey(kv);
                memcpy(path, sid, n * 2);
                memcpy(path + n, tail, sizeof tail);
                e = RegOpenKeyExW(HKEY_USERS, path, 0, KEY_READ, &hu);
                CHECK_ERR(e, 0, "HKEY_USERS\\<SID>\\... opens the tree HKEY_CURRENT_USER shows");
                if (e == 0) {
                    cb = 4; dw = 0;
                    e = RegQueryValueExW(hu, L"marker", 0, 0, (BYTE *)&dw, &cb);
                    CHECK(e == 0 && dw == 0x5A5A, "a value written through HKCU is visible through HKU\\<SID>");
                    RegCloseKey(hu);
                }
                {
                    /* NtQueryKey(KeyNameInformation) of an HKCU handle is the same absolute path */
                    HKEY hc;
                    BYTE nbuf[512];
                    ULONG res = 0;
                    SHZ_KEY_NAME_INFORMATION *ni = (SHZ_KEY_NAME_INFORMATION *)nbuf;
                    RegOpenKeyExW(HKEY_CURRENT_USER, NULL, 0, KEY_READ, &hc);
                    if (hc) {
                        st = NtQueryKey((HANDLE)hc, SHZ_KeyNameInformation, nbuf, sizeof nbuf, &res);
                        CHECK(st == 0 && ni->NameLength == cu.Length && weq_ci_n(ni->Name, cu.Buffer, cu.Length / 2),
                              "NtQueryKey names the HKEY_CURRENT_USER key exactly as RtlFormatCurrentUserKeyPath does (case aside)");
                        RegCloseKey(hc);
                    }
                }
                NtClose(nh);
            }
            RtlFreeUnicodeString(&cu);
            CHECK(cu.Buffer == 0 && cu.Length == 0, "RtlFreeUnicodeString frees and clears the string");
        }
    }
    {
        HKEY cr, m;
        DWORD disp = 0;
        cr = create_key(HKEY_CLASSES_ROOT, L"ShzRegTestClass", KEY_ALL_ACCESS, &disp);
        CHECK(cr && disp == REG_CREATED_NEW_KEY, "a key can be created below HKEY_CLASSES_ROOT");
        if (cr) { set_dword(cr, L"marker", 0xC1A5); RegCloseKey(cr); }
        e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\ShzRegTestClass", 0, KEY_READ, &m);
        CHECK_ERR(e, 0, "HKCR maps to HKLM\\SOFTWARE\\Classes (documented simplification)");
        if (e == 0) RegCloseKey(m);
        RegDeleteKeyW(HKEY_CLASSES_ROOT, L"ShzRegTestClass");
    }
    e = RegOpenKeyExW(HKEY_CURRENT_CONFIG, NULL, 0, KEY_READ, &k);
    CHECK_ERR(e, 0, "HKEY_CURRENT_CONFIG opens");
    if (e == 0) RegCloseKey(k);
    k = 0;
    e = RegOpenKeyExW(HKEY_PERFORMANCE_DATA, NULL, 0, KEY_READ, &k);
    CHECK(e != 0 && k == 0, "HKEY_PERFORMANCE_DATA is not supported: an error, never a handle");
    e = RegOpenKeyExW((HKEY)(ULONG_PTR)0x80000002u, L"SOFTWARE", 0, KEY_READ, &k);
    CHECK_ERR(e, 0, "a zero-extended HKEY_LOCAL_MACHINE value is accepted");
    if (e == 0) RegCloseKey(k);
    {   /* long name below a predefined key: exercises the heap path of the name builder */
        WCHAR longsub[400];
        DWORD n = 0, seg, j;
        for (seg = 0; seg < 3; ++seg) { for (j = 0; j < 120; ++j) longsub[n++] = L'L'; longsub[n++] = L'\\'; }
        longsub[n - 1] = 0;
        e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, longsub, 0, KEY_READ, &k);
        CHECK_ERR(e, ERROR_FILE_NOT_FOUND, "a 362-character path below a predefined key is resolved (and not found)");
    }
    {   /* RtlGetLastNtStatus follows RtlNtStatusToDosError, as on Windows */
        const ULONG err = RtlNtStatusToDosError((NTSTATUS)0xC0000034);
        CHECK(err == ERROR_FILE_NOT_FOUND && RtlGetLastNtStatus() == (NTSTATUS)0xC0000034, "RtlGetLastNtStatus returns the status last translated (STATUS_OBJECT_NAME_NOT_FOUND)");
        RtlNtStatusToDosError((NTSTATUS)0x8000001A);
        CHECK(RtlGetLastNtStatus() == (NTSTATUS)0x8000001A, "and it follows the next translation (STATUS_NO_MORE_ENTRIES)");
    }
}

static void test_volatile_and_limits(void)
{
    HKEY v = 0, c = 0, k;
    DWORD disp = 0, cb, i;
    LONG e;
    WCHAR *big = (WCHAR *)shz_malloc(20000 * sizeof(WCHAR));
    BYTE *bigdata = (BYTE *)shz_malloc(300000);
    e = RegCreateKeyExW(HKEY_CURRENT_USER, ROOT L"\\Vol", 0, 0, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, 0, &v, &disp);
    CHECK(e == 0 && disp == REG_CREATED_NEW_KEY, "create a volatile key");
    e = RegCreateKeyExW(v, L"Stable", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &c, 0);
    CHECK_ERR(e, ERROR_CHILD_MUST_BE_VOLATILE, "a non-volatile key below a volatile one is ERROR_CHILD_MUST_BE_VOLATILE");
    e = RegCreateKeyExW(v, L"Vol2", 0, 0, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, 0, &c, 0);
    CHECK_ERR(e, 0, "a volatile key below a volatile one is fine");
    if (c) RegCloseKey(c);
    if (v) RegCloseKey(v);

    /* documented limits: key name 255 characters, value name 16,383 characters */
    k = create_key(HKEY_CURRENT_USER, ROOT L"\\Limits", KEY_ALL_ACCESS, 0);
    if (big && bigdata && k) {
        for (i = 0; i < 255; ++i) big[i] = L'K';
        big[255] = 0;
        e = RegCreateKeyExW(k, big, 0, 0, 0, KEY_ALL_ACCESS, 0, &c, 0);
        CHECK_ERR(e, 0, "a 255-character key name is accepted");
        if (e == 0) { RegCloseKey(c); RegDeleteKeyW(k, big); }
        big[255] = L'K';
        big[256] = 0;
        e = RegCreateKeyExW(k, big, 0, 0, 0, KEY_ALL_ACCESS, 0, &c, 0);
        CHECK(e != 0, "a 256-character key name is rejected");
        for (i = 0; i < 16383; ++i) big[i] = L'N';
        big[16383] = 0;
        CHECK_ERR(set_dword(k, big, 1), 0, "a 16,383-character value name is accepted");
        {
            DWORD got = 0, t = 0;
            cb = 4;
            e = RegQueryValueExW(k, big, 0, &t, (BYTE *)&got, &cb);
            CHECK(e == 0 && got == 1, "and reads back");
        }
        big[16383] = L'N';
        big[16384] = 0;
        CHECK(set_dword(k, big, 1) != 0, "a 16,384-character value name is rejected");
        /* a big value round trip: the pattern is generated here and verified here */
        for (i = 0; i < 200000; ++i) bigdata[i] = (BYTE)((i * 7 + (i >> 8)) & 0xFF);
        CHECK_ERR(RegSetValueExW(k, L"big", 0, REG_BINARY, bigdata, 200000), 0, "store a 200,000-byte value");
        memset(bigdata, 0, 300000);
        cb = 300000;
        e = RegQueryValueExW(k, L"big", 0, 0, bigdata, &cb);
        {
            int ok = e == 0 && cb == 200000;
            for (i = 0; ok && i < 200000; ++i) if (bigdata[i] != (BYTE)((i * 7 + (i >> 8)) & 0xFF)) ok = 0;
            CHECK(ok, "the 200,000-byte value reads back byte for byte");
        }
        CHECK_ERR(RegDeleteValueW(k, L"big"), 0, "delete the big value");
        CHECK(RegSetValueExW(k, L"toobig", 0, REG_BINARY, bigdata, 300000) != 0, "a value beyond this system's 256 KiB per-value limit is refused, not truncated");
    }
    if (k) RegCloseKey(k);
    if (big) shz_free(big);
    if (bigdata) shz_free(bigdata);
}

static void test_resources(void)
{
    HKEY k = create_key(HKEY_CURRENT_USER, ROOT L"\\Res", KEY_ALL_ACCESS, 0), t;
    BYTE *blob = (BYTE *)shz_malloc(200000);
    DWORD i, fails = 0, made = 0;
    LONG e = 0;
    static const WCHAR *const vn[8] = { L"a0", L"a1", L"a2", L"a3", L"a4", L"a5", L"a6", L"a7" };
    if (!k || !blob) return;
    memset(blob, 0x5C, 200000);
    /* create/delete churn: a leak of keys or values would exhaust the registry's 1 MiB budget long before 3000 rounds */
    for (i = 0; i < 3000 && !fails; ++i) {
        t = 0;
        e = RegCreateKeyExW(k, L"Churn", 0, 0, 0, KEY_ALL_ACCESS, 0, &t, 0);
        if (e) { ++fails; break; }
        if (RegSetValueExW(t, L"data", 0, REG_BINARY, blob, 1024)) ++fails;
        RegCloseKey(t);
        if (RegDeleteKeyW(k, L"Churn")) ++fails;
    }
    CHECK(fails == 0, "3000 create+write+delete rounds of a key with a 1 KiB value never fail (no leak)");
    for (i = 0; i < 3000 && !fails; ++i)
        if (RegSetValueExW(k, L"grow", 0, REG_BINARY, blob, (i & 1) ? 100 : 5000)) ++fails;
    CHECK(fails == 0, "3000 overwrites alternating between 100 and 5000 bytes never fail (no leak)");
    RegDeleteValueW(k, L"grow");
    /* eight 200,000-byte values cannot all fit into the 1 MiB budget: the failure is an error code, then the space is reclaimed */
    for (i = 0; i < 8; ++i) {
        e = RegSetValueExW(k, vn[i], 0, REG_BINARY, blob, 200000);
        if (e) break;
        ++made;
    }
    CHECK(made >= 3 && made < 8 && e != 0, "the registry budget is enforced with an error code (3 to 7 big values fit)");
    for (i = 0; i < made; ++i) RegDeleteValueW(k, vn[i]);
    for (i = 0; i < 4; ++i) if (RegSetValueExW(k, vn[i], 0, REG_BINARY, blob, 200000)) ++fails;
    CHECK(fails == 0, "after deleting them, four big values fit again (the budget was returned)");
    for (i = 0; i < 4; ++i) RegDeleteValueW(k, vn[i]);
    RegCloseKey(k);
    shz_free(blob);
}

int main(void)
{
    printf("t_reg_basic: Win32 registry API over the Kernel64 registry\n");
    test_create_open();
    test_types();
    test_case_and_default();
    test_nested_and_delete();
    test_handles();
    test_enumeration();
    test_access();
    test_getvalue();
    test_ansi();
    test_predefined();
    test_volatile_and_limits();
    test_resources();
    delete_tree(HKEY_CURRENT_USER, L"Software\\ShzRegTest");
    return finish_tests("t_reg_basic");
}
