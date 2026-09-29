/* SPDX-License-Identifier: GPL-2.0-only
 * advapi32 self-check, beyond the registry: SID functions (byte layouts and string forms worked out by hand from the SID
 * structure definition), CreateWellKnownSid, MapGenericMask, LsaNtStatusToWinError, GetUserName, the ETW provider API, and the
 * api-set contracts that resolve to advapi32.dll.
 */
#include "reg_check.h"
#include <sddl.h>
#include <ntsecapi.h>
#include <evntprov.h>

static BYTE *mk(BYTE *b, DWORD n, ...)
{
    DWORD i;
    va_list ap;
    va_start(ap, n);
    for (i = 0; i < n; ++i) b[i] = (BYTE)va_arg(ap, int);
    va_end(ap);
    return b;
}

static void test_sid_basics(void)
{
    BYTE ba[16], other[16], bad[16], buf[64];
    SID_IDENTIFIER_AUTHORITY nt = { { 0, 0, 0, 0, 0, 5 } };
    PSID s = 0;
    DWORD i;
    /* S-1-5-32-544 as the SID structure defines it: revision, count, 6-byte big-endian authority, little-endian sub-authorities */
    mk(ba, 16, 1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 0x02, 0, 0);
    CHECK(IsValidSid(ba), "IsValidSid accepts revision 1 with 2 sub-authorities");
    CHECK(GetLengthSid(ba) == 16, "GetLengthSid = 8 + 4 * 2");
    CHECK(*GetSidSubAuthorityCount(ba) == 2, "GetSidSubAuthorityCount");
    CHECK(*GetSidSubAuthority(ba, 0) == 32 && *GetSidSubAuthority(ba, 1) == 544, "GetSidSubAuthority reads 32 and 544");
    CHECK(GetSidLengthRequired(3) == 20 && GetSidLengthRequired(0) == 8 && GetSidLengthRequired(15) == 68, "GetSidLengthRequired: 8 + 4n");
    memcpy(bad, ba, 16); bad[0] = 2;
    CHECK(!IsValidSid(bad), "revision 2 is not a valid SID");
    memcpy(bad, ba, 16); bad[1] = 16;
    CHECK(!IsValidSid(bad), "16 sub-authorities is one too many");
    memcpy(bad, ba, 16); bad[1] = 15;
    CHECK(IsValidSid(bad), "15 sub-authorities is the maximum and valid");

    memcpy(other, ba, 16);
    CHECK(EqualSid(ba, other), "EqualSid of identical SIDs");
    other[12] = 0x21;
    CHECK(!EqualSid(ba, other), "EqualSid detects a different sub-authority");
    memcpy(other, ba, 16); other[1] = 1;
    CHECK(!EqualSid(ba, other), "EqualSid detects a different count");
    memcpy(other, ba, 16); other[7] = 6;
    CHECK(!EqualSid(ba, other), "EqualSid detects a different authority");

    memset(buf, 0xAA, sizeof buf);
    SetLastError(0);
    CHECK(!CopySid(15, buf, ba) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && buf[0] == 0xAA, "CopySid into 15 bytes fails with ERROR_INSUFFICIENT_BUFFER and writes nothing");
    CHECK(CopySid(16, buf, ba) && !memcmp(buf, ba, 16) && buf[16] == 0xAA, "CopySid into exactly 16 bytes copies the SID");

    memset(buf, 0xEE, sizeof buf);
    CHECK(InitializeSid(buf, &nt, 4), "InitializeSid with 4 sub-authorities");
    CHECK(buf[0] == 1 && buf[1] == 4 && !memcmp(buf + 2, "\0\0\0\0\0\5", 6) && GetLengthSid(buf) == 24, "revision 1, count 4, authority 5, length 24");
    SetLastError(0);
    CHECK(!InitializeSid(buf, &nt, 16) && GetLastError() == ERROR_INVALID_PARAMETER, "InitializeSid rejects 16 sub-authorities");

    CHECK(AllocateAndInitializeSid(&nt, 5, 21, 111, 222, 333, 444, 0, 0, 0, &s) && s != 0, "AllocateAndInitializeSid S-1-5-21-111-222-333-444");
    if (s) {
        const BYTE want[28] = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 111, 0, 0, 0, 222, 0, 0, 0, 77, 1, 0, 0, 188, 1, 0, 0 };
        CHECK(GetLengthSid(s) == 28 && !memcmp(s, want, 28), "the allocated SID has exactly the expected 28 bytes");
        CHECK(FreeSid(s) == 0, "FreeSid returns NULL");
    }
    s = 0;
    SetLastError(0);
    CHECK(!AllocateAndInitializeSid(&nt, 9, 1, 2, 3, 4, 5, 6, 7, 8, &s) && GetLastError() == ERROR_INVALID_SID && !s, "AllocateAndInitializeSid: more than 8 sub-authorities is ERROR_INVALID_SID");
    for (i = 0; i < 4; ++i) { CHECK(AllocateAndInitializeSid(&nt, 1, 18 + i, 0, 0, 0, 0, 0, 0, 0, &s), "allocate again"); FreeSid(s); }
}

static void test_sid_strings(void)
{
    BYTE b[64];
    LPWSTR w = 0;
    LPSTR a = 0;
    PSID s = 0;
    LONG e;
    SetLastError(0);
    mk(b, 16, 1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 0x02, 0, 0);
    CHECK(ConvertSidToStringSidW(b, &w) && w && weq(w, L"S-1-5-32-544"), "S-1-5-32-544 to string (W)");
    if (w) LocalFree(w);
    CHECK(ConvertSidToStringSidA(b, &a) && a && strcmp(a, "S-1-5-32-544") == 0, "S-1-5-32-544 to string (A)");
    if (a) LocalFree(a);
    mk(b, 8, 1, 0, 0, 0, 0, 0, 0, 5);
    CHECK(ConvertSidToStringSidW(b, &w) && weq(w, L"S-1-5"), "a SID without sub-authorities is \"S-1-5\"");
    if (w) LocalFree(w);
    mk(b, 12, 1, 1, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 1, 0, 0, 0);
    CHECK(ConvertSidToStringSidW(b, &w) && weq(w, L"S-1-0x123456789abc-1"), "an authority beyond 32 bits is written as 0x + 12 hex digits");
    if (w) LocalFree(w);
    mk(b, 12, 1, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    CHECK(ConvertSidToStringSidW(b, &w) && weq(w, L"S-1-4294967295-4294967295"), "a 32-bit authority and sub-authority are decimal");
    if (w) LocalFree(w);
    mk(b, 8, 2, 0, 0, 0, 0, 0, 0, 5);
    SetLastError(0);
    CHECK(!ConvertSidToStringSidW(b, &w) && GetLastError() == ERROR_INVALID_SID, "an invalid SID (revision 2) is ERROR_INVALID_SID");

    /* string to SID */
    CHECK(ConvertStringSidToSidW(L"S-1-5-21-1-2-3-500", &s) && s, "parse S-1-5-21-1-2-3-500");
    if (s) {
        const BYTE want[28] = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xF4, 1, 0, 0 };
        CHECK(GetLengthSid(s) == 28 && !memcmp(s, want, 28), "the parsed SID has the expected bytes (500 = 0x1F4)");
        LocalFree(s);
    }
    CHECK(ConvertStringSidToSidW(L"S-1-0x123456789abc-7", &s) && s, "parse a hexadecimal authority");
    if (s) {
        CHECK(((BYTE *)s)[2] == 0x12 && ((BYTE *)s)[7] == 0xbc && *GetSidSubAuthority(s, 0) == 7, "authority bytes 12 34 56 78 9a bc");
        LocalFree(s);
    }
    {
        static const WCHAR *const bad[] = { L"", L"S", L"S-", L"S-1", L"S-1-", L"S-2-5-32", L"S-1-5-32-", L"S-1-5--32", L"S-1-5-32x", L"hello",
                                            L"S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16", L"S-1-5-4294967296", L"S-1-4294967296-1" };
        int i, ok = 1;
        for (i = 0; i < (int)(sizeof bad / sizeof bad[0]); ++i) {
            s = 0;
            SetLastError(0);
            if (ConvertStringSidToSidW(bad[i], &s) || s || GetLastError() != ERROR_INVALID_SID) { ok = 0; printf("info: accepted or wrong error for bad string #%d\n", i); }
            if (s) LocalFree(s);
        }
        CHECK(ok, "malformed SID strings (13 variants) are all rejected with ERROR_INVALID_SID");
    }
    CHECK(ConvertStringSidToSidW(L"S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15", &s) && s && *GetSidSubAuthorityCount(s) == 15, "15 sub-authorities parse");
    if (s) LocalFree(s);
    {   /* SDDL abbreviations */
        static const struct { const WCHAR *abbr; const WCHAR *full; } t[] = {
            { L"BA", L"S-1-5-32-544" }, { L"SY", L"S-1-5-18" }, { L"WD", L"S-1-1-0" }, { L"AU", L"S-1-5-11" }, { L"BU", L"S-1-5-32-545" },
            { L"LS", L"S-1-5-19" }, { L"NS", L"S-1-5-20" }, { L"AN", L"S-1-5-7" }, { L"IU", L"S-1-5-4" }, { L"ME", L"S-1-16-8192" } };
        int i, ok = 1;
        for (i = 0; i < (int)(sizeof t / sizeof t[0]); ++i) {
            w = 0; s = 0;
            if (!ConvertStringSidToSidW(t[i].abbr, &s) || !ConvertSidToStringSidW(s, &w) || !weq(w, t[i].full)) ok = 0;
            if (w) LocalFree(w);
            if (s) LocalFree(s);
        }
        CHECK(ok, "SDDL abbreviations BA SY WD AU BU LS NS AN IU ME map to their documented SIDs");
    }
    /* round trip of the system user's SID (its string is what Kernel64 seeds \Registry\User\<SID> with) */
    {
        HKEY k;
        CHECK(ConvertStringSidToSidW(SHZ_USER_SID_W, &s) && s && IsValidSid(s), "the system user's SID string parses");
        if (s) {
            CHECK(ConvertSidToStringSidW(s, &w) && weq(w, SHZ_USER_SID_W), "and converts back to the identical string");
            if (w) LocalFree(w);
            LocalFree(s);
        }
        e = RegOpenKeyExW(HKEY_USERS, SHZ_USER_SID_W, 0, KEY_READ, &k);
        CHECK_ERR(e, 0, "HKEY_USERS contains a key named after that SID");
        if (e == 0) RegCloseKey(k);
    }
}

static void check_wk(WELL_KNOWN_SID_TYPE t, const WCHAR *want, const char *what)
{
    BYTE buf[SECURITY_MAX_SID_SIZE];
    DWORD cb = sizeof buf;
    LPWSTR w = 0;
    if (!CreateWellKnownSid(t, 0, buf, &cb)) { CHECK(0, what); return; }
    CHECK(cb == GetLengthSid(buf) && IsValidSid(buf) && ConvertSidToStringSidW(buf, &w) && weq(w, want), what);
    if (w) LocalFree(w);
}

static void test_well_known(void)
{
    BYTE buf[SECURITY_MAX_SID_SIZE], small[8], dom[64];
    DWORD cb;
    PSID d = 0;
    SID_IDENTIFIER_AUTHORITY nt = { { 0, 0, 0, 0, 0, 5 } };
    check_wk(WinNullSid, L"S-1-0-0", "WinNullSid is S-1-0-0");
    check_wk(WinWorldSid, L"S-1-1-0", "WinWorldSid is S-1-1-0");
    check_wk(WinCreatorOwnerSid, L"S-1-3-0", "WinCreatorOwnerSid is S-1-3-0");
    check_wk(WinNtAuthoritySid, L"S-1-5", "WinNtAuthoritySid is S-1-5");
    check_wk(WinInteractiveSid, L"S-1-5-4", "WinInteractiveSid is S-1-5-4");
    check_wk(WinAuthenticatedUserSid, L"S-1-5-11", "WinAuthenticatedUserSid is S-1-5-11");
    check_wk(WinLocalSystemSid, L"S-1-5-18", "WinLocalSystemSid is S-1-5-18");
    check_wk(WinBuiltinAdministratorsSid, L"S-1-5-32-544", "WinBuiltinAdministratorsSid is S-1-5-32-544");
    check_wk(WinBuiltinUsersSid, L"S-1-5-32-545", "WinBuiltinUsersSid is S-1-5-32-545");
    check_wk(WinBuiltinGuestsSid, L"S-1-5-32-546", "WinBuiltinGuestsSid is S-1-5-32-546");
    check_wk(WinLowLabelSid, L"S-1-16-4096", "WinLowLabelSid is S-1-16-4096");
    check_wk(WinMediumLabelSid, L"S-1-16-8192", "WinMediumLabelSid is S-1-16-8192");
    check_wk(WinHighLabelSid, L"S-1-16-12288", "WinHighLabelSid is S-1-16-12288");
    check_wk(WinSystemLabelSid, L"S-1-16-16384", "WinSystemLabelSid is S-1-16-16384");
    check_wk(WinBuiltinAnyPackageSid, L"S-1-15-2-1", "WinBuiltinAnyPackageSid (ALL APPLICATION PACKAGES) is S-1-15-2-1");
    cb = 4;
    SetLastError(0);
    CHECK(!CreateWellKnownSid(WinBuiltinAdministratorsSid, 0, small, &cb) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && cb == 16,
          "a too small buffer: ERROR_INSUFFICIENT_BUFFER and *cbSid = 16 (documented)");
    cb = 16;
    CHECK(CreateWellKnownSid(WinBuiltinAdministratorsSid, 0, buf, &cb) && cb == 16, "a buffer of exactly the needed size works");
    /* domain-relative types */
    CHECK(ConvertStringSidToSidW(L"S-1-5-21-1-2-3", &d) && d, "domain SID S-1-5-21-1-2-3");
    if (d) {
        LPWSTR w = 0;
        cb = sizeof dom;
        CHECK(CreateWellKnownSid(WinAccountAdministratorSid, d, dom, &cb) && ConvertSidToStringSidW(dom, &w) && weq(w, L"S-1-5-21-1-2-3-500"), "WinAccountAdministratorSid is domain-500");
        if (w) LocalFree(w);
        w = 0; cb = sizeof dom;
        CHECK(CreateWellKnownSid(WinAccountDomainUsersSid, d, dom, &cb) && ConvertSidToStringSidW(dom, &w) && weq(w, L"S-1-5-21-1-2-3-513"), "WinAccountDomainUsersSid is domain-513");
        if (w) LocalFree(w);
        cb = 4;
        SetLastError(0);
        CHECK(!CreateWellKnownSid(WinAccountGuestSid, d, dom, &cb) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && cb == 28, "domain-relative: 4 domain sub-authorities + the RID need 8 + 4 * 5 = 28 bytes");
        LocalFree(d);
    }
    cb = sizeof dom;
    SetLastError(0);
    CHECK(!CreateWellKnownSid(WinAccountAdministratorSid, 0, dom, &cb) && GetLastError() == ERROR_INVALID_PARAMETER, "a domain-relative type without a domain SID is ERROR_INVALID_PARAMETER");
    cb = sizeof dom;
    SetLastError(0);
    CHECK(!CreateWellKnownSid((WELL_KNOWN_SID_TYPE)9999, 0, dom, &cb) && GetLastError() == ERROR_INVALID_PARAMETER, "an unknown type is ERROR_INVALID_PARAMETER");
    (void)nt;
}

static void test_misc(void)
{
    DWORD mask;
    GENERIC_MAPPING gm = { 0x1, 0x2, 0x4, 0x7 };
    WCHAR wb[16];
    char ab[16];
    DWORD n;
    mask = GENERIC_READ | GENERIC_WRITE | 0x100;
    MapGenericMask(&mask, &gm);
    CHECK(mask == 0x103, "MapGenericMask: GENERIC_READ|GENERIC_WRITE|0x100 -> 0x103");
    mask = GENERIC_ALL;
    MapGenericMask(&mask, &gm);
    CHECK(mask == 0x7, "MapGenericMask: GENERIC_ALL -> GenericAll");
    mask = MAXIMUM_ALLOWED | GENERIC_EXECUTE;
    MapGenericMask(&mask, &gm);
    CHECK(mask == (MAXIMUM_ALLOWED | 0x4), "MapGenericMask leaves other bits alone and clears the generic bits");
    CHECK(LsaNtStatusToWinError((NTSTATUS)0xC0000034) == ERROR_FILE_NOT_FOUND && LsaNtStatusToWinError((NTSTATUS)0x8000001A) == ERROR_NO_MORE_ITEMS &&
          LsaNtStatusToWinError(0) == 0, "LsaNtStatusToWinError translates like RtlNtStatusToDosError");

    n = 16;
    CHECK(GetUserNameW(wb, &n) && n == 8 && weq(wb, L"shizuku"), "GetUserNameW: \"shizuku\", size 8 including the NUL");
    n = 4;
    SetLastError(0);
    CHECK(!GetUserNameW(wb, &n) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && n == 8, "GetUserNameW too small: ERROR_INSUFFICIENT_BUFFER and the size needed (8)");
    n = 8;
    CHECK(GetUserNameW(wb, &n) && n == 8, "GetUserNameW with exactly 8 characters works");
    n = 16;
    CHECK(GetUserNameA(ab, &n) && n == 8 && strcmp(ab, "shizuku") == 0, "GetUserNameA");
    n = 7;
    SetLastError(0);
    CHECK(!GetUserNameA(ab, &n) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && n == 8, "GetUserNameA too small");
}

static volatile LONG g_callback_calls;
static void NTAPI enable_cb(LPCGUID id, ULONG src, UCHAR level, ULONGLONG any, ULONGLONG all, PEVENT_FILTER_DESCRIPTOR f, PVOID ctx)
{
    (void)id; (void)src; (void)level; (void)any; (void)all; (void)f; (void)ctx;
    InterlockedIncrement(&g_callback_calls);
}

static void test_etw(void)
{
    static const GUID prov = { 0x12345678, 0x1234, 0x5678, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    REGHANDLE h = 0, h2 = 0;
    EVENT_DESCRIPTOR ed;
    EVENT_DATA_DESCRIPTOR dd;
    DWORD payload = 7;
    ULONG e;
    memset(&ed, 0, sizeof ed);
    ed.Id = 1; ed.Level = 4;
    dd.Ptr = (ULONGLONG)(ULONG_PTR)&payload; dd.Size = 4; dd.Reserved = 0;
    CHECK(EventRegister(&prov, enable_cb, 0, &h) == 0 && h != 0, "EventRegister returns a non-zero handle");
    CHECK(EventRegister(&prov, 0, 0, &h2) == 0 && h2 != 0 && h2 != h, "a provider may be registered twice; handles differ");
    CHECK(EventWrite(h, &ed, 1, &dd) == 0, "EventWrite to a registered provider with no session succeeds (event discarded)");
    CHECK(EventWrite(h, &ed, 0, 0) == 0, "EventWrite without payload");
    CHECK(EventWriteTransfer(h, &ed, &prov, 0, 1, &dd) == 0, "EventWriteTransfer with an activity id");
    CHECK(EventWrite(h, 0, 0, 0) == ERROR_INVALID_PARAMETER, "EventWrite without descriptor is ERROR_INVALID_PARAMETER");
    CHECK(EventWrite(h, &ed, 2, 0) == ERROR_INVALID_PARAMETER, "payload count without payload is ERROR_INVALID_PARAMETER");
    CHECK(EventRegister(0, 0, 0, &h2) == ERROR_INVALID_PARAMETER && EventRegister(&prov, 0, 0, 0) == ERROR_INVALID_PARAMETER, "EventRegister validates its arguments");
    CHECK(EventUnregister(h) == 0, "EventUnregister");
    e = EventWrite(h, &ed, 1, &dd);
    CHECK(e == ERROR_INVALID_HANDLE, "EventWrite through an unregistered handle is ERROR_INVALID_HANDLE");
    CHECK(EventUnregister(h) == ERROR_INVALID_HANDLE, "unregistering twice is ERROR_INVALID_HANDLE");
    CHECK(EventUnregister(0x1234) == ERROR_INVALID_HANDLE, "a made-up handle is ERROR_INVALID_HANDLE");
    CHECK(EventSetInformation(h2, (EVENT_INFO_CLASS)3, 0, 0) == 0, "EventSetInformation(EventProviderUseDescriptorType)");
    CHECK(EventSetInformation(h2, (EVENT_INFO_CLASS)99, 0, 0) == ERROR_INVALID_PARAMETER, "an unknown information class is ERROR_INVALID_PARAMETER");
    CHECK(EventSetInformation(h, (EVENT_INFO_CLASS)3, 0, 0) == ERROR_INVALID_HANDLE, "EventSetInformation on an unregistered handle");
    CHECK(EventUnregister(h2) == 0, "unregister the second registration");
    CHECK(g_callback_calls == 0, "the enable callback was never invoked: no session exists that could enable the provider");
}

static void test_apiset(void)
{
    HMODULE adv = GetModuleHandleW(L"advapi32.dll"), m;
    static const WCHAR *const contracts[] = { L"api-ms-win-core-registry-l1-1-0.dll", L"api-ms-win-core-registry-l2-1-0.dll",
                                              L"api-ms-win-security-base-l1-1-0.dll", L"api-ms-win-security-sddl-l1-1-0.dll",
                                              L"api-ms-win-eventing-provider-l1-1-0.dll" };
    int i, ok = 1;
    LONG (WINAPI *open_ex)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    HKEY k = 0;
    CHECK(adv != 0, "advapi32.dll is loaded in this process (the test imports it)");
    for (i = 0; i < (int)(sizeof contracts / sizeof contracts[0]); ++i) {
        m = LoadLibraryW(contracts[i]);
        if (m != adv) ok = 0;
    }
    CHECK(ok, "the registry, security-base, sddl and eventing contracts all resolve to the advapi32.dll module");
    m = LoadLibraryW(L"api-ms-win-core-registry-l1-1-0.dll");
    open_ex = (void *)GetProcAddress(m, "RegOpenKeyExW");
    CHECK(open_ex != 0 && open_ex(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_READ, &k) == 0, "RegOpenKeyExW resolved through the contract works");
    if (k) RegCloseKey(k);
    SetLastError(0);
    m = LoadLibraryW(L"api-ms-win-core-registry-l9-1-0.dll");
    CHECK(m == 0 && GetLastError() == ERROR_MOD_NOT_FOUND, "an unknown contract version is not forwarded blindly: ERROR_MOD_NOT_FOUND");
    CHECK(GetProcAddress(adv, "OpenProcessToken") == 0 && GetProcAddress(adv, "GetTokenInformation") == 0 && GetProcAddress(adv, "AccessCheck") == 0,
          "token and access-check functions are not exported: there are no tokens on this system");
}

int main(void)
{
    printf("t_adv_misc: SIDs, well-known SIDs, user name, ETW providers, api-set contracts\n");
    test_sid_basics();
    test_sid_strings();
    test_well_known();
    test_misc();
    test_etw();
    test_apiset();
    return finish_tests("t_adv_misc");
}
