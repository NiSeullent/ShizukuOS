/* SPDX-License-Identifier: GPL-2.0-only
 * Chromium's Win32 shared-memory transfer contract, independently exercised:
 * empty DACL + writable section -> reduced permissions -> read-only handle
 * -> write-access duplication fails. A NULL DACL permits that same expansion.
 * This tests real APIs and shared page contents; it does not claim Chromium runs.
 */
#include "ipc_test.h"
#include "../include/nt_ipc.h"

static void transfer(int empty_dacl)
{
    ACL acl;
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa = { sizeof sa, &sd, FALSE };
    HANDLE original = 0, reduced = 0, ro = 0, same = 0, write = 0;
    unsigned char *v = 0, *r = 0;
    struct { PVOID base; ULONG attrs; LARGE_INTEGER size; } basic;
    DWORD need = 0;
    BYTE saved[128];
    BOOL present = FALSE, defaulted = FALSE, ok;
    PACL saved_acl = 0;
    CHECK(InitializeAcl(&acl, sizeof acl, ACL_REVISION), "initialize empty ACL");
    CHECK(InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION), "initialize absolute SD");
    CHECK(SetSecurityDescriptorDacl(&sd, TRUE, empty_dacl ? &acl : 0, FALSE), "set %s DACL", empty_dacl ? "empty" : "NULL");
    original = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 65536, 0);
    CHECK(original != 0, "create writable section with %s DACL", empty_dacl ? "empty" : "NULL");
    if (!original) return;
    CHECK(GetKernelObjectSecurity(original, DACL_SECURITY_INFORMATION, saved, sizeof saved, &need) &&
          GetSecurityDescriptorDacl(saved, &present, &saved_acl, &defaulted) && present &&
          (empty_dacl ? saved_acl && saved_acl->AceCount == 0 : saved_acl == 0), "creation descriptor preserved by security query");
    CHECK(DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(), &reduced,
                          FILE_MAP_READ | FILE_MAP_WRITE | SECTION_QUERY | READ_CONTROL, FALSE, 0), "reduce section standard access rights");
    v = reduced ? MapViewOfFile(reduced, FILE_MAP_WRITE, 0, 0, 65536) : 0;
    CHECK(v != 0, "map reduced writable section");
    if (v) { memcpy(v, "chromium readonly transfer", 26); v[65535] = 42; }
    CHECK(reduced && DuplicateHandle(GetCurrentProcess(), reduced, GetCurrentProcess(), &ro,
                                     FILE_MAP_READ | SECTION_QUERY, FALSE, 0), "convert section handle to read-only");
    CHECK(ro && NtQuerySection(ro, 0, &basic, sizeof basic, 0) == 0 && basic.size.QuadPart == 65536 && !(basic.attrs & SEC_IMAGE),
          "Chromium section safety query succeeds");
    r = ro ? MapViewOfFile(ro, FILE_MAP_READ, 0, 0, 65536) : 0;
    CHECK(r && !memcmp(r, "chromium readonly transfer", 26) && r[65535] == 42, "read-only view shares original section contents");
    CHECK(ro && DuplicateHandle(GetCurrentProcess(), ro, GetCurrentProcess(), &same, 0, FALSE, DUPLICATE_SAME_ACCESS),
          "same-access duplication preserves read-only rights");
    SetLastError(0);
    ok = ro && DuplicateHandle(GetCurrentProcess(), ro, GetCurrentProcess(), &write, FILE_MAP_WRITE, FALSE, 0);
    CHECK(empty_dacl ? !ok && GetLastError() == ERROR_ACCESS_DENIED : ok && write,
          "Chromium write-access probe: %s DACL %s expansion", empty_dacl ? "empty" : "NULL", empty_dacl ? "denies" : "permits");
    if (write) { unsigned char *w = MapViewOfFile(write, FILE_MAP_WRITE, 0, 0, 65536); CHECK(w && r, "expanded writable handle maps");
        if (w && r) { w[77] = 99; CHECK(r[77] == 99, "permitted expansion refers to the same section"); }
        if (w) UnmapViewOfFile(w);
        CloseHandle(write); write = 0;
    }
    SetLastError(0);
    ok = same && DuplicateHandle(GetCurrentProcess(), same, GetCurrentProcess(), &write, FILE_MAP_WRITE, FALSE, DUPLICATE_CLOSE_SOURCE);
    CHECK(empty_dacl ? !ok && GetLastError() == ERROR_ACCESS_DENIED : ok,
          "close-source expansion has the same access result");
    { DWORD flags; CHECK(same && !GetHandleInformation(same, &flags), "DUPLICATE_CLOSE_SOURCE closes source on success and failure"); }
    if (write) CloseHandle(write);
    if (r) UnmapViewOfFile(r);
    if (v) UnmapViewOfFile(v);
    if (ro) CloseHandle(ro);
    if (reduced) CloseHandle(reduced);
    CloseHandle(original);
}

static void named_and_relative(void)
{
    ACL acl;
    SECURITY_DESCRIPTOR absolute;
    BYTE relative[128];
    SECURITY_ATTRIBUTES sa = { sizeof sa, relative, FALSE };
    HANDLE original = 0, ro = 0, opened = 0, write = 0;
    char name[48];
    DWORD bytes = sizeof relative;
    BOOL ok;
    CHECK(InitializeAcl(&acl, sizeof acl, ACL_REVISION) &&
          InitializeSecurityDescriptor(&absolute, SECURITY_DESCRIPTOR_REVISION) &&
          SetSecurityDescriptorDacl(&absolute, TRUE, &acl, FALSE), "prepare empty DACL for relative descriptor");
    CHECK(MakeSelfRelativeSD(&absolute, relative, &bytes) && bytes <= sizeof relative,
          "convert security descriptor to self-relative form");
    snprintf(name, sizeof name, "Local\\chrome_sec_%u", (unsigned)GetCurrentProcessId());
    original = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 65536, name);
    CHECK(original != 0, "create named section through ANSI wrapper with relative descriptor");
    if (!original) return;
    SetLastError(0);
    opened = OpenFileMappingA(FILE_MAP_READ, FALSE, name);
    CHECK(!opened && GetLastError() == ERROR_ACCESS_DENIED, "named OpenFileMapping cannot bypass empty DACL");
    if (opened) CloseHandle(opened);
    SetLastError(0);
    opened = CreateFileMappingA(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 65536, name);
    CHECK(!opened && GetLastError() == ERROR_ACCESS_DENIED, "OPENIF CreateFileMapping cannot bypass existing empty DACL");
    if (opened) CloseHandle(opened);
    CHECK(DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(), &ro,
                          FILE_MAP_READ | SECTION_QUERY, FALSE, 0), "relative descriptor permits existing rights reduction");
    SetLastError(0);
    ok = ro && DuplicateHandle(GetCurrentProcess(), ro, GetCurrentProcess(), &write, FILE_MAP_WRITE, FALSE, 0);
    CHECK(!ok && GetLastError() == ERROR_ACCESS_DENIED, "relative empty DACL denies writable duplication");
    if (write) { CloseHandle(write); write = 0; }
    CHECK(SetSecurityDescriptorDacl(&absolute, TRUE, 0, FALSE) &&
          SetKernelObjectSecurity(original, DACL_SECURITY_INFORMATION, &absolute), "replace creation DACL with NULL DACL");
    CHECK(ro && DuplicateHandle(GetCurrentProcess(), ro, GetCurrentProcess(), &write, FILE_MAP_WRITE, FALSE, 0),
          "access check observes the current descriptor after security update");
    if (write) CloseHandle(write);
    opened = OpenFileMappingA(FILE_MAP_READ, FALSE, name);
    CHECK(opened != 0, "named OpenFileMapping succeeds after NULL DACL update");
    if (opened) CloseHandle(opened);
    if (ro) CloseHandle(ro);
    CloseHandle(original);
}

int main(void)
{
    kstats_t before, after;
    CHECK(kstats(&before), "kernel statistics before section transfer");
    transfer(1);
    transfer(0);
    named_and_relative();
    CHECK(kstats(&after) && after.sections == before.sections && after.views == before.views,
          "section transfer releases every section and view");
    printf("chrome section transfer: %d failed\n", g_bad);
    return g_bad;
}
