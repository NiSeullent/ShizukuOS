/* SPDX-License-Identifier: GPL-2.0-only
 * Access rights of section (file mapping) handles under DuplicateHandle and MapViewOfFile. Chromium's shared memory regions
 * (base::subtle::PlatformSharedMemoryRegion) convert a region to read-only by duplicating its handle with FILE_MAP_READ |
 * SECTION_QUERY, and Take() then checks the mode: a read-only handle must REFUSE DuplicateHandle(FILE_MAP_WRITE), a writable
 * one must allow it; a region that answers wrongly is rejected ("File mapping handle has wrong access rights"), which made the
 * in-process renderer's mojo deserialization fail. As in Chromium's actual creation path, this fixture installs an EMPTY DACL:
 * new section-specific rights are then denied, while existing rights remain usable. A NULL/default DACL permits expansion,
 * tested separately with current-descriptor updates in unchanged T_CHROME_SECTION. This fixture retains READ_CONTROL so
 * GENERIC_READ maps to rights already held, without assuming an unimplemented owner/token standard-rights evaluator.
 * MAXIMUM_ALLOWED preserves the source grant; MapViewOfFile still needs the matching map right.
 */
#include "k32test.h"

#ifndef SECTION_QUERY
#define SECTION_QUERY 1
#endif

static DWORD dup_err;
static BOOL dup(HANDLE src, DWORD access, DWORD options, HANDLE *out)
{
    *out = 0;
    SetLastError(0);
    if (DuplicateHandle(GetCurrentProcess(), src, GetCurrentProcess(), out, access, FALSE, options)) return TRUE;
    dup_err = GetLastError();
    return FALSE;
}

/* Chromium's test for "is this handle read-only": a duplicate asking for FILE_MAP_WRITE fails */
static int handle_is_read_only(HANDLE h)
{
    HANDLE d;
    if (dup(h, FILE_MAP_WRITE, 0, &d)) { CloseHandle(d); return 0; }
    return 1;
}

int main(void)
{
    ACL acl;
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa = { sizeof sa, &sd, FALSE };
    HANDLE full;
    HANDLE ro = 0, x = 0, y = 0;
    unsigned char *w, *r;
    CHECK(InitializeAcl(&acl, sizeof acl, ACL_REVISION), "initialize the actual empty section ACL");
    CHECK(InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION), "initialize the actual section descriptor");
    CHECK(SetSecurityDescriptorDacl(&sd, TRUE, &acl, FALSE), "install the actual empty DACL used by Chromium");
    full = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 0x2000, 0);
    CHECKV(full != 0, "CreateFileMappingW (pagefile-backed, 8 KiB)", "err %lu", (unsigned long)GetLastError());
    if (!full) return k32t_finish("t_sec_access");

    CHECK(!handle_is_read_only(full), "the creator's handle allows FILE_MAP_WRITE duplicates (a writable region)");
    CHECK(dup(full, FILE_MAP_READ | SECTION_QUERY | READ_CONTROL, 0, &ro) && ro != 0 && ro != full, "DuplicateHandle(FILE_MAP_READ | SECTION_QUERY | READ_CONTROL) narrows it to a read-only handle");
    CHECK(handle_is_read_only(ro), "the read-only handle refuses a FILE_MAP_WRITE duplicate (what Take() probes)");
    CHECK(!dup(ro, FILE_MAP_WRITE, 0, &x) && dup_err == ERROR_ACCESS_DENIED, "... with ERROR_ACCESS_DENIED");
    CHECK(!dup(ro, FILE_MAP_READ | FILE_MAP_WRITE, 0, &x) && dup_err == ERROR_ACCESS_DENIED, "asking for write among other rights is refused too");
    CHECK(!dup(ro, GENERIC_ALL, 0, &x) && dup_err == ERROR_ACCESS_DENIED, "GENERIC_ALL cannot widen it");
    CHECK(!dup(ro, GENERIC_WRITE, 0, &x) && dup_err == ERROR_ACCESS_DENIED, "GENERIC_WRITE cannot widen it");
    CHECK(!dup(ro, FILE_MAP_EXECUTE, 0, &x) && dup_err == ERROR_ACCESS_DENIED, "an execute right it never had is refused");
    CHECK(dup(ro, FILE_MAP_READ, 0, &x) && x != 0, "an equal request is fine");
    CloseHandle(x);
    CHECK(dup(ro, SECTION_QUERY, 0, &x) && x != 0, "narrowing further (query only) is fine");
    CloseHandle(x);
    CHECK(dup(ro, GENERIC_READ, 0, &x) && x != 0, "GENERIC_READ maps to read and query rights the handle has");
    CloseHandle(x);
    CHECK(dup(ro, 0, DUPLICATE_SAME_ACCESS, &x) && handle_is_read_only(x), "DUPLICATE_SAME_ACCESS keeps it read-only");
    CloseHandle(x);
    CHECK(dup(ro, MAXIMUM_ALLOWED, 0, &x) && handle_is_read_only(x), "MAXIMUM_ALLOWED is what the source has: still read-only");
    CloseHandle(x);

    /* the rights are enforced by the mapping calls on the duplicates, and the duplicates share the same pages */
    w = MapViewOfFile(full, FILE_MAP_WRITE, 0, 0, 0x2000);
    r = MapViewOfFile(ro, FILE_MAP_READ, 0, 0, 0x2000);
    CHECK(w != 0 && r != 0, "a writable view of the full handle and a read view of the read-only handle");
    if (w && r) {
        w[0] = 0x5a; w[0x1fff] = 0xa5;
        CHECK(r[0] == 0x5a && r[0x1fff] == 0xa5, "both views show the same pages");
    }
    SetLastError(0);
    y = MapViewOfFile(ro, FILE_MAP_WRITE, 0, 0, 0x2000) ? (HANDLE)1 : 0;
    CHECK(y == 0 && GetLastError() == ERROR_ACCESS_DENIED, "MapViewOfFile(FILE_MAP_WRITE) on the read-only handle: ERROR_ACCESS_DENIED");
    if (w) UnmapViewOfFile(w);
    if (r) UnmapViewOfFile(r);

    /* the full handle can still be duplicated with any subset, and a widening request on a narrowed copy of the copy stays refused */
    CHECK(dup(full, FILE_MAP_WRITE | FILE_MAP_READ, 0, &x) && !handle_is_read_only(x), "a writable duplicate of the full handle");
    CHECK(dup(x, FILE_MAP_READ, 0, &y) && handle_is_read_only(y), "narrowed again, it is read-only");
    CHECK(!dup(y, FILE_MAP_WRITE, 0, &ro) && dup_err == ERROR_ACCESS_DENIED, "and a copy of a narrowed copy cannot be widened");
    CloseHandle(y); CloseHandle(x);

    /* other object types are not affected */
    CHECK(dup(GetCurrentProcess(), PROCESS_ALL_ACCESS, 0, &x) && x != 0, "a process handle duplicate with full access still works");
    CloseHandle(x);
    {
        HANDLE ev = CreateEventW(0, TRUE, FALSE, 0);
        CHECK(ev != 0 && dup(ev, EVENT_ALL_ACCESS, 0, &x) && x != 0, "an event handle duplicate still works");
        CloseHandle(x); CloseHandle(ev);
    }
    CloseHandle(full);
    return k32t_finish("t_sec_access");
}
