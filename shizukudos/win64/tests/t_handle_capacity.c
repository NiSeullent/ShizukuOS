/* SPDX-License-Identifier: GPL-2.0-only
 * Real guest event/duplicate/close contracts beyond the former 512-handle
 * startup ceiling, then actual native exhaustion and reuse of the bounded
 * 4096-entry policy. No manufactured object or successful exhaustion result. */
#include "nt.h"
#include "k32test.h"

enum { EVENT_COUNT = 1024, DUP_COUNT = 64, HANDLE_POLICY = 4096, FILLER_PROBE = HANDLE_POLICY + 64 };
static HANDLE events[EVENT_COUNT], duplicates[DUP_COUNT], fillers[FILLER_PROBE];

static int selected(unsigned i) { return i % 7 == 0 || i == 511 || i == 512 || i == EVENT_COUNT - 1; }

int main(void)
{
    unsigned n = 0, nd = 0, nf = 0, i, j, errors = 0;
    HANDLE moved = NULL, old, extra = NULL;
    NTSTATUS st = STATUS_SUCCESS;
    DWORD wait, error;
    BOOL ok;
    for (i = 0; i < EVENT_COUNT; ++i) {
        events[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!events[i]) break;
        ++n;
    }
    CHECK(n == EVENT_COUNT, "1024 distinct real event objects exceed the former 512-slot ceiling");
    if (n != EVENT_COUNT) goto cleanup;
    for (i = 0; i < n; ++i) {
        for (j = i + 1; j < n; ++j) if (events[i] == events[j]) ++errors;
        if (WaitForSingleObject(events[i], 0) != WAIT_TIMEOUT) ++errors;
    }
    CHECK(errors == 0, "all 1024 live handles are distinct and initially unsignaled");
    errors = 0;
    for (i = 0; i < n; ++i) if (selected(i) && !SetEvent(events[i])) ++errors;
    for (i = 0; i < n; ++i)
        if (WaitForSingleObject(events[i], 0) != (selected(i) ? WAIT_OBJECT_0 : WAIT_TIMEOUT)) ++errors;
    CHECK(errors == 0, "event signals remain independent across the former 512-handle boundary and full object set");
    errors = 0;
    for (i = 0; i < n; ++i) {
        if (!ResetEvent(events[i])) ++errors;
        if (WaitForSingleObject(events[i], 0) != WAIT_TIMEOUT) ++errors;
    }
    CHECK(errors == 0, "reset clears each real event without aliasing another object");

    for (i = 0; i < DUP_COUNT; ++i) {
        unsigned index = (i * 17) % EVENT_COUNT;
        if (!DuplicateHandle(GetCurrentProcess(), events[index], GetCurrentProcess(), &duplicates[i], 0, FALSE, DUPLICATE_SAME_ACCESS)) break;
        ++nd;
    }
    CHECK(nd == DUP_COUNT, "64 new handles duplicate existing events beyond the former limit");
    errors = 0;
    for (i = 0; i < nd; ++i) {
        unsigned index = (i * 17) % EVENT_COUNT, neighbor = (index + 1) % EVENT_COUNT;
        if (duplicates[i] == events[index] || !SetEvent(duplicates[i]) ||
            WaitForSingleObject(events[index], 0) != WAIT_OBJECT_0 ||
            WaitForSingleObject(events[neighbor], 0) != WAIT_TIMEOUT ||
            !ResetEvent(events[index]) || WaitForSingleObject(duplicates[i], 0) != WAIT_TIMEOUT) ++errors;
        old = events[index];
        if (!CloseHandle(old)) ++errors;
        events[index] = NULL;
        SetLastError(0);
        wait = WaitForSingleObject(old, 0); error = GetLastError();
        if (wait != WAIT_FAILED || error != ERROR_INVALID_HANDLE || NtClose(old) != STATUS_INVALID_HANDLE) ++errors;
        if (!SetEvent(duplicates[i]) || WaitForSingleObject(duplicates[i], 0) != WAIT_OBJECT_0) ++errors;
    }
    CHECK(errors == 0, "duplicate owns the same event after the original closes, and closed handles fail before reuse");
    errors = 0;
    for (i = 0; i < nd; ++i) {
        old = duplicates[i];
        if (!CloseHandle(old) || NtClose(old) != STATUS_INVALID_HANDLE) ++errors;
        duplicates[i] = NULL;
    }
    CHECK(errors == 0, "every duplicate closes exactly once");
    errors = 0;
    for (i = 0; i < n; ++i) if (!events[i]) {
        events[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!events[i] || WaitForSingleObject(events[i], 0) != WAIT_TIMEOUT) ++errors;
    }
    CHECK(errors == 0, "released slots accept newly allocated unsignaled objects");
    if (errors) goto cleanup;

    old = events[EVENT_COUNT - 1];
    ok = DuplicateHandle(GetCurrentProcess(), old, GetCurrentProcess(), &moved, 0, FALSE,
                         DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    /* A valid source is closed by CLOSE_SOURCE even if duplication fails. */
    events[EVENT_COUNT - 1] = NULL;
    CHECK(ok && moved && moved != old, "DUPLICATE_CLOSE_SOURCE transfers a real object reference to a new handle");
    if (!ok || !moved) goto cleanup;
    CHECK(NtClose(old) == STATUS_INVALID_HANDLE && SetEvent(moved) &&
          WaitForSingleObject(moved, 0) == WAIT_OBJECT_0 &&
          WaitForSingleObject(events[EVENT_COUNT - 2], 0) == WAIT_TIMEOUT,
          "transferred source is closed while its independent event remains alive");
    CHECK(CloseHandle(moved), "transferred handle releases the event");
    moved = NULL;
    events[EVENT_COUNT - 1] = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(events[EVENT_COUNT - 1] && WaitForSingleObject(events[EVENT_COUNT - 1], 0) == WAIT_TIMEOUT,
          "slot and event state are freshly reusable after final reference closes");
    if (!events[EVENT_COUNT - 1]) goto cleanup;

    for (i = 0; i < FILLER_PROBE; ++i) {
        st = NtCreateEvent(&fillers[i], EVENT_ALL_ACCESS, NULL, 0, FALSE);
        if (st) break;
        ++nf;
    }
    printf("HANDLE_CAPACITY: %u distinct events at exhaustion; native status %08x\n", n + nf, (unsigned)st);
    CHECK(n + nf >= HANDLE_POLICY - 64 && n + nf <= HANDLE_POLICY && st == STATUS_NO_MEMORY,
          "real native event creation exhausts near 4096 and returns STATUS_NO_MEMORY");
    st = NtDuplicateObject(GetCurrentProcess(), events[0], GetCurrentProcess(), &extra, 0, 0, DUPLICATE_SAME_ACCESS);
    CHECK(st == STATUS_NO_MEMORY, "duplicate allocation fails genuinely when every table slot is occupied");
    if (extra) { CloseHandle(extra); extra = NULL; }
    CHECK(WaitForSingleObject(events[0], 0) == WAIT_TIMEOUT && SetEvent(events[0]) &&
          WaitForSingleObject(events[0], 0) == WAIT_OBJECT_0 &&
          WaitForSingleObject(events[1], 0) == WAIT_TIMEOUT,
          "exhaustion leaves existing object identities and signals intact");
    if (nf) {
        --nf;
        old = fillers[nf]; fillers[nf] = NULL;
        CHECK(NtClose(old) == STATUS_SUCCESS && NtClose(old) == STATUS_INVALID_HANDLE,
              "closing one real filler releases exactly one slot");
        st = NtCreateEvent(&extra, EVENT_ALL_ACCESS, NULL, 0, FALSE);
        CHECK(st == STATUS_SUCCESS && extra && WaitForSingleObject(extra, 0) == WAIT_TIMEOUT &&
              SetEvent(extra) && WaitForSingleObject(extra, 0) == WAIT_OBJECT_0,
              "one freed slot permits a new independent native event after exhaustion");
        if (extra) { CloseHandle(extra); extra = NULL; }
    }
cleanup:
    errors = 0;
    if (moved && !CloseHandle(moved)) ++errors;
    if (extra && !CloseHandle(extra)) ++errors;
    for (i = 0; i < nd; ++i) if (duplicates[i] && !CloseHandle(duplicates[i])) ++errors;
    for (i = 0; i < n; ++i) if (events[i] && !CloseHandle(events[i])) ++errors;
    for (i = 0; i < nf; ++i) if (fillers[i] && NtClose(fillers[i]) != STATUS_SUCCESS) ++errors;
    CHECK(errors == 0, "all remaining real handles close during fixture cleanup");
    return k32t_finish("T_HANDLE_CAPACITY");
}
