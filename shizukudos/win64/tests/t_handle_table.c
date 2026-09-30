/* SPDX-License-Identifier: GPL-2.0-only
 * The per-process handle table holds thousands of handles. Chromium's browser process creates several hundred within seconds of
 * starting (threads, events, I/O completion ports, sections, files, registry keys) and NtCreateEvent failed with
 * STATUS_NO_MEMORY at the old limit of 512 entries. The test creates 3000 handles of mixed kinds, checks that they are
 * distinct and work (including handles above the old limit, DuplicateHandle and waits on them), that GetProcessHandleCount
 * follows, that the table fails cleanly when it is full and recovers after a close, and that everything is released afterwards.
 */
#include "k32test.h"

#define N 3000
static HANDLE h[N];

int main(void)
{
    DWORD base = 0, now = 0, i, distinct = 1;
    HANDLE dup = 0, last = 0, more[4200];
    unsigned made = 0, extra = 0;
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &base), "GetProcessHandleCount");
    for (i = 0; i < N; ++i) {
        switch (i % 3) {
        case 0: h[i] = CreateEventW(0, TRUE, (i % 2) == 0, 0); break;
        case 1: h[i] = CreateSemaphoreW(0, 1, 4, 0); break;
        default: h[i] = CreateMutexW(0, FALSE, 0); break;
        }
        if (!h[i]) break;
    }
    CHECKV(i == N, "3000 handles of three kinds are created (the old table ended at 512)", "stopped at %lu, error %lu", (unsigned long)i, (unsigned long)GetLastError());
    made = i;
    for (i = 1; i < made && distinct; ++i) if (h[i] == h[i - 1] || h[i] == 0) distinct = 0;
    CHECK(distinct, "neighbouring handles are distinct and non-NULL");
    CHECKV(made > 2500 && (ULONG_PTR)h[made - 1] > 4096, "handle values go well past the old limit (512 entries = value 2048)", "last %p", (void *)h[made ? made - 1 : 0]);
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &now) && now >= base + made, "GetProcessHandleCount counts them");
    /* the last, highest handles work */
    last = h[made - 1];
    CHECK(DuplicateHandle(GetCurrentProcess(), last, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS) && dup != 0 && dup != last, "DuplicateHandle of the highest handle");
    CHECK(WaitForSingleObject(h[0], 0) == WAIT_OBJECT_0, "an event created signaled (index 0) is signaled");
    CHECK(WaitForSingleObject(h[3], 0) == WAIT_TIMEOUT, "an event created unsignaled (index 3) times out");
    CHECK(WaitForSingleObject(h[made - 2 - ((made - 2) % 3) + 1], 0) == WAIT_OBJECT_0, "a semaphore with a count of one acquires (highest kind-1 handle)");
    CHECK(SetEvent(h[made - 3 - ((made - 3) % 3)]) && WaitForSingleObject(h[made - 3 - ((made - 3) % 3)], 0) == WAIT_OBJECT_0, "SetEvent and a wait on a high event handle");
    CloseHandle(dup);

    /* a full table is a clean failure, and a close makes room again */
    for (i = 0; i < 4200; ++i) {
        more[i] = CreateEventW(0, TRUE, FALSE, 0);
        if (!more[i]) break;
        ++extra;
    }
    CHECKV(i < 4200 && extra > 0, "creating handles until the table is full ends in a NULL return, not a crash", "%u extra before failing", extra);
    SetLastError(0);
    CHECK(CreateEventW(0, TRUE, FALSE, 0) == 0 && GetLastError() != 0, "and keeps failing with a last error set");
    CloseHandle(more[0]);
    {
        HANDLE again = CreateEventW(0, TRUE, FALSE, 0);
        CHECK(again != 0, "a closed handle's slot is reusable");
        if (again) CloseHandle(again);
    }
    for (i = 1; i < extra; ++i) CloseHandle(more[i]);
    for (i = 0; i < made; ++i) CloseHandle(h[i]);
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &now) && now <= base + 1, "every handle is released again");
    return k32t_finish("t_handle_table");
}
