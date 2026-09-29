/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 SLIST: InitializeSListHead, InterlockedPush/Pop/FlushSList, InterlockedPushListSListEx, QueryDepthSList.
 * Single-thread semantics from the documentation, then a multi-thread conservation stress (no entry lost or duplicated). */
#include "k32test.h"

typedef struct { SLIST_ENTRY link; ULONG64 id; volatile LONG hits; } NODE;

#define NENT 24
#define NTHREADS 4
#define ROUNDS 3000

static SLIST_HEADER head;
static NODE nodes[NENT] __attribute__((aligned(16)));

static DWORD WINAPI worker(LPVOID arg)
{
    LONG i, bad = 0;
    (void)arg;
    for (i = 0; i < ROUNDS; ++i) {
        NODE *n;
        do { n = (NODE *)InterlockedPopEntrySList(&head); } while (!n);
        if (n->id < 1000 || n->id >= 1000 + NENT) ++bad;                 /* the payload must be intact */
        InterlockedIncrement(&n->hits);
        InterlockedPushEntrySList(&head, &n->link);
    }
    return (DWORD)bad;
}

static void test_basic(void)
{
    PSLIST_ENTRY e;
    NODE *n[4];
    unsigned i;
    static SLIST_HEADER hh __attribute__((aligned(16)));
    static NODE loc[4] __attribute__((aligned(16)));
    InitializeSListHead(&hh);
    CHECK(QueryDepthSList(&hh) == 0, "a new list has depth 0");
    CHECK(InterlockedPopEntrySList(&hh) == 0, "popping an empty list returns NULL");
    CHECK(InterlockedFlushSList(&hh) == 0, "flushing an empty list returns NULL");
    for (i = 0; i < 4; ++i) { n[i] = &loc[i]; loc[i].id = i + 1; }
    CHECK(InterlockedPushEntrySList(&hh, &n[0]->link) == 0, "the first push returns NULL (the previous top)");
    CHECK(InterlockedPushEntrySList(&hh, &n[1]->link) == &n[0]->link, "push returns the previous top");
    CHECK(InterlockedPushEntrySList(&hh, &n[2]->link) == &n[1]->link, "push returns the previous top (2)");
    CHECK(QueryDepthSList(&hh) == 3, "depth is 3 after three pushes");
    e = InterlockedPopEntrySList(&hh);
    CHECK(e == &n[2]->link && ((NODE *)e)->id == 3, "pop returns the most recent entry (LIFO)");
    CHECK(QueryDepthSList(&hh) == 2, "depth is 2 after a pop");
    InterlockedPushEntrySList(&hh, &n[3]->link);
    e = InterlockedFlushSList(&hh);
    CHECK(e == &n[3]->link && e->Next == &n[1]->link && e->Next->Next == &n[0]->link && e->Next->Next->Next == 0,
          "flush returns the whole chain, newest first, NULL terminated");
    CHECK(QueryDepthSList(&hh) == 0 && InterlockedPopEntrySList(&hh) == 0, "the list is empty after a flush");
    CHECK(InterlockedPushEntrySList(&hh, &n[0]->link) == 0, "the list is reusable after a flush");
    InterlockedPopEntrySList(&hh);
    /* a pre-linked list pushed in one operation */
    loc[0].link.Next = &loc[1].link;
    loc[1].link.Next = &loc[2].link;
    CHECK(InterlockedPushEntrySList(&hh, &n[3]->link) == 0, "seed entry");
    CHECK(InterlockedPushListSListEx(&hh, &loc[0].link, &loc[2].link, 3) == &n[3]->link, "PushListSListEx returns the previous top");
    CHECK(QueryDepthSList(&hh) == 4, "PushListSListEx adds Count to the depth");
    CHECK(InterlockedPopEntrySList(&hh) == &loc[0].link && InterlockedPopEntrySList(&hh) == &loc[1].link &&
          InterlockedPopEntrySList(&hh) == &loc[2].link && InterlockedPopEntrySList(&hh) == &n[3]->link &&
          InterlockedPopEntrySList(&hh) == 0, "the pushed list comes off in order, then the old top");
    {
        static NODE big[1000] __attribute__((aligned(16)));
        for (i = 0; i < 1000; ++i) InterlockedPushEntrySList(&hh, &big[i].link);
        CHECK(QueryDepthSList(&hh) == 1000, "depth counts pushes (1000)");
        e = InterlockedFlushSList(&hh);
        CHECK(e == &big[999].link && QueryDepthSList(&hh) == 0, "flush returns the newest of 1000 and resets the depth");
        for (i = 0; e; e = e->Next) ++i;
        CHECK(i == 1000, "the flushed chain has 1000 entries");
    }
}

static void test_stress(void)
{
    HANDLE th[NTHREADS];
    DWORD code, total_bad = 0;
    LONG total_hits = 0;
    unsigned i, seen = 0;
    int created = 0;
    PSLIST_ENTRY e;
    unsigned char mark[NENT];
    InitializeSListHead(&head);
    for (i = 0; i < NENT; ++i) { nodes[i].id = 1000 + i; nodes[i].hits = 0; InterlockedPushEntrySList(&head, &nodes[i].link); }
    CHECK(QueryDepthSList(&head) == NENT, "stress list holds every node");
    for (i = 0; i < NTHREADS; ++i) {
        th[i] = CreateThread(0, 0, worker, 0, 0, 0);
        if (th[i]) ++created;
    }
    CHECKV(created == NTHREADS, "worker threads created", "created %d", created);
    for (i = 0; i < (unsigned)created; ++i) {
        WaitForSingleObject(th[i], INFINITE);
        code = 0;
        GetExitCodeThread(th[i], &code);
        total_bad += code;
        CloseHandle(th[i]);
    }
    CHECKV(total_bad == 0, "no worker saw a corrupt node", "bad=%u", (unsigned)total_bad);
    CHECKV(QueryDepthSList(&head) == NENT, "depth is back to the node count", "depth=%u", (unsigned)QueryDepthSList(&head));
    for (i = 0; i < NENT; ++i) { total_hits += nodes[i].hits; mark[i] = 0; }
    CHECKV(total_hits == created * ROUNDS, "every pop was matched by a push", "hits=%d expected=%d", (int)total_hits, created * ROUNDS);
    e = InterlockedFlushSList(&head);
    for (; e; e = e->Next) {
        NODE *n = (NODE *)e;
        const ULONG64 k = n->id - 1000;
        if (k < NENT && !mark[k]) { mark[k] = 1; ++seen; } else seen += 1000;   /* duplicate or foreign node */
    }
    CHECKV(seen == NENT, "flush yields every node exactly once", "seen=%u", seen);
}

int main(void)
{
    test_basic();
    test_stress();
    return k32t_finish("t_k32_slist");
}
