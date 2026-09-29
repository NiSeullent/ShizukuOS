/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 Global/Local memory: fixed and movable blocks, locking, resizing, handles, flags. Documented Win32 semantics. */
#include "k32test.h"

static int all_zero(const unsigned char *p, size_t n) { size_t i; for (i = 0; i < n; ++i) if (p[i]) return 0; return 1; }

static void test_fixed(void)
{
    unsigned char *p;
    HGLOBAL g;
    p = GlobalAlloc(GPTR, 100);
    CHECK(p != NULL, "GlobalAlloc(GPTR, 100)");
    CHECK(p && GlobalSize(p) >= 100, "GlobalSize of a fixed block is at least the requested size");
    CHECK(p && all_zero(p, 100), "GPTR memory is zero-initialised");
    memset(p, 0xA5, 100);
    CHECK(GlobalHandle(p) == (HGLOBAL)p, "for fixed memory the handle is the pointer");
    CHECK(GlobalLock(p) == p, "GlobalLock on fixed memory returns the pointer");
    SetLastError(0);
    CHECK_W(!GlobalUnlock(p), "GlobalUnlock on fixed memory returns FALSE");
    g = GlobalReAlloc(p, 300, GMEM_MOVEABLE | GMEM_ZEROINIT);
    CHECK(g != NULL, "GlobalReAlloc(fixed, GMEM_MOVEABLE) succeeds");
    p = g;
    CHECK(p && GlobalSize(p) >= 300, "the resized block is at least 300 bytes");
    {
        size_t i;
        int intact = 1;
        for (i = 0; i < 100 && p; ++i) if (p[i] != 0xA5) intact = 0;
        CHECK(intact, "resizing preserves the old contents");
        CHECK(p && all_zero(p + 100, 200), "GMEM_ZEROINIT zeroes the added bytes");
    }
    CHECK(GlobalFree(p) == NULL, "GlobalFree of a fixed block returns NULL");
    p = GlobalAlloc(GMEM_FIXED, 1 << 20);
    CHECK(p != NULL && GlobalSize(p) >= (1 << 20), "a 1 MiB fixed block");
    if (p) { p[0] = 1; p[(1 << 20) - 1] = 2; GlobalFree(p); }
    p = LocalAlloc(LPTR, 64);
    CHECK(p != NULL && all_zero(p, 64) && LocalSize(p) >= 64, "LocalAlloc(LPTR)");
    CHECK(LocalHandle(p) == (HLOCAL)p && LocalLock(p) == p, "LocalHandle/LocalLock on fixed memory");
    CHECK(LocalFree(p) == NULL, "LocalFree of a fixed block returns NULL");
}

static void test_movable(void)
{
    HGLOBAL h, h2;
    unsigned char *p, *q;
    h = GlobalAlloc(GHND, 64);
    CHECK(h != NULL, "GlobalAlloc(GHND, 64)");
    CHECK(h && GlobalSize(h) >= 64, "GlobalSize of a movable block");
    p = GlobalLock(h);
    CHECK(p != NULL && (void *)p != (void *)h, "GlobalLock returns a data pointer that is not the handle");
    CHECK(p && all_zero(p, 64), "GHND memory is zero-initialised");
    CHECK((GlobalFlags(h) & GMEM_LOCKCOUNT) == 1, "the lock count is 1 after GlobalLock");
    q = GlobalLock(h);
    CHECK(q == p && (GlobalFlags(h) & GMEM_LOCKCOUNT) == 2, "a second GlobalLock returns the same pointer and counts 2");
    CHECK(GlobalHandle(p) == h, "GlobalHandle maps the data pointer back to the handle");
    memcpy(p, "hello movable memory", 21);
    SetLastError(0xdead);
    CHECK(GlobalUnlock(h) == TRUE, "GlobalUnlock returns TRUE while locks remain");
    SetLastError(0xdead);
    CHECK(GlobalUnlock(h) == FALSE, "the last GlobalUnlock returns FALSE");
    CHECK_ERR(NO_ERROR, "the last GlobalUnlock reports NO_ERROR");
    SetLastError(0);
    CHECK(GlobalUnlock(h) == FALSE, "unlocking an unlocked block returns FALSE");
    CHECK_ERR(ERROR_NOT_LOCKED, "unlocking an unlocked block: ERROR_NOT_LOCKED");
    CHECK((GlobalFlags(h) & GMEM_LOCKCOUNT) == 0, "the lock count is back to 0");
    h2 = GlobalReAlloc(h, 4096, GMEM_MOVEABLE | GMEM_ZEROINIT);
    CHECK(h2 == h, "reallocating a movable block keeps the handle");
    p = GlobalLock(h);
    CHECK(p != NULL && !memcmp(p, "hello movable memory", 21), "the contents survive GlobalReAlloc");
    CHECK(p && all_zero(p + 64, 4096 - 64), "GMEM_ZEROINIT zeroes the added bytes of a movable block");
    CHECK(GlobalSize(h) >= 4096, "the movable block grew");
    GlobalUnlock(h);
    h2 = GlobalReAlloc(h, 16, GMEM_MOVEABLE);
    p = GlobalLock(h2);
    CHECK(p != NULL && !memcmp(p, "hello movable me", 16), "shrinking keeps the leading bytes");
    GlobalUnlock(h2);
    CHECK(GlobalFree(h2) == NULL, "GlobalFree of a movable block returns NULL");
    /* zero-size movable memory */
    h = GlobalAlloc(GMEM_MOVEABLE, 0);
    CHECK(h != NULL, "a zero-size movable block has a handle");
    CHECK(h && GlobalSize(h) == 0, "and a size of zero");
    if (h) GlobalFree(h);
    /* the Local functions address the same memory */
    h = LocalAlloc(LHND, 32);
    p = LocalLock(h);
    CHECK(h != NULL && p != NULL && (void *)p != (void *)h && all_zero(p, 32), "LocalAlloc(LHND)/LocalLock");
    CHECK(GlobalHandle(p) == h && LocalHandle(p) == h, "Local and Global see the same block");
    CHECK(LocalUnlock(h) == FALSE, "LocalUnlock of the only lock returns FALSE");
    CHECK(LocalSize(h) >= 32, "LocalSize");
    CHECK(LocalReAlloc(h, 64, LMEM_MOVEABLE) == h, "LocalReAlloc keeps the handle");
    CHECK(LocalFree(h) == NULL, "LocalFree of a movable block returns NULL");
}

static void test_many(void)
{
    enum { N = 500 };
    HGLOBAL h[N];
    int i, distinct = 1, ok = 1;
    for (i = 0; i < N; ++i) {
        h[i] = GlobalAlloc(GMEM_MOVEABLE, 16 + (SIZE_T)i);
        if (!h[i]) ok = 0;
        else { unsigned char *p = GlobalLock(h[i]); if (!p) ok = 0; else { p[0] = (unsigned char)i; p[15] = (unsigned char)(i * 3); GlobalUnlock(h[i]); } }
    }
    CHECK(ok, "500 movable blocks can be allocated and locked");
    for (i = 1; i < N; ++i) if (h[i] == h[i - 1]) distinct = 0;
    CHECK(distinct, "handles are distinct");
    ok = 1;
    for (i = 0; i < N; ++i) {
        unsigned char *p = GlobalLock(h[i]);
        if (!p || p[0] != (unsigned char)i || p[15] != (unsigned char)(i * 3) || GlobalSize(h[i]) < (SIZE_T)(16 + i)) ok = 0;
        if (p) GlobalUnlock(h[i]);
    }
    CHECK(ok, "every block kept its own data");
    for (i = 0; i < N; i += 2) GlobalFree(h[i]);
    for (i = 0; i < N; i += 2) h[i] = GlobalAlloc(GMEM_MOVEABLE, 8);          /* reuse the released slots */
    ok = 1;
    for (i = 0; i < N; ++i) if (!h[i]) ok = 0;
    CHECK(ok, "released slots are reused");
    for (i = 0; i < N; ++i) GlobalFree(h[i]);
}

static void test_errors(void)
{
    SetLastError(0);
    CHECK_W(GlobalAlloc(0x10000000, 10) == NULL, "an undefined flag bit is rejected");
    CHECK_W(GetLastError() == ERROR_INVALID_PARAMETER, "undefined flag: ERROR_INVALID_PARAMETER");
    SetLastError(0);
    CHECK(GlobalLock(NULL) == NULL, "GlobalLock(NULL) fails");
    CHECK_W(GetLastError() == ERROR_INVALID_HANDLE, "GlobalLock(NULL): ERROR_INVALID_HANDLE");
    CHECK((GlobalFlags((HGLOBAL)(ULONG_PTR)0x1234) & GMEM_INVALID_HANDLE) != 0, "GlobalFlags of a bogus handle reports GMEM_INVALID_HANDLE");
    {
        unsigned char stack_block[64] __attribute__((aligned(16)));
        CHECK_W((GlobalFlags((HGLOBAL)stack_block) & GMEM_INVALID_HANDLE) != 0, "GlobalFlags of a 16-byte aligned stack address reports GMEM_INVALID_HANDLE");
        CHECK_W((LocalFlags((HLOCAL)(stack_block + 32)) & LMEM_INVALID_HANDLE) != 0, "LocalFlags of another stack address reports LMEM_INVALID_HANDLE");
    }
}

/* HeapValidate / HeapSize / HeapReAlloc on the process heap: documented results for valid, freed and foreign blocks. */
static void test_heap(void)
{
    HANDLE heap = GetProcessHeap();
    unsigned char stack_block[64] __attribute__((aligned(16)));
    unsigned char *p, *q, *big;
    size_t i;
    int intact;
    p = HeapAlloc(heap, 0, 200);
    CHECK(p != NULL && HeapSize(heap, 0, p) == 200, "HeapAlloc(200): HeapSize is 200");
    CHECK(HeapValidate(heap, 0, p), "HeapValidate accepts a live block");
    CHECK(HeapValidate(heap, 0, NULL), "HeapValidate(heap, 0, NULL) validates the whole heap");
    CHECK(!HeapValidate(heap, 0, stack_block), "HeapValidate rejects a stack address");
    for (i = 0; i < 200; ++i) p[i] = (unsigned char)i;
    q = HeapReAlloc(heap, HEAP_REALLOC_IN_PLACE_ONLY, p, 100);
    CHECK(q == p, "shrinking with HEAP_REALLOC_IN_PLACE_ONLY keeps the block where it is");
    CHECK(HeapSize(heap, 0, p) == 100, "and HeapSize reports the new size");
    for (i = 0, intact = 1; i < 100; ++i) if (p[i] != (unsigned char)i) intact = 0;
    CHECK(intact, "the leading bytes are unchanged");
    q = HeapReAlloc(heap, HEAP_ZERO_MEMORY, p, 5000);
    CHECK(q != NULL && HeapSize(heap, 0, q) == 5000, "growing to 5000 bytes");
    for (i = 0, intact = 1; q && i < 100; ++i) if (q[i] != (unsigned char)i) intact = 0;
    CHECK(intact, "growing keeps the contents");
    for (i = 100, intact = 1; q && i < 5000; ++i) if (q[i]) intact = 0;
    CHECK(intact, "HEAP_ZERO_MEMORY zeroes the added bytes");
    CHECK(q && HeapFree(heap, 0, q), "HeapFree");
    CHECK(q && !HeapValidate(heap, 0, q), "HeapValidate rejects a freed block");
    big = HeapAlloc(heap, HEAP_ZERO_MEMORY, 3 << 20);
    CHECK(big != NULL && HeapSize(heap, 0, big) == (SIZE_T)3 << 20, "a 3 MiB block has HeapSize 3 MiB");
    CHECK(big && big[0] == 0 && big[(3 << 20) - 1] == 0, "HEAP_ZERO_MEMORY on the 3 MiB block");
    CHECK(big && HeapValidate(heap, 0, big), "HeapValidate accepts the large block");
    CHECK(big && !HeapValidate(heap, 0, big + 4096), "HeapValidate rejects a pointer into the middle of it");
    CHECK(big && HeapFree(heap, 0, big), "HeapFree of the large block");
    p = GlobalAlloc(GMEM_FIXED, 256);
    q = GlobalReAlloc(p, 64, 0);
    CHECK(p != NULL && q == p, "GlobalReAlloc of fixed memory to a smaller size without GMEM_MOVEABLE stays in place");
    CHECK(q && GlobalSize(q) >= 64 && GlobalSize(q) < 256, "and the size shrinks");
    if (q) GlobalFree(q);
}

int main(void)
{
    test_fixed();
    test_movable();
    test_many();
    test_errors();
    test_heap();
    return k32t_finish("t_k32_mem");
}
