/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: interlocked singly linked lists (SLIST), lock-free with CMPXCHG16B.
 *
 * Header layout is the documented HeaderX64 of winnt.h: low quadword Depth:16 | Sequence:48, high quadword HeaderType:1
 * | Reserved:3 | NextEntry:60 (the entry pointer, which is 16-byte aligned, so NextEntry holds pointer >> 4). Both quadwords are
 * replaced with one 16-byte compare-exchange; the sequence number grows on every push and pop, which defeats the ABA problem.
 * Entries and the header must be 16-byte aligned (otherwise STATUS_DATATYPE_MISALIGNMENT is raised, as on Windows).
 * Like Windows this code reads the link of the entry it is about to pop; an entry must therefore stay mapped until no thread can
 * still be popping (Windows papers over an unmapped entry with an exception handler, this implementation does not).
 */
#include "k32.h"

typedef struct { volatile uint64_t lo, hi; } slist_raw;

static inline int cas16(slist_raw *h, uint64_t old_lo, uint64_t old_hi, uint64_t new_lo, uint64_t new_hi)
{
    unsigned char ok;
    __asm__ volatile("lock cmpxchg16b %1\n\tsetz %0"
                     : "=q"(ok), "+m"(*h), "+a"(old_lo), "+d"(old_hi)
                     : "b"(new_lo), "c"(new_hi)
                     : "memory", "cc");
    return ok;
}

static void require_aligned(const void *p)
{
    if ((uintptr_t)p & 15) RaiseException(STATUS_DATATYPE_MISALIGNMENT, EXCEPTION_NONCONTINUABLE, 0, 0);
}

static uint64_t pack_lo(uint64_t lo, unsigned depth_delta_sign, unsigned n)
{
    const uint64_t depth = depth_delta_sign ? (lo - n) & 0xffff : (lo + n) & 0xffff;
    const uint64_t seq = ((lo >> 16) + 1) & 0xffffffffffffull;
    return depth | (seq << 16);
}

#define NEXT_OF(hi) ((PSLIST_ENTRY)(uintptr_t)((hi) & ~0xfull))
#define HDR(next) (((uint64_t)(uintptr_t)(next)) | 1ull)                  /* HeaderType = 1: the 16-byte format */

K32API VOID WINAPI InitializeSListHead(PSLIST_HEADER head)
{
    slist_raw *h = (slist_raw *)head;
    require_aligned(head);
    h->lo = 0;
    h->hi = HDR(0);
}

K32API USHORT WINAPI QueryDepthSList(PSLIST_HEADER head) { return (USHORT)(((slist_raw *)head)->lo & 0xffff); }

K32API PSLIST_ENTRY WINAPI InterlockedPushEntrySList(PSLIST_HEADER head, PSLIST_ENTRY entry)
{
    slist_raw *h = (slist_raw *)head;
    require_aligned(head);
    require_aligned(entry);
    for (;;) {
        const uint64_t lo = h->lo, hi = h->hi;
        PSLIST_ENTRY first = NEXT_OF(hi);
        entry->Next = first;
        if (cas16(h, lo, hi, pack_lo(lo, 0, 1), HDR(entry))) return first;
    }
}

K32API PSLIST_ENTRY WINAPI InterlockedPushListSListEx(PSLIST_HEADER head, PSLIST_ENTRY list, PSLIST_ENTRY list_end, ULONG count)
{
    slist_raw *h = (slist_raw *)head;
    require_aligned(head);
    require_aligned(list);
    require_aligned(list_end);
    for (;;) {
        const uint64_t lo = h->lo, hi = h->hi;
        PSLIST_ENTRY first = NEXT_OF(hi);
        list_end->Next = first;
        if (cas16(h, lo, hi, pack_lo(lo, 0, count), HDR(list))) return first;
    }
}

K32API PSLIST_ENTRY WINAPI InterlockedPopEntrySList(PSLIST_HEADER head)
{
    slist_raw *h = (slist_raw *)head;
    require_aligned(head);
    for (;;) {
        const uint64_t lo = h->lo, hi = h->hi;
        PSLIST_ENTRY first = NEXT_OF(hi);
        if (!first) return 0;
        if (cas16(h, lo, hi, pack_lo(lo, 1, 1), HDR(first->Next))) return first;
    }
}

K32API PSLIST_ENTRY WINAPI InterlockedFlushSList(PSLIST_HEADER head)
{
    slist_raw *h = (slist_raw *)head;
    require_aligned(head);
    for (;;) {
        const uint64_t lo = h->lo, hi = h->hi;
        PSLIST_ENTRY first = NEXT_OF(hi);
        if (!first) return 0;
        if (cas16(h, lo, hi, pack_lo(lo, 1, (unsigned)(lo & 0xffff)), HDR(0))) return first;
    }
}
