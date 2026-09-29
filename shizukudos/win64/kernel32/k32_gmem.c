/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: GlobalAlloc/LocalAlloc family with fixed and movable memory (Local and Global are the same memory on Win32).
 *
 * Fixed memory (GMEM_FIXED) is a block of the process heap and its handle is its address. Movable memory (GMEM_MOVEABLE) has a
 * handle that is the address of a slot in a private table (one 1 MiB reservation, 32 bytes per slot, 32768 slots); the slot holds
 * the data pointer, the size and the lock count. Whether a value is a handle is decided by its address alone, which is how
 * GlobalFree, GlobalLock and friends tell the two apart. Anything else must be a live block of the process heap: that is checked
 * with RtlValidateHeap (which only reads the heap's own memory) before the heap is asked about it, so a bogus or stale value fails
 * with ERROR_INVALID_HANDLE instead of being dereferenced. GlobalLock counts up to 255. GlobalReAlloc of fixed memory without
 * GMEM_MOVEABLE resizes in place or fails; a locked movable block is reallocated regardless of its lock count (its data pointer may
 * change). GMEM_DISCARDABLE is stored and reported by GlobalFlags but memory is never discarded.
 */
#include "k32.h"

typedef struct gh {
    void *data;
    SIZE_T size;
    USHORT lock, flags;
    ULONG magic;
    struct gh *next_free;
} gh_t;
#define GH_MAGIC 0x484c4747u
#define GH_TABLE_BYTES (1u << 20)
#define GMEM_ALLOC_VALID GMEM_VALID_FLAGS                         /* 0x7f72, as in winbase.h */

static volatile LONG gh_lock;
static gh_t *gh_tab, *gh_next, *gh_end, *gh_free;

static void gl_lock(void) { while (__sync_lock_test_and_set(&gh_lock, 1)) NtYieldExecution(); }
static void gl_unlock(void) { __sync_lock_release(&gh_lock); }

static int gh_is_handle(const void *h)
{
    const gh_t *s = h;
    return gh_tab && s >= gh_tab && s < gh_end && ((uintptr_t)s - (uintptr_t)gh_tab) % sizeof(gh_t) == 0 && s->magic == GH_MAGIC;
}

static gh_t *gh_alloc(void)
{
    gh_t *s = 0;
    gl_lock();
    if (!gh_tab) {
        PVOID base = 0;
        SIZE_T size = GH_TABLE_BYTES;
        if (NtAllocateVirtualMemory(CURRENT_PROCESS, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) == 0) {
            gh_tab = gh_next = base;
            gh_end = (gh_t *)((uint8_t *)base + size);
        }
    }
    if (gh_free) { s = gh_free; gh_free = s->next_free; }
    else if (gh_next && gh_next < gh_end) s = gh_next++;
    if (s) { memset(s, 0, sizeof *s); s->magic = GH_MAGIC; }
    gl_unlock();
    return s;
}

static void gh_release(gh_t *s)
{
    gl_lock();
    s->magic = 0;
    s->data = 0;
    s->next_free = gh_free;
    gh_free = s;
    gl_unlock();
}

/* A fixed block is a live allocation of the process heap; heap payloads are 16-byte aligned. */
static int fixed_valid(const void *p) { return p && !((uintptr_t)p & 15) && RtlValidateHeap(ShzProcessHeap(), 0, (PVOID)p); }

static HGLOBAL mem_alloc(UINT flags, SIZE_T size)
{
    if (flags & ~(UINT)GMEM_ALLOC_VALID) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (!(flags & GMEM_MOVEABLE)) {
        PVOID p = RtlAllocateHeap(ShzProcessHeap(), (flags & GMEM_ZEROINIT) ? HEAP_ZERO_MEMORY : 0, size);
        if (!p) shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return p;
    }
    {
        gh_t *s = gh_alloc();
        if (!s) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
        s->flags = (USHORT)(flags & GMEM_DISCARDABLE);
        s->size = size;
        if (size) {
            s->data = RtlAllocateHeap(ShzProcessHeap(), (flags & GMEM_ZEROINIT) ? HEAP_ZERO_MEMORY : 0, size);
            if (!s->data) { gh_release(s); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
        }
        return s;
    }
}

static HGLOBAL mem_free(HGLOBAL h)
{
    if (!h) return 0;                                   /* GlobalFree(NULL)/LocalFree(NULL): no-op, LastError untouched (as Windows) */
    if (gh_is_handle(h)) {
        gh_t *s = h;
        if (s->data) RtlFreeHeap(ShzProcessHeap(), 0, s->data);
        gh_release(s);
        return 0;
    }
    if (!fixed_valid(h)) { shz_set_last_error(ERROR_INVALID_HANDLE); return h; }
    return RtlFreeHeap(ShzProcessHeap(), 0, h) ? 0 : h;
}

static LPVOID mem_lock(HGLOBAL h)
{
    if (!h) { shz_set_last_error(ERROR_INVALID_HANDLE); return 0; }
    if (gh_is_handle(h)) {
        gh_t *s = h;
        gl_lock();
        if (s->data && s->lock < 0xFF) ++s->lock;
        gl_unlock();
        if (!s->data) shz_set_last_error(ERROR_DISCARDED);
        return s->data;
    }
    if (!fixed_valid(h)) { shz_set_last_error(ERROR_INVALID_HANDLE); return 0; }
    return h;
}

static BOOL mem_unlock(HGLOBAL h)
{
    if (!h) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    if (gh_is_handle(h)) {
        gh_t *s = h;
        BOOL still;
        gl_lock();
        if (s->lock == 0) { gl_unlock(); shz_set_last_error(ERROR_NOT_LOCKED); return FALSE; }
        still = --s->lock != 0;
        gl_unlock();
        if (!still) shz_set_last_error(NO_ERROR);                       /* unlocked: FALSE with NO_ERROR */
        return still;
    }
    if (!fixed_valid(h)) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    shz_set_last_error(ERROR_NOT_LOCKED);                                 /* fixed memory is never locked */
    return FALSE;
}

static SIZE_T mem_size(HGLOBAL h)
{
    if (gh_is_handle(h)) return ((gh_t *)h)->size;
    if (fixed_valid(h)) return RtlSizeHeap(ShzProcessHeap(), 0, h);
    shz_set_last_error(ERROR_INVALID_HANDLE);
    return 0;
}

static HGLOBAL mem_realloc(HGLOBAL h, SIZE_T size, UINT flags)
{
    if (flags & ~(UINT)(GMEM_ALLOC_VALID | GMEM_MODIFY)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (gh_is_handle(h)) {
        gh_t *s = h;
        if (flags & GMEM_MODIFY) {
            s->flags = (USHORT)((s->flags & ~GMEM_DISCARDABLE) | (flags & GMEM_DISCARDABLE));
            return h;
        }
        if (size == 0) {                                                  /* discard the contents */
            if (s->data) RtlFreeHeap(ShzProcessHeap(), 0, s->data);
            s->data = 0; s->size = 0;
            return h;
        }
        {
            PVOID n = s->data ? RtlReAllocateHeap(ShzProcessHeap(), (flags & GMEM_ZEROINIT) ? HEAP_ZERO_MEMORY : 0, s->data, size)
                              : RtlAllocateHeap(ShzProcessHeap(), (flags & GMEM_ZEROINIT) ? HEAP_ZERO_MEMORY : 0, size);
            if (!n) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
            if ((flags & GMEM_ZEROINIT) && s->data && size > s->size) memset((uint8_t *)n + s->size, 0, size - s->size);
            s->data = n;
            s->size = size;
        }
        return h;
    }
    if (!fixed_valid(h)) { shz_set_last_error(ERROR_INVALID_HANDLE); return 0; }
    if (flags & GMEM_MODIFY) return h;                                    /* nothing to change for fixed memory */
    if (size == RtlSizeHeap(ShzProcessHeap(), 0, h)) return h;
    {
        const ULONG hf = ((flags & GMEM_ZEROINIT) ? HEAP_ZERO_MEMORY : 0) | ((flags & GMEM_MOVEABLE) ? 0 : HEAP_REALLOC_IN_PLACE_ONLY);
        PVOID n = RtlReAllocateHeap(ShzProcessHeap(), hf, h, size);
        if (!n) shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY);                            /* without GMEM_MOVEABLE: cannot resize in place */
        return n;
    }
}

static HGLOBAL mem_handle(LPCVOID p)
{
    gh_t *s;
    if (!p) { shz_set_last_error(ERROR_INVALID_HANDLE); return 0; }
    if (gh_is_handle(p)) return (HGLOBAL)p;
    gl_lock();
    if (gh_tab)
        for (s = gh_tab; s < gh_next; ++s)
            if (s->magic == GH_MAGIC && s->data == p) { gl_unlock(); return s; }
    gl_unlock();
    if (fixed_valid(p)) return (HGLOBAL)p;
    shz_set_last_error(ERROR_INVALID_HANDLE);
    return 0;
}

static UINT mem_flags(HGLOBAL h)
{
    if (gh_is_handle(h)) {
        const gh_t *s = h;
        return (UINT)(s->lock & GMEM_LOCKCOUNT) | (s->data ? 0 : GMEM_DISCARDED) | (s->flags & GMEM_DISCARDABLE);
    }
    if (fixed_valid(h)) return 0;
    return GMEM_INVALID_HANDLE;
}

K32API HGLOBAL WINAPI GlobalAlloc(UINT flags, SIZE_T size) { return mem_alloc(flags, size); }
K32API HGLOBAL WINAPI GlobalFree(HGLOBAL h) { return mem_free(h); }
K32API LPVOID WINAPI GlobalLock(HGLOBAL h) { return mem_lock(h); }
K32API BOOL WINAPI GlobalUnlock(HGLOBAL h) { return mem_unlock(h); }
K32API SIZE_T WINAPI GlobalSize(HGLOBAL h) { return mem_size(h); }
K32API HGLOBAL WINAPI GlobalReAlloc(HGLOBAL h, SIZE_T size, UINT flags) { return mem_realloc(h, size, flags); }
K32API HGLOBAL WINAPI GlobalHandle(LPCVOID p) { return mem_handle(p); }
K32API UINT WINAPI GlobalFlags(HGLOBAL h) { return mem_flags(h); }

K32API HLOCAL WINAPI LocalAlloc(UINT flags, SIZE_T size) { return mem_alloc(flags, size); }
K32API HLOCAL WINAPI LocalFree(HLOCAL h) { return mem_free(h); }
K32API LPVOID WINAPI LocalLock(HLOCAL h) { return mem_lock(h); }
K32API BOOL WINAPI LocalUnlock(HLOCAL h) { return mem_unlock(h); }
K32API SIZE_T WINAPI LocalSize(HLOCAL h) { return mem_size(h); }
K32API HLOCAL WINAPI LocalReAlloc(HLOCAL h, SIZE_T size, UINT flags) { return mem_realloc(h, size, flags); }
K32API HLOCAL WINAPI LocalHandle(LPCVOID p) { return mem_handle(p); }
K32API UINT WINAPI LocalFlags(HLOCAL h) { return mem_flags(h); }
