/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku ntdll.dll (NTDLLWrapper9x, user mode, AMD64). Process/thread start-up, loader
 * initialisation hand-over, heap, NTSTATUS mapping and the Ldr* entry points that sit on
 * top of the kernel's stage-0 PE loader.
 *
 * Owner of: Nt* and Zw* stubs (generated), Rtl heap/string/status helpers, Ldr*, Rtl exception
 * dispatch (unwind.c), critical sections/SRW/condition variables/WaitOnAddress (sync.c).
 * Not owner of: Win32 semantics (kernel32.dll), C runtime.
 */
#include "nt.h"
#include "ntdll_int.h"

/* ---------------------------------------------------------------- diagnostics */
void ShzDebugLine(const char *s)
{
    ULONG n = 0;
    while (s[n]) ++n;
    NtShzDebugPrint(s, n);
}

void ShzEvidence(unsigned slot, unsigned long long v) { NtShzEvidence(slot, v); }

/* ---------------------------------------------------------------- heap */
/* Segment-based first-fit allocator with coalescing. Blocks are 16-byte aligned; the heap
 * handle is the address of the heap descriptor. Large requests get their own reservation. */
#define HEAP_MAGIC 0x50414548u             /* "HEAP" */
#define BLOCK_MAGIC 0x4b4c4231u
#define BLOCK_FREE 0
#define BLOCK_USED 1
#define BLOCK_LARGE 2
#define SEGMENT_BYTES (1u << 20)
#define LARGE_THRESHOLD (256u * 1024u)

typedef struct blk {
    uint32_t magic;
    uint32_t state;
    uint64_t size;                         /* payload bytes */
    struct blk *prev_phys;                 /* previous block in the same segment (address order) */
    uint64_t user_size;                    /* requested size (RtlSizeHeap) or reservation for large */
} blk_t;                                    /* 32 bytes: payload stays 16-byte aligned */

typedef struct seg { struct seg *next; uint64_t size; } seg_t;

typedef struct heap {
    uint32_t magic;
    volatile LONG lock;
    uint32_t flags;
    seg_t *segments;
    uint64_t allocated, count;
} heap_t;

static heap_t *g_process_heap;

static void heap_lock(heap_t *h) { while (__sync_lock_test_and_set(&h->lock, 1)) NtYieldExecution(); }
static void heap_unlock(heap_t *h) { __sync_lock_release(&h->lock); }

static blk_t *next_phys(seg_t *s, blk_t *b)
{
    uint8_t *n = (uint8_t *)(b + 1) + b->size;
    return n + sizeof(blk_t) <= (uint8_t *)s + s->size ? (blk_t *)n : 0;
}

static seg_t *new_segment(heap_t *h, uint64_t min_payload)
{
    PVOID base = 0;
    SIZE_T size = SEGMENT_BYTES;
    seg_t *s;
    blk_t *b;
    while (size < min_payload + sizeof(seg_t) + 2 * sizeof(blk_t)) size *= 2;
    if (NtAllocateVirtualMemory(CURRENT_PROCESS, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
        return 0;
    s = base;
    s->size = size;
    s->next = h->segments;
    h->segments = s;
    b = (blk_t *)((uint8_t *)(s + 1) + 16);
    b = (blk_t *)(((uintptr_t)b + 15) & ~(uintptr_t)15);
    b->magic = BLOCK_MAGIC;
    b->state = BLOCK_FREE;
    b->prev_phys = 0;
    b->size = (uint8_t *)s + size - (uint8_t *)(b + 1);
    return s;
}

PVOID NTAPI RtlCreateHeap(ULONG flags, PVOID base, SIZE_T reserve, SIZE_T commit, PVOID lock, PVOID params)
{
    PVOID mem = 0;
    SIZE_T size = 4096;
    heap_t *h;
    (void)base; (void)reserve; (void)commit; (void)lock; (void)params;
    if (NtAllocateVirtualMemory(CURRENT_PROCESS, &mem, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) return 0;
    h = mem;
    h->magic = HEAP_MAGIC;
    h->flags = flags;
    return h;
}

static blk_t *first_block(seg_t *s)
{
    blk_t *b = (blk_t *)((uint8_t *)(s + 1) + 16);
    return (blk_t *)(((uintptr_t)b + 15) & ~(uintptr_t)15);
}

PVOID NTAPI RtlAllocateHeap(PVOID hp, ULONG flags, SIZE_T size)
{
    heap_t *h = hp;
    seg_t *s;
    uint64_t need;
    if (!h || h->magic != HEAP_MAGIC) return 0;
    need = (size + 15) & ~15ull;
    if (!need) need = 16;
    if (need > LARGE_THRESHOLD) {                         /* dedicated reservation */
        PVOID base = 0;
        SIZE_T total = need + sizeof(blk_t) + 4096;
        blk_t *b;
        total = (total + 4095) & ~4095ull;
        if (NtAllocateVirtualMemory(CURRENT_PROCESS, &base, 0, &total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) return 0;
        b = base;
        b->magic = BLOCK_MAGIC; b->state = BLOCK_LARGE; b->size = need; b->user_size = size; b->prev_phys = (blk_t *)total;
        return b + 1;
    }
    heap_lock(h);
    for (;;) {
        for (s = h->segments; s; s = s->next) {
            blk_t *b;
            for (b = first_block(s); b; b = next_phys(s, b)) {
                if (b->magic != BLOCK_MAGIC) { heap_unlock(h); return 0; }      /* corruption: refuse to continue */
                if (b->state == BLOCK_FREE && b->size >= need) {
                    if (b->size >= need + sizeof(blk_t) + 32) {
                        blk_t *rest = (blk_t *)((uint8_t *)(b + 1) + need);
                        blk_t *after;
                        rest->magic = BLOCK_MAGIC;
                        rest->state = BLOCK_FREE;
                        rest->size = b->size - need - sizeof(blk_t);
                        rest->prev_phys = b;
                        b->size = need;
                        after = next_phys(s, rest);
                        if (after) after->prev_phys = rest;
                    }
                    b->state = BLOCK_USED;
                    b->user_size = size;
                    ++h->count;
                    h->allocated += b->size;
                    heap_unlock(h);
                    if (flags & HEAP_ZERO_MEMORY) {
                        uint8_t *p = (uint8_t *)(b + 1);
                        uint64_t i;
                        for (i = 0; i < size; ++i) p[i] = 0;
                    }
                    return b + 1;
                }
            }
        }
        if (!new_segment(h, need)) { heap_unlock(h); return 0; }
    }
}

static seg_t *segment_of(heap_t *h, blk_t *b)
{
    seg_t *s;
    for (s = h->segments; s; s = s->next)
        if ((uint8_t *)b >= (uint8_t *)s && (uint8_t *)b < (uint8_t *)s + s->size) return s;
    return 0;
}

BOOLEAN NTAPI RtlFreeHeap(PVOID hp, ULONG flags, PVOID p)
{
    heap_t *h = hp;
    blk_t *b, *n;
    seg_t *s;
    (void)flags;
    if (!p) return TRUE;
    if (!h || h->magic != HEAP_MAGIC) return FALSE;
    b = (blk_t *)p - 1;
    if (b->magic != BLOCK_MAGIC) return FALSE;
    if (b->state == BLOCK_LARGE) {
        PVOID base = b;
        SIZE_T zero = 0;
        b->magic = 0;
        return NtFreeVirtualMemory(CURRENT_PROCESS, &base, &zero, MEM_RELEASE) == 0;
    }
    heap_lock(h);
    s = segment_of(h, b);
    if (!s || b->state != BLOCK_USED) { heap_unlock(h); return FALSE; }        /* foreign pointer or double free */
    b->state = BLOCK_FREE;
    --h->count;
    h->allocated -= b->size;
    n = next_phys(s, b);
    if (n && n->state == BLOCK_FREE) {                                            /* merge with next */
        blk_t *nn;
        b->size += sizeof(blk_t) + n->size;
        n->magic = 0;
        nn = next_phys(s, b);
        if (nn) nn->prev_phys = b;
    }
    if (b->prev_phys && b->prev_phys->state == BLOCK_FREE) {                     /* merge with previous */
        blk_t *pv = b->prev_phys, *nn;
        pv->size += sizeof(blk_t) + b->size;
        b->magic = 0;
        nn = next_phys(s, pv);
        if (nn) nn->prev_phys = pv;
    }
    heap_unlock(h);
    return TRUE;
}

SIZE_T NTAPI RtlSizeHeap(PVOID hp, ULONG flags, PVOID p)
{
    blk_t *b;
    (void)hp; (void)flags;
    if (!p) return (SIZE_T)-1;
    b = (blk_t *)p - 1;
    return b->magic == BLOCK_MAGIC && b->state != BLOCK_FREE ? b->user_size : (SIZE_T)-1;
}

PVOID NTAPI RtlReAllocateHeap(PVOID hp, ULONG flags, PVOID p, SIZE_T size)
{
    PVOID n;
    SIZE_T old;
    if (!p) return RtlAllocateHeap(hp, flags, size);
    old = RtlSizeHeap(hp, flags, p);
    if (old == (SIZE_T)-1) return 0;
    n = RtlAllocateHeap(hp, flags, size);
    if (!n) return 0;
    {
        SIZE_T i, c = old < size ? old : size;
        for (i = 0; i < c; ++i) ((uint8_t *)n)[i] = ((uint8_t *)p)[i];
    }
    RtlFreeHeap(hp, flags, p);
    return n;
}

BOOLEAN NTAPI RtlDestroyHeap(PVOID hp) { (void)hp; return TRUE; }
ULONG NTAPI RtlGetProcessHeaps(ULONG n, PVOID *out) { if (n && out) out[0] = g_process_heap; return 1; }
BOOLEAN NTAPI RtlLockHeap(PVOID hp) { heap_lock(hp); return TRUE; }
BOOLEAN NTAPI RtlUnlockHeap(PVOID hp) { heap_unlock(hp); return TRUE; }
BOOLEAN NTAPI RtlValidateHeap(PVOID hp, ULONG flags, PVOID p)
{
    (void)flags;
    if (!hp || ((heap_t *)hp)->magic != HEAP_MAGIC) return FALSE;
    return !p || ((blk_t *)p - 1)->magic == BLOCK_MAGIC;
}

void ShzInitHeap(void)
{
    g_process_heap = RtlCreateHeap(0, 0, 0, 0, 0, 0);
    if (g_process_heap) PEB_PROCESS_HEAP(shz_peb()) = g_process_heap;
    else NtTerminateProcess(CURRENT_PROCESS, STATUS_NO_MEMORY);
}

/* ---------------------------------------------------------------- strings and status */
VOID NTAPI RtlInitUnicodeString(SHZ_UNICODE_STRING *d, PCWSTR s)
{
    USHORT n = 0;
    if (!s) { d->Length = d->MaximumLength = 0; d->Buffer = 0; return; }
    while (s[n]) ++n;
    d->Buffer = (PWSTR)s;
    d->Length = (USHORT)(n * 2);
    d->MaximumLength = (USHORT)(n * 2 + 2);
}

typedef struct { USHORT Length, MaximumLength; PCHAR Buffer; } SHZ_ANSI_STRING;
VOID NTAPI RtlInitAnsiString(SHZ_ANSI_STRING *d, const char *s)
{
    USHORT n = 0;
    if (!s) { d->Length = d->MaximumLength = 0; d->Buffer = 0; return; }
    while (s[n]) ++n;
    d->Buffer = (PCHAR)s;
    d->Length = n;
    d->MaximumLength = (USHORT)(n + 1);
}

static const struct { NTSTATUS status; ULONG error; } status_map[] = {
    {STATUS_SUCCESS, 0}, {STATUS_INVALID_HANDLE, ERROR_INVALID_HANDLE}, {STATUS_INVALID_PARAMETER, ERROR_INVALID_PARAMETER},
    {STATUS_ACCESS_VIOLATION, ERROR_NOACCESS}, {STATUS_NO_MEMORY, ERROR_NOT_ENOUGH_MEMORY},
    {STATUS_ACCESS_DENIED, ERROR_ACCESS_DENIED}, {STATUS_OBJECT_NAME_NOT_FOUND, ERROR_FILE_NOT_FOUND},
    {STATUS_OBJECT_PATH_NOT_FOUND, ERROR_PATH_NOT_FOUND}, {STATUS_NO_SUCH_FILE, ERROR_FILE_NOT_FOUND},
    {STATUS_OBJECT_NAME_COLLISION, ERROR_ALREADY_EXISTS}, {STATUS_END_OF_FILE, ERROR_HANDLE_EOF},
    {STATUS_BUFFER_TOO_SMALL, ERROR_INSUFFICIENT_BUFFER}, {STATUS_BUFFER_OVERFLOW, ERROR_MORE_DATA},
    {STATUS_NOT_IMPLEMENTED, ERROR_CALL_NOT_IMPLEMENTED}, {STATUS_TIMEOUT, WAIT_TIMEOUT},
    {STATUS_DLL_NOT_FOUND, ERROR_MOD_NOT_FOUND}, {STATUS_ENTRYPOINT_NOT_FOUND, ERROR_PROC_NOT_FOUND},
    {STATUS_INVALID_IMAGE_FORMAT, ERROR_BAD_EXE_FORMAT}, {STATUS_CONFLICTING_ADDRESSES, ERROR_INVALID_ADDRESS},
    {STATUS_UNABLE_TO_FREE_VM, ERROR_INVALID_PARAMETER}, {STATUS_FREE_VM_NOT_AT_BASE, ERROR_INVALID_PARAMETER},
    {STATUS_MUTANT_NOT_OWNED, ERROR_NOT_OWNER}, {STATUS_SEMAPHORE_LIMIT_EXCEEDED, ERROR_TOO_MANY_POSTS},
    {STATUS_NOT_A_DIRECTORY, ERROR_DIRECTORY}, {STATUS_FILE_IS_A_DIRECTORY, ERROR_ACCESS_DENIED},
    {STATUS_DIRECTORY_NOT_EMPTY, ERROR_DIR_NOT_EMPTY}, {STATUS_DISK_FULL, ERROR_DISK_FULL},
    {STATUS_NO_MORE_FILES, ERROR_NO_MORE_FILES}, {STATUS_OBJECT_NAME_INVALID, ERROR_INVALID_NAME},
    {STATUS_INVALID_INFO_CLASS, ERROR_INVALID_PARAMETER}, {STATUS_NOT_SUPPORTED, ERROR_NOT_SUPPORTED},
    {STATUS_SHARING_VIOLATION, ERROR_SHARING_VIOLATION}, {STATUS_CANCELLED, ERROR_OPERATION_ABORTED},
    {STATUS_PENDING, ERROR_IO_PENDING}, {STATUS_OBJECT_TYPE_MISMATCH, ERROR_INVALID_HANDLE},
    {STATUS_STACK_OVERFLOW, ERROR_STACK_OVERFLOW}, {STATUS_UNSUCCESSFUL, ERROR_GEN_FAILURE},
    /* registry (kernel64/sysreg.c) */
    {STATUS_NO_MORE_ENTRIES, ERROR_NO_MORE_ITEMS}, {STATUS_KEY_DELETED, ERROR_KEY_DELETED},
    {STATUS_CANNOT_DELETE, ERROR_ACCESS_DENIED}, {STATUS_KEY_HAS_CHILDREN, ERROR_KEY_HAS_CHILDREN},
    {STATUS_CHILD_MUST_BE_VOLATILE, ERROR_CHILD_MUST_BE_VOLATILE}, {STATUS_OBJECT_PATH_SYNTAX_BAD, ERROR_BAD_PATHNAME},
    {STATUS_INFO_LENGTH_MISMATCH, ERROR_BAD_LENGTH}, {STATUS_INSUFFICIENT_RESOURCES, ERROR_NO_SYSTEM_RESOURCES},
};

ULONG NTAPI RtlNtStatusToDosError(NTSTATUS status)
{
    unsigned i;
    shz_set_last_status(status);                   /* like Windows: TEB.LastStatusValue follows the last translation */
    for (i = 0; i < sizeof status_map / sizeof status_map[0]; ++i)
        if (status_map[i].status == status) return status_map[i].error;
    if (NT_SUCCESS(status)) return 0;
    return ERROR_MR_MID_NOT_FOUND;                 /* 317: unmapped status, never silently "success" */
}

ULONG NTAPI RtlGetLastWin32Error(void) { return shz_last_error(); }
VOID NTAPI RtlSetLastWin32Error(ULONG e) { shz_set_last_error(e); }

/* ---------------------------------------------------------------- module init */
static int call_dll_main(SHZ_LDR_ENTRY *e, int reason, void *reserved)
{
    BOOL (WINAPI *entry)(HINSTANCE, DWORD, LPVOID) = e->EntryPoint;
    return entry ? entry((HINSTANCE)e->DllBase, (DWORD)reason, reserved) : 1;
}

static void run_tls_callbacks(void *base, int reason, void *reserved)
{
    const IMAGE_DOS_HEADER *dos = base;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)((const uint8_t *)base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY *d = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    const IMAGE_TLS_DIRECTORY64 *tls;
    PIMAGE_TLS_CALLBACK *cb;
    if (!d->VirtualAddress) return;
    tls = (const IMAGE_TLS_DIRECTORY64 *)((const uint8_t *)base + d->VirtualAddress);
    cb = (PIMAGE_TLS_CALLBACK *)(uintptr_t)tls->AddressOfCallBacks;
    while (cb && *cb) {
        (*cb)(base, (DWORD)reason, reserved);
        ++cb;
    }
}

/* Runs DLL_PROCESS_ATTACH (TLS callbacks first, then DllMain) for every module the loader marked. */
void ShzRunInitRoutines(int reason, void *reserved)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InInitializationOrderModuleList, *l;
    for (l = head->Flink; l != head; l = l->Flink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InInitializationOrderLinks);
        if (reason == DLL_PROCESS_ATTACH) {
            if (!(e->Flags & SHZ_LDR_NEEDS_INIT)) continue;
            e->Flags &= ~SHZ_LDR_NEEDS_INIT;
            run_tls_callbacks(e->DllBase, reason, reserved);
            if (!call_dll_main(e, reason, reserved)) {
                ShzDebugLine("ntdll: DllMain(DLL_PROCESS_ATTACH) failed\n");
                NtTerminateProcess(CURRENT_PROCESS, (NTSTATUS)0xC0000142);       /* STATUS_DLL_INIT_FAILED */
            }
        }
    }
    if (reason == DLL_PROCESS_ATTACH) {                       /* executable TLS callbacks run after the DLLs */
        run_tls_callbacks(PEB_IMAGE_BASE(shz_peb()), reason, reserved);
    } else if (reason == DLL_PROCESS_DETACH) {                /* reverse order */
        for (l = head->Blink; l != head; l = l->Blink) {
            SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InInitializationOrderLinks);
            run_tls_callbacks(e->DllBase, reason, reserved);
            call_dll_main(e, reason, reserved);
        }
    }
}

void ShzRunThreadAttach(int reason)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InInitializationOrderModuleList, *l;
    for (l = reason == DLL_THREAD_ATTACH ? head->Flink : head->Blink; l != head;
         l = reason == DLL_THREAD_ATTACH ? l->Flink : l->Blink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InInitializationOrderLinks);
        run_tls_callbacks(e->DllBase, reason, 0);
        call_dll_main(e, reason, 0);
    }
    if (reason == DLL_THREAD_ATTACH) run_tls_callbacks(PEB_IMAGE_BASE(shz_peb()), reason, 0);
}

/* ---------------------------------------------------------------- process and thread start */
extern void ShzInitSync(void);

SHZ_EXPORT void NTAPI RtlExitUserProcess(NTSTATUS code)
{
    ShzRunInitRoutines(DLL_PROCESS_DETACH, (void *)1);
    NtTerminateProcess(CURRENT_PROCESS, code);
    for (;;) __asm__ volatile("hlt");
}

SHZ_EXPORT void NTAPI RtlExitUserThread(NTSTATUS code)
{
    ShzRunThreadAttach(DLL_THREAD_DETACH);
    NtTerminateThread(CURRENT_THREAD, code);
    for (;;) __asm__ volatile("hlt");
}

/* First user-mode code of every process: RCX = executable entry point (from the loader). */
SHZ_EXPORT void NTAPI ShzProcessStart(void *entry, void *unused)
{
    DWORD (WINAPI *main_entry)(PVOID) = entry;
    DWORD code;
    (void)unused;
    ShzInitHeap();
    ShzInitSync();
    ShzRunInitRoutines(DLL_PROCESS_ATTACH, (void *)1);
    code = main_entry((PVOID)shz_peb());
    RtlExitUserProcess((NTSTATUS)code);
}

/* First user-mode code of every additional thread: RCX = start routine, RDX = parameter. */
SHZ_EXPORT void NTAPI ShzThreadStart(void *start, void *param)
{
    DWORD (WINAPI *fn)(PVOID) = start;
    DWORD code;
    ShzRunThreadAttach(DLL_THREAD_ATTACH);
    code = fn(param);
    RtlExitUserThread((NTSTATUS)code);
}

/* ---------------------------------------------------------------- Ldr* */
static int wcs_eq_ci(const WCHAR *a, USHORT alen, const WCHAR *b, USHORT blen)
{
    USHORT i;
    if (alen != blen) return 0;
    for (i = 0; i < alen / 2; ++i) {
        WCHAR x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
    }
    return 1;
}

static SHZ_LDR_ENTRY *find_entry_by_name(const SHZ_UNICODE_STRING *name)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList, *l;
    WCHAR tmp[64];
    USHORT n = name->Length / 2, i;
    SHZ_UNICODE_STRING want;
    int has_dot = 0, last_sep = 0;
    /* compare the base name; add ".dll" when the caller omitted an extension */
    for (i = 0; i < n; ++i) if (name->Buffer[i] == '\\' || name->Buffer[i] == '/') last_sep = i + 1;
    for (i = last_sep; i < n && (i - last_sep) < 55; ++i) { tmp[i - last_sep] = name->Buffer[i]; if (name->Buffer[i] == '.') has_dot = 1; }
    n = (USHORT)(n - last_sep);
    if (n > 55) n = 55;
    if (!has_dot) { tmp[n++] = '.'; tmp[n++] = 'd'; tmp[n++] = 'l'; tmp[n++] = 'l'; }
    want.Buffer = tmp; want.Length = (USHORT)(n * 2); want.MaximumLength = want.Length;
    for (l = head->Flink; l != head; l = l->Flink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InLoadOrderLinks);
        if (wcs_eq_ci(e->BaseDllName.Buffer, e->BaseDllName.Length, want.Buffer, want.Length)) return e;
    }
    return 0;
}

SHZ_EXPORT NTSTATUS NTAPI LdrGetDllHandle(PWSTR path, PULONG flags, SHZ_UNICODE_STRING *name, PVOID *handle)
{
    SHZ_LDR_ENTRY *e = find_entry_by_name(name);
    (void)path; (void)flags;
    if (!e) return STATUS_DLL_NOT_FOUND;
    *handle = e->DllBase;
    return STATUS_SUCCESS;
}

SHZ_EXPORT NTSTATUS NTAPI LdrLoadDll(PWSTR path, PULONG flags, SHZ_UNICODE_STRING *name, PVOID *handle)
{
    ULONG64 base = 0;
    NTSTATUS st;
    SHZ_LDR_ENTRY *e = find_entry_by_name(name);
    (void)path; (void)flags;
    if (e) { ++e->LoadCount; *handle = e->DllBase; return STATUS_SUCCESS; }       /* already loaded: bump the count */
    st = NtLoadImage(name, &base);
    if (st) return st;
    *handle = (PVOID)(uintptr_t)base;
    ShzRunInitRoutines(DLL_PROCESS_ATTACH, 0);                                     /* only entries still marked NEEDS_INIT */
    return STATUS_SUCCESS;
}

SHZ_EXPORT NTSTATUS NTAPI LdrUnloadDll(PVOID handle)
{
    /* FreeLibrary drops the reference count; the image stays mapped (documented limitation). */
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList, *l;
    for (l = head->Flink; l != head; l = l->Flink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InLoadOrderLinks);
        if (e->DllBase == handle) { if (e->LoadCount) --e->LoadCount; return STATUS_SUCCESS; }
    }
    return STATUS_INVALID_PARAMETER;
}

static int str_eq(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }

SHZ_EXPORT NTSTATUS NTAPI LdrGetProcedureAddress(PVOID module, const void *name_or_null, ULONG ordinal, PVOID *address)
{
    const uint8_t *base = module;
    const IMAGE_DOS_HEADER *dos = module;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_DATA_DIRECTORY *dd;
    const IMAGE_EXPORT_DIRECTORY *ex;
    const DWORD *funcs, *names;
    const WORD *ords;
    DWORD idx, rva;
    if (!module || dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_PARAMETER;
    nt = (const IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->VirtualAddress) return STATUS_ENTRYPOINT_NOT_FOUND;
    ex = (const IMAGE_EXPORT_DIRECTORY *)(base + dd->VirtualAddress);
    funcs = (const DWORD *)(base + ex->AddressOfFunctions);
    names = (const DWORD *)(base + ex->AddressOfNames);
    ords = (const WORD *)(base + ex->AddressOfNameOrdinals);
    if (name_or_null) {
        const SHZ_UNICODE_STRING *dummy = 0; (void)dummy;
        const struct { USHORT Length, MaximumLength; PCHAR Buffer; } *as = name_or_null;         /* ANSI_STRING */
        char tmp[128];
        USHORT i;
        DWORD k;
        for (i = 0; i < as->Length && i < 127; ++i) tmp[i] = as->Buffer[i];
        tmp[i] = 0;
        for (k = 0; k < ex->NumberOfNames; ++k)
            if (str_eq((const char *)(base + names[k]), tmp)) { idx = ords[k]; goto found; }
        return STATUS_ENTRYPOINT_NOT_FOUND;
    } else {
        if (ordinal < ex->Base || ordinal - ex->Base >= ex->NumberOfFunctions) return STATUS_ORDINAL_NOT_FOUND;
        idx = ordinal - ex->Base;
    }
found:
    rva = funcs[idx];
    if (!rva) return STATUS_ENTRYPOINT_NOT_FOUND;
    if (rva >= dd->VirtualAddress && rva < dd->VirtualAddress + dd->Size) {
        /* forwarder string "DLL.Function": resolve through the loader, no self-recursion into ourselves */
        const char *fwd = (const char *)(base + rva);
        WCHAR wdll[64];
        SHZ_UNICODE_STRING us;
        struct { USHORT Length, MaximumLength; PCHAR Buffer; } as2;
        char fn[96];
        PVOID hmod = 0;
        unsigned d = 0, f = 0;
        NTSTATUS st;
        while (fwd[d] && fwd[d] != '.' && d < 56) { wdll[d] = (WCHAR)(unsigned char)fwd[d]; ++d; }
        if (fwd[d] != '.') return STATUS_ENTRYPOINT_NOT_FOUND;
        wdll[d++] = '.'; wdll[d] = 'd'; wdll[d + 1] = 'l'; wdll[d + 2] = 'l'; wdll[d + 3] = 0;
        us.Buffer = wdll; us.Length = (USHORT)((d + 3) * 2); us.MaximumLength = us.Length + 2;
        {
            unsigned k2 = 0;
            while (fwd[k2] && fwd[k2] != '.') ++k2;
            ++k2;
            while (fwd[k2] && f < sizeof fn - 1) fn[f++] = fwd[k2++];
            fn[f] = 0;
        }
        st = LdrLoadDll(0, 0, &us, &hmod);
        if (st) return st;
        as2.Buffer = fn; as2.Length = (USHORT)f; as2.MaximumLength = (USHORT)(f + 1);
        return fn[0] == '#' ? STATUS_ENTRYPOINT_NOT_FOUND : LdrGetProcedureAddress(hmod, &as2, 0, address);
    }
    *address = (PVOID)(base + rva);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- misc Rtl */
SHZ_EXPORT NTSTATUS NTAPI RtlGetVersion(OSVERSIONINFOW *v)
{
    /* Profile declaration (win11-amd64 target), not a verified Windows build. */
    if (v->dwOSVersionInfoSize < sizeof(OSVERSIONINFOW)) return STATUS_INVALID_PARAMETER;
    v->dwMajorVersion = PEB_OS_MAJOR(shz_peb());
    v->dwMinorVersion = PEB_OS_MINOR(shz_peb());
    v->dwBuildNumber = PEB_OS_BUILD(shz_peb());
    v->dwPlatformId = PEB_OS_PLATFORM(shz_peb());
    v->szCSDVersion[0] = 0;
    return STATUS_SUCCESS;
}

/* DLL entry (ntdll has no DllMain on Windows; the loader still expects a valid entry point here). */
BOOL WINAPI ShzNtdllEntry(HINSTANCE h, DWORD reason, LPVOID reserved) { (void)h; (void)reason; (void)reserved; return TRUE; }
