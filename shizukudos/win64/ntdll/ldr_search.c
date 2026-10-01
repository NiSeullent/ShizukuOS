/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll: DLL search-path state, the loader lock and the runtime load request (the worker of LdrLoadDll).
 *
 *   LdrSetDllDirectory / LdrGetDllDirectory     back SetDllDirectoryW / GetDllDirectoryW
 *   LdrSetDefaultDllDirectories                 backs SetDefaultDllDirectories
 *   LdrAddDllDirectory / LdrRemoveDllDirectory  back AddDllDirectory / RemoveDllDirectory
 *   LdrLockLoaderLock / LdrUnlockLoaderLock     the recursive loader lock (held during loads and DLL_PROCESS_ATTACH)
 *
 * Semantics follow the public documentation (learn.microsoft.com: "Dynamic-link library search order",
 * SetDllDirectoryW, SetDefaultDllDirectories, AddDllDirectory, RemoveDllDirectory, LoadLibraryExW). ntdll keeps the
 * process-wide state and turns every request into (flags, directory list) for the kernel loader (NtLoadImage), which
 * walks the directories in the documented order for the DLL and for its dependencies (kernel64/ldr.c).
 *
 * LdrLoadDll's first parameter: a pointer with bit 0 set carries LoadLibraryExW flags in bits 1..31 (kernel32 passes
 * (flags << 1) | 1); an ordinary string pointer is a ';'-separated search path, searched like
 * LOAD_LIBRARY_SEARCH_USER_DIRS; NULL means the default search order.
 */
#include "nt.h"
#include "ntdll_int.h"
#include <string.h>

#define SEARCH_MASK 0x00001f00u         /* LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR .. LOAD_LIBRARY_SEARCH_DEFAULT_DIRS */
#define SEARCH_DLL_LOAD_DIR 0x00000100u
#define SEARCH_USER_DIRS 0x00000400u
#define SEARCH_DEFAULT_DIRS 0x00001000u
#define ALTERED_SEARCH_PATH 0x00000008u
#define LDRS_DLL_DIRECTORY 0x80000000u  /* kernel64/ldr.c: `dirs` is SetDllDirectory's directory */
#define LDRS_NO_CWD 0x40000000u         /* kernel64/ldr.c: the current directory is not searched */
#define DIRS_CAP 512                    /* characters of the directory list handed to the kernel */

/* ---------------------------------------------------------------- loader lock
 * An RTL_CRITICAL_SECTION published in PEB.LoaderLock (x64 PEB + 0x110), as on Windows: programs inspect it directly
 * (Chromium's chrome_elf compares LoaderLock->OwningThread with its thread id to know whether it runs under the lock). It is
 * held while DLLs are loaded and their DLL_PROCESS_ATTACH notifications run, at process start and at run time. */
NTSTATUS NTAPI RtlInitializeCriticalSectionEx(RTL_CRITICAL_SECTION *, ULONG, ULONG);
NTSTATUS NTAPI RtlEnterCriticalSection(RTL_CRITICAL_SECTION *);
NTSTATUS NTAPI RtlLeaveCriticalSection(RTL_CRITICAL_SECTION *);
BOOLEAN NTAPI RtlTryEnterCriticalSection(RTL_CRITICAL_SECTION *);
static RTL_CRITICAL_SECTION g_loader_cs;
static volatile LONG g_ldr_ready;

void ShzLoaderLockInit(void)
{
    if (g_ldr_ready) return;
    RtlInitializeCriticalSectionEx(&g_loader_cs, 0, 0);
    *(RTL_CRITICAL_SECTION **)(shz_peb() + 0x110) = &g_loader_cs;           /* PEB.LoaderLock */
    g_ldr_ready = 1;
}

void ShzLoaderLock(void)
{
    ShzLoaderLockInit();
    RtlEnterCriticalSection(&g_loader_cs);
}

void ShzLoaderUnlock(void)
{
    if (g_loader_cs.OwningThread != (HANDLE)(ULONG_PTR)shz_tid()) return;
    RtlLeaveCriticalSection(&g_loader_cs);
}

/* LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY (2): disposition 1 = acquired, 2 = busy. The cookie is the owner's thread id. */
SHZ_EXPORT NTSTATUS NTAPI LdrLockLoaderLock(ULONG flags, PULONG disposition, PULONG_PTR cookie)
{
    const LONG me = (LONG)shz_tid();
    if (flags & ~3u) return STATUS_INVALID_PARAMETER;
    if ((flags & 2) && !disposition) return STATUS_INVALID_PARAMETER;
    ShzLoaderLockInit();
    if (flags & 2) {
        if (!RtlTryEnterCriticalSection(&g_loader_cs)) {
            *disposition = 2;
            if (cookie) *cookie = 0;
            return STATUS_SUCCESS;
        }
        *disposition = 1;
    } else {
        RtlEnterCriticalSection(&g_loader_cs);
        if (disposition) *disposition = 1;
    }
    if (cookie) *cookie = (ULONG_PTR)me;
    return STATUS_SUCCESS;
}

SHZ_EXPORT NTSTATUS NTAPI LdrUnlockLoaderLock(ULONG flags, ULONG_PTR cookie)
{
    (void)flags;
    if (!cookie) return STATUS_SUCCESS;
    if (cookie != (ULONG_PTR)(LONG)shz_tid() || g_loader_cs.OwningThread != (HANDLE)cookie) return STATUS_INVALID_PARAMETER;
    RtlLeaveCriticalSection(&g_loader_cs);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- DLL load notifications
 * LdrRegisterDllNotification / LdrUnregisterDllNotification (Windows Vista+; Chromium's module database and third-party
 * DLL tracking register one). A registered callback receives LDR_DLL_NOTIFICATION_REASON_LOADED (1) for every module a
 * run-time LdrLoadDll maps (the module and the dependencies it pulled in, in load order, after their DllMain(PROCESS_ATTACH)
 * ran), with the loader lock held, as on Windows. Modules the kernel loader maps before user mode runs (the executable and its
 * load-time imports) were loaded before anything could register, as on Windows. A genuine dynamic retirement reports
 * LDR_DLL_NOTIFICATION_REASON_UNLOADED (2) while the image is mapped and before the kernel commit.
 * Flags must be 0 (reserved). The cookie is the address of the registration record; unregistering takes the loader lock. */
typedef struct { ULONG Flags; const SHZ_UNICODE_STRING *FullDllName, *BaseDllName; PVOID DllBase; ULONG SizeOfImage; } SHZ_LDR_DLL_NOTIFICATION;
typedef VOID (NTAPI *SHZ_LDR_NOTIFY_FN)(ULONG reason, const SHZ_LDR_DLL_NOTIFICATION *data, PVOID context);
typedef struct notify_reg {
    struct notify_reg *next, *retired_next;
    SHZ_LDR_NOTIFY_FN fn; PVOID context;
    ULONG64 sequence; unsigned active;
} notify_reg_t;
static ULONG64 g_notify_sequence;
static unsigned g_notify_depth;
static notify_reg_t *g_notify_retired;
static notify_reg_t *g_notify;          /* registration order; protected by the loader lock */

SHZ_EXPORT NTSTATUS NTAPI LdrRegisterDllNotification(ULONG flags, SHZ_LDR_NOTIFY_FN fn, PVOID context, PVOID *cookie)
{
    notify_reg_t *r, **tail;
    if (flags || !fn || !cookie) return STATUS_INVALID_PARAMETER;
    r = RtlAllocateHeap(ShzProcessHeap(), 0, sizeof *r);
    if (!r) return STATUS_NO_MEMORY;
    r->next = 0; r->retired_next = 0; r->fn = fn; r->context = context; r->active = 1;
    ShzLoaderLock();
    if (g_notify_sequence == ~(ULONG64)0) {
        ShzLoaderUnlock(); RtlFreeHeap(ShzProcessHeap(), 0, r); return STATUS_NO_MEMORY;
    }
    r->sequence = ++g_notify_sequence;
    for (tail = &g_notify; *tail; tail = &(*tail)->next) {}
    *tail = r;
    ShzLoaderUnlock();
    *cookie = r;
    return STATUS_SUCCESS;
}

SHZ_EXPORT NTSTATUS NTAPI LdrUnregisterDllNotification(PVOID cookie)
{
    notify_reg_t **pp, *r = cookie;
    NTSTATUS st = STATUS_INVALID_PARAMETER;
    if (!r) return STATUS_INVALID_PARAMETER;
    ShzLoaderLock();
    for (pp = &g_notify; *pp; pp = &(*pp)->next)
        if (*pp == r) {
            *pp = r->next; r->active = 0; st = STATUS_SUCCESS;
            if (g_notify_depth) { r->retired_next = g_notify_retired; g_notify_retired = r; }
            else RtlFreeHeap(ShzProcessHeap(), 0, r);
            break;
        }
    ShzLoaderUnlock();
    return st;
}

/* Registration records remain owned throughout recursive dispatch, including
 * self-unregistration. New registrations never receive an already active event. */
static void notify_entry(ULONG reason, SHZ_LDR_ENTRY *e)
{
    const ULONG64 snapshot = g_notify_sequence;
    SHZ_LDR_DLL_NOTIFICATION d;
    notify_reg_t *r;
    d.Flags = 0; d.FullDllName = &e->FullDllName; d.BaseDllName = &e->BaseDllName;
    d.DllBase = e->DllBase; d.SizeOfImage = e->SizeOfImage;
    ++g_notify_depth;
    for (r = g_notify; r && r->sequence <= snapshot; r = r->next)
        if (r->active) r->fn(reason, &d, r->context);
    if (!--g_notify_depth) while (g_notify_retired) {
        r = g_notify_retired; g_notify_retired = r->retired_next;
        RtlFreeHeap(ShzProcessHeap(), 0, r);
    }
}

void ShzNotifyUnloaded(SHZ_LDR_ENTRY *e) { notify_entry(2, e); }

/* Called with the exact newly published range captured by LdrLoadDll before
 * attach callbacks. An attach may genuinely retire the unrelated prior tail,
 * whose retained entry is then self-linked, or recursively load another batch
 * which has already received its own notifications. Neither changes this range.
 * first == head means no new image. The explicit root reference and its import
 * edges retain the new images; CALLBACK_ACTIVE protects notification reentry. */
void ShzNotifyLoaded(LIST_ENTRY *first, LIST_ENTRY *last)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList, *l;
    for (l = first; l != head; l = l->Flink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InLoadOrderLinks);
        ULONG active = e->Flags & SHZ_LDR_CALLBACK_ACTIVE;
        e->Flags |= SHZ_LDR_CALLBACK_ACTIVE;
        notify_entry(1, e);
        e->Flags = (e->Flags & ~SHZ_LDR_CALLBACK_ACTIVE) | active;
        if (l == last) break;         /* recursively loaded modules already received their own event */
    }
}

/* ---------------------------------------------------------------- directory state */
typedef struct dll_dir { struct dll_dir *next; USHORT chars; WCHAR path[1]; } dll_dir_t;

static volatile LONG g_dir_lock;
static dll_dir_t *g_user_dirs;          /* AddDllDirectory, in insertion order */
static WCHAR g_dll_dir[261];            /* SetDllDirectory */
static int g_dll_dir_state;             /* 0 unset (default order), 1 empty string (no current dir), 2 directory set */
static ULONG g_default_flags;           /* SetDefaultDllDirectories, 0 = standard search order */

static void dlock(void) { while (__sync_lock_test_and_set(&g_dir_lock, 1)) NtYieldExecution(); }
static void dunlock(void) { __sync_lock_release(&g_dir_lock); }

static int is_absolute(const WCHAR *s, USHORT chars)
{
    if (chars >= 3 && ((s[0] | 32) >= 'a' && (s[0] | 32) <= 'z') && s[1] == ':' && (s[2] == '\\' || s[2] == '/')) return 1;
    return chars >= 3 && s[0] == '\\' && s[1] == '\\';                      /* UNC or \\?\ prefix */
}

SHZ_EXPORT NTSTATUS NTAPI LdrSetDllDirectory(const SHZ_UNICODE_STRING *dir)
{
    USHORT n;
    if (!dir || !dir->Buffer) {                                             /* NULL: back to the default order */
        dlock(); g_dll_dir_state = 0; g_dll_dir[0] = 0; dunlock();
        return STATUS_SUCCESS;
    }
    n = dir->Length / 2;
    if (n >= sizeof g_dll_dir / sizeof g_dll_dir[0]) return STATUS_NAME_TOO_LONG;
    dlock();
    memcpy(g_dll_dir, dir->Buffer, n * sizeof(WCHAR));
    g_dll_dir[n] = 0;
    g_dll_dir_state = n ? 2 : 1;
    dunlock();
    return STATUS_SUCCESS;
}

/* Copies the directory set by LdrSetDllDirectory into `out` (MaximumLength bytes); STATUS_BUFFER_TOO_SMALL reports the
 * needed Length. An unset directory yields an empty string. */
SHZ_EXPORT NTSTATUS NTAPI LdrGetDllDirectory(SHZ_UNICODE_STRING *out)
{
    USHORT n = 0;
    NTSTATUS st = STATUS_SUCCESS;
    dlock();
    while (g_dll_dir[n]) ++n;
    if (out->MaximumLength < (n + 1) * sizeof(WCHAR)) st = STATUS_BUFFER_TOO_SMALL;
    else { memcpy(out->Buffer, g_dll_dir, (n + 1) * sizeof(WCHAR)); }
    out->Length = (USHORT)(n * sizeof(WCHAR));
    dunlock();
    return st;
}

SHZ_EXPORT NTSTATUS NTAPI LdrSetDefaultDllDirectories(ULONG flags)
{
    const ULONG allowed = 0x00000200u | 0x00000400u | 0x00000800u | 0x00001000u;   /* APPLICATION_DIR USER_DIRS SYSTEM32 DEFAULT_DIRS */
    if (!flags || (flags & ~allowed)) return STATUS_INVALID_PARAMETER;
    dlock(); g_default_flags = flags; dunlock();
    return STATUS_SUCCESS;
}

SHZ_EXPORT NTSTATUS NTAPI LdrAddDllDirectory(const SHZ_UNICODE_STRING *dir, PVOID *cookie)
{
    dll_dir_t *d, **pp;
    USHORT n;
    if (!dir || !dir->Buffer || !cookie) return STATUS_INVALID_PARAMETER;
    n = dir->Length / 2;
    while (n > 3 && (dir->Buffer[n - 1] == '\\' || dir->Buffer[n - 1] == '/')) --n;     /* "C:\dir\" == "C:\dir" */
    if (!is_absolute(dir->Buffer, n) || n > 259) return STATUS_INVALID_PARAMETER;
    d = RtlAllocateHeap(ShzProcessHeap(), 0, sizeof *d + n * sizeof(WCHAR));
    if (!d) return STATUS_NO_MEMORY;
    memcpy(d->path, dir->Buffer, n * sizeof(WCHAR));
    d->path[n] = 0;
    d->chars = n;
    d->next = 0;
    dlock();
    for (pp = &g_user_dirs; *pp; pp = &(*pp)->next) {}
    *pp = d;
    dunlock();
    *cookie = d;
    return STATUS_SUCCESS;
}

SHZ_EXPORT NTSTATUS NTAPI LdrRemoveDllDirectory(PVOID cookie)
{
    dll_dir_t **pp, *found = 0;
    dlock();
    for (pp = &g_user_dirs; *pp; pp = &(*pp)->next)
        if (*pp == cookie) { found = *pp; *pp = found->next; break; }
    dunlock();
    if (!found) return STATUS_INVALID_PARAMETER;
    RtlFreeHeap(ShzProcessHeap(), 0, found);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- the load request */
static void append(WCHAR *list, USHORT *len, const WCHAR *s, USHORT n)
{
    if (*len && *len < DIRS_CAP) list[(*len)++] = ';';
    while (n-- && *len < DIRS_CAP) list[(*len)++] = *s++;
}

/* Maps LdrLoadDll's first parameter onto (kernel flags, directory list) and asks the kernel to load `name`. */
NTSTATUS ShzLdrLoadImage(PWSTR path_or_flags, SHZ_UNICODE_STRING *name, ULONG64 *base)
{
    WCHAR list[DIRS_CAP + 1];
    USHORT len = 0;
    ULONG flags = 0;
    SHZ_UNICODE_STRING dirs;
    int have_dirs = 0;
    if ((ULONG_PTR)path_or_flags & 1) flags = (ULONG)((ULONG_PTR)path_or_flags >> 1);
    else if (path_or_flags) {
        USHORT n = 0;
        while (path_or_flags[n] && n < DIRS_CAP) ++n;
        append(list, &len, path_or_flags, n);
        flags = SEARCH_USER_DIRS;
        have_dirs = 1;
    }
    if ((flags & ALTERED_SEARCH_PATH) && (flags & SEARCH_MASK)) return STATUS_INVALID_PARAMETER;
    dlock();
    if (!have_dirs) {
        if (!(flags & (SEARCH_MASK | ALTERED_SEARCH_PATH)) && g_default_flags) flags |= g_default_flags;
        if (flags & SEARCH_MASK) {
            if (flags & (SEARCH_USER_DIRS | SEARCH_DEFAULT_DIRS)) {
                dll_dir_t *d;
                for (d = g_user_dirs; d; d = d->next) append(list, &len, d->path, d->chars);
                have_dirs = 1;
            }
        } else if (g_dll_dir_state == 2) {
            USHORT n = 0;
            while (g_dll_dir[n]) ++n;
            append(list, &len, g_dll_dir, n);
            flags |= LDRS_DLL_DIRECTORY;
            have_dirs = 1;
        } else if (g_dll_dir_state == 1) {
            flags |= LDRS_NO_CWD;
        }
    }
    dunlock();
    list[len] = 0;
    dirs.Buffer = list;
    dirs.Length = (USHORT)(len * sizeof(WCHAR));
    dirs.MaximumLength = (USHORT)(dirs.Length + sizeof(WCHAR));
    return NtLoadImage(name, base, flags, have_dirs ? &dirs : 0);
}
