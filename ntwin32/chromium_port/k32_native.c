/* SPDX-License-Identifier: GPL-2.0-only
 * M98K32CE.DLL: Win98-native KERNEL32 provider for NT6+ names imported by
 * Chromium 157 x86 chrome_elf.dll. Bound only through the hash-checked
 * contract in api_contract.c; never a blanket KERNEL32 replacement.
 * Uses only Win98 SE KERNEL32 exports. FLS, INIT_ONCE and SLIST reuse the
 * existing src/m98_fls.c, src/m98_initonce.c and src/m98_slist.c unchanged.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <tlhelp32.h>
#include "k32_compat.h"
#include "../../src/m98_fls.h"
#include "../../src/m98_initonce.h"
#include "../../src/m98_slist.h"

static CRITICAL_SECTION queue_lock;
static DWORD event_slot = TLS_OUT_OF_INDEXES;
static volatile LONG pointer_cookie;

void k32p_lock(void) { EnterCriticalSection(&queue_lock); }
void k32p_unlock(void) { LeaveCriticalSection(&queue_lock); }
void *k32p_thread_event(void)
{
    HANDLE event;
    if (event_slot == TLS_OUT_OF_INDEXES) return NULL;
    event = TlsGetValue(event_slot);
    if (event) return event;
    event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (event && !TlsSetValue(event_slot, event)) { CloseHandle(event); event = NULL; }
    return event;
}
int k32p_wait(void *event, uint32_t ms)
{
    DWORD r = WaitForSingleObject((HANDLE)event, ms);
    return r == WAIT_OBJECT_0 ? 0 : r == WAIT_TIMEOUT ? 1 : -1;
}
void k32p_signal(void *event) { SetEvent((HANDLE)event); }
void k32p_yield(void) { Sleep(1); }
uint32_t k32p_ticks(void) { return GetTickCount(); }

static void close_thread_event(void)
{
    HANDLE event;
    if (event_slot == TLS_OUT_OF_INDEXES) return;
    event = TlsGetValue(event_slot);
    if (event) { TlsSetValue(event_slot, NULL); CloseHandle(event); }
}

static void veh_restore_filter(void);
BOOL WINAPI dll_entry(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        event_slot = TlsAlloc();
        if (event_slot == TLS_OUT_OF_INDEXES) return FALSE;
        InitializeCriticalSection(&queue_lock);
    } else if (reason == DLL_THREAD_DETACH) {
        m98_fls_rundown_current_thread();
        close_thread_event();
    } else if (reason == DLL_PROCESS_DETACH) {
        m98_fls_rundown_current_thread();
        close_thread_event();
        veh_restore_filter();
        DeleteCriticalSection(&queue_lock);
        TlsFree(event_slot);
        event_slot = TLS_OUT_OF_INDEXES;
    }
    return TRUE;
}

/* ---- SRW / condition variables (pointer-sized objects, zero init) ----- */
#define CONDITION_VARIABLE_LOCKMODE_SHARED_ 1u
static void srw_release_cb(void *lock, int shared) { k32_srw_release((volatile uint32_t *)lock, !shared); }
static void srw_acquire_cb(void *lock, int shared) { k32_srw_acquire((volatile uint32_t *)lock, !shared); }
static void cs_release_cb(void *lock, int shared) { (void)shared; LeaveCriticalSection((CRITICAL_SECTION *)lock); }
static void cs_acquire_cb(void *lock, int shared) { (void)shared; EnterCriticalSection((CRITICAL_SECTION *)lock); }

VOID WINAPI m98ce_InitializeSRWLock(PVOID lock) { if (lock) *(volatile uint32_t *)lock = 0; }
VOID WINAPI m98ce_AcquireSRWLockExclusive(PVOID lock) { k32_srw_acquire(lock, 1); }
VOID WINAPI m98ce_AcquireSRWLockShared(PVOID lock) { k32_srw_acquire(lock, 0); }
BOOLEAN WINAPI m98ce_TryAcquireSRWLockExclusive(PVOID lock) { return (BOOLEAN)k32_srw_try_acquire(lock, 1); }
BOOLEAN WINAPI m98ce_TryAcquireSRWLockShared(PVOID lock) { return (BOOLEAN)k32_srw_try_acquire(lock, 0); }
VOID WINAPI m98ce_ReleaseSRWLockExclusive(PVOID lock) { k32_srw_release(lock, 1); }
VOID WINAPI m98ce_ReleaseSRWLockShared(PVOID lock) { k32_srw_release(lock, 0); }
VOID WINAPI m98ce_InitializeConditionVariable(PVOID cv) { if (cv) *(volatile uint32_t *)cv = 0; }
VOID WINAPI m98ce_WakeConditionVariable(PVOID cv) { k32_cv_wake(cv, 0); }
VOID WINAPI m98ce_WakeAllConditionVariable(PVOID cv) { k32_cv_wake(cv, 1); }

static BOOL cv_result(int r)
{
    if (!r) return TRUE;
    SetLastError(r == 1 ? ERROR_TIMEOUT : r == 2 ? ERROR_NOT_ENOUGH_MEMORY : ERROR_INVALID_HANDLE);
    return FALSE;
}
BOOL WINAPI m98ce_SleepConditionVariableSRW(PVOID cv, PVOID lock, DWORD ms, ULONG flags)
{
    if (!cv || !lock || (flags & ~CONDITION_VARIABLE_LOCKMODE_SHARED_)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return cv_result(k32_cv_sleep(cv, lock, (flags & CONDITION_VARIABLE_LOCKMODE_SHARED_) != 0, ms, srw_release_cb, srw_acquire_cb));
}
BOOL WINAPI m98ce_SleepConditionVariableCS(PVOID cv, CRITICAL_SECTION *cs, DWORD ms)
{
    if (!cv || !cs) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return cv_result(k32_cv_sleep(cv, cs, 0, ms, cs_release_cb, cs_acquire_cb));
}

/* ---- Version ----------------------------------------------------------- */
typedef struct m98ce_osvexw {
    DWORD size, major, minor, build, platform;
    WCHAR csd[128];
    WORD sp_major, sp_minor, suite;
    BYTE product, reserved;
} m98ce_osvexw;

ULONGLONG WINAPI m98ce_VerSetConditionMask(ULONGLONG mask, DWORD type, BYTE condition)
{
    return k32_ver_set_condition_mask(mask, type, condition);
}
BOOL WINAPI m98ce_VerifyVersionInfoW(m98ce_osvexw *info, DWORD type, DWORDLONG conditions)
{
    OSVERSIONINFOA os;
    k32_osver have, want;
    int r;
    if (!info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    os.dwOSVersionInfoSize = sizeof(os);
    if (!GetVersionExA(&os)) return FALSE;
    /* Actual running Win98 values; 9x has no service-pack, suite or
     * product-type fields, which therefore compare as zero. */
    have.major = os.dwMajorVersion; have.minor = os.dwMinorVersion;
    have.build = os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS ? (os.dwBuildNumber & 0xffffu) : os.dwBuildNumber;
    have.platform = os.dwPlatformId; have.sp_major = have.sp_minor = have.suite = 0; have.product = 0;
    want.major = info->major; want.minor = info->minor; want.build = info->build; want.platform = info->platform;
    want.sp_major = info->sp_major; want.sp_minor = info->sp_minor; want.suite = info->suite; want.product = info->product;
    r = k32_verify_version(&have, &want, type, conditions);
    if (r == K32_VERIFY_OK) return TRUE;
    SetLastError(r == K32_VERIFY_MISMATCH ? ERROR_OLD_WIN_VERSION : ERROR_BAD_ARGUMENTS);
    return FALSE;
}

/* ---- Modules -------------------------------------------------------------- */
#define GMH_PIN 1u
#define GMH_UNCHANGED 2u
#define GMH_FROM_ADDRESS 4u
BOOL WINAPI m98ce_GetModuleHandleExW(DWORD flags, LPCWSTR name, HMODULE *out)
{
    HMODULE module;
    char path[MAX_PATH];
    if (out) *out = NULL;
    if (!out || (flags & ~7u) || (flags & (GMH_PIN | GMH_UNCHANGED)) == (GMH_PIN | GMH_UNCHANGED)) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    if (flags & GMH_FROM_ADDRESS) {
        MEMORY_BASIC_INFORMATION info;
        uintptr_t image;
        /* Image mapped by NTWPE32 and registered through M98K32CE_RegisterImage:
         * its lifetime is owned by that loader (unmapped only at its cleanup),
         * so no Win98 reference is taken and PIN is inherently satisfied. */
        if (name && k32_image_find((uintptr_t)name, &image, NULL, NULL, 0) == 1) { *out = (HMODULE)image; return TRUE; }
        if (!name || VirtualQuery(name, &info, sizeof(info)) != sizeof(info) || info.State != MEM_COMMIT ||
            !info.AllocationBase) { SetLastError(ERROR_MOD_NOT_FOUND); return FALSE; }
        module = (HMODULE)info.AllocationBase;
        /* Only a module Win98 itself has loaded qualifies; images mapped by
         * a private loader are not Win98 modules and are reported missing. */
        if (!GetModuleFileNameA(module, path, sizeof(path)) || GetModuleHandleA(path) != module) {
            SetLastError(ERROR_MOD_NOT_FOUND); return FALSE;
        }
    } else if (!name) {
        module = GetModuleHandleA(NULL);
        if (!module) return FALSE;
        *out = module;
        return TRUE;                   /* the process image is never refcounted */
    } else {
        char narrow[MAX_PATH];
        if (!WideCharToMultiByte(CP_ACP, 0, name, -1, narrow, sizeof(narrow), NULL, NULL)) {
            SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE;
        }
        module = GetModuleHandleA(narrow);
        if (!module) {
            uintptr_t image;
            if (k32_image_by_name(narrow, &image)) { *out = (HMODULE)image; SetLastError(NO_ERROR); return TRUE; }
            return FALSE;
        }
    }
    if (!(flags & GMH_UNCHANGED)) {
        HMODULE again;
        if (!GetModuleFileNameA(module, path, sizeof(path))) { SetLastError(ERROR_MOD_NOT_FOUND); return FALSE; }
        /* +1 reference. PIN keeps this reference forever; Win98 cannot stop
         * an unbalanced FreeLibrary elsewhere from dropping the module. */
        again = LoadLibraryA(path);
        if (again != module) { if (again) FreeLibrary(again); SetLastError(ERROR_MOD_NOT_FOUND); return FALSE; }
    }
    *out = module;
    return TRUE;
}

/* ---- Files / memory / system ------------------------------------------- */
BOOL WINAPI m98ce_SetFilePointerEx(HANDLE file, LARGE_INTEGER distance, PLARGE_INTEGER position, DWORD method)
{
    LONG high = distance.HighPart;
    DWORD low;
    if (method > FILE_END) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    SetLastError(NO_ERROR);
    low = SetFilePointer(file, (LONG)distance.LowPart, &high, method);
    if (low == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) return FALSE;
    if (position) { position->LowPart = low; position->HighPart = high; }
    return TRUE;
}
BOOL WINAPI m98ce_GetFileSizeEx(HANDLE file, PLARGE_INTEGER size)
{
    DWORD high = 0, low;
    if (!size) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    SetLastError(NO_ERROR);
    low = GetFileSize(file, &high);
    if (low == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) return FALSE;
    size->LowPart = low; size->HighPart = (LONG)high;
    return TRUE;
}
typedef struct m98ce_memstatusex {
    DWORD length, load;
    ULONGLONG total_phys, avail_phys, total_page, avail_page, total_virtual, avail_virtual, avail_ext;
} m98ce_memstatusex;
BOOL WINAPI m98ce_GlobalMemoryStatusEx(m98ce_memstatusex *status)
{
    MEMORYSTATUS s;
    if (!status || status->length != sizeof(*status)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    s.dwLength = sizeof(s);
    GlobalMemoryStatus(&s);
    status->load = s.dwMemoryLoad;
    status->total_phys = s.dwTotalPhys; status->avail_phys = s.dwAvailPhys;
    status->total_page = s.dwTotalPageFile; status->avail_page = s.dwAvailPageFile;
    status->total_virtual = s.dwTotalVirtual; status->avail_virtual = s.dwAvailVirtual;
    status->avail_ext = 0;
    return TRUE;
}
VOID WINAPI m98ce_GetNativeSystemInfo(LPSYSTEM_INFO info) { GetSystemInfo(info); }  /* x86 Win98 is native */
BOOL WINAPI m98ce_IsWow64Process(HANDLE process, PBOOL wow64)
{
    (void)process;
    if (!wow64) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *wow64 = FALSE;                     /* a 32-bit kernel has no WOW64 layer */
    return TRUE;
}
BOOL WINAPI m98ce_InitializeCriticalSectionEx(CRITICAL_SECTION *section, DWORD spin, DWORD flags)
{
    if (!section || (flags & ~0x01000000u) || (spin & 0xff000000u)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    InitializeCriticalSection(section);  /* Win98 has no spin count */
    return TRUE;
}

static uint32_t cookie(void)
{
    LONG c = pointer_cookie;
    if (!c) {
        LARGE_INTEGER pc;
        uint32_t v = GetTickCount() ^ GetCurrentProcessId() ^ ((uint32_t)(UINT_PTR)&pc << 7);
        if (QueryPerformanceCounter(&pc)) v ^= pc.LowPart * 2654435761u;
        if (!v) v = 0x9e3779b9u;
        InterlockedCompareExchange((LONG *)&pointer_cookie, (LONG)v, 0);
        c = pointer_cookie;
    }
    return (uint32_t)c;
}
PVOID WINAPI m98ce_EncodePointer(PVOID p) { return (PVOID)(UINT_PTR)k32_encode((uint32_t)(UINT_PTR)p, cookie()); }
PVOID WINAPI m98ce_DecodePointer(PVOID p) { return (PVOID)(UINT_PTR)k32_decode((uint32_t)(UINT_PTR)p, cookie()); }


/* ==== Batch 3: remaining chrome_elf KERNEL32 names ======================== */
#define M98CE_NOT_SUPPORTED(ret) do { SetLastError(ERROR_NOT_SUPPORTED); return ret; } while (0)

/* NTWPE32 registers the images it maps itself (not Win98 modules). */
BOOL WINAPI M98K32CE_RegisterImage(PVOID base, DWORD size, LPCSTR path)
{
    if (!k32_image_register((uintptr_t)base, size, path)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}
BOOL WINAPI M98K32CE_UnregisterImage(PVOID base)
{
    if (!k32_image_unregister((uintptr_t)base)) { SetLastError(ERROR_MOD_NOT_FOUND); return FALSE; }
    return TRUE;
}

/* ---- Vectored exception handlers (last-chance only on Win98) ----------- */
typedef LONG (WINAPI *m98ce_veh_fn)(EXCEPTION_POINTERS *);
static LPTOP_LEVEL_EXCEPTION_FILTER veh_previous;
static volatile LONG veh_installed;
static long veh_invoke(void *handler, void *pointers) { return ((m98ce_veh_fn)handler)((EXCEPTION_POINTERS *)pointers); }
static LONG WINAPI veh_filter(EXCEPTION_POINTERS *pointers)
{
    if (k32_veh_dispatch(pointers, veh_invoke) == -1) return EXCEPTION_CONTINUE_EXECUTION;
    return veh_previous ? veh_previous(pointers) : EXCEPTION_CONTINUE_SEARCH;
}
static void veh_restore_filter(void)
{
    LPTOP_LEVEL_EXCEPTION_FILTER current;
    if (!veh_installed) return;
    current = SetUnhandledExceptionFilter(veh_previous);
    if (current != veh_filter) SetUnhandledExceptionFilter(current);   /* someone replaced ours: keep theirs */
    veh_installed = 0;
}
PVOID WINAPI m98ce_AddVectoredExceptionHandler(ULONG first, m98ce_veh_fn handler)
{
    void *node;
    if (!handler) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    node = k32_veh_add(first != 0, (void *)handler);
    if (!node) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    k32p_lock();
    if (!veh_installed) { veh_previous = SetUnhandledExceptionFilter(veh_filter); veh_installed = 1; }
    k32p_unlock();
    return node;
}
ULONG WINAPI m98ce_RemoveVectoredExceptionHandler(PVOID handle) { return (ULONG)k32_veh_remove(handle); }

/* ---- Stack back trace: bounded EBP chain on the current thread stack ---- */
__attribute__((noinline)) USHORT WINAPI m98ce_RtlCaptureStackBackTrace(ULONG skip, ULONG count, PVOID *trace, PULONG hash)
{
    NT_TIB *tib = (NT_TIB *)(UINT_PTR)__readfsdword(0x18);
    uintptr_t fp = (uintptr_t)__builtin_frame_address(0);
    uint32_t sum = 0;
    unsigned n;
    if (hash) *hash = 0;
    if (!trace || !count || !tib || skip > 0xffffu) return 0;
    if (count > 0xffffu) count = 0xffffu;
    /* Frames lie between our own frame and the thread's stack base. */
    n = k32_walk_frames(fp, fp, (uintptr_t)tib->StackBase, skip, count, trace, &sum);
    if (hash) *hash = sum;
    return (USHORT)n;
}

/* ---- Process / thread ids: only the current process/thread are knowable */
static int current_process(HANDLE h) { return h == GetCurrentProcess() || h == (HANDLE)(LONG_PTR)-1; }
DWORD WINAPI m98ce_GetProcessId(HANDLE process)
{
    if (current_process(process)) return GetCurrentProcessId();
    /* Win98 exposes no handle -> process id query for real handles. */
    M98CE_NOT_SUPPORTED(0);
}
DWORD WINAPI m98ce_GetThreadId(HANDLE thread)
{
    if (thread == GetCurrentThread() || thread == (HANDLE)(LONG_PTR)-2) return GetCurrentThreadId();
    M98CE_NOT_SUPPORTED(0);
}

/* ---- PSAPI (current process only) -------------------------------------- */
typedef struct m98ce_modinfo { LPVOID base; DWORD size; LPVOID entry; } m98ce_modinfo;
static int image_bounds(HMODULE module, DWORD *size, LPVOID *entry)
{
    const BYTE *b = (const BYTE *)module;
    uintptr_t base, rsize;
    DWORD pe;
    if (k32_image_find((uintptr_t)module, &base, NULL, NULL, 0) != 1 || base != (uintptr_t)module) {
        char path[MAX_PATH];
        if (!GetModuleFileNameA(module, path, sizeof(path))) return 0;
    }
    if (b[0] != 'M' || b[1] != 'Z') return 0;
    pe = *(const DWORD *)(b + 0x3c);
    if (pe > 0x1000 || *(const DWORD *)(b + pe) != 0x4550u || *(const WORD *)(b + pe + 0x18) != 0x10b) return 0;
    rsize = *(const DWORD *)(b + pe + 0x18 + 56);
    *size = (DWORD)rsize;
    *entry = *(const DWORD *)(b + pe + 0x18 + 16) ? (LPVOID)(b + *(const DWORD *)(b + pe + 0x18 + 16)) : NULL;
    return 1;
}
BOOL WINAPI m98ce_K32EnumProcessModules(HANDLE process, HMODULE *modules, DWORD bytes, LPDWORD needed)
{
    HANDLE snap;
    MODULEENTRY32 entry;
    HMODULE exe = GetModuleHandleA(NULL);
    uintptr_t mapped[K32_IMAGE_MAX];
    DWORD count = 0, cap = bytes / sizeof(HMODULE), i, total_mapped;
    if (!needed || (bytes && !modules)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!current_process(process)) M98CE_NOT_SUPPORTED(FALSE);
    if (count < cap) modules[count] = exe;
    count++;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    entry.dwSize = sizeof(entry);
    if (Module32First(snap, &entry)) do {
        if (entry.hModule == exe) continue;
        if (count < cap) modules[count] = entry.hModule;
        count++;
    } while (Module32Next(snap, &entry));
    CloseHandle(snap);
    total_mapped = k32_image_list(mapped, K32_IMAGE_MAX);
    for (i = 0; i < total_mapped && i < K32_IMAGE_MAX; i++) { if (count < cap) modules[count] = (HMODULE)mapped[i]; count++; }
    *needed = count * sizeof(HMODULE);
    return TRUE;
}
DWORD WINAPI m98ce_K32GetModuleFileNameExA(HANDLE process, HMODULE module, LPSTR out, DWORD size)
{
    uintptr_t base;
    int r;
    if (!out || !size) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!current_process(process)) M98CE_NOT_SUPPORTED(0);
    if (module && (r = k32_image_find((uintptr_t)module, &base, NULL, out, size)) != 0 && base == (uintptr_t)module) {
        DWORD n = 0;
        while (out[n]) n++;
        if (r < 0) SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return n;
    }
    return GetModuleFileNameA(module, out, size);
}
BOOL WINAPI m98ce_K32GetModuleInformation(HANDLE process, HMODULE module, m98ce_modinfo *info, DWORD bytes)
{
    DWORD size; LPVOID entry;
    if (!info || bytes < sizeof(*info)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (!current_process(process)) M98CE_NOT_SUPPORTED(FALSE);
    if (!module) module = GetModuleHandleA(NULL);
    if (!image_bounds(module, &size, &entry)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    info->base = module; info->size = size; info->entry = entry;
    return TRUE;
}
/* NT device-namespace path of a mapped section: Win98 has no NT object
 * namespace, so no truthful "\Device\..." name exists. */
DWORD WINAPI m98ce_K32GetMappedFileNameW(HANDLE process, LPVOID address, LPWSTR out, DWORD size)
{ (void)process; (void)address; (void)out; (void)size; M98CE_NOT_SUPPORTED(0); }
/* Working-set residency is not observable through any Win98 interface. */
BOOL WINAPI m98ce_K32QueryWorkingSetEx(HANDLE process, PVOID info, DWORD bytes)
{ (void)process; (void)info; (void)bytes; M98CE_NOT_SUPPORTED(FALSE); }

/* ---- System facts ------------------------------------------------------- */
BOOL WINAPI m98ce_GetLogicalProcessorInformation(PVOID buffer, PDWORD length)
{
    SYSTEM_INFO si;
    uint32_t len;
    int r;
    if (!length) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    GetSystemInfo(&si);
    len = *length;
    r = k32_logical_processor_info((uint32_t)si.dwActiveProcessorMask, (uint8_t *)buffer, &len);
    *length = len;
    if (r == K32_LPI_OK) return TRUE;
    SetLastError(r == K32_LPI_SHORT ? ERROR_INSUFFICIENT_BUFFER : ERROR_INVALID_PARAMETER);
    return FALSE;
}
static void mstcp_value(const char *name, char *out, DWORD cap)
{
    HKEY key;
    DWORD type, bytes = cap;
    out[0] = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\VxD\\MSTCP", 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return;
    if (RegQueryValueExA(key, name, NULL, &type, (BYTE *)out, &bytes) != ERROR_SUCCESS || type != REG_SZ || !bytes || bytes > cap) out[0] = 0;
    else out[bytes - 1] = 0;
    RegCloseKey(key);
}
BOOL WINAPI m98ce_GetComputerNameExW(DWORD format, LPWSTR out, LPDWORD size)
{
    char netbios[MAX_COMPUTERNAME_LENGTH + 1], host[256], domain[256], composed[520];
    DWORD nb = sizeof(netbios);
    unsigned need;
    int r, w;
    if (!size || format > 7 || (*size && !out)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!GetComputerNameA(netbios, &nb)) return FALSE;
    host[0] = domain[0] = 0;
    if ((format & 3) != 0) { mstcp_value("HostName", host, sizeof(host)); mstcp_value("Domain", domain, sizeof(domain)); }
    r = k32_compose_computer_name(format, netbios, host, domain, composed, sizeof(composed), &need);
    if (r < 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    w = MultiByteToWideChar(CP_ACP, 0, composed, -1, NULL, 0);
    if (w <= 0) return FALSE;
    if (*size < (DWORD)w) { *size = (DWORD)w; SetLastError(ERROR_MORE_DATA); return FALSE; }
    if (!MultiByteToWideChar(CP_ACP, 0, composed, -1, out, (int)*size)) return FALSE;
    *size = (DWORD)w - 1;
    return TRUE;
}
/* Win98 (platform VER_PLATFORM_WIN32_WINDOWS) has no NT product SKU: the
 * documented answer for an unknown product is PRODUCT_UNDEFINED (0). */
BOOL WINAPI m98ce_GetProductInfo(DWORD major, DWORD minor, DWORD sp_major, DWORD sp_minor, PDWORD type)
{
    OSVERSIONINFOA os;
    (void)major; (void)minor; (void)sp_major; (void)sp_minor;
    if (!type) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    os.dwOSVersionInfoSize = sizeof(os);
    if (!GetVersionExA(&os)) return FALSE;
    *type = 0;
    return TRUE;
}

/* ---- Explicitly unsupported on Win98 (truthful failure, never success) -- */
/* No per-thread cycle accounting exists (GetThreadTimes is NT-only too). */
BOOL WINAPI m98ce_QueryThreadCycleTime(HANDLE thread, PULONG64 cycles)
{ (void)thread; if (!cycles) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } M98CE_NOT_SUPPORTED(FALSE); }
/* No DEP/ASLR/CFG/extension-point mitigation machinery to enforce a policy. */
BOOL WINAPI m98ce_SetProcessMitigationPolicy(DWORD policy, PVOID buffer, SIZE_T length)
{ (void)policy; if (!buffer || !length) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } M98CE_NOT_SUPPORTED(FALSE); }
/* No memory-priority / power-throttling thread classes in the Win98 scheduler. */
BOOL WINAPI m98ce_SetThreadInformation(HANDLE thread, DWORD info_class, PVOID info, DWORD length)
{ (void)thread; (void)info_class; if (!info || !length) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } M98CE_NOT_SUPPORTED(FALSE); }
/* No Windows Error Reporting service exists on Win98. */
HRESULT WINAPI m98ce_WerRegisterRuntimeExceptionModule(LPCWSTR dll, PVOID context)
{ (void)dll; (void)context; return (HRESULT)0x80070032L; /* HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED) */ }
