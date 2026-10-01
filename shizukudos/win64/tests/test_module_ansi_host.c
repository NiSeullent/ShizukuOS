/* SPDX-License-Identifier: GPL-2.0-only
 * Complete ANSI bridge, unchanged real Toolhelp snapshot functions and UTF
 * functions; only headers/platform providers adapted for the host.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

typedef uint32_t DWORD, ULONG, UINT;
typedef uint64_t ULONG64, ULONG_PTR;
typedef int32_t LONG, NTSTATUS;
typedef uint16_t WCHAR;
typedef uint8_t BYTE;
typedef int BOOL;
typedef void *HANDLE, *HMODULE, *PVOID;
typedef pthread_mutex_t SRWLOCK;
typedef struct { DWORD dwSize,th32ModuleID,th32ProcessID,GlblcntUsage,ProccntUsage;
                 BYTE *modBaseAddr; DWORD modBaseSize; HMODULE hModule; char szModule[256],szExePath[260]; } MODULEENTRY32,*LPMODULEENTRY32;
typedef struct { DWORD dwSize,th32ModuleID,th32ProcessID,GlblcntUsage,ProccntUsage;
                 BYTE *modBaseAddr; DWORD modBaseSize; HMODULE hModule; WCHAR szModule[256],szExePath[260]; } MODULEENTRY32W,*LPMODULEENTRY32W;
typedef struct { DWORD dwSize,cntUsage,th32ProcessID; ULONG_PTR th32DefaultHeapID; DWORD th32ModuleID,cntThreads,th32ParentProcessID;
                 LONG pcPriClassBase; DWORD dwFlags; WCHAR szExeFile[260]; } PROCESSENTRY32W,*LPPROCESSENTRY32W;
#define K32API
#define WINAPI
#define SRWLOCK_INIT PTHREAD_MUTEX_INITIALIZER
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define MAX_MODULE_NAME32 255
#define HEAP_ZERO_MEMORY 8u
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define ERROR_INVALID_HANDLE 6u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_INVALID_DATA 13u
#define ERROR_NO_MORE_FILES 18u
#define ERROR_BAD_LENGTH 24u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define ERROR_MR_MID_NOT_FOUND 317u
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define TH32CS_SNAPPROCESS 2u
#define TH32CS_SNAPMODULE 8u
#define TH32CS_SNAPMODULE32 0x10u
#define K32Q_PROCESS_LIST 4u
#define K32Q_MODULE_LIST 5u
#define IDLE_PRIORITY_CLASS 0x40u
#define BELOW_NORMAL_PRIORITY_CLASS 0x4000u
#define ABOVE_NORMAL_PRIORITY_CLASS 0x8000u
#define HIGH_PRIORITY_CLASS 0x80u
#define REALTIME_PRIORITY_CLASS 0x100u

static unsigned checks, allocations, events;
static DWORD last_error;
static DWORD shz_last_error(void) { return last_error; }
static void shz_set_last_error(DWORD error) { last_error = error; }
static DWORD GetLastError(void) { return last_error; }
static BOOL fail_err(DWORD error) { last_error = error; return FALSE; }
static DWORD GetCurrentProcessId(void) { return 0x5678; }
static PVOID ShzProcessHeap(void) { return NULL; }
static PVOID RtlAllocateHeap(PVOID, ULONG, size_t);
static BOOL RtlFreeHeap(PVOID, ULONG, PVOID);
static NTSTATUS NtShzQueryK32(ULONG, HANDLE, void *, ULONG, ULONG *);
static DWORD k32_nt_error(NTSTATUS);
static HANDLE CreateEventW(void *, BOOL, BOOL, const WCHAR *);
static void AcquireSRWLockExclusive(SRWLOCK *lock) { if (pthread_mutex_lock(lock)) abort(); }
static void ReleaseSRWLockExclusive(SRWLOCK *lock) { if (pthread_mutex_unlock(lock)) abort(); }
static size_t k32_volume_device(WCHAR letter, WCHAR *out) { (void)letter; out[0] = 0; return 0; }

#include "actual_utf.inc"
#include "actual_format_path.inc"
#include "actual_toolhelp.inc"
static BOOL host_first_with_fault(HANDLE, LPMODULEENTRY32W);
static BOOL host_next_with_fault(HANDLE, LPMODULEENTRY32W);
#define Module32FirstW host_first_with_fault
#define Module32NextW host_next_with_fault
#include "module_ansi.inc"
#undef Module32FirstW
#undef Module32NextW

#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(2); } } while (0)
static k_mod live_modules[4];
static unsigned live_count;
static BOOL force_long_wide, force_unterminated_wide, force_long_path;
/* Faults are added only by a public W-call adapter. The complete actual W
 * functions still run exactly once and advance their actual snapshot cursor. */

static PVOID RtlAllocateHeap(PVOID heap, ULONG flags, size_t bytes)
{
    void *p;
    CHECK(!heap && !(flags & ~HEAP_ZERO_MEMORY));
    p = flags ? calloc(1,bytes) : malloc(bytes);
    if (p) ++allocations;
    return p;
}
static BOOL RtlFreeHeap(PVOID heap, ULONG flags, PVOID memory)
{
    CHECK(!heap && !flags && memory && allocations > 0); --allocations; free(memory); return TRUE;
}
static HANDLE CreateEventW(void *security, BOOL manual, BOOL initial, const WCHAR *name)
{
    void *event;
    CHECK(!security && manual && !initial && !name); event = malloc(1);
    if (event) ++events;
    return event;
}
static BOOL close_snapshot(HANDLE snapshot)
{
    CHECK(snapshot && snapshot != INVALID_HANDLE_VALUE && events > 0);
    k32_snapshot_closing(snapshot); free(snapshot); --events; return TRUE;
}
static DWORD k32_nt_error(NTSTATUS status)
{
    CHECK(status == (NTSTATUS)0xc000000b); last_error = ERROR_MR_MID_NOT_FOUND; return last_error;
}
static NTSTATUS NtShzQueryK32(ULONG cls, HANDLE pid, void *buffer, ULONG capacity, ULONG *required)
{
    unsigned bytes;
    CHECK(required);
    if (cls == K32Q_MODULE_LIST) {
        CHECK(!pid || (uintptr_t)pid == 0x1234);
        bytes = live_count * sizeof(k_mod);
        *required = bytes;
        if (capacity < bytes) return STATUS_BUFFER_TOO_SMALL;
        if (bytes) memcpy(buffer,live_modules,bytes);
    } else {
        CHECK(cls == K32Q_PROCESS_LIST && !pid); *required = 0;
    }
    return 0;
}
static void reset_records(void)
{
    CHECK(!events && !allocations && !g_snaps);
    memset(live_modules,0,sizeof live_modules); live_count = 3;
    live_modules[0].base = 0x7ffd12345000ULL; live_modules[0].size = 0x234560;
    strcpy(live_modules[0].name,"program.exe"); strcpy(live_modules[0].path,"\\TESTS\\program.exe");
    live_modules[1].base = 0x7ffaabcdef00ULL; live_modules[1].size = 0x345670;
    strcpy(live_modules[1].name,"\xeb\x8f\x84\xea\xb5\xac.dll"); strcpy(live_modules[1].path,"D:\\\xeb\x8f\x84\xea\xb5\xac.dll");
    live_modules[2].base = 0x700000001000ULL; live_modules[2].size = 0x456780;
    strcpy(live_modules[2].name,"last.dll"); strcpy(live_modules[2].path,"C:\\TESTS\\last.dll");
    last_error = 0x321765; force_long_wide = force_unterminated_wide = force_long_path = FALSE;
}
static void check_record(const MODULEENTRY32 *entry, unsigned index, DWORD pid)
{
    static const char *paths[] = { "C:\\TESTS\\program.exe", "D:\\\xeb\x8f\x84\xea\xb5\xac.dll", "C:\\TESTS\\last.dll" };
    CHECK(entry->th32ModuleID == 1 && entry->th32ProcessID == pid && entry->GlblcntUsage == 0xffff && entry->ProccntUsage == 0xffff);
    CHECK((uintptr_t)entry->modBaseAddr == live_modules[index].base && (uintptr_t)entry->hModule == live_modules[index].base);
    CHECK(entry->modBaseSize == live_modules[index].size && !strcmp(entry->szModule,live_modules[index].name) && !strcmp(entry->szExePath,paths[index]));
}

/* These wrappers are wired at the candidate's API boundary by preprocessor
 * name substitution only in the host adapter. No production body is edited. */
static BOOL faulted_wide(BOOL ok, LPMODULEENTRY32W entry)
{
    unsigned i;
    if (ok && force_long_wide) { for (i = 0; i < 200; ++i) entry->szModule[i] = 0x4e00; entry->szModule[200] = 0; }
    if (ok && force_unterminated_wide) { for (i = 0; i < 256; ++i) entry->szModule[i] = 'X'; }
    if (ok && force_long_path) { for (i = 0; i < 200; ++i) entry->szExePath[i] = 0x4e00; entry->szExePath[200] = 0; }
    return ok;
}
static BOOL host_first_with_fault(HANDLE snapshot, LPMODULEENTRY32W entry) { return faulted_wide(Module32FirstW(snapshot,entry),entry); }
static BOOL host_next_with_fault(HANDLE snapshot, LPMODULEENTRY32W entry) { return faulted_wide(Module32NextW(snapshot,entry),entry); }

int main(void)
{
    HANDLE snapshot, second, empty;
    MODULEENTRY32 entry, before;
    MODULEENTRY32W wide;
    struct { MODULEENTRY32 entry; unsigned char guard[32]; } larger;
    unsigned i, size;
    DWORD prior;
    reset_records(); snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0);
    CHECK(snapshot != INVALID_HANDLE_VALUE);
    memset(&entry,0xa5,sizeof entry); entry.dwSize = sizeof entry; prior = last_error;
    CHECK(Module32First(snapshot,&entry) && last_error == prior); check_record(&entry,0,0x5678);
    for (size = 0; size < sizeof entry; ++size) {
        entry.dwSize = size; before = entry;
        CHECK(!(size & 1 ? Module32First(snapshot,&entry) : Module32Next(snapshot,&entry)));
        CHECK(last_error == 24 && !memcmp(&entry,&before,sizeof entry) && g_snaps->mod_pos == 1);
    }
    entry.dwSize = sizeof entry;
    CHECK(!Module32Next(snapshot,NULL) && last_error == 24 && g_snaps->mod_pos == 1);
    memset(&wide,0,sizeof wide); wide.dwSize = sizeof wide;
    CHECK(Module32NextW(snapshot,&wide) && (uintptr_t)wide.hModule == live_modules[1].base);
    prior = last_error; CHECK(Module32Next(snapshot,&entry) && last_error == prior); check_record(&entry,2,0x5678);
    before = entry;
    CHECK(!Module32Next(snapshot,&entry) && last_error == 18 && !memcmp(&entry,&before,sizeof entry));
    CHECK(!Module32Next(snapshot,&entry) && last_error == 18 && g_snaps->mod_pos == 3);
    CHECK(Module32First(snapshot,&entry)); check_record(&entry,0,0x5678);
    memset(&larger,0xa5,sizeof larger); larger.entry.dwSize = sizeof larger;
    CHECK(Module32First(snapshot,&larger.entry) && larger.entry.dwSize == sizeof larger);
    for (i = 0; i < sizeof larger.guard; ++i) CHECK(larger.guard[i] == 0xa5);
    CHECK(close_snapshot(snapshot));

    reset_records(); snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32,0); second = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0x1234);
    CHECK(Module32First(snapshot,&entry)); check_record(&entry,0,0x5678);
    CHECK(Module32First(second,&entry)); check_record(&entry,0,0x1234);
    CHECK(Module32Next(second,&entry)); check_record(&entry,1,0x1234);
    CHECK(Module32Next(snapshot,&entry)); check_record(&entry,1,0x5678);
    CHECK(close_snapshot(snapshot) && close_snapshot(second));

    reset_records(); snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0);
    strcpy(live_modules[0].name,"CHANGED.exe"); live_modules[0].base = 0x22220000;
    CHECK(Module32First(snapshot,&entry) && !strcmp(entry.szModule,"program.exe") && (uintptr_t)entry.modBaseAddr == 0x7ffd12345000ULL);
    second = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0);
    CHECK(Module32First(second,&entry) && !strcmp(entry.szModule,"CHANGED.exe") && (uintptr_t)entry.modBaseAddr == 0x22220000);
    CHECK(close_snapshot(snapshot) && close_snapshot(second));

    reset_records(); empty = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); before = entry;
    CHECK(!Module32First(empty,&entry) && last_error == 18 && !memcmp(&entry,&before,sizeof entry));
    CHECK(close_snapshot(empty)); before = entry;
    CHECK(!Module32First(empty,&entry) && last_error == 6 && !memcmp(&entry,&before,sizeof entry));
    CHECK(!Module32Next(INVALID_HANDLE_VALUE,&entry) && last_error == 6);
    live_count = 0; snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0);
    CHECK(!Module32First(snapshot,&entry) && last_error == 18); CHECK(close_snapshot(snapshot));

    reset_records(); snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0); before = entry; force_long_wide = TRUE;
    CHECK(!Module32First(snapshot,&entry) && last_error == 122 && !memcmp(&entry,&before,sizeof entry) && g_snaps->mod_pos == 1);
    force_long_wide = FALSE; CHECK(Module32Next(snapshot,&entry)); check_record(&entry,1,0x5678); CHECK(close_snapshot(snapshot));
    reset_records(); snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0); before = entry; force_long_path = TRUE;
    CHECK(!Module32First(snapshot,&entry) && last_error == 122 && !memcmp(&entry,&before,sizeof entry) && g_snaps->mod_pos == 1);
    force_long_path = FALSE; CHECK(Module32Next(snapshot,&entry)); check_record(&entry,1,0x5678); CHECK(close_snapshot(snapshot));
    reset_records(); snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0); before = entry; force_unterminated_wide = TRUE;
    CHECK(!Module32First(snapshot,&entry) && last_error == 13 && !memcmp(&entry,&before,sizeof entry) && g_snaps->mod_pos == 1);
    force_unterminated_wide = FALSE; CHECK(Module32Next(snapshot,&entry)); check_record(&entry,1,0x5678); CHECK(close_snapshot(snapshot));
    CHECK(!events && !allocations && !g_snaps);
    printf("MODULE_ANSI_HOST: %u checks PASS\n",checks);
    return 0;
}
