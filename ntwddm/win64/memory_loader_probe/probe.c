/* SPDX-License-Identifier: GPL-2.0-only
 * Original freestanding actual-guest loader and memory ownership diagnostic.
 * No mock endpoint, CRT, forged module handle, exit or filesystem evidence.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include "trial_nonce.h"

typedef struct { ULONGLONG Type; union { ULONGLONG ULong64; void *Pointer; SIZE_T Size; HANDLE Handle; ULONG ULong; } u; } extended;
typedef void *(WINAPI *alloc2_fn)(HANDLE, void *, SIZE_T, ULONG, ULONG, extended *, ULONG);
typedef void *(WINAPI *map3_fn)(HANDLE, HANDLE, void *, ULONGLONG, SIZE_T, ULONG, ULONG, extended *, ULONG);
typedef BOOL (WINAPI *unmap2_fn)(HANDLE, void *, ULONG);
typedef DWORD (WINAPI *pid_fn)(void);
static alloc2_fn alloc2;
static map3_fn map3;
static unmap2_fn unmap2;
static unsigned checks, failures;
static HANDLE output;
static int output_ok = 1;
static char line[1536];
static unsigned line_used;
static void *volatile relocation_anchor = &checks;
static void zero(void *p, SIZE_T n) { unsigned char *b = p; while (n--) *b++ = 0; }
static void text(const char *s)
{
    while (*s) {
        DWORD done = 0; char c = *s++;
        if (line_used == sizeof line) { output_ok = 0; line_used = 0; }
        line[line_used++] = c;
        if (c == '\n') {
            if (!WriteFile(output, line, line_used, &done, 0) || done != line_used) output_ok = 0;
            line_used = 0;
        }
    }
}
static void number(unsigned n)
{
    char b[12]; unsigned i = 0, j;
    do { b[i++] = (char)('0' + n % 10); n /= 10; } while (n);
    for (j = 0; j < i / 2; ++j) { char t = b[j]; b[j] = b[i - 1 - j]; b[i - 1 - j] = t; }
    b[i] = 0; text(b);
}
static void hex64(ULONGLONG value)
{
    char b[17]; unsigned i;
    for (i = 0; i < 16; ++i) { b[15 - i] = "0123456789abcdef"[value & 15]; value >>= 4; }
    b[16] = 0; text(b);
}
static void check(int good, const char *name)
{
    ++checks; if (!good) ++failures;
    text(good ? "LP64 PASS " : "LP64 FAIL "); text(name); text("\r\n");
}
static void record(const char *name, ULONGLONG value, DWORD error)
{
    text("LP64 VALUE "); text(name); text(" value="); hex64(value); text(" error="); number(error); text("\r\n");
}
static void module_name(HMODULE module, const char *name)
{
    WCHAR buffer[300]; DWORD got, error, i;
    if (!module) return;
    zero(buffer, sizeof buffer); SetLastError(0);
    got = GetModuleFileNameW(module, buffer, 300); error = GetLastError();
    text("LP64 PATH "); text(name); text(" chars="); number(got); text(" error="); number(error); text(" path=");
    for (i = 0; i < got && i < 299; ++i) { char one[2] = {buffer[i] >= 32 && buffer[i] < 127 ? (char)buffer[i] : '?', 0}; text(one); }
    text("\r\n"); check(got > 0 && got < 300, "loaded_module_filename");
}
static FARPROC symbol(HMODULE module, const char *name)
{
    FARPROC p; DWORD error;
    SetLastError(0); p = GetProcAddress(module, name); error = GetLastError();
    record(name, (ULONGLONG)(ULONG_PTR)p, error); check(p != 0, name); return p;
}
#define RESOLVE(variable, type, name) do { union { FARPROC raw; type typed; } f; f.raw = symbol(module, name); variable = f.typed; } while (0)
static int equal_bytes(const unsigned char *p, SIZE_T bytes, unsigned char expected)
{
    SIZE_T i; for (i = 0; i < bytes; ++i) if (p[i] != expected) return 0; return 1;
}
static int mapped_at(void *base)
{
    MEMORY_BASIC_INFORMATION info; SIZE_T got;
    zero(&info, sizeof info); got = VirtualQuery(base, &info, sizeof info);
    return got == sizeof info && info.AllocationBase == base && info.Type == MEM_MAPPED;
}
static void candidate_file(void)
{
    HANDLE file; DWORD error, got = 0; LARGE_INTEGER size; unsigned char header[64]; BOOL good;
    SetLastError(0); file = CreateFileW(L"C:\\SHZ\\SYS64\\KERNELBASE.DLL", GENERIC_READ, FILE_SHARE_READ, 0,
                                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0); error = GetLastError();
    record("file_open", file == INVALID_HANDLE_VALUE ? 0 : (ULONGLONG)(ULONG_PTR)file, error);
    check(file != INVALID_HANDLE_VALUE, "kernelbase_live_file_read_open");
    if (file == INVALID_HANDLE_VALUE) return;
    zero(&size, sizeof size); SetLastError(0); good = GetFileSizeEx(file, &size); error = GetLastError();
    record("file_size", (ULONGLONG)size.QuadPart, error);
    check(good && size.QuadPart == CANDIDATE_BYTES, "kernelbase_live_file_exact_size");
    zero(header, sizeof header); SetLastError(0); good = ReadFile(file, header, sizeof header, &got, 0); error = GetLastError();
    record("file_read_bytes", got, error); record("file_mz", (ULONGLONG)header[0] | ((ULONGLONG)header[1] << 8), error);
    check(good && got == sizeof header && header[0] == 'M' && header[1] == 'Z', "kernelbase_live_file_mz_header");
    check(CloseHandle(file), "close_live_candidate_file");
}
static void memory_trial(void)
{
    SYSTEM_INFO info; MEMORY_BASIC_INFORMATION mbi;
    void *allocated = 0, *reserved = 0, *first = 0, *second = 0, *copy = 0;
    HANDLE mapping = 0, real_process = 0;
    SIZE_T size; DWORD e; extended param;
    text("LP64 MEMORY BEGIN\r\n");
    zero(&info, sizeof info); GetSystemInfo(&info);
    check(info.dwPageSize == 4096 && info.dwAllocationGranularity == 65536, "actual_consumer_memory_layout");
    if (info.dwPageSize != 4096 || info.dwAllocationGranularity != 65536) return;
    size = info.dwAllocationGranularity;
    zero(&param, sizeof param); param.Type = 1; param.u.ULong64 = 0x1122334455667788ull;
    SetLastError(0x5a5a); allocated = alloc2(0, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, 0, 0);
    e = GetLastError(); record("allocated", (ULONGLONG)(ULONG_PTR)allocated, e);
    check(allocated != 0, "real_virtualalloc2_allocates"); if (!allocated) goto cleanup;
    check(e == 0x5a5a, "virtualalloc2_success_preserves_error");
    check(equal_bytes(allocated, size, 0), "allocation_bytes_zeroed");
    ((unsigned char *)allocated)[0] = 0x4d; ((unsigned char *)allocated)[size - 1] = 0x29;
    check(((unsigned char *)allocated)[0] == 0x4d && ((unsigned char *)allocated)[size - 1] == 0x29, "allocation_real_bytes_writable");
    zero(&mbi, sizeof mbi);
    check(VirtualQuery(allocated, &mbi, sizeof mbi) == sizeof mbi && mbi.AllocationBase == allocated &&
          mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_READWRITE, "allocation_query_ownership");
    check(!alloc2(0, 0, size, MEM_RESERVE | 0x40000u, PAGE_NOACCESS, 0, 0) && GetLastError() == ERROR_NOT_SUPPORTED,
          "allocation_placeholder_refused");
    check(!alloc2(0, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &param, 1) && GetLastError() == ERROR_NOT_SUPPORTED &&
          param.Type == 1 && param.u.ULong64 == 0x1122334455667788ull, "allocation_extension_untouched");
    check(!alloc2(0, 0, size + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, 0, 0) && GetLastError() == ERROR_INVALID_PARAMETER,
          "allocation_unaligned_size_refused");
    check(!alloc2(0, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD, 0, 0) && GetLastError() == ERROR_NOT_SUPPORTED,
          "allocation_guard_refused");
    check(((unsigned char *)allocated)[0] == 0x4d && ((unsigned char *)allocated)[size - 1] == 0x29,
          "unsupported_allocation_keeps_owner_bytes");
    SetLastError(0); check(!alloc2(0, allocated, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, 0, 0) &&
                            GetLastError() != 0, "allocation_conflict_propagated");
    check(((unsigned char *)allocated)[0] == 0x4d, "failed_reservation_keeps_bytes");
    real_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    check(real_process != 0, "real_query_only_process_handle");
    if (real_process) check(!alloc2(real_process, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, 0, 0) &&
                            GetLastError() == ERROR_NOT_SUPPORTED, "real_process_rights_not_bypassed");
    reserved = alloc2(GetCurrentProcess(), 0, size, MEM_RESERVE, PAGE_NOACCESS, 0, 0);
    check(reserved != 0, "real_virtualalloc2_reservation");
    if (reserved) {
        zero(&mbi, sizeof mbi);
        check(VirtualQuery(reserved, &mbi, sizeof mbi) == sizeof mbi && mbi.State == MEM_RESERVE, "reservation_query_state");
        check(alloc2(GetCurrentProcess(), reserved, size, MEM_COMMIT, PAGE_READWRITE, 0, 0) == reserved, "reservation_commit_same_base");
        zero(&mbi, sizeof mbi);
        if (VirtualQuery(reserved, &mbi, sizeof mbi) == sizeof mbi && mbi.State == MEM_COMMIT)
            check(equal_bytes(reserved, size, 0), "committed_reservation_zeroed");
        else check(0, "committed_reservation_zeroed");
    }
    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, (DWORD)size, 0);
    check(mapping != 0, "real_pagefile_mapping_handle"); if (!mapping) goto cleanup;
    SetLastError(0x6161); first = map3(mapping, 0, 0, 0, size, 0, PAGE_READWRITE, 0, 0); e = GetLastError();
    record("first_view", (ULONGLONG)(ULONG_PTR)first, e);
    check(first != 0, "real_mapview3_writable"); if (!first) goto cleanup;
    check(e == 0x6161 && mapped_at(first), "mapped_view_error_and_ownership");
    check(equal_bytes(first, size, 0), "pagefile_view_zeroed");
    ((unsigned char *)first)[0] = 0x71; ((unsigned char *)first)[size - 1] = 0x55;
    second = map3(mapping, GetCurrentProcess(), 0, 0, 0, 0, PAGE_READONLY, 0, 0);
    check(second != 0 && second != first, "real_mapview3_second_independent_view");
    if (second) check(((unsigned char *)second)[0] == 0x71 && ((unsigned char *)second)[size - 1] == 0x55,
                      "same_section_views_coherent");
    copy = map3(mapping, GetCurrentProcess(), 0, 0, size, 0, PAGE_WRITECOPY, 0, 0);
    check(copy != 0, "real_copy_on_write_view");
    if (copy) {
        check(((unsigned char *)copy)[0] == 0x71, "copy_view_initial_bytes");
        ((unsigned char *)copy)[0] = 0x19;
        check(((unsigned char *)copy)[0] == 0x19 && ((unsigned char *)first)[0] == 0x71 &&
              (!second || ((unsigned char *)second)[0] == 0x71), "copy_view_private_write");
    }
    check(!map3(mapping, 0, 0, 1, size, 0, PAGE_READWRITE, 0, 0) && GetLastError() == ERROR_MAPPED_ALIGNMENT,
          "mapping_unaligned_offset_refused");
    check(!map3(mapping, 0, 0, 0, size, 0x4000u, PAGE_READWRITE, 0, 0) && GetLastError() == ERROR_NOT_SUPPORTED,
          "mapping_placeholder_refused");
    check(!map3(mapping, 0, 0, 0, size, 0, PAGE_READWRITE, &param, 1) && GetLastError() == ERROR_NOT_SUPPORTED &&
          param.u.ULong64 == 0x1122334455667788ull, "mapping_extension_untouched");
    check(!map3(mapping, 0, 0, size, size, 0, PAGE_READWRITE, 0, 0) && GetLastError() != 0,
          "mapping_owner_size_failure_propagated");
    check(!map3(INVALID_HANDLE_VALUE, 0, 0, 0, size, 0, PAGE_READWRITE, 0, 0) && GetLastError() == ERROR_INVALID_HANDLE,
          "mapping_bad_handle_failure_propagated");
    check(!unmap2(GetCurrentProcess(), (char *)first + 1, 0) && GetLastError() == ERROR_INVALID_ADDRESS,
          "unmap_interior_address_refused");
    check(!unmap2(GetCurrentProcess(), first, 2) && GetLastError() == ERROR_NOT_SUPPORTED,
          "unmap_placeholder_preservation_refused");
    check(!unmap2(GetCurrentProcess(), allocated, 0) && GetLastError() == ERROR_INVALID_ADDRESS,
          "unmap_private_allocation_refused");
    check(mapped_at(first) && ((unsigned char *)first)[0] == 0x71 && ((unsigned char *)allocated)[0] == 0x4d,
          "failed_unmap_preserves_owners");
    { BOOL closed = CloseHandle(mapping); check(closed, "close_mapping_handle_before_views"); if (closed) mapping = 0; }
    check(((unsigned char *)first)[0] == 0x71 && (!second || ((unsigned char *)second)[0] == 0x71),
          "views_outlive_mapping_handle");
    if (copy) { BOOL released = unmap2(GetCurrentProcess(), copy, 0); check(released, "release_copy_view"); if (released) copy = 0; }
    if (second) { BOOL released = unmap2(GetCurrentProcess(), second, 0); check(released, "release_second_view"); if (released) second = 0; }
    { void *saved = first; SetLastError(0x6262); BOOL released = unmap2(GetCurrentProcess(), first, 0); e = GetLastError();
      check(released && e == 0x6262, "release_first_view_preserves_error");
      if (released) { first = 0; check(!mapped_at(saved), "released_view_no_longer_owned");
        check(!unmap2(GetCurrentProcess(), saved, 0) && GetLastError() == ERROR_INVALID_ADDRESS, "double_unmap_refused"); }
    }
cleanup:
    /* Every still-owned region/handle is explicitly cleaned, even after failure. */
    if (copy) check(UnmapViewOfFile(copy), "cleanup_copy_view");
    if (second) check(UnmapViewOfFile(second), "cleanup_second_view");
    if (first) check(UnmapViewOfFile(first), "cleanup_first_view");
    if (mapping) check(CloseHandle(mapping), "cleanup_mapping_handle");
    if (real_process) check(CloseHandle(real_process), "close_real_process_handle");
    if (reserved) check(VirtualFree(reserved, 0, MEM_RELEASE), "release_reserved_allocation");
    if (allocated) check(VirtualFree(allocated, 0, MEM_RELEASE), "release_private_allocation");
    text("LP64 MEMORY DONE\r\n");
}

void LoaderProbeEntry(void)
{
    HMODULE fiber = 0, first = 0, exa = 0, lower = 0, upper = 0, module = 0;
    DWORD attributes, error;
    pid_fn forwarded = 0;
    output = GetStdHandle(STD_OUTPUT_HANDLE);
    text("LP64 BEGIN " TRIAL_NONCE "\r\n");
    check(relocation_anchor == &checks, "relocated_probe_anchor");
    text("LP64 ORDER fiber_exw_system32_then_kbase_exw_exa_plain_absolute_before_file_io\r\n");
    SetLastError(0); fiber = LoadLibraryExW(L"api-ms-win-core-fibers-l1-1-2.dll", 0, 0x800u); error = GetLastError();
    record("fiber_first_exw_system32", (ULONGLONG)(ULONG_PTR)fiber, error);
    check(!fiber && error == ERROR_MOD_NOT_FOUND, "exact_unprovided_fiber_contract_refused");
    SetLastError(0); first = LoadLibraryExW(L"kernelbase.dll", 0, 0x800u); error = GetLastError();
    record("load_first_exw_system32", (ULONGLONG)(ULONG_PTR)first, error);
    check(first != 0, "kernelbase_load_first_exw_system32_before_file_io");
    SetLastError(0); exa = LoadLibraryExA("kernelbase.dll", 0, 0x800u); error = GetLastError();
    record("load_exa_system32", (ULONGLONG)(ULONG_PTR)exa, error);
    check(exa != 0, "kernelbase_load_exa_system32_before_file_io");
    SetLastError(0); lower = LoadLibraryA("kernelbase.dll"); error = GetLastError();
    record("load_lower_basename", (ULONGLONG)(ULONG_PTR)lower, error); check(lower != 0, "kernelbase_load_lower_basename");
    SetLastError(0); upper = LoadLibraryW(L"KERNELBASE.DLL"); error = GetLastError();
    record("load_upper_basename", (ULONGLONG)(ULONG_PTR)upper, error); check(upper != 0, "kernelbase_load_upper_basename");
    SetLastError(0); module = LoadLibraryW(L"C:\\SHZ\\SYS64\\KERNELBASE.DLL"); error = GetLastError();
    record("load_absolute", (ULONGLONG)(ULONG_PTR)module, error); check(module != 0, "kernelbase_load_absolute");
    text("LP64 ORDER all_initial_kbase_load_attempts_complete_before_file_io\r\n");
    module_name(first, "first_exw_system32"); module_name(exa, "exa_system32");
    module_name(lower, "lower_basename"); module_name(upper, "upper_basename"); module_name(module, "absolute");
    SetLastError(0); attributes = GetFileAttributesA("C:\\SHZ\\SYS64\\KERNELBASE.DLL"); error = GetLastError();
    record("attributes_a", attributes, error); check(attributes != INVALID_FILE_ATTRIBUTES, "kernelbase_file_attributes_a");
    SetLastError(0); attributes = GetFileAttributesW(L"C:\\SHZ\\SYS64\\KERNELBASE.DLL"); error = GetLastError();
    record("attributes_w", attributes, error); check(attributes != INVALID_FILE_ATTRIBUTES, "kernelbase_file_attributes_w");
    candidate_file();
    if (module) {
        RESOLVE(alloc2, alloc2_fn, "VirtualAlloc2"); RESOLVE(map3, map3_fn, "MapViewOfFile3");
        RESOLVE(unmap2, unmap2_fn, "UnmapViewOfFile2"); RESOLVE(forwarded, pid_fn, "GetCurrentProcessId");
        if (forwarded) check(forwarded() == GetCurrentProcessId() && forwarded() != 0, "genuine_kernel32_forwarder");
        if (alloc2 && map3 && unmap2) memory_trial();
    }
    if (module) check(FreeLibrary(module), "unload_absolute_module");
    if (upper) check(FreeLibrary(upper), "unload_upper_module");
    if (lower) check(FreeLibrary(lower), "unload_lower_module");
    if (exa) check(FreeLibrary(exa), "unload_exa_module");
    if (first) check(FreeLibrary(first), "unload_first_exw_module");
    if (fiber) check(FreeLibrary(fiber), "unload_unexpected_fiber_module");
    check(output_ok, "serial_output_complete");
    text("LP64 COUNTS checks="); number(checks); text(" failures="); number(failures); text("\r\n");
    text(failures ? "LP64 FINAL FAIL " : "LP64 FINAL PASS "); text(TRIAL_NONCE); text("\r\n");
    ExitProcess(failures || !output_ok ? 1 : 0);
}
