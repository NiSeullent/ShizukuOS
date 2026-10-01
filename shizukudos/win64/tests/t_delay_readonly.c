/* SPDX-License-Identifier: GPL-2.0-only
 * Real resolver patching of protected module and IAT pages, not a mock loader.
 * The genuine exported function is called after the original page protections
 * have been restored. Concurrent resolvers share the same initially empty slot.
 */
#include "k32test.h"

typedef struct {
    DWORD Attributes, DllNameRVA, ModuleHandleRVA, ImportAddressTableRVA,
          ImportNameTableRVA, BoundImportAddressTableRVA,
          UnloadInformationTableRVA, TimeDateStamp;
} delay_descriptor;
typedef PVOID (WINAPI *system_hook)(LPCSTR, LPCSTR);
typedef PVOID (WINAPI *resolve_fn)(PVOID, const delay_descriptor *, PVOID,
                                 system_hook, PIMAGE_THUNK_DATA, ULONG);
typedef ULONGLONG (WINAPI *tick_fn)(void);
typedef struct {
    BYTE *base;
    delay_descriptor *descriptor;
    PIMAGE_THUNK_DATA thunk;
    HMODULE *module;
    PVOID expected;
} fixture;
static resolve_fn resolve;
static volatile LONG errors, hook_calls;

static DWORD protection(void *address)
{
    MEMORY_BASIC_INFORMATION info;
    return VirtualQuery(address, &info, sizeof info) ? info.Protect : 0;
}
static BOOL initialize(fixture *f, LPCSTR dll, LPCSTR proc, DWORD slot_protect, DWORD iat_protect)
{
    DWORD old;
    IMAGE_IMPORT_BY_NAME *name;
    PIMAGE_THUNK_DATA names;
    memset(f, 0, sizeof *f);
    f->base = VirtualAlloc(NULL, 12288, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!f->base) return FALSE;
    f->module = (HMODULE *)(f->base + 64);
    f->thunk = (PIMAGE_THUNK_DATA)(f->base + 4096 + 64);
    f->descriptor = (delay_descriptor *)(f->base + 8192);
    names = (PIMAGE_THUNK_DATA)(f->base + 8192 + 64);
    name = (IMAGE_IMPORT_BY_NAME *)(f->base + 8192 + 128);
    strcpy((char *)name->Name, proc);
    strcpy((char *)(f->base + 8192 + 512), dll);
    names[0].u1.AddressOfData = 8192 + 128;
    f->descriptor->Attributes = 1;
    f->descriptor->DllNameRVA = 8192 + 512;
    f->descriptor->ModuleHandleRVA = 64;
    f->descriptor->ImportAddressTableRVA = 4096 + 64;
    f->descriptor->ImportNameTableRVA = 8192 + 64;
    return VirtualProtect(f->base, 4096, slot_protect, &old) &&
           VirtualProtect(f->base + 4096, 4096, iat_protect, &old) &&
           VirtualProtect(f->base + 8192, 4096, PAGE_READONLY, &old);
}
static PVOID WINAPI fail_hook(LPCSTR dll, LPCSTR proc)
{
    if (!dll || strcmp(dll, "kernel32.dll") || !proc || strcmp(proc, "ShzMissingDelayExport"))
        InterlockedIncrement(&errors);
    InterlockedIncrement(&hook_calls);
    return NULL;
}
static DWORD WINAPI worker(void *context)
{
    fixture *f = context;
    unsigned i;
    for (i = 0; i < 64; ++i) {
        PVOID result = resolve(f->base, f->descriptor, NULL, NULL, f->thunk, 0);
        if (result != f->expected || (tick_fn)result == NULL) InterlockedIncrement(&errors);
        else (void)((tick_fn)result)();
    }
    return 0;
}
static void dispose(fixture *f)
{
    if (f->base) {
        if (*f->module) FreeLibrary(*f->module);
        CHECK(VirtualFree(f->base, 0, MEM_RELEASE), "actual delay descriptor mapping released");
    }
}
int main(void)
{
    fixture f;
    HANDLE threads[8];
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    PVOID result, expected = (PVOID)GetProcAddress(kernel, "GetTickCount64");
    unsigned i, created = 0;
    DWORD code, old;
    ULONGLONG before, after;
    resolve = (resolve_fn)GetProcAddress(kernel, "ResolveDelayLoadedAPI");
    CHECK(resolve && expected, "genuine delay resolver and tick export resolve");
    if (!resolve || !expected) return 1;
    CHECK(initialize(&f, "kernel32.dll", "GetTickCount64", PAGE_READONLY, PAGE_READONLY),
          "module slot, IAT and descriptor are genuinely read-only");
    if (!f.base) return 1;
    CHECK(protection(f.module) == PAGE_READONLY && protection(f.thunk) == PAGE_READONLY,
          "actual VM query confirms both protected target pages");
    result = resolve(f.base, f.descriptor, NULL, NULL, f.thunk, 0);
    CHECK(result == expected && *f.module == kernel && f.thunk->u1.Function == (ULONG_PTR)expected,
          "read-only module and IAT slots publish the genuine loaded function");
    CHECK(protection(f.module) == PAGE_READONLY && protection(f.thunk) == PAGE_READONLY,
          "both original read-only protections restored after resolution");
    if (result == expected) {
        before = ((tick_fn)result)(); Sleep(20); after = ((tick_fn)result)();
        CHECK(after > before, "patched function returns genuinely advancing kernel clock");
    }
    CHECK(resolve(f.base, f.descriptor, NULL, NULL, f.thunk, 0) == expected,
          "repeat resolution reuses the real published module");
    dispose(&f);
    CHECK(initialize(&f, "kernel32.dll", "GetTickCount64", PAGE_READONLY, PAGE_READONLY),
          "fresh protected mapping for concurrent initially-empty resolution");
    if (!f.base) return 1;
    f.expected = expected; errors = 0;
    for (i = 0; i < 8; ++i) {
        threads[i] = CreateThread(NULL, 0, worker, &f, 0, NULL);
        if (threads[i]) ++created;
    }
    CHECK(created == 8, "eight real resolver threads started");
    for (i = 0; i < 8; ++i) if (threads[i]) {
        DWORD waited = WaitForSingleObject(threads[i], 15000);
        CHECK(waited == WAIT_OBJECT_0 && GetExitCodeThread(threads[i], &code) && code == 0,
              "real resolver worker completed");
        CloseHandle(threads[i]);
        /* A failed join must not free the mapping still used by a worker.
         * Process exit cleans up the mapping and any remaining threads. */
        if (waited != WAIT_OBJECT_0) return 1;
    }
    CHECK(errors == 0 && f.thunk->u1.Function == (ULONG_PTR)expected && *f.module == kernel,
          "512 actual concurrent resolutions and function calls retain correct binding");
    CHECK(protection(f.module) == PAGE_READONLY && protection(f.thunk) == PAGE_READONLY,
          "concurrent protection transactions leave both target pages read-only");
    dispose(&f);
    CHECK(initialize(&f, "kernel32.dll", "GetTickCount64", PAGE_READWRITE, PAGE_EXECUTE_READ),
          "actual executable read-only IAT page prepared");
    if (!f.base) return 1;
    CHECK(resolve(f.base, f.descriptor, NULL, NULL, f.thunk, 0) == expected &&
          protection(f.thunk) == PAGE_EXECUTE_READ && protection(f.module) == PAGE_READWRITE,
          "executable IAT and independently writable module protection restored exactly");
    CHECK(!resolve(f.base, f.descriptor, NULL, NULL, f.thunk, 1) && GetLastError() == ERROR_INVALID_PARAMETER,
          "reserved nonzero flags fail before patching");
    CHECK(VirtualProtect(f.base + 4096, 4096, PAGE_NOACCESS, &old), "IAT is genuinely made inaccessible");
    CHECK(!resolve(f.base, f.descriptor, NULL, NULL, f.thunk, 0) && GetLastError() == ERROR_NOACCESS &&
          protection(f.thunk) == PAGE_NOACCESS, "inaccessible IAT fails without changing its protection");
    CHECK(VirtualProtect(f.base, 4096, PAGE_NOACCESS, &old), "module slot is genuinely made inaccessible");
    CHECK(!resolve(f.base, f.descriptor, NULL, NULL, f.thunk, 0) && GetLastError() == ERROR_NOACCESS &&
          protection(f.module) == PAGE_NOACCESS, "inaccessible module slot fails before the loader without a fault");
    CHECK(VirtualProtect(f.base, 4096, PAGE_READWRITE, &old), "module slot restored for owned fixture cleanup");
    dispose(&f);
    CHECK(initialize(&f, "kernel32.dll", "ShzMissingDelayExport", PAGE_READONLY, PAGE_READONLY),
          "actual missing export fixture with protected IAT prepared");
    if (!f.base) return 1;
    hook_calls = 0; errors = 0;
    CHECK(!resolve(f.base, f.descriptor, NULL, fail_hook, f.thunk, 0) && hook_calls == 1 && errors == 0 &&
          f.thunk->u1.Function == 0 && protection(f.thunk) == PAGE_READONLY,
          "real absent export calls failure hook and leaves IAT unpatched");
    dispose(&f);
    return k32t_finish("T_DELAY_READONLY");
}
