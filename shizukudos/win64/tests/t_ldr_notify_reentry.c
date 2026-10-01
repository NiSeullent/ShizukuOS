/* SPDX-License-Identifier: GPL-2.0-only: genuine attach-time retirement and notification batching. */
#include "k32test.h"
#include "nt.h"
typedef ULONG (WINAPI *value_fn)(void);
typedef HMODULE (WINAPI *module_fn)(void);
typedef struct { ULONG Flags; const SHZ_UNICODE_STRING *FullDllName, *BaseDllName; PVOID DllBase; ULONG SizeOfImage; } notify_data;
typedef void (NTAPI *notify_fn)(ULONG, const notify_data *, PVOID);
typedef NTSTATUS (NTAPI *register_fn)(ULONG, notify_fn, PVOID, PVOID *);
typedef NTSTATUS (NTAPI *unregister_fn)(PVOID);
static ULONG prior_loads, prior_unloads, reentry_loads, leaf_loads, mapped_unloads;
static BOOL named(const SHZ_UNICODE_STRING *s, const WCHAR *name)
{
    ULONG i;
    for (i = 0; name[i]; ++i)
        if (i >= s->Length / 2 || s->Buffer[i] != name[i]) return FALSE;
    return i == s->Length / 2;
}
static void NTAPI observe(ULONG reason, const notify_data *data, PVOID context)
{
    MEMORY_BASIC_INFORMATION mbi;
    (void)context;
    if (named(data->BaseDllName, L"loader_fixture_b.dll")) {
        if (reason == 1) ++prior_loads;
        else if (reason == 2) {
            ++prior_unloads;
            if (VirtualQuery(data->DllBase, &mbi, sizeof mbi) == sizeof mbi && mbi.State == MEM_COMMIT) ++mapped_unloads;
        }
    }
    if (reason == 1 && named(data->BaseDllName, L"loader_fixture_notify_reentry.dll")) ++reentry_loads;
    if (reason == 1 && named(data->BaseDllName, L"loader_fixture_notify_leaf.dll")) ++leaf_loads;
}
static BOOL mapped(HMODULE module, DWORD state)
{
    MEMORY_BASIC_INFORMATION mbi;
    return VirtualQuery(module, &mbi, sizeof mbi) == sizeof mbi && mbi.State == state;
}
static BOOL absent_from_three_lists(HMODULE module)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *heads[3] = { &ldr->InLoadOrderModuleList, &ldr->InMemoryOrderModuleList, &ldr->InInitializationOrderModuleList };
    unsigned i;
    for (i = 0; i < 3; ++i) {
        LIST_ENTRY *l; unsigned count = 0;
        for (l = heads[i]->Flink; l != heads[i]; l = l->Flink) {
            SHZ_LDR_ENTRY *e = (SHZ_LDR_ENTRY *)((BYTE *)l - i * sizeof(LIST_ENTRY));
            if (++count > SHZ_LDR_RETIRE_MAX || e->DllBase == module) return FALSE;
        }
    }
    return TRUE;
}
int main(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll"), prior, reentry, leaf, second;
    register_fn reg = (register_fn)GetProcAddress(ntdll, "LdrRegisterDllNotification");
    unregister_fn unreg = (unregister_fn)GetProcAddress(ntdll, "LdrUnregisterDllNotification");
    value_fn attached, retired, leaf_attached;
    module_fn get_prior, get_leaf;
    PVOID cookie = 0;
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    CHECK(reg && unreg && reg(0, observe, 0, &cookie) == 0, "register actual notification observer");
    if (!reg || !unreg || !cookie) return 1;
    prior = LoadLibraryW(L"loader_fixture_b.dll");
    CHECK(prior && prior_loads == 1, "unrelated prior dynamic image attaches and reports one load");
    if (!prior) return 1;
    CHECK(CONTAINING_RECORD(ldr->InLoadOrderModuleList.Blink, SHZ_LDR_ENTRY, InLoadOrderLinks)->DllBase == prior,
          "fixture proves old dynamic image is the real prior load-list tail");
    reentry = LoadLibraryW(L"loader_fixture_notify_reentry.dll");
    CHECK(reentry != 0, "new DllMain can retire prior tail and return from actual load");
    if (!reentry) return 1;
    attached = (value_fn)GetProcAddress(reentry, "LoaderNotifyReentryAttached");
    retired = (value_fn)GetProcAddress(reentry, "LoaderNotifyPriorRetired");
    get_prior = (module_fn)GetProcAddress(reentry, "LoaderNotifyPrior");
    get_leaf = (module_fn)GetProcAddress(reentry, "LoaderNotifyLeaf");
    CHECK(attached && retired && get_prior && get_leaf, "real attach state exports resolve");
    if (!attached || !retired || !get_prior || !get_leaf) return 1;
    leaf = get_leaf();
    CHECK(attached() == 1 && retired() == 1 && get_prior() == prior, "real attach freed the selected prior image exactly once");
    CHECK(prior_loads == 1 && prior_unloads == 1 && mapped_unloads == 1, "prior unload reports while mapped and receives no spurious later load");
    CHECK(!GetModuleHandleW(L"loader_fixture_b.dll") && absent_from_three_lists(prior) && mapped(prior, MEM_FREE),
          "prior image truly leaves all lists and releases its reservation during attach");
    CHECK(leaf && reentry_loads == 1 && leaf_loads == 1, "outer and recursive load batches each report exactly one real notification");
    if (!leaf) return 1;
    leaf_attached = (value_fn)GetProcAddress(leaf, "LoaderNotifyLeafAttached");
    CHECK(leaf_attached && leaf_attached() == 1, "recursively loaded image attaches once and remains callable");
    second = LoadLibraryW(L"loader_fixture_notify_reentry.dll");
    CHECK(second == reentry && attached() == 1 && reentry_loads == 1 && leaf_loads == 1, "existing-image reference adds no attach or notification batch");
    CHECK(FreeLibrary(second) && mapped(reentry, MEM_COMMIT), "extra explicit reference releases without retiring outer image");
    CHECK(FreeLibrary(reentry) && mapped(reentry, MEM_FREE) && mapped(leaf, MEM_COMMIT), "outer retires while explicit nested leaf reference survives");
    CHECK(FreeLibrary(leaf) && mapped(leaf, MEM_FREE), "transferred nested reference genuinely detaches and retires");
    CHECK(unreg(cookie) == 0, "actual observer unregisters");
    return k32t_finish("T_LDR_NOTIFY_REENTRY");
}
