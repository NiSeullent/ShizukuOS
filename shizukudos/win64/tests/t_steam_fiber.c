/* SPDX-License-Identifier: GPL-2.0-only
 * Real fiber behavior: repeated separate-stack execution, TEB identity/limits,
 * TLS versus FLS, FP control, reverse conversion, synchronized migration,
 * callback reentry and converted-stack ownership. Not a Steam UI test. */
#include "k32test.h"

static LPVOID root_fiber, child_fiber;
static DWORD fls_index, tls_index;
static volatile LONG child_faults, visits, child_callbacks, root_callbacks, callback_reentry;

static ULONG_PTR teb(void) { ULONG_PTR v; __asm__ volatile("movq %%gs:0x30,%0" : "=r"(v)); return v; }
/* Use the actual ABI fields directly: MinGW's __readgsqword inline models
 * GS addressing as a null-based C array and triggers GCC -Warray-bounds. */
static LPVOID current_fiber_address(void) { ULONG_PTR v; __asm__ volatile("movq %%gs:0x20,%0" : "=r"(v)); return (LPVOID)v; }
static LPVOID fiber_parameter(void) { return *(LPVOID *)current_fiber_address(); }
static DWORD mxcsr(void) { DWORD v; __asm__ volatile("stmxcsr %0" : "=m"(v)); return v; }
static void set_mxcsr(DWORD v) { __asm__ volatile("ldmxcsr %0" : : "m"(v)); }
static USHORT x87cw(void) { USHORT v; __asm__ volatile("fnstcw %0" : "=m"(v)); return v; }
static void set_x87cw(USHORT v) { __asm__ volatile("fldcw %0" : : "m"(v)); }
static void fault_if(int condition) { if (!condition) InterlockedIncrement(&child_faults); }

static VOID CALLBACK idle(LPVOID ignored) { (void)ignored; for (;;) SwitchToFiber(root_fiber); }

static VOID CALLBACK destructor(LPVOID value)
{
    if (value == (LPVOID)(ULONG_PTR)0x2222) {
        DWORD temporary;
        LPVOID new_fiber;
        InterlockedIncrement(&child_callbacks);
        fault_if(current_fiber_address() == root_fiber);        /* DeleteFiber callbacks execute on the caller */
        fault_if(FlsGetValue(fls_index) == (LPVOID)(ULONG_PTR)0x1111);
        DeleteFiber(child_fiber);                         /* recursive deletion must not free twice */
        temporary = FlsAlloc(NULL);                       /* the callback must not inherit the registry lock */
        fault_if(temporary != FLS_OUT_OF_INDEXES);
        if (temporary != FLS_OUT_OF_INDEXES) {
            fault_if(FlsSetValue(temporary, (LPVOID)(ULONG_PTR)0x3333));
            fault_if(FlsFree(temporary));
        }
        new_fiber = CreateFiber(32768, idle, NULL);
        fault_if(new_fiber != NULL);
        if (new_fiber) DeleteFiber(new_fiber);
        InterlockedIncrement(&callback_reentry);
    } else if (value == (LPVOID)(ULONG_PTR)0x1111) {
        InterlockedIncrement(&root_callbacks);
    } else {
        InterlockedIncrement(&child_faults);
    }
}

static VOID CALLBACK child(LPVOID parameter)
{
    volatile ULONG_PTR local = (ULONG_PTR)0x123456789abcdef0ull;
    ULONG_PTR low, high;
    MEMORY_BASIC_INFORMATION memory;
    fault_if(parameter == (LPVOID)(ULONG_PTR)0x4444 && fiber_parameter() == parameter);
    fault_if(current_fiber_address() == child_fiber && IsThreadAFiber());
    GetCurrentThreadStackLimits(&low, &high);
    fault_if(low < (ULONG_PTR)&local && (ULONG_PTR)&local < high);
    fault_if(*(ULONG_PTR *)(teb() + 0x08) == high && *(ULONG_PTR *)(teb() + 0x10) > low);
    fault_if(VirtualQuery((LPVOID)low, &memory, sizeof memory) == sizeof memory && memory.Protect == PAGE_NOACCESS);
    fault_if(FlsGetValue(fls_index) == NULL);               /* created fibers start with independent FLS */
    fault_if(TlsGetValue(tls_index) == (LPVOID)(ULONG_PTR)0x5555);
    fault_if(FlsSetValue(fls_index, (LPVOID)(ULONG_PTR)0x2222));
    fault_if(TlsSetValue(tls_index, (LPVOID)(ULONG_PTR)0x6666));
    set_mxcsr(0x3f80); set_x87cw(0x067f);
    for (;;) {
        fault_if(local == (ULONG_PTR)0x123456789abcdef0ull);
        fault_if((mxcsr() & 0x6000) == 0x2000 && (x87cw() & 0x0c00) == 0x0400);
        fault_if(FlsGetValue(fls_index) == (LPVOID)(ULONG_PTR)0x2222);
        InterlockedIncrement(&visits);
        SwitchToFiber(root_fiber);
    }
}

static DWORD WINAPI migrate(LPVOID ignored)
{
    unsigned i;
    (void)ignored;
    root_fiber = ConvertThreadToFiber(NULL);
    if (!root_fiber) return 2;
    for (i = 0; i < 100; ++i) SwitchToFiber(child_fiber);
    if (!ConvertFiberToThread()) return 3;
    return 0;
}

struct ownership_state {
    LPVOID original, original_stack, new_stack, probe;
    SIZE_T original_bytes;
    BOOL retained, refused_reuse;
};

static VOID CALLBACK delete_original(LPVOID argument)
{
    struct ownership_state *state = argument;
    MEMORY_BASIC_INFORMATION memory;
    LPVOID reuse;
    ULONG_PTR low, high;
    GetCurrentThreadStackLimits(&low, &high);
    state->new_stack = (LPVOID)low;
    DeleteFiber(state->original);
    state->retained = VirtualQuery(state->original_stack, &memory, sizeof memory) == sizeof memory && memory.State == MEM_COMMIT;
    reuse = VirtualAlloc(state->original_stack, state->original_bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    state->refused_reuse = reuse == NULL;
    state->probe = VirtualAlloc(NULL, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (state->probe) *(DWORD *)state->probe = 0xface1234;
    if (!ConvertFiberToThread()) ExitThread(2);
    ExitThread(73);                                       /* kernel now releases its original stack owner */
}

static DWORD WINAPI ownership_worker(LPVOID argument)
{
    struct ownership_state *state = argument;
    ULONG_PTR low, high;
    LPVOID fiber;
    GetCurrentThreadStackLimits(&low, &high);
    state->original_stack = (LPVOID)low;
    state->original_bytes = high - low;
    state->original = ConvertThreadToFiber(NULL);
    if (!state->original) return 1;
    fiber = CreateFiber(32768, delete_original, state);
    if (!fiber) return 2;
    SwitchToFiber(fiber);
    return 3;                                             /* callback is required to exit its thread */
}

static DWORD WINAPI self_delete(LPVOID ignored)
{
    LPVOID fiber;
    (void)ignored;
    fiber = ConvertThreadToFiber(NULL);
    if (!fiber) return 2;
    DeleteFiber(fiber);
    return 3;
}

static DWORD WINAPI retain_converted(LPVOID output)
{
    *(LPVOID *)output = ConvertThreadToFiber(NULL);
    return *(LPVOID *)output ? 0 : 1;
}

int main(void)
{
    ULONG_PTR original_low, original_high, low, high;
    DWORD saved_mx = mxcsr(), code, waited;
    USHORT saved_cw = x87cw();
    LPVOID main_root, converted_other = NULL;
    HANDLE thread;
    unsigned i;
    struct ownership_state ownership;
    MEMORY_BASIC_INFORMATION memory;

    CHECK(!IsThreadAFiber(), "ordinary thread has no fiber bit");
    CHECK(!ConvertFiberToThread() && GetLastError() == ERROR_ALREADY_THREAD, "reverse conversion rejects ordinary thread");
    CHECK(!ConvertThreadToFiberEx(NULL, 2) && GetLastError() == ERROR_INVALID_PARAMETER, "conversion rejects unknown flag");
    CHECK(!CreateFiberEx(0, 0, 2, child, NULL) && GetLastError() == ERROR_INVALID_PARAMETER, "creation rejects unknown flag");
    fls_index = FlsAlloc(destructor); tls_index = TlsAlloc();
    CHECK(fls_index != FLS_OUT_OF_INDEXES && tls_index != TLS_OUT_OF_INDEXES, "allocate actual FLS and TLS slots");
    CHECK(FlsSetValue(fls_index, (LPVOID)(ULONG_PTR)0x1111) && TlsSetValue(tls_index, (LPVOID)(ULONG_PTR)0x5555), "set pre-conversion thread values");
    GetCurrentThreadStackLimits(&original_low, &original_high);
    main_root = root_fiber = ConvertThreadToFiber((LPVOID)(ULONG_PTR)0x7777);
    CHECK(root_fiber && IsThreadAFiber() && current_fiber_address() == root_fiber && fiber_parameter() == (LPVOID)(ULONG_PTR)0x7777,
          "conversion publishes real TEB fiber identity and parameter");
    CHECK(!ConvertThreadToFiber(NULL) && GetLastError() == ERROR_ALREADY_FIBER, "double conversion rejected");
    CHECK(FlsGetValue(fls_index) == (LPVOID)(ULONG_PTR)0x1111, "conversion preserves existing FLS value");
    child_fiber = CreateFiberEx(16384, 65536, FIBER_FLAG_FLOAT_SWITCH, child, (LPVOID)(ULONG_PTR)0x4444);
    CHECK(child_fiber != NULL && visits == 0, "creation allocates a fiber without executing its callback");
    if (!root_fiber || !child_fiber) return 1;
    set_mxcsr(0x5f80); set_x87cw(0x0a7f);
    for (i = 0; i < 1000; ++i) {
        SwitchToFiber(child_fiber);
        fault_if(visits == (LONG)i + 1);
        fault_if((mxcsr() & 0x6000) == 0x4000 && (x87cw() & 0x0c00) == 0x0800);
        fault_if(FlsGetValue(fls_index) == (LPVOID)(ULONG_PTR)0x1111);
        GetCurrentThreadStackLimits(&low, &high);
        fault_if(low == original_low && high == original_high);
    }
    CHECK(visits == 1000 && !child_faults, "1000 actual stack switches preserve TEB/FLS/local variables/FP controls");
    CHECK(TlsGetValue(tls_index) == (LPVOID)(ULONG_PTR)0x6666, "TLS remains shared by fibers on one thread");
    thread = CreateThread(NULL, 0, migrate, NULL, 0, NULL);
    if (!thread) return 1;
    waited = WaitForSingleObject(thread, 5000);
    CHECK(waited == WAIT_OBJECT_0, "migration worker finishes before shared-state inspection");
    if (waited != WAIT_OBJECT_0) return 1;
    CHECK(GetExitCodeThread(thread, &code) && code == 0 && visits == 1100 && !child_faults,
          "synchronized suspended fiber migrates to another real guest thread");
    CloseHandle(thread);
    root_fiber = main_root;
    SwitchToFiber(child_fiber);
    CHECK(visits == 1101 && !child_faults, "migrated fiber resumes on the original thread");
    thread = CreateThread(NULL, 0, retain_converted, &converted_other, 0, NULL);
    if (!thread) return 1;
    waited = WaitForSingleObject(thread, 5000);
    CHECK(waited == WAIT_OBJECT_0, "converted original owner exits before migration-limit probe");
    if (waited != WAIT_OBJECT_0) return 1;
    if (converted_other) {
        SwitchToFiber(converted_other);
        CHECK(GetLastError() == ERROR_NOT_SUPPORTED && current_fiber_address() == main_root,
              "known limit: original kernel-owned stack migration fails explicitly before touching freed stack");
        DeleteFiber(converted_other);
    } else {
        CHECK(FALSE, "create converted original for migration-limit probe");
    }
    CloseHandle(thread);
    DeleteFiber(child_fiber);
    CHECK(child_callbacks == 1 && callback_reentry == 1 && !child_faults, "deletion invokes callback once and permits registry/self-delete/allocation reentry");
    CHECK(FlsGetValue(fls_index) == (LPVOID)(ULONG_PTR)0x1111, "suspended fiber deletion leaves caller FLS intact");
    CHECK(ConvertFiberToThread() && !IsThreadAFiber(), "reverse conversion clears fiber identity bit");
    CHECK(FlsGetValue(fls_index) == (LPVOID)(ULONG_PTR)0x1111 && root_callbacks == 0,
          "reverse conversion transfers FLS to the thread without calling destructors");
    CHECK(FlsFree(fls_index) && root_callbacks == 1 && TlsFree(tls_index), "caller FLS destructor still runs on explicit free");
    set_mxcsr(saved_mx); set_x87cw(saved_cw);

    memset(&ownership, 0, sizeof ownership);
    thread = CreateThread(NULL, 0, ownership_worker, &ownership, 0, NULL);
    if (!thread) return 1;
    waited = WaitForSingleObject(thread, 5000);
    CHECK(waited == WAIT_OBJECT_0, "ownership worker finishes before allocation inspection");
    if (waited != WAIT_OBJECT_0) return 1;
    CHECK(GetExitCodeThread(thread, &code) && code == 73 && ownership.retained && ownership.refused_reuse,
          "deleting converted original defers its kernel-owned stack, prevents stale-owner address reuse");
    CHECK(ownership.probe && *(DWORD *)ownership.probe == 0xface1234,
          "thread teardown does not free the independent allocation made after original-fiber deletion");
    CHECK(VirtualQuery(ownership.original_stack, &memory, sizeof memory) == sizeof memory && memory.State == MEM_FREE,
          "kernel releases its original thread stack on worker exit");
    /* Reverse conversion from an independently created stack currently retains
     * that extra VAD until process teardown. Explicitly test and record the limit,
     * then release it after the thread stopped so the regression owns its cleanup. */
    CHECK(VirtualQuery(ownership.new_stack, &memory, sizeof memory) == sizeof memory && memory.State == MEM_COMMIT,
          "known limit: reverse-converted created stack remains until process teardown");
    if (ownership.probe) VirtualFree(ownership.probe, 0, MEM_RELEASE);
    if (ownership.new_stack) VirtualFree(ownership.new_stack, 0, MEM_RELEASE);
    CloseHandle(thread);
    thread = CreateThread(NULL, 0, self_delete, NULL, 0, NULL);
    if (!thread) return 1;
    waited = WaitForSingleObject(thread, 5000);
    CHECK(waited == WAIT_OBJECT_0, "self-deletion worker finishes before inspection");
    if (waited != WAIT_OBJECT_0) return 1;
    CHECK(GetExitCodeThread(thread, &code) && code == 1, "DeleteFiber of the executing fiber terminates its thread");
    CloseHandle(thread);
    return k32t_finish("T_STEAM_FIBER");
}
