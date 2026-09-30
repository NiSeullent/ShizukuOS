/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll x64 structured exception handling: RUNTIME_FUNCTION lookup over the loader database,
 * RtlVirtualUnwind (Microsoft x64 unwind-code semantics, including epilogue detection and
 * chained unwind info), RtlUnwindEx, the two-phase exception dispatcher and vectored handlers.
 *
 * Written from Microsoft's public documentation of the x64 exception-handling data structures
 * ("x64 exception handling", UNWIND_INFO / UNWIND_CODE). It is not derived from Windows binaries.
 */
#include "nt.h"

#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_EPILOG 6
#define UWOP_SPARE 7
#define UWOP_SAVE_XMM128 8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10

typedef struct { BYTE ver_flags, prolog, count, frame; BYTE codes[]; } unwind_info_t;
#define UI_VERSION(i) ((i)->ver_flags & 7)
#define UI_FLAGS(i) ((i)->ver_flags >> 3)

static DWORD64 *reg_slot(CONTEXT *c, unsigned r) { return &c->Rax + r; }         /* Rax,Rcx,Rdx,Rbx,Rsp,Rbp,Rsi,Rdi,R8..R15 */

/* ---------------------------------------------------------------- function tables */
/* Dynamically registered unwind info for runtime-generated code (JIT: V8, .NET). A table is either a fixed array of
 * RUNTIME_FUNCTIONs (RtlAddFunctionTable) or a callback that returns the RUNTIME_FUNCTION for a PC in its range
 * (RtlInstallFunctionTableCallback). The registry is guarded by a spin lock so a JIT thread may add/remove tables
 * while another thread unwinds. */
typedef struct {
    PRUNTIME_FUNCTION table;                    /* array form: entries; callback form: 0 */
    DWORD count;
    DWORD64 base;                               /* the code region's base address (RUNTIME_FUNCTION RVAs are from it) */
    DWORD64 length;                             /* callback form: size of the region */
    PGET_RUNTIME_FUNCTION_CALLBACK callback;    /* callback form: resolver */
    PVOID context;
    DWORD64 identifier;                         /* RtlInstallFunctionTableCallback's TableIdentifier (low 3 bits = 3) */
    int used;
    int growable;                               /* RtlAddGrowableFunctionTable: `count` may grow up to `max`, PCs outside [base, range_end) never match */
    DWORD max;
    DWORD64 range_end;
} dyn_table_t;
static dyn_table_t dyn_tables[128];
static volatile LONG dyn_lock;

static void dyn_acquire(void) { while (__sync_lock_test_and_set(&dyn_lock, 1)) NtYieldExecution(); }
static void dyn_release(void) { __sync_lock_release(&dyn_lock); }

SHZ_EXPORT BOOLEAN NTAPI RtlAddFunctionTable(PRUNTIME_FUNCTION table, DWORD count, DWORD64 base)
{
    unsigned i;
    if (!table || !count) return FALSE;
    dyn_acquire();
    for (i = 0; i < 128; ++i)
        if (!dyn_tables[i].used) {
            dyn_tables[i] = (dyn_table_t){ table, count, base, 0, 0, 0, 0, 1, 0, 0, 0 };
            dyn_release();
            return TRUE;
        }
    dyn_release();
    return FALSE;
}

/* TableIdentifier has its low two bits set (Windows convention: 0x3 | BaseAddress); Callback returns the
 * RUNTIME_FUNCTION for a PC, letting a JIT describe code it has not laid out in a contiguous table. */
SHZ_EXPORT BOOLEAN __cdecl RtlInstallFunctionTableCallback(DWORD64 identifier, DWORD64 base, DWORD length,
                                                           PGET_RUNTIME_FUNCTION_CALLBACK callback, PVOID context,
                                                           PCWSTR out_of_process_dll)
{
    unsigned i;
    (void)out_of_process_dll;                   /* remote unwinding is not supported; in-process callback only */
    if (!callback || !length || (identifier & 3) != 3) return FALSE;
    dyn_acquire();
    for (i = 0; i < 128; ++i)
        if (!dyn_tables[i].used) {
            dyn_tables[i] = (dyn_table_t){ 0, 0, base, length, callback, context, identifier, 1, 0, 0, 0 };
            dyn_release();
            return TRUE;
        }
    dyn_release();
    return FALSE;
}

SHZ_EXPORT BOOLEAN __cdecl RtlDeleteFunctionTable(PRUNTIME_FUNCTION table)
{
    unsigned i;
    BOOLEAN found = FALSE;
    dyn_acquire();
    for (i = 0; i < 128; ++i)
        if (dyn_tables[i].used && (dyn_tables[i].table == table || dyn_tables[i].identifier == (DWORD64)(uintptr_t)table))
            { dyn_tables[i].used = 0; found = TRUE; break; }
    dyn_release();
    return found;
}

/* Growable function tables (Windows 8+; V8 registers its JIT code range with them and appends unwind entries as it emits code).
 * RtlAddGrowableFunctionTable(&handle, table, count, max, range_base, range_end) registers `table` (RUNTIME_FUNCTIONs sorted by
 * BeginAddress, RVAs relative to range_base) for PCs in [range_base, range_end), with `count` valid entries now and room for
 * `max`; RtlGrowFunctionTable(handle, n) makes the first n entries valid (the owner wrote them into the same array first);
 * RtlDeleteGrowableFunctionTable(handle) unregisters. The handle is the address of the registry slot: opaque, non-NULL, and
 * checked (a stale or foreign handle is ignored by the two VOID functions, as on Windows). RtlLookupFunctionEntry reports
 * range_base as the image base for a hit. */
/* NTSTATUS values as plain numbers: this file is also compiled by the host unwinder test (tests/test_unwind.c) with a header
 * shim that has no ntstatus.h. */
#define GROW_STATUS_INVALID_PARAMETER 0xC000000Du
#define GROW_STATUS_NO_MEMORY 0xC0000017u
SHZ_EXPORT DWORD NTAPI RtlAddGrowableFunctionTable(   /* DWORD: the winnt.h prototype; the value is an NTSTATUS */
                                                      PVOID *handle, PRUNTIME_FUNCTION table, DWORD count, DWORD max,
                                                      ULONG_PTR range_base, ULONG_PTR range_end)
{
    unsigned i;
    if (!handle || !table || count > max || !max || range_end <= range_base) return GROW_STATUS_INVALID_PARAMETER;
    dyn_acquire();
    for (i = 0; i < 128; ++i)
        if (!dyn_tables[i].used) {
            dyn_tables[i] = (dyn_table_t){ table, count, range_base, 0, 0, 0, 0, 1, 1, max, range_end };
            dyn_release();
            *handle = &dyn_tables[i];
            return 0;
        }
    dyn_release();
    return GROW_STATUS_NO_MEMORY;
}

static dyn_table_t *growable_of(PVOID handle)
{
    dyn_table_t *t = handle;
    if (t < &dyn_tables[0] || t >= &dyn_tables[128] || ((uintptr_t)t - (uintptr_t)&dyn_tables[0]) % sizeof *t) return 0;
    return t->used && t->growable ? t : 0;
}

SHZ_EXPORT VOID NTAPI RtlGrowFunctionTable(PVOID handle, DWORD new_count)
{
    dyn_table_t *t;
    dyn_acquire();
    if ((t = growable_of(handle)) && new_count <= t->max) t->count = new_count;
    dyn_release();
}

SHZ_EXPORT VOID NTAPI RtlDeleteGrowableFunctionTable(PVOID handle)
{
    dyn_table_t *t;
    dyn_acquire();
    if ((t = growable_of(handle))) t->used = 0;
    dyn_release();
}

static PRUNTIME_FUNCTION search_table(PRUNTIME_FUNCTION t, DWORD n, DWORD64 base, DWORD64 pc)
{
    long lo = 0, hi = (long)n - 1;
    const DWORD rva = (DWORD)(pc - base);
    while (lo <= hi) {
        const long mid = (lo + hi) / 2;
        if (rva < t[mid].BeginAddress) hi = mid - 1;
        else if (rva >= t[mid].EndAddress) lo = mid + 1;
        else return &t[mid];
    }
    return 0;
}

SHZ_EXPORT PVOID NTAPI RtlPcToFileHeader(PVOID pc, PVOID *base)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList, *l;
    for (l = head->Flink; l != head; l = l->Flink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InLoadOrderLinks);
        if ((uint8_t *)pc >= (uint8_t *)e->DllBase && (uint8_t *)pc < (uint8_t *)e->DllBase + e->SizeOfImage) {
            *base = e->DllBase;
            return e->DllBase;
        }
    }
    *base = 0;
    return 0;
}

SHZ_EXPORT PRUNTIME_FUNCTION NTAPI RtlLookupFunctionEntry(DWORD64 pc, PDWORD64 image_base, PUNWIND_HISTORY_TABLE hist)
{
    PVOID base = 0;
    unsigned i;
    (void)hist;
    dyn_acquire();
    for (i = 0; i < 128; ++i) {
        if (!dyn_tables[i].used) continue;
        if (dyn_tables[i].callback) {                       /* callback table: PC in [base, base+length) */
            if (pc >= dyn_tables[i].base && pc < dyn_tables[i].base + dyn_tables[i].length) {
                PGET_RUNTIME_FUNCTION_CALLBACK cb = dyn_tables[i].callback;
                PVOID ctx = dyn_tables[i].context;
                const DWORD64 b = dyn_tables[i].base;
                dyn_release();
                *image_base = b;
                return cb(pc, ctx);
            }
        } else {
            PRUNTIME_FUNCTION f;
            if (dyn_tables[i].growable && (pc < dyn_tables[i].base || pc >= dyn_tables[i].range_end)) continue;
            f = search_table(dyn_tables[i].table, dyn_tables[i].count, dyn_tables[i].base, pc);
            if (f) { const DWORD64 b = dyn_tables[i].base; dyn_release(); *image_base = b; return f; }
        }
    }
    dyn_release();
    if (!RtlPcToFileHeader((PVOID)pc, &base)) { *image_base = 0; return 0; }
    {
        const IMAGE_DOS_HEADER *dos = base;
        const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)((const uint8_t *)base + dos->e_lfanew);
        const IMAGE_DATA_DIRECTORY *d = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        *image_base = (DWORD64)(uintptr_t)base;
        if (!d->VirtualAddress || !d->Size) return 0;
        return search_table((PRUNTIME_FUNCTION)((uint8_t *)base + d->VirtualAddress), d->Size / sizeof(RUNTIME_FUNCTION),
                            (DWORD64)(uintptr_t)base, pc);
    }
}

/* Version 2 UNWIND_INFO records the epilog(s) explicitly with UWOP_EPILOG codes (so the unwinder need not decode
 * instructions to find an epilog). The first UWOP_EPILOG: OpInfo = flag "at end", CodeOffset = size of the epilog in
 * bytes; when the flag is set, that single record covers an epilog that ends at the function end. Any further
 * UWOP_EPILOG records give (CodeOffset = offset of the epilog's last byte from the function end, OpInfo = high nibble
 * of that offset). Returns 1 when `control_offset` lies inside a described epilog and sets *epilog_at to the RVA of the
 * epilog's first instruction; 0 otherwise. (Public: the x64 UNWIND_INFO version 2 layout.) */
static int v2_epilog(const unwind_info_t *info, DWORD64 fn_len, DWORD64 control_offset, DWORD64 *epilog_at)
{
    unsigned i;
    unsigned epilog_size = 0;
    if (UI_VERSION(info) != 2) return 0;
    for (i = 0; i < info->count;) {
        const BYTE code_off = info->codes[i * 2], b1 = info->codes[i * 2 + 1];
        const unsigned op = b1 & 15, opinfo = b1 >> 4;
        if (op == UWOP_EPILOG) {
            if (!epilog_size) {                             /* first record: epilog byte count, "at function end" flag */
                epilog_size = code_off;
                if (opinfo & 1) {                           /* an epilog ending exactly at the function end */
                    const DWORD64 start = fn_len - epilog_size;
                    if (control_offset >= start && control_offset < fn_len) { *epilog_at = start; return 1; }
                }
            } else {                                        /* subsequent record: offset of the epilog end from fn end */
                const DWORD64 end = fn_len - (code_off | ((DWORD64)opinfo << 8));
                const DWORD64 start = end - epilog_size;
                if (control_offset >= start && control_offset < end) { *epilog_at = start; return 1; }
            }
            ++i;
        } else {
            unsigned slots = 1;
            switch (op) {
            case UWOP_ALLOC_LARGE: slots = opinfo ? 3 : 2; break;
            case UWOP_SAVE_NONVOL: case UWOP_SAVE_XMM128: slots = 2; break;
            case UWOP_SAVE_NONVOL_FAR: case UWOP_SAVE_XMM128_FAR: slots = 3; break;
            default: break;
            }
            i += slots;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- epilogue emulation */
static int in_epilogue(const uint8_t *pc, DWORD64 fn_begin, DWORD64 fn_end, CONTEXT *ctx, int apply)
{
    /* Recognised epilogue: [add rsp,imm | lea rsp,[fp+imm]] , pop* , (ret | rep ret | jmp out-of-function). */
    const uint8_t *p = pc;
    DWORD64 rsp = ctx->Rsp;
    CONTEXT tmp = *ctx;
    if ((p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xc4)) { rsp += (int8_t)p[3]; p += 4; }                        /* add rsp, imm8 */
    else if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xc4) { int32_t v; memcpy(&v, p + 3, 4); rsp += v; p += 7; }  /* add rsp, imm32 */
    else if ((p[0] & 0xfb) == 0x48 && p[1] == 0x8d && (p[2] & 0xc7) == 0x45 && ((p[2] >> 3) & 7) == 4 && !(p[0] & 4)) {
        /* lea rsp, [rbp/rbp-like + disp8]: 48 8d 65 xx (rbp) or 49 8d 65 xx (r13) */
        const unsigned reg = (p[2] & 7) | ((p[0] & 1) ? 8 : 0);
        rsp = *reg_slot(&tmp, reg) + (int8_t)p[3];
        p += 4;
    } else if ((p[0] & 0xfa) == 0x48 && p[1] == 0x8d && (p[2] & 0xc7) == 0x85 && ((p[2] >> 3) & 7) == 4) {
        const unsigned reg = (p[2] & 7) | ((p[0] & 1) ? 8 : 0);
        int32_t v; memcpy(&v, p + 3, 4);
        rsp = *reg_slot(&tmp, reg) + v;
        p += 7;
    }
    for (;;) {                                                            /* pops */
        unsigned reg;
        if (p[0] >= 0x58 && p[0] <= 0x5f) { reg = p[0] - 0x58; p += 1; }
        else if (p[0] == 0x41 && p[1] >= 0x58 && p[1] <= 0x5f) { reg = 8 + p[1] - 0x58; p += 2; }
        else break;
        *reg_slot(&tmp, reg) = *(DWORD64 *)rsp;
        rsp += 8;
    }
    if (p[0] == 0xc3 || (p[0] == 0xf3 && p[1] == 0xc3) || (p[0] == 0xc2)) {
        if (apply) {
            *ctx = tmp;
            ctx->Rip = *(DWORD64 *)rsp;
            ctx->Rsp = rsp + 8;
        }
        return 1;
    }
    /* tail-call jump out of the function: rex.w jmp r/m64, jmp rel32/rel8, jmp [mem] */
    if ((p[0] == 0x48 && p[1] == 0xff && (p[2] & 0x38) == 0x20) || p[0] == 0xe9 || p[0] == 0xeb ||
        (p[0] == 0xff && p[1] == 0x25)) {
        int outside = 1;
        if (p[0] == 0xe9) { int32_t rel; memcpy(&rel, p + 1, 4); outside = ((DWORD64)(p + 5 + rel) < fn_begin || (DWORD64)(p + 5 + rel) >= fn_end); }
        else if (p[0] == 0xeb) { outside = ((DWORD64)(p + 2 + (int8_t)p[1]) < fn_begin || (DWORD64)(p + 2 + (int8_t)p[1]) >= fn_end); }
        if (outside) {
            if (apply) {
                *ctx = tmp;
                ctx->Rip = *(DWORD64 *)rsp;
                ctx->Rsp = rsp + 8;
            }
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- RtlVirtualUnwind */
static void apply_codes(const unwind_info_t *info, CONTEXT *c, DWORD64 control_offset, int all, DWORD64 frame_base,
                        PKNONVOLATILE_CONTEXT_POINTERS ptrs)
{
    unsigned i = 0;
    const unsigned frame_off = (info->frame >> 4) * 16u;
    const unsigned frame_reg = info->frame & 15;
    (void)ptrs;
    while (i < info->count) {
        const BYTE off = info->codes[i * 2], b1 = info->codes[i * 2 + 1];
        const unsigned op = b1 & 15, opinfo = b1 >> 4;
        unsigned slots = 1;
        int active = all || control_offset >= off;
        switch (op) {
        case UWOP_ALLOC_LARGE: slots = opinfo ? 3 : 2; break;
        case UWOP_SAVE_NONVOL: case UWOP_SAVE_XMM128: slots = 2; break;
        case UWOP_SAVE_NONVOL_FAR: case UWOP_SAVE_XMM128_FAR: slots = 3; break;
        default: slots = 1;
        }
        if (active) {
            switch (op) {
            case UWOP_PUSH_NONVOL: *reg_slot(c, opinfo) = *(DWORD64 *)c->Rsp; c->Rsp += 8; break;
            case UWOP_ALLOC_LARGE: {
                DWORD64 sz = opinfo ? *(const DWORD *)&info->codes[(i + 1) * 2]
                                    : (DWORD64)*(const WORD *)&info->codes[(i + 1) * 2] * 8;
                c->Rsp += sz;
                break;
            }
            case UWOP_ALLOC_SMALL: c->Rsp += (DWORD64)opinfo * 8 + 8; break;
            case UWOP_SET_FPREG: c->Rsp = *reg_slot(c, frame_reg) - frame_off; (void)frame_base; break;
            case UWOP_SAVE_NONVOL: *reg_slot(c, opinfo) = *(DWORD64 *)(c->Rsp + (DWORD64)*(const WORD *)&info->codes[(i + 1) * 2] * 8); break;
            case UWOP_SAVE_NONVOL_FAR: *reg_slot(c, opinfo) = *(DWORD64 *)(c->Rsp + *(const DWORD *)&info->codes[(i + 1) * 2]); break;
            case UWOP_SAVE_XMM128: c->FltSave.XmmRegisters[opinfo] = *(M128A *)(c->Rsp + (DWORD64)*(const WORD *)&info->codes[(i + 1) * 2] * 16); break;
            case UWOP_SAVE_XMM128_FAR: c->FltSave.XmmRegisters[opinfo] = *(M128A *)(c->Rsp + *(const DWORD *)&info->codes[(i + 1) * 2]); break;
            case UWOP_PUSH_MACHFRAME: {
                DWORD64 sp = c->Rsp;
                if (opinfo) sp += 8;                                            /* skip the hardware error code */
                c->Rip = *(DWORD64 *)sp;
                c->EFlags = (DWORD)*(DWORD64 *)(sp + 16);
                c->Rsp = *(DWORD64 *)(sp + 24);
                break;
            }
            default: break;                                                     /* EPILOG / SPARE */
            }
        }
        i += slots;
    }
}

SHZ_EXPORT PEXCEPTION_ROUTINE NTAPI RtlVirtualUnwind(DWORD handler_type, DWORD64 image_base, DWORD64 pc,
                                                      PRUNTIME_FUNCTION fe, PCONTEXT ctx, PVOID *handler_data,
                                                      PDWORD64 establisher, PKNONVOLATILE_CONTEXT_POINTERS ptrs)
{
    const DWORD64 begin = image_base + fe->BeginAddress, end = image_base + fe->EndAddress;
    const DWORD64 control_offset = pc - begin;
    const unwind_info_t *info = (const unwind_info_t *)(image_base + fe->UnwindData);
    PEXCEPTION_ROUTINE handler = 0;
    unsigned set_fp_off = 0xffff, i;
    const unwind_info_t *cur = info;
    if (handler_data) *handler_data = 0;
    /* establisher frame: frame register based when established, else the incoming RSP */
    {
        const unsigned frame_reg = info->frame & 15, frame_off = (info->frame >> 4) * 16u;
        for (i = 0; i < info->count;) {
            const BYTE b1 = info->codes[i * 2 + 1];
            unsigned slots = 1;
            switch (b1 & 15) {
            case UWOP_ALLOC_LARGE: slots = (b1 >> 4) ? 3 : 2; break;
            case UWOP_SAVE_NONVOL: case UWOP_SAVE_XMM128: slots = 2; break;
            case UWOP_SAVE_NONVOL_FAR: case UWOP_SAVE_XMM128_FAR: slots = 3; break;
            default: break;
            }
            if ((b1 & 15) == UWOP_SET_FPREG) set_fp_off = info->codes[i * 2];
            i += slots;
        }
        *establisher = frame_reg && control_offset >= set_fp_off ? *reg_slot(ctx, frame_reg) - frame_off : ctx->Rsp;
    }
    /* In an epilog the prolog's saves have already been undone: emulate the remaining epilog instructions instead of
     * replaying unwind codes. Version 2 marks the epilog authoritatively; earlier versions are detected from the
     * instruction stream. Either way the register-restoring instructions from PC to the RET are simulated. */
    {
        DWORD64 ep = 0;
        if ((v2_epilog(info, end - begin, control_offset, &ep) || control_offset >= info->prolog) &&
            in_epilogue((const uint8_t *)pc, begin, end, ctx, 1))
            return 0;
    }
    apply_codes(info, ctx, control_offset, 0, *establisher, ptrs);
    /* chained unwind info: the parent's operations always complete */
    while (UI_FLAGS(cur) & UNW_FLAG_CHAININFO) {
        const RUNTIME_FUNCTION *chain = (const RUNTIME_FUNCTION *)&cur->codes[((cur->count + 1) & ~1u) * 2];
        cur = (const unwind_info_t *)(image_base + chain->UnwindData);
        apply_codes(cur, ctx, 0, 1, *establisher, ptrs);
    }
    ctx->Rip = *(DWORD64 *)ctx->Rsp;
    ctx->Rsp += 8;
    if ((UI_FLAGS(info) & handler_type) && !(UI_FLAGS(info) & UNW_FLAG_CHAININFO) && control_offset >= info->prolog) {
        const DWORD *h = (const DWORD *)&info->codes[((info->count + 1) & ~1u) * 2];
        handler = (PEXCEPTION_ROUTINE)(uintptr_t)(image_base + h[0]);
        if (handler_data) *handler_data = (PVOID)(h + 1);
    }
    return handler;
}

/* ---------------------------------------------------------------- vectored handlers */
typedef struct veh { struct veh *next; PVECTORED_EXCEPTION_HANDLER fn; } veh_t;
static veh_t *veh_first, *vch_first;
static volatile LONG veh_lock;
static PTOP_LEVEL_EXCEPTION_FILTER g_unhandled_filter;

static void vlock(void) { while (__sync_lock_test_and_set(&veh_lock, 1)) NtYieldExecution(); }
static void vunlock(void) { __sync_lock_release(&veh_lock); }

static PVOID add_handler(veh_t **head, ULONG first, PVECTORED_EXCEPTION_HANDLER fn)
{
    veh_t *v = RtlAllocateHeap(ShzProcessHeap(), 0, sizeof *v);
    if (!v) return 0;
    v->fn = fn;
    vlock();
    if (first || !*head) { v->next = *head; *head = v; }
    else { veh_t *t = *head; while (t->next) t = t->next; v->next = 0; t->next = v; }
    vunlock();
    return v;
}
static ULONG remove_handler(veh_t **head, PVOID h)
{
    veh_t **pp;
    ULONG found = 0;
    vlock();
    for (pp = head; *pp; pp = &(*pp)->next)
        if (*pp == h) { *pp = (*pp)->next; found = 1; break; }
    vunlock();
    if (found) RtlFreeHeap(ShzProcessHeap(), 0, h);
    return found;
}
SHZ_EXPORT PVOID NTAPI RtlAddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn) { return add_handler(&veh_first, first, fn); }
SHZ_EXPORT ULONG NTAPI RtlRemoveVectoredExceptionHandler(PVOID h) { return remove_handler(&veh_first, h); }
SHZ_EXPORT PVOID NTAPI RtlAddVectoredContinueHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn) { return add_handler(&vch_first, first, fn); }
SHZ_EXPORT ULONG NTAPI RtlRemoveVectoredContinueHandler(PVOID h) { return remove_handler(&vch_first, h); }
SHZ_EXPORT PTOP_LEVEL_EXCEPTION_FILTER NTAPI RtlSetUnhandledExceptionFilter(PTOP_LEVEL_EXCEPTION_FILTER f)
{
    PTOP_LEVEL_EXCEPTION_FILTER old = g_unhandled_filter;
    g_unhandled_filter = f;
    return old;
}

static int run_vectored(veh_t *head, PEXCEPTION_RECORD rec, PCONTEXT ctx)
{
    EXCEPTION_POINTERS ep = { rec, ctx };
    veh_t *v;
    vlock();
    for (v = head; v; v = v->next) {
        PVECTORED_EXCEPTION_HANDLER fn = v->fn;
        LONG r;
        vunlock();
        r = fn(&ep);
        vlock();
        if (r == EXCEPTION_CONTINUE_EXECUTION) { vunlock(); return 1; }
    }
    vunlock();
    return 0;
}

/* ---------------------------------------------------------------- frame walking */
static int stack_ok(DWORD64 sp)
{
    uint64_t base, limit;
    __asm__ volatile("movq %%gs:8, %0" : "=r"(base));
    __asm__ volatile("movq %%gs:16, %0" : "=r"(limit));
    return sp >= limit && sp < base && !(sp & 7);
}

static BOOLEAN dispatch_frames(PEXCEPTION_RECORD rec, PCONTEXT orig)
{
    CONTEXT c = *orig;
    unsigned depth = 0;
    while (depth++ < 4096) {
        DWORD64 image_base = 0, establisher = 0;
        PRUNTIME_FUNCTION fe = RtlLookupFunctionEntry(c.Rip, &image_base, 0);
        CONTEXT unwound = c;
        PVOID hdata = 0;
        PEXCEPTION_ROUTINE handler;
        if (!stack_ok(c.Rsp) && depth > 1) return FALSE;
        if (!fe) {                                                  /* leaf: return address is at RSP */
            if (!stack_ok(c.Rsp)) return FALSE;
            c.Rip = *(DWORD64 *)c.Rsp;
            c.Rsp += 8;
            if (!c.Rip) return FALSE;
            continue;
        }
        handler = RtlVirtualUnwind(UNW_FLAG_EHANDLER, image_base, c.Rip, fe, &unwound, &hdata, &establisher, 0);
        if (handler) {
            DISPATCHER_CONTEXT dc;
            EXCEPTION_DISPOSITION d;
            memset(&dc, 0, sizeof dc);
            dc.ControlPc = c.Rip;
            dc.ImageBase = image_base;
            dc.FunctionEntry = fe;
            dc.EstablisherFrame = establisher;
            dc.ContextRecord = &c;
            dc.LanguageHandler = handler;
            dc.HandlerData = hdata;
            d = handler(rec, (PVOID)establisher, &c, &dc);
            if (d == ExceptionContinueExecution) {
                if (rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE) return FALSE;
                *orig = c;                                          /* handler may have modified the context */
                return TRUE;
            }
            /* ExceptionContinueSearch / nested / collided: keep walking */
        }
        c = unwound;
        if (!c.Rip) return FALSE;
    }
    return FALSE;
}

static BOOLEAN dispatch_exception(PEXCEPTION_RECORD rec, PCONTEXT ctx)
{
    if (run_vectored(veh_first, rec, ctx)) return TRUE;
    if (dispatch_frames(rec, ctx)) return TRUE;
    /* second chance: top-level filter */
    if (g_unhandled_filter) {
        EXCEPTION_POINTERS ep = { rec, ctx };
        LONG r = g_unhandled_filter(&ep);
        if (r == EXCEPTION_CONTINUE_EXECUTION) return TRUE;
        if (r == EXCEPTION_EXECUTE_HANDLER) {
            RtlExitUserProcess((NTSTATUS)rec->ExceptionCode);
        }
    }
    return FALSE;
}

/* Entry point for hardware exceptions redirected by the kernel: RCX = record, RDX = context. */
SHZ_EXPORT VOID NTAPI KiUserExceptionDispatcher(PEXCEPTION_RECORD rec, PCONTEXT ctx)
{
    if (dispatch_exception(rec, ctx)) {
        run_vectored(vch_first, rec, ctx);
        NtContinue(ctx, FALSE);
    } else {
        NtRaiseException(rec, ctx, FALSE);
    }
    for (;;) NtTerminateProcess(CURRENT_PROCESS, rec->ExceptionCode);
}

/* Software exceptions: RaiseException / RtlRaiseException. */
SHZ_EXPORT VOID NTAPI RtlRaiseException(PEXCEPTION_RECORD rec)
{
    CONTEXT ctx;
    /* The captured RIP/RSP belong to this frame: unwind one level so the exception is reported
     * (and dispatched) from the caller's frame, as on Windows. */
    {
        DWORD64 image_base;
        PRUNTIME_FUNCTION fe;
        DWORD64 establisher;
        PVOID hd;
        RtlCaptureContext(&ctx);
        fe = RtlLookupFunctionEntry(ctx.Rip, &image_base, 0);
        if (fe) RtlVirtualUnwind(0, image_base, ctx.Rip, fe, &ctx, &hd, &establisher, 0);
    }
    rec->ExceptionAddress = (PVOID)(uintptr_t)ctx.Rip;
    if (dispatch_exception(rec, &ctx)) {
        NtContinue(&ctx, FALSE);
    } else {
        NtRaiseException(rec, &ctx, FALSE);
    }
}

SHZ_EXPORT VOID NTAPI RtlRaiseStatus(NTSTATUS status)
{
    EXCEPTION_RECORD rec;
    memset(&rec, 0, sizeof rec);
    rec.ExceptionCode = (DWORD)status;
    rec.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    RtlRaiseException(&rec);
}

/* Walks the calling thread's stack with the .pdata unwind tables. The first frame returned (after `skip` frames were dropped)
 * is the return address into the function that called RtlCaptureStackBackTrace. The walk ends at a null return address, when
 * the stack pointer leaves the thread's stack, or after `count` frames. `hash` receives the sum of the return addresses. */
SHZ_EXPORT USHORT NTAPI RtlCaptureStackBackTrace(ULONG skip, ULONG count, PVOID *frames, PULONG hash)
{
    CONTEXT ctx;
    ULONG64 sum = 0;
    ULONG seen = 0, got = 0, guard;
    const uint64_t teb = shz_teb();
    const DWORD64 stack_top = *(const DWORD64 *)(teb + 8), stack_low = *(const DWORD64 *)(teb + 0x10);
    if (hash) *hash = 0;
    if (!frames || !count) return 0;
    RtlCaptureContext(&ctx);                                   /* RIP is inside this function: unwind out of it first */
    for (guard = 0; guard < 4096 && got < count; ++guard) {
        DWORD64 image_base = 0, establisher;
        PVOID hd;
        PRUNTIME_FUNCTION fe = RtlLookupFunctionEntry(ctx.Rip, &image_base, 0);
        if (fe) {
            RtlVirtualUnwind(0, image_base, ctx.Rip, fe, &ctx, &hd, &establisher, 0);
        } else {                                               /* a leaf function without unwind data */
            ctx.Rip = *(const DWORD64 *)ctx.Rsp;
            ctx.Rsp += 8;
        }
        if (!ctx.Rip || ctx.Rsp < stack_low || ctx.Rsp > stack_top) break;
        if (seen++ < skip) continue;
        frames[got++] = (PVOID)(uintptr_t)ctx.Rip;
        sum += ctx.Rip;
    }
    if (hash) *hash = (ULONG)sum;
    return (USHORT)got;
}

SHZ_EXPORT VOID NTAPI RtlRestoreContext(PCONTEXT ctx, PEXCEPTION_RECORD rec)
{
    (void)rec;
    NtContinue(ctx, FALSE);
    for (;;) __asm__ volatile("ud2");
}

/* mingw declares RtlCaptureContext returns_twice; ours is an ordinary call, so -Wclobbered is a false positive. */
#pragma GCC diagnostic ignored "-Wclobbered"
/* ---------------------------------------------------------------- RtlUnwindEx */
SHZ_EXPORT VOID NTAPI RtlUnwindEx(PVOID target_frame, PVOID target_ip, PEXCEPTION_RECORD rec, PVOID return_value,
                                  PCONTEXT original, PUNWIND_HISTORY_TABLE hist)
{
    CONTEXT c;
    EXCEPTION_RECORD local;
    unsigned depth = 0;
    (void)hist;
    if (original) c = *original; else RtlCaptureContext(&c);
    if (!rec) {
        memset(&local, 0, sizeof local);
        local.ExceptionCode = STATUS_UNWIND;
        local.ExceptionAddress = (PVOID)(uintptr_t)c.Rip;
        rec = &local;
    }
    rec->ExceptionFlags |= EXCEPTION_UNWINDING | (target_frame ? 0 : EXCEPTION_EXIT_UNWIND);
    while (depth++ < 4096) {
        DWORD64 image_base = 0, establisher = 0;
        PRUNTIME_FUNCTION fe = RtlLookupFunctionEntry(c.Rip, &image_base, 0);
        CONTEXT unwound = c;
        PVOID hdata = 0;
        PEXCEPTION_ROUTINE handler;
        int final;
        if (!fe) {
            if (!stack_ok(c.Rsp)) break;
            c.Rip = *(DWORD64 *)c.Rsp;
            c.Rsp += 8;
            if (!c.Rip) break;
            continue;
        }
        handler = RtlVirtualUnwind(UNW_FLAG_UHANDLER, image_base, c.Rip, fe, &unwound, &hdata, &establisher, 0);
        final = target_frame && establisher == (DWORD64)(uintptr_t)target_frame;
        if (target_frame && establisher > (DWORD64)(uintptr_t)target_frame) break;      /* overshot: invalid target */
        if (final) rec->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
        if (handler) {
            DISPATCHER_CONTEXT dc;
            memset(&dc, 0, sizeof dc);
            dc.ControlPc = c.Rip;
            dc.ImageBase = image_base;
            dc.FunctionEntry = fe;
            dc.EstablisherFrame = establisher;
            dc.TargetIp = (DWORD64)(uintptr_t)target_ip;
            dc.ContextRecord = &c;
            dc.LanguageHandler = handler;
            dc.HandlerData = hdata;
            handler(rec, (PVOID)establisher, &c, &dc);
        }
        if (final) break;
        c = unwound;
    }
    rec->ExceptionFlags &= ~EXCEPTION_TARGET_UNWIND;
    /* Resume in the target frame: `c` is that frame's own context (its callees were unwound, so its
     * non-volatile registers and RSP are exactly as they were at the call site). */
    {
        CONTEXT target = c;
        target.Rip = (DWORD64)(uintptr_t)target_ip;
        target.Rax = (DWORD64)(uintptr_t)return_value;
        target.ContextFlags = CONTEXT_FULL;
        NtContinue(&target, FALSE);
    }
}

SHZ_EXPORT VOID NTAPI RtlUnwind(PVOID target_frame, PVOID target_ip, PEXCEPTION_RECORD rec, PVOID return_value)
{
    RtlUnwindEx(target_frame, target_ip, rec, return_value, 0, 0);
}

/* ---------------------------------------------------------------- __C_specific_handler
 * The language-specific handler that MSVC- and Clang-compiled C code registers for __try/__except/__finally (the
 * exception directory's UNWIND_INFO names it, and its HandlerData is a SCOPE_TABLE). It is invoked twice by the
 * dispatcher: in the search phase (evaluate __except filters) and in the unwind phase (run __finally blocks). This is
 * the documented algorithm ("x64 exception handling", SCOPE_TABLE_AMD64); no Windows code is copied.
 *
 * Scope record (RVAs from DispatcherContext->ImageBase): BeginAddress..EndAddress is the guarded region; JumpTarget==0
 * marks a __finally (HandlerAddress is the termination handler), JumpTarget!=0 marks an __except (HandlerAddress is the
 * filter, or the constant 1 meaning EXCEPTION_EXECUTE_HANDLER, and JumpTarget is the __except body). */
typedef struct { DWORD Count; struct { DWORD Begin, End, Handler, Target; } Rec[1]; } c_scope_table_t;
typedef LONG (*c_filter_t)(PEXCEPTION_POINTERS, PVOID frame);
typedef void (*c_finally_t)(BOOLEAN abnormal, PVOID frame);

/* winnt.h declares __C_specific_handler dllimport; we define it here and export it by name from the .def, so the
 * ignored-dllimport attribute is expected. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
EXCEPTION_DISPOSITION __C_specific_handler(PEXCEPTION_RECORD rec, PVOID frame, PCONTEXT ctx,
                                                     PDISPATCHER_CONTEXT dc)
{
    const c_scope_table_t *st = dc->HandlerData;
    const DWORD64 base = dc->ImageBase;
    const DWORD control = (DWORD)(dc->ControlPc - base);
    DWORD i;
    if (!st) return ExceptionContinueSearch;
    if (rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
        /* unwind phase: run every __finally whose scope contains the control PC, except the target scope itself */
        for (i = 0; i < st->Count; ++i) {
            const DWORD tgt = st->Rec[i].Target;
            if (control < st->Rec[i].Begin || control >= st->Rec[i].End) continue;
            if (tgt) continue;                                  /* an __except, not a __finally */
            if ((rec->ExceptionFlags & EXCEPTION_TARGET_UNWIND) && dc->TargetIp == base + st->Rec[i].Handler) continue;
            ((c_finally_t)(uintptr_t)(base + st->Rec[i].Handler))(TRUE, frame);
        }
        return ExceptionContinueSearch;
    }
    /* search phase: evaluate __except filters */
    for (i = 0; i < st->Count; ++i) {
        EXCEPTION_POINTERS ep;
        LONG r;
        if (control < st->Rec[i].Begin || control >= st->Rec[i].End || !st->Rec[i].Target) continue;
        if (st->Rec[i].Handler == 1) r = EXCEPTION_EXECUTE_HANDLER;      /* __except(EXCEPTION_EXECUTE_HANDLER) */
        else {
            ep.ExceptionRecord = rec;
            ep.ContextRecord = ctx;
            r = ((c_filter_t)(uintptr_t)(base + st->Rec[i].Handler))(&ep, frame);
        }
        if (r == EXCEPTION_CONTINUE_EXECUTION) return ExceptionContinueExecution;
        if (r == EXCEPTION_CONTINUE_SEARCH) continue;
        /* EXCEPTION_EXECUTE_HANDLER: unwind to the __except body; RtlUnwindEx does not return */
        RtlUnwindEx(frame, (PVOID)(uintptr_t)(base + st->Rec[i].Target), rec,
                    (PVOID)(uintptr_t)(ULONG)rec->ExceptionCode, ctx, dc->HistoryTable);
    }
    return ExceptionContinueSearch;
}
#pragma GCC diagnostic pop
