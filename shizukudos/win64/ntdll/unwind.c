/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll x64 structured exception handling: RUNTIME_FUNCTION lookup over the loader database,
 * RtlVirtualUnwind (Microsoft x64 unwind-code semantics, including epilogue detection and
 * chained unwind info), RtlUnwindEx, the two-phase exception dispatcher and vectored handlers.
 *
 * Written from Microsoft's public documentation of the x64 exception-handling data structures
 * ("x64 exception handling", UNWIND_INFO / UNWIND_CODE). It is not derived from Windows binaries.
 */
#include "nt.h"
#include "unwind_internal.h"

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
 * checked for slot alignment and active ownership. Deleted handles must not be reused after a slot is recycled. RtlLookupFunctionEntry reports
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
    const uintptr_t h = (uintptr_t)handle, first = (uintptr_t)&dyn_tables[0];
    if (h < first || h - first >= sizeof dyn_tables || (h - first) % sizeof *t) return 0;
    return t->used && t->growable ? t : 0;
}

SHZ_EXPORT VOID NTAPI RtlGrowFunctionTable(PVOID handle, DWORD new_count)
{
    dyn_table_t *t;
    dyn_acquire();
    if ((t = growable_of(handle)) && new_count > t->count && new_count <= t->max) t->count = new_count;
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
                    const DWORD64 start = epilog_size <= fn_len ? fn_len - epilog_size : fn_len;
                    if (control_offset >= start && control_offset < fn_len) { *epilog_at = start; return 1; }
                }
            } else {                                        /* subsequent record: offset of the epilog end from fn end */
                const DWORD64 distance = code_off | ((DWORD64)opinfo << 8);
                const DWORD64 end = distance <= fn_len ? fn_len - distance : 0;
                const DWORD64 start = epilog_size <= end ? end - epilog_size : end;
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

/* ---------------------------------------------------------------- bounded reads and metadata validation */
/* A malformed record must not recursively fault the exception dispatcher. Snapshot each record through the existing
 * checked self-process read syscall; a short/failed copy ends this walk. The caller still owns ctx/output pointers.
 * This is a local fail-closed policy for invalid data, not a Windows compatibility promise for invalid input. */
static int unwind_read(DWORD64 addr, void *out, size_t n)
{
    size_t got = 0;
    if (!addr || !n || addr > UINT64_MAX - n) return 0;
    return NtReadVirtualMemory(CURRENT_PROCESS, (PVOID)(uintptr_t)addr, out, n, &got) == 0 && got == n;
}

static int unwind_add(DWORD64 a, DWORD64 b, DWORD64 *out)
{
    if (a > UINT64_MAX - b) return 0;
    *out = a + b;
    return 1;
}

static int unwind_stack_read(DWORD64 addr, void *out, size_t n)
{
    DWORD64 low, high;
    shz_unwind_stack_limits(&low, &high);
    return low < high && addr >= low && addr < high && !(addr & 7) && n <= high - addr &&
           unwind_read(addr, out, n);
}

static WORD unwind_word(const BYTE *p) { WORD v; memcpy(&v, p, sizeof v); return v; }
static DWORD unwind_dword(const BYTE *p) { DWORD v; memcpy(&v, p, sizeof v); return v; }

static unsigned unwind_slots(unsigned op, unsigned opinfo)
{
    switch (op) {
    case UWOP_ALLOC_LARGE: return opinfo <= 1 ? (opinfo ? 3 : 2) : 0;
    case UWOP_SAVE_NONVOL: case UWOP_SAVE_XMM128: return 2;
    case UWOP_SAVE_NONVOL_FAR: case UWOP_SAVE_XMM128_FAR: return 3;
    case UWOP_SET_FPREG: return opinfo == 0 ? 1 : 0;
    case UWOP_PUSH_MACHFRAME: return opinfo <= 1 ? 1 : 0;
    case UWOP_PUSH_NONVOL: case UWOP_ALLOC_SMALL: case UWOP_EPILOG: return 1;
    default: return 0;
    }
}

/* Largest record: 4-byte header + 256 padded slots + 12-byte chained RUNTIME_FUNCTION. */
typedef union { DWORD align; BYTE bytes[4 + 512 + sizeof(RUNTIME_FUNCTION)]; } unwind_record_t;
static int unwind_record(DWORD64 addr, unwind_record_t *record)
{
    unwind_info_t *info = (unwind_info_t *)record->bytes;
    unsigned i, flags, tail, bytes;
    BYTE header[4];
    if ((addr & 3) || !unwind_read(addr, record->bytes, 4)) return 0;
    memcpy(header, record->bytes, 4);
    flags = UI_FLAGS(info);
    if ((UI_VERSION(info) != 1 && UI_VERSION(info) != 2) || (flags & ~7u) ||
        ((flags & UNW_FLAG_CHAININFO) && (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)))) return 0;
    tail = (flags & UNW_FLAG_CHAININFO) ? sizeof(RUNTIME_FUNCTION) : flags ? sizeof(DWORD) : 0;
    bytes = 4 + ((info->count + 1u) & ~1u) * 2 + tail;
    if (!unwind_read(addr, record->bytes, bytes) || memcmp(header, record->bytes, 4)) return 0;
    for (i = 0; i < info->count;) {
        unsigned op = info->codes[i * 2 + 1] & 15, opinfo = info->codes[i * 2 + 1] >> 4;
        unsigned slots = unwind_slots(op, opinfo);
        if (!slots || slots > info->count - i || (op == UWOP_EPILOG && UI_VERSION(info) != 2) ||
            (op == UWOP_SET_FPREG && !(info->frame & 15))) return 0;
        i += slots;
    }
    return 1;
}

/* ---------------------------------------------------------------- epilogue emulation */
static int epilogue_read(DWORD64 pc, DWORD64 end, BYTE *bytes, size_t n)
{
    return pc < end && n <= end - pc && unwind_read(pc, bytes, n);
}
static int in_epilogue(DWORD64 pc, DWORD64 fn_begin, DWORD64 fn_end, CONTEXT *ctx)
{
    /* Read only complete instructions inside the function. All speculative state stays in tmp. */
    BYTE b[7];
    DWORD64 p = pc, rsp = ctx->Rsp, value;
    CONTEXT tmp = *ctx;
    unsigned pops = 0;
    if (!epilogue_read(p, fn_end, b, 1)) return -1;
    if (b[0] == 0x48 || b[0] == 0x49) {
        if (!epilogue_read(p, fn_end, b, 3)) return 0;
        if (b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xc4) {
            if (!epilogue_read(p, fn_end, b, 4)) return 0;
            if ((int8_t)b[3] < 0 || !unwind_add(rsp, b[3], &rsp)) return -1;
            p += 4;
        } else if (b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xc4) {
            int32_t v;
            if (!epilogue_read(p, fn_end, b, 7)) return 0;
            memcpy(&v, b + 3, 4);
            if (v < 0 || !unwind_add(rsp, (DWORD)v, &rsp)) return -1;
            p += 7;
        } else if (b[1] == 0x8d && ((b[2] >> 3) & 7) == 4 &&
                   ((b[2] & 0xc7) == 0x45 || (b[2] & 0xc7) == 0x85)) {
            const unsigned reg = (b[2] & 7) | ((b[0] & 1) ? 8 : 0);
            const unsigned n = (b[2] & 0xc0) == 0x40 ? 4 : 7;
            int32_t v;
            if (!epilogue_read(p, fn_end, b, n)) return 0;
            if (n == 4) v = (int8_t)b[3]; else memcpy(&v, b + 3, 4);
            value = *reg_slot(&tmp, reg);
            if (v < 0) { if (value < (DWORD64)-(int64_t)v) return -1; rsp = value - (DWORD64)-(int64_t)v; }
            else if (!unwind_add(value, (DWORD)v, &rsp)) return -1;
            p += n;
        }
    }
    for (;;) {
        unsigned reg, n;
        if (!epilogue_read(p, fn_end, b, 1)) return 0;
        if (b[0] >= 0x58 && b[0] <= 0x5f) { reg = b[0] - 0x58; n = 1; }
        else if (b[0] == 0x41) {
            if (!epilogue_read(p, fn_end, b, 2)) return 0;
            if (b[1] < 0x58 || b[1] > 0x5f) break;
            reg = 8 + b[1] - 0x58; n = 2;
        } else break;
        if (++pops > 16 || reg == 4 || !unwind_stack_read(rsp, &value, 8) || !unwind_add(rsp, 8, &rsp)) return -1;
        *reg_slot(&tmp, reg) = value;
        p += n;
    }
    if (b[0] == 0xc3 || (b[0] == 0xf3 && epilogue_read(p, fn_end, b, 2) && b[1] == 0xc3)) goto finish;
    if (b[0] == 0xe9 || b[0] == 0xeb) {
        int32_t rel;
        const unsigned n = b[0] == 0xe9 ? 5 : 2;
        if (!epilogue_read(p, fn_end, b, n)) return 0;
        if (n == 5) memcpy(&rel, b + 1, 4); else rel = (int8_t)b[1];
        value = p + n;
        if (rel < 0) { if (value < (DWORD64)-(int64_t)rel) return 0; value -= (DWORD64)-(int64_t)rel; }
        else if (!unwind_add(value, (DWORD)rel, &value)) return 0;
        if (value >= fn_begin && value < fn_end) return 0;
        goto finish;
    }
    if (b[0] == 0xff && epilogue_read(p, fn_end, b, 6) && b[1] == 0x25) goto finish;
    if (b[0] == 0x48 && epilogue_read(p, fn_end, b, 3) && b[1] == 0xff && (b[2] & 0xf8) == 0xe0) goto finish;
    return 0;
finish:
    if (!unwind_stack_read(rsp, &value, 8) || !unwind_add(rsp, 8, &rsp)) return -1;
    tmp.Rip = value; tmp.Rsp = rsp;
    *ctx = tmp;
    return 1;
}

/* ---------------------------------------------------------------- RtlVirtualUnwind */
static int apply_codes(const unwind_info_t *info, CONTEXT *c, DWORD64 control_offset, int all, int *machframe)
{
    unsigned i = 0;
    const unsigned frame_off = (info->frame >> 4) * 16u, frame_reg = info->frame & 15;
    while (i < info->count) {
        const BYTE off = info->codes[i * 2], b1 = info->codes[i * 2 + 1];
        const unsigned op = b1 & 15, opinfo = b1 >> 4, slots = unwind_slots(op, opinfo);
        DWORD64 addr, value;
        if (all || control_offset >= off) {
            switch (op) {
            case UWOP_PUSH_NONVOL:
                if (!unwind_stack_read(c->Rsp, &value, 8) || !unwind_add(c->Rsp, 8, &c->Rsp)) return 0;
                *reg_slot(c, opinfo) = value; break;
            case UWOP_ALLOC_LARGE:
                value = opinfo ? unwind_dword(&info->codes[(i + 1) * 2]) : (DWORD64)unwind_word(&info->codes[(i + 1) * 2]) * 8;
                if (!unwind_add(c->Rsp, value, &c->Rsp)) return 0;
                break;
            case UWOP_ALLOC_SMALL:
                if (!unwind_add(c->Rsp, (DWORD64)opinfo * 8 + 8, &c->Rsp)) return 0;
                break;
            case UWOP_SET_FPREG:
                if (*reg_slot(c, frame_reg) < frame_off) return 0;
                c->Rsp = *reg_slot(c, frame_reg) - frame_off; break;
            case UWOP_SAVE_NONVOL: case UWOP_SAVE_NONVOL_FAR:
                value = op == UWOP_SAVE_NONVOL ? (DWORD64)unwind_word(&info->codes[(i + 1) * 2]) * 8 : unwind_dword(&info->codes[(i + 1) * 2]);
                if (!unwind_add(c->Rsp, value, &addr) || !unwind_stack_read(addr, &value, 8)) return 0;
                *reg_slot(c, opinfo) = value; break;
            case UWOP_SAVE_XMM128: case UWOP_SAVE_XMM128_FAR:
                value = op == UWOP_SAVE_XMM128 ? (DWORD64)unwind_word(&info->codes[(i + 1) * 2]) * 16 : unwind_dword(&info->codes[(i + 1) * 2]);
                if (!unwind_add(c->Rsp, value, &addr) || !unwind_stack_read(addr, &c->FltSave.XmmRegisters[opinfo], sizeof(M128A))) return 0;
                break;
            case UWOP_PUSH_MACHFRAME: {
                DWORD64 frame[5];
                if (!unwind_add(c->Rsp, opinfo ? 8 : 0, &addr) || !unwind_stack_read(addr, frame, sizeof frame)) return 0;
                c->Rip = frame[0]; c->EFlags = (DWORD)frame[2]; c->Rsp = frame[3]; *machframe = 1;
                break;
            }
            default: break; /* validated version 2 EPILOG descriptor */
            }
        }
        i += slots;
    }
    return 1;
}

SHZ_EXPORT PEXCEPTION_ROUTINE NTAPI RtlVirtualUnwind(DWORD handler_type, DWORD64 image_base, DWORD64 pc,
                                                      PRUNTIME_FUNCTION fe, PCONTEXT ctx, PVOID *handler_data,
                                                      PDWORD64 establisher, PKNONVOLATILE_CONTEXT_POINTERS ptrs)
{
    RUNTIME_FUNCTION entry;
    unwind_record_t record;
    const unwind_info_t *info = (const unwind_info_t *)record.bytes;
    CONTEXT c = *ctx;
    DWORD64 begin, end, addr, est = c.Rsp, control_offset, value;
    unsigned i, set_fp_off = 0xffff, depth = 0;
    int machframe = 0, ep;
    PEXCEPTION_ROUTINE handler = 0;
    PVOID hdata = 0;
    (void)ptrs;
    if (handler_data) *handler_data = 0;
    *establisher = 0;
    if (!unwind_read((DWORD64)(uintptr_t)fe, &entry, sizeof entry) || entry.BeginAddress >= entry.EndAddress ||
        !unwind_add(image_base, entry.BeginAddress, &begin) || !unwind_add(image_base, entry.EndAddress, &end) ||
        pc < begin || pc >= end || !unwind_add(image_base, entry.UnwindData, &addr) || !unwind_record(addr, &record)) goto bad;
    control_offset = pc - begin;
    for (i = 0; i < info->count;) {
        const BYTE b1 = info->codes[i * 2 + 1];
        if ((b1 & 15) == UWOP_SET_FPREG) set_fp_off = info->codes[i * 2];
        i += unwind_slots(b1 & 15, b1 >> 4);
    }
    if ((info->frame & 15) && control_offset >= set_fp_off) {
        value = *reg_slot(&c, info->frame & 15);
        if (value < (DWORD64)(info->frame >> 4) * 16) goto bad;
        est = value - (DWORD64)(info->frame >> 4) * 16;
    }
    {
        DWORD64 epilog_at;
        if (v2_epilog(info, end - begin, control_offset, &epilog_at) || control_offset >= info->prolog) {
            ep = in_epilogue(pc, begin, end, &c);
            if (ep < 0) goto bad;
            if (ep) goto done;
        }
    }
    if (!apply_codes(info, &c, control_offset, 0, &machframe)) goto bad;
    while (UI_FLAGS(info) & UNW_FLAG_CHAININFO) {
        const BYTE *chain = &info->codes[((info->count + 1u) & ~1u) * 2];
        DWORD64 next;
        memcpy(&entry, chain, sizeof entry);
        /* Cap even valid-address cycles before they can exhaust the exception stack or hang forever. */
        if (++depth > SHZ_UNWIND_CHAIN_LIMIT || entry.BeginAddress >= entry.EndAddress ||
            !unwind_add(image_base, entry.UnwindData, &next) || next == addr || !unwind_record(next, &record)) goto bad;
        addr = next;
        if (!apply_codes(info, &c, 0, 1, &machframe)) goto bad;
    }
    if (!machframe) {
        if (!unwind_stack_read(c.Rsp, &value, 8) || !unwind_add(c.Rsp, 8, &c.Rsp)) goto bad;
        c.Rip = value;
    }
    if ((UI_FLAGS(info) & handler_type) && control_offset >= info->prolog) {
        const unsigned at = 4 + ((info->count + 1u) & ~1u) * 2;
        if (!unwind_add(image_base, unwind_dword(record.bytes + at), &value)) goto bad;
        handler = (PEXCEPTION_ROUTINE)(uintptr_t)value;
        if (!unwind_add(addr, at + 4, &value)) goto bad;
        hdata = (PVOID)(uintptr_t)value;
    }
done:
    *ctx = c;
    *establisher = est;
    if (handler_data) *handler_data = hdata;
    return handler;
bad:
    /* Existing walkers stop at RIP == 0. Do not publish speculative register/SP restores or call a handler. */
    ctx->Rip = 0;
    return 0;
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
    DWORD64 base, limit;
    shz_unwind_stack_limits(&limit, &base);
    return limit < base && sp >= limit && sp < base && !(sp & 7) && base - sp >= 8;
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

/* mingw marks RtlCaptureContext returns_twice; this runtime's implementation returns once. Keep the warning
 * suppression local to functions that capture contexts, including RtlCaptureStackBackTrace. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif
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
    /* The SDK declares RtlCaptureContext returns_twice. Keep the walk's
     * accumulated state in memory across that compiler-visible boundary. */
    volatile ULONG64 sum = 0;
    volatile ULONG seen = 0;
    ULONG got = 0, guard;
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

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

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
