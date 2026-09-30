/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: structured exception handling for hosted drivers.
 *
 * Drivers built with MSVC/clang keep their __try/__except/__finally state in the image's exception directory (.pdata:
 * RUNTIME_FUNCTION -> UNWIND_INFO, whose language handler is __C_specific_handler with a SCOPE_TABLE). This file provides
 * what ntoskrnl.exe exports for that: RtlLookupFunctionEntry, RtlVirtualUnwind, RtlUnwindEx/RtlUnwind,
 * __C_specific_handler, RtlCaptureContext/RtlRestoreContext, the raise entry points (RtlRaiseException, RtlRaiseStatus,
 * ExRaiseStatus, ExRaiseAccessViolation, ExRaiseDatatypeMisalignment), and a hook the CPU-exception path calls so a fault
 * inside a driver (page fault, divide error, ...) is dispatched to the driver's handlers exactly like a raised exception.
 *
 * Only driver images carry unwind data here (the kernel itself is built without it), so the frame walk stops at the first
 * frame outside a driver image: an exception nobody in the driver handles is a KMODE_EXCEPTION_NOT_HANDLED bug check, as
 * on Windows when no handler exists in the driver's frames.
 *
 * Written from Microsoft's public documentation of the x64 exception-handling structures (UNWIND_INFO, UNWIND_CODE,
 * SCOPE_TABLE, DISPATCHER_CONTEXT, CONTEXT); the algorithm follows the repository's user-mode ntdll unwinder
 * (win64/ntdll/unwind.c) with kernel stack checks and without vectored handlers.
 *
 * Calling convention: every export is NTAPI (Microsoft x64). The raise entry points and RtlUnwind(Ex) are assembly thunks
 * that capture the CALLER's register state at entry (the state an unwinder needs: the frame that called the export) and
 * pass a pointer to it as an extra final argument to the C worker.
 */
#include "ntdrv.h"
#include "k64.h"

#define EXCEPTION_NONCONTINUABLE 0x01u
#define EXCEPTION_UNWINDING 0x02u
#define EXCEPTION_EXIT_UNWIND 0x04u
#define EXCEPTION_NESTED_CALL 0x10u
#define EXCEPTION_TARGET_UNWIND 0x20u
#define EXCEPTION_COLLIDED_UNWIND 0x40u
#define UNW_FLAG_EHANDLER 1u
#define UNW_FLAG_UHANDLER 2u
#define UNW_FLAG_CHAININFO 4u
#define STATUS_UNWIND_CODE ((int32_t)0xC0000027)
#define STATUS_KMODE_EXCEPTION_NOT_HANDLED 0x1E
#define STATUS_BREAKPOINT_CODE ((int32_t)0x80000003)
#define STATUS_DATATYPE_MISALIGNMENT_CODE ((int32_t)0x80000002)
#define STATUS_INTEGER_OVERFLOW_CODE ((int32_t)0xC0000095)
#define STATUS_ARRAY_BOUNDS_EXCEEDED_CODE ((int32_t)0xC000008C)
#define STATUS_PRIVILEGED_INSTRUCTION_CODE ((int32_t)0xC0000096)
#define CONTEXT_ALL_X64 0x10001Fu
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#define ExceptionContinueExecution 0
#define ExceptionContinueSearch 1

/* x64 CONTEXT, 0x4d0 bytes: the eight home slots, control/segment words, debug registers, the sixteen general registers in
 * hardware-encoding order (Rax Rcx Rdx Rbx Rsp Rbp Rsi Rdi R8..R15), Rip, the XSAVE-legacy area (XMM0..15 at 0x1a0) and the
 * vector registers. */
typedef struct __attribute__((aligned(16))) {
    uint64_t P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;      /* 0x00 */
    uint32_t ContextFlags, MxCsr;                                 /* 0x30 */
    uint16_t SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;            /* 0x38 */
    uint32_t EFlags;                                              /* 0x44 */
    uint64_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;                        /* 0x48 */
    union {
        struct { uint64_t Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15; };
        uint64_t R[16];
    };                                                            /* 0x78 */
    uint64_t Rip;                                                 /* 0xf8 */
    uint8_t FltSave[0x200];                                       /* 0x100: XMM registers start at FltSave + 0xa0 */
    uint8_t VectorRegister[26 * 16];                              /* 0x300 */
    uint64_t VectorControl, DebugControl, LastBranchToRip, LastBranchFromRip, LastExceptionToRip, LastExceptionFromRip;
} CONTEXT;
_Static_assert(sizeof(CONTEXT) == 0x4d0 && __builtin_offsetof(CONTEXT, Rax) == 0x78 && __builtin_offsetof(CONTEXT, Rsp) == 0x98 &&
               __builtin_offsetof(CONTEXT, R8) == 0xb8 && __builtin_offsetof(CONTEXT, R15) == 0xf0 &&
               __builtin_offsetof(CONTEXT, Rip) == 0xf8 && __builtin_offsetof(CONTEXT, FltSave) == 0x100 &&
               __builtin_offsetof(CONTEXT, EFlags) == 0x44, "CONTEXT layout");

typedef struct _EXCEPTION_RECORD {
    int32_t ExceptionCode;                      /* 0x00 */
    uint32_t ExceptionFlags;                    /* 0x04 */
    struct _EXCEPTION_RECORD *ExceptionRecord;  /* 0x08 */
    void *ExceptionAddress;                     /* 0x10 */
    uint32_t NumberParameters, _pad;            /* 0x18 */
    uint64_t ExceptionInformation[15];          /* 0x20 */
} EXCEPTION_RECORD;
_Static_assert(sizeof(EXCEPTION_RECORD) == 0x98, "EXCEPTION_RECORD");

typedef struct { uint32_t BeginAddress, EndAddress, UnwindData; } RUNTIME_FUNCTION;

typedef struct DISPATCHER_CONTEXT DISPATCHER_CONTEXT;
typedef int32_t (NTAPI *EXCEPTION_ROUTINE)(EXCEPTION_RECORD *, void *frame, CONTEXT *, DISPATCHER_CONTEXT *);
struct DISPATCHER_CONTEXT {
    uint64_t ControlPc;                         /* 0x00 */
    uint64_t ImageBase;                         /* 0x08 */
    RUNTIME_FUNCTION *FunctionEntry;            /* 0x10 */
    uint64_t EstablisherFrame;                  /* 0x18 */
    uint64_t TargetIp;                          /* 0x20 */
    CONTEXT *ContextRecord;                     /* 0x28 */
    EXCEPTION_ROUTINE LanguageHandler;          /* 0x30 */
    void *HandlerData;                          /* 0x38 */
    void *HistoryTable;                         /* 0x40 */
    uint32_t ScopeIndex, Fill0;                 /* 0x48 */
};
_Static_assert(sizeof(DISPATCHER_CONTEXT) == 0x50 && __builtin_offsetof(DISPATCHER_CONTEXT, HandlerData) == 0x38, "DISPATCHER_CONTEXT");

typedef struct { EXCEPTION_RECORD *ExceptionRecord; CONTEXT *ContextRecord; } EXCEPTION_POINTERS;

/* ---------------------------------------------------------------- unwind data */
#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_EPILOG 6
#define UWOP_SAVE_XMM128 8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10

typedef struct { uint8_t ver_flags, prolog, count, frame; uint8_t codes[]; } unwind_info_t;
#define UI_VERSION(i) ((i)->ver_flags & 7)
#define UI_FLAGS(i) ((i)->ver_flags >> 3)

static uint8_t *xmm_slot(CONTEXT *c, unsigned i) { return c->FltSave + 0xa0 + 16u * i; }

/* Kernel stack plausibility: aligned, and in the upper half of the address space where kernel stacks live. */
static int stack_ok(uint64_t sp) { return sp >= 0xffff800000000000ull && !(sp & 7); }

/* ---------------------------------------------------------------- function lookup */
static RUNTIME_FUNCTION *search_table(RUNTIME_FUNCTION *t, uint32_t n, uint64_t base, uint64_t pc)
{
    long lo = 0, hi = (long)n - 1;
    const uint32_t rva = (uint32_t)(pc - base);
    while (lo <= hi) {
        const long mid = (lo + hi) / 2;
        if (rva < t[mid].BeginAddress) hi = mid - 1;
        else if (rva >= t[mid].EndAddress) lo = mid + 1;
        else return &t[mid];
    }
    return 0;
}

void *NTAPI RtlPcToFileHeader(void *pc, void **base)
{
    ntdrv_driver_t *d = ntdrv_driver_by_address((uint64_t)pc);
    *base = d ? (void *)d->image_base : 0;
    return *base;
}

RUNTIME_FUNCTION *NTAPI RtlLookupFunctionEntry(uint64_t pc, uint64_t *image_base, void *history)
{
    ntdrv_driver_t *d = ntdrv_driver_by_address(pc);
    const uint8_t *base;
    uint32_t e_lfanew, dir_rva, dir_size;
    (void)history;
    *image_base = 0;
    if (!d) return 0;
    base = (const uint8_t *)d->image_base;
    *image_base = d->image_base;
    memcpy(&e_lfanew, base + 0x3c, 4);
    if (e_lfanew > 0x400) return 0;
    memcpy(&dir_rva, base + e_lfanew + 0xa0, 4);                 /* OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] */
    memcpy(&dir_size, base + e_lfanew + 0xa4, 4);
    if (!dir_rva || !dir_size || (uint64_t)dir_rva + dir_size > d->image_size) return 0;
    return search_table((RUNTIME_FUNCTION *)(base + dir_rva), dir_size / sizeof(RUNTIME_FUNCTION), d->image_base, pc);
}

/* ---------------------------------------------------------------- RtlVirtualUnwind */
/* Version 2 UNWIND_INFO records epilogs explicitly with UWOP_EPILOG codes. Returns 1 when `control_offset` lies inside a
 * described epilog. */
static int v2_epilog(const unwind_info_t *info, uint64_t fn_len, uint64_t control_offset)
{
    unsigned i, epilog_size = 0;
    if (UI_VERSION(info) != 2) return 0;
    for (i = 0; i < info->count;) {
        const uint8_t code_off = info->codes[i * 2], b1 = info->codes[i * 2 + 1];
        const unsigned op = b1 & 15, opinfo = b1 >> 4;
        if (op == UWOP_EPILOG) {
            if (!epilog_size) {
                epilog_size = code_off;
                if (opinfo & 1) {
                    const uint64_t start = fn_len - epilog_size;
                    if (control_offset >= start && control_offset < fn_len) return 1;
                }
            } else {
                const uint64_t end = fn_len - (code_off | ((uint64_t)opinfo << 8));
                const uint64_t start = end - epilog_size;
                if (control_offset >= start && control_offset < end) return 1;
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

/* Recognised epilogue: [add rsp,imm | lea rsp,[fp+imm]], pop*, (ret | rep ret | jmp out of the function). When `apply`,
 * the remaining instructions are simulated on ctx. */
static int in_epilogue(const uint8_t *pc, uint64_t fn_begin, uint64_t fn_end, CONTEXT *ctx, int apply)
{
    const uint8_t *p = pc;
    uint64_t rsp = ctx->Rsp;
    CONTEXT tmp = *ctx;
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xc4) { rsp += (uint64_t)(int64_t)(int8_t)p[3]; p += 4; }          /* add rsp, imm8 */
    else if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xc4) { int32_t v; memcpy(&v, p + 3, 4); rsp += (uint64_t)(int64_t)v; p += 7; }
    else if ((p[0] & 0xfb) == 0x48 && p[1] == 0x8d && (p[2] & 0xc7) == 0x45 && ((p[2] >> 3) & 7) == 4 && !(p[0] & 4)) {
        const unsigned reg = (p[2] & 7) | ((p[0] & 1) ? 8 : 0);                                                    /* lea rsp, [reg+disp8] */
        rsp = tmp.R[reg] + (uint64_t)(int64_t)(int8_t)p[3];
        p += 4;
    } else if ((p[0] & 0xfa) == 0x48 && p[1] == 0x8d && (p[2] & 0xc7) == 0x85 && ((p[2] >> 3) & 7) == 4) {
        const unsigned reg = (p[2] & 7) | ((p[0] & 1) ? 8 : 0);                                                    /* lea rsp, [reg+disp32] */
        int32_t v; memcpy(&v, p + 3, 4);
        rsp = tmp.R[reg] + (uint64_t)(int64_t)v;
        p += 7;
    }
    for (;;) {
        unsigned reg;
        if (p[0] >= 0x58 && p[0] <= 0x5f) { reg = p[0] - 0x58u; p += 1; }
        else if (p[0] == 0x41 && p[1] >= 0x58 && p[1] <= 0x5f) { reg = 8u + p[1] - 0x58u; p += 2; }
        else break;
        tmp.R[reg] = *(uint64_t *)rsp;
        rsp += 8;
    }
    if (p[0] == 0xc3 || (p[0] == 0xf3 && p[1] == 0xc3) || p[0] == 0xc2) {
        if (apply) { *ctx = tmp; ctx->Rip = *(uint64_t *)rsp; ctx->Rsp = rsp + 8; }
        return 1;
    }
    if ((p[0] == 0x48 && p[1] == 0xff && (p[2] & 0x38) == 0x20) || p[0] == 0xe9 || p[0] == 0xeb || (p[0] == 0xff && p[1] == 0x25)) {
        int outside = 1;
        if (p[0] == 0xe9) { int32_t rel; memcpy(&rel, p + 1, 4); outside = ((uint64_t)(p + 5 + rel) < fn_begin || (uint64_t)(p + 5 + rel) >= fn_end); }
        else if (p[0] == 0xeb) { outside = ((uint64_t)(p + 2 + (int8_t)p[1]) < fn_begin || (uint64_t)(p + 2 + (int8_t)p[1]) >= fn_end); }
        if (outside) {
            if (apply) { *ctx = tmp; ctx->Rip = *(uint64_t *)rsp; ctx->Rsp = rsp + 8; }
            return 1;
        }
    }
    return 0;
}

static void apply_codes(const unwind_info_t *info, CONTEXT *c, uint64_t control_offset, int all)
{
    unsigned i = 0;
    const unsigned frame_off = (info->frame >> 4) * 16u, frame_reg = info->frame & 15;
    while (i < info->count) {
        const uint8_t off = info->codes[i * 2], b1 = info->codes[i * 2 + 1];
        const unsigned op = b1 & 15, opinfo = b1 >> 4;
        unsigned slots;
        const int active = all || control_offset >= off;
        switch (op) {
        case UWOP_ALLOC_LARGE: slots = opinfo ? 3 : 2; break;
        case UWOP_SAVE_NONVOL: case UWOP_SAVE_XMM128: slots = 2; break;
        case UWOP_SAVE_NONVOL_FAR: case UWOP_SAVE_XMM128_FAR: slots = 3; break;
        default: slots = 1;
        }
        if (active) {
            switch (op) {
            case UWOP_PUSH_NONVOL: c->R[opinfo] = *(uint64_t *)c->Rsp; c->Rsp += 8; break;
            case UWOP_ALLOC_LARGE: {
                uint32_t big; uint16_t small;
                if (opinfo) { memcpy(&big, &info->codes[(i + 1) * 2], 4); c->Rsp += big; }
                else { memcpy(&small, &info->codes[(i + 1) * 2], 2); c->Rsp += (uint64_t)small * 8; }
                break;
            }
            case UWOP_ALLOC_SMALL: c->Rsp += (uint64_t)opinfo * 8 + 8; break;
            case UWOP_SET_FPREG: c->Rsp = c->R[frame_reg] - frame_off; break;
            case UWOP_SAVE_NONVOL: { uint16_t s; memcpy(&s, &info->codes[(i + 1) * 2], 2); c->R[opinfo] = *(uint64_t *)(c->Rsp + (uint64_t)s * 8); break; }
            case UWOP_SAVE_NONVOL_FAR: { uint32_t s; memcpy(&s, &info->codes[(i + 1) * 2], 4); c->R[opinfo] = *(uint64_t *)(c->Rsp + s); break; }
            case UWOP_SAVE_XMM128: { uint16_t s; memcpy(&s, &info->codes[(i + 1) * 2], 2); memcpy(xmm_slot(c, opinfo), (void *)(c->Rsp + (uint64_t)s * 16), 16); break; }
            case UWOP_SAVE_XMM128_FAR: { uint32_t s; memcpy(&s, &info->codes[(i + 1) * 2], 4); memcpy(xmm_slot(c, opinfo), (void *)(c->Rsp + s), 16); break; }
            case UWOP_PUSH_MACHFRAME: {
                uint64_t sp = c->Rsp;
                if (opinfo) sp += 8;                                 /* skip the hardware error code */
                c->Rip = *(uint64_t *)sp;
                c->EFlags = (uint32_t)*(uint64_t *)(sp + 16);
                c->Rsp = *(uint64_t *)(sp + 24);
                break;
            }
            default: break;
            }
        }
        i += slots;
    }
}

EXCEPTION_ROUTINE NTAPI RtlVirtualUnwind(uint32_t handler_type, uint64_t image_base, uint64_t pc, RUNTIME_FUNCTION *fe,
                                         CONTEXT *ctx, void **handler_data, uint64_t *establisher, void *ptrs)
{
    const uint64_t begin = image_base + fe->BeginAddress, end = image_base + fe->EndAddress;
    const uint64_t control_offset = pc - begin;
    const unwind_info_t *info = (const unwind_info_t *)(image_base + fe->UnwindData);
    const unwind_info_t *cur = info;
    EXCEPTION_ROUTINE handler = 0;
    unsigned set_fp_off = 0xffff, i;
    (void)ptrs;
    if (handler_data) *handler_data = 0;
    {
        const unsigned frame_reg = info->frame & 15, frame_off = (info->frame >> 4) * 16u;
        for (i = 0; i < info->count;) {
            const uint8_t b1 = info->codes[i * 2 + 1];
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
        *establisher = frame_reg && control_offset >= set_fp_off ? ctx->R[frame_reg] - frame_off : ctx->Rsp;
    }
    if ((v2_epilog(info, end - begin, control_offset) || control_offset >= info->prolog) &&
        in_epilogue((const uint8_t *)pc, begin, end, ctx, 1))
        return 0;
    apply_codes(info, ctx, control_offset, 0);
    while (UI_FLAGS(cur) & UNW_FLAG_CHAININFO) {                     /* chained unwind info: the parent's operations always complete */
        const RUNTIME_FUNCTION *chain = (const RUNTIME_FUNCTION *)&cur->codes[((cur->count + 1u) & ~1u) * 2];
        cur = (const unwind_info_t *)(image_base + chain->UnwindData);
        apply_codes(cur, ctx, 0, 1);
    }
    ctx->Rip = *(uint64_t *)ctx->Rsp;
    ctx->Rsp += 8;
    if ((UI_FLAGS(info) & handler_type) && !(UI_FLAGS(info) & UNW_FLAG_CHAININFO) && control_offset >= info->prolog) {
        uint32_t hrva;
        const uint8_t *h = &info->codes[((info->count + 1u) & ~1u) * 2];
        memcpy(&hrva, h, 4);
        handler = (EXCEPTION_ROUTINE)(uintptr_t)(image_base + hrva);
        if (handler_data) *handler_data = (void *)(h + 4);
    }
    return handler;
}

/* ---------------------------------------------------------------- context save / restore / thunks (assembly) */
/* CONTEXT field offsets used below: EFlags 0x44 Rax 0x78 Rcx 0x80 Rdx 0x88 Rbx 0x90 Rsp 0x98 Rbp 0xa0 Rsi 0xa8 Rdi 0xb0
 * R8..R15 0xb8..0xf0 Rip 0xf8, XMM6..15 at 0x200. */
extern void NTAPI ntdrv_restore_context(CONTEXT *ctx);
__asm__(
    ".text\n"
    ".intel_syntax noprefix\n"

    /* void RtlCaptureContext(CONTEXT *rcx): state as if the call had returned (Rip = return address, Rsp = rsp + 8). */
    ".globl RtlCaptureContext\n.type RtlCaptureContext, @function\nRtlCaptureContext:\n"
    "  mov [rcx+0x78], rax\n  mov [rcx+0x80], rcx\n  mov [rcx+0x88], rdx\n  mov [rcx+0x90], rbx\n"
    "  lea rax, [rsp+8]\n  mov [rcx+0x98], rax\n  mov [rcx+0xa0], rbp\n  mov [rcx+0xa8], rsi\n  mov [rcx+0xb0], rdi\n"
    "  mov [rcx+0xb8], r8\n  mov [rcx+0xc0], r9\n  mov [rcx+0xc8], r10\n  mov [rcx+0xd0], r11\n"
    "  mov [rcx+0xd8], r12\n  mov [rcx+0xe0], r13\n  mov [rcx+0xe8], r14\n  mov [rcx+0xf0], r15\n"
    "  mov rax, [rsp]\n  mov [rcx+0xf8], rax\n"
    "  movups [rcx+0x200], xmm6\n  movups [rcx+0x210], xmm7\n  movups [rcx+0x220], xmm8\n  movups [rcx+0x230], xmm9\n"
    "  movups [rcx+0x240], xmm10\n  movups [rcx+0x250], xmm11\n  movups [rcx+0x260], xmm12\n  movups [rcx+0x270], xmm13\n"
    "  movups [rcx+0x280], xmm14\n  movups [rcx+0x290], xmm15\n"
    "  pushfq\n  pop rax\n  mov [rcx+0x44], eax\n"
    "  mov dword ptr [rcx+0x30], 0x10001f\n"
    "  mov rax, [rcx+0x78]\n  ret\n"

    /* void ntdrv_restore_context(CONTEXT *rcx): load the general registers, XMM6-15, the flags and the stack pointer, and
     * continue at Rip. Volatile registers other than Rax/Rcx are not preserved (R11 carries the flags). Never returns. */
    ".globl ntdrv_restore_context\n.type ntdrv_restore_context, @function\nntdrv_restore_context:\n"
    "  mov r11, rcx\n"
    "  movups xmm6, [r11+0x200]\n  movups xmm7, [r11+0x210]\n  movups xmm8, [r11+0x220]\n  movups xmm9, [r11+0x230]\n"
    "  movups xmm10, [r11+0x240]\n  movups xmm11, [r11+0x250]\n  movups xmm12, [r11+0x260]\n  movups xmm13, [r11+0x270]\n"
    "  movups xmm14, [r11+0x280]\n  movups xmm15, [r11+0x290]\n"
    "  mov rax, [r11+0x78]\n  mov rdx, [r11+0x88]\n  mov rbx, [r11+0x90]\n  mov rbp, [r11+0xa0]\n  mov rsi, [r11+0xa8]\n"
    "  mov rdi, [r11+0xb0]\n  mov r8, [r11+0xb8]\n  mov r9, [r11+0xc0]\n  mov r10, [r11+0xc8]\n  mov r12, [r11+0xd8]\n"
    "  mov r13, [r11+0xe0]\n  mov r14, [r11+0xe8]\n  mov r15, [r11+0xf0]\n  mov rcx, [r11+0x80]\n"
    "  mov rsp, [r11+0x98]\n  push qword ptr [r11+0xf8]\n"
    "  mov r11d, dword ptr [r11+0x44]\n  or r11d, 2\n  push r11\n  popfq\n  ret\n"

    /* void RtlRestoreContext(CONTEXT *rcx, EXCEPTION_RECORD *rdx) */
    ".globl RtlRestoreContext\n.type RtlRestoreContext, @function\nRtlRestoreContext:\n  jmp ntdrv_restore_context\n"

    /* Entry thunks. Frame: 0x20 shadow + three stack-argument slots (0x20..0x37) + CONTEXT at +0x40 = 0x518 with the return
     * address slot keeping rsp 16-byte aligned at the call. The caller's own arguments 5 and 6 are re-pushed so the worker
     * sees (rcx, rdx, r8, r9, arg5, arg6, CONTEXT* of the caller at entry). */
    ".macro SEH_THUNK name, cfn\n"
    ".globl \\name\n.type \\name, @function\n\\name:\n"
    "  sub rsp, 0x518\n"
    "  mov rax, [rsp+0x540]\n  mov [rsp+0x20], rax\n"
    "  mov rax, [rsp+0x548]\n  mov [rsp+0x28], rax\n"
    "  mov [rsp+0xc0], rcx\n  mov [rsp+0xc8], rdx\n  mov [rsp+0xd0], rbx\n  mov [rsp+0xe0], rbp\n"
    "  mov [rsp+0xe8], rsi\n  mov [rsp+0xf0], rdi\n  mov [rsp+0xf8], r8\n  mov [rsp+0x100], r9\n"
    "  mov [rsp+0x108], r10\n  mov [rsp+0x110], r11\n  mov [rsp+0x118], r12\n  mov [rsp+0x120], r13\n"
    "  mov [rsp+0x128], r14\n  mov [rsp+0x130], r15\n"
    "  lea rax, [rsp+0x520]\n  mov [rsp+0xd8], rax\n"
    "  mov rax, [rsp+0x518]\n  mov [rsp+0x138], rax\n"
    "  movups [rsp+0x240], xmm6\n  movups [rsp+0x250], xmm7\n  movups [rsp+0x260], xmm8\n  movups [rsp+0x270], xmm9\n"
    "  movups [rsp+0x280], xmm10\n  movups [rsp+0x290], xmm11\n  movups [rsp+0x2a0], xmm12\n  movups [rsp+0x2b0], xmm13\n"
    "  movups [rsp+0x2c0], xmm14\n  movups [rsp+0x2d0], xmm15\n"
    "  pushfq\n  pop rax\n  mov [rsp+0x84], eax\n"
    "  mov dword ptr [rsp+0x70], 0x10001f\n"
    "  lea rax, [rsp+0x40]\n  mov [rsp+0x30], rax\n"
    "  call \\cfn\n"
    "  lea rcx, [rsp+0x40]\n  call ntdrv_restore_context\n"
    ".size \\name, .-\\name\n"
    ".endm\n"
    "SEH_THUNK RtlRaiseException, seh_raise_record\n"
    "SEH_THUNK RtlRaiseStatus, seh_raise_status\n"
    "SEH_THUNK ExRaiseStatus, seh_raise_status\n"
    "SEH_THUNK ExRaiseAccessViolation, seh_raise_access_violation\n"
    "SEH_THUNK ExRaiseDatatypeMisalignment, seh_raise_misalignment\n"
    "SEH_THUNK RtlUnwindEx, seh_unwind_ex\n"
    "SEH_THUNK RtlUnwind, seh_unwind\n"
    ".att_syntax prefix\n");

/* ---------------------------------------------------------------- dispatch */
extern void NTAPI KeBugCheckEx(uint32_t code, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4);
static int32_t call_handler(EXCEPTION_ROUTINE h, EXCEPTION_RECORD *rec, void *frame, CONTEXT *ctx, DISPATCHER_CONTEXT *dc)
{
    return h(rec, frame, ctx, dc);
}

/* Preconditions for walking one frame. A call or jump through a bad pointer faults at an address outside every image; the
 * caller's return address is then on top of the stack, so the very first frame is popped as if it were a leaf. */
static int frame_walkable(CONTEXT *c, unsigned depth)
{
    if (!stack_ok(c->Rsp)) return 0;
    if (ntdrv_driver_by_address(c->Rip)) return 1;
    if (depth == 1 && ntdrv_driver_by_address(*(uint64_t *)c->Rsp)) {
        c->Rip = *(uint64_t *)c->Rsp;
        c->Rsp += 8;
        return 1;
    }
    return 0;
}

/* Phase 1: walk the driver frames from `orig`, offering the exception to each frame's exception handler. Returns 1 when a
 * handler resumed execution (the possibly modified context is copied back into `orig`); a handler that decides to unwind
 * ends in RtlUnwindEx, which does not return. */
static int dispatch_frames(EXCEPTION_RECORD *rec, CONTEXT *orig)
{
    CONTEXT c = *orig;                                               /* 32 KiB kernel stacks: a few CONTEXTs per level are fine */
    unsigned depth = 0;
    while (depth++ < 4096) {
        uint64_t image_base = 0, establisher = 0;
        RUNTIME_FUNCTION *fe;
        CONTEXT unwound;
        void *hdata = 0;
        EXCEPTION_ROUTINE handler;
        if (!frame_walkable(&c, depth)) return 0;
        fe = RtlLookupFunctionEntry(c.Rip, &image_base, 0);
        unwound = c;
        if (!fe) {                                                   /* leaf function without unwind data: return address at Rsp */
            c.Rip = *(uint64_t *)c.Rsp;
            c.Rsp += 8;
            continue;
        }
        handler = RtlVirtualUnwind(UNW_FLAG_EHANDLER, image_base, c.Rip, fe, &unwound, &hdata, &establisher, 0);
        if (handler) {
            DISPATCHER_CONTEXT dc;
            int32_t d;
            memset(&dc, 0, sizeof dc);
            dc.ControlPc = c.Rip; dc.ImageBase = image_base; dc.FunctionEntry = fe; dc.EstablisherFrame = establisher;
            dc.ContextRecord = &c; dc.LanguageHandler = handler; dc.HandlerData = hdata;
            /* The handler's ContextRecord argument is the ORIGINAL exception context (RtlUnwindEx starts unwinding there so
             * frames below the handler's own are unwound too); DISPATCHER_CONTEXT carries this frame's context. A handler
             * that returns ExceptionContinueExecution may have edited the original context in place. */
            d = call_handler(handler, rec, (void *)establisher, orig, &dc);
            if (d == ExceptionContinueExecution) return !(rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE);
        }
        c = unwound;
        if (!c.Rip) return 0;
    }
    return 0;
}

static void fill_code_info(EXCEPTION_RECORD *rec, int32_t code, uint32_t flags, void *addr)
{
    memset(rec, 0, sizeof *rec);
    rec->ExceptionCode = code;
    rec->ExceptionFlags = flags;
    rec->ExceptionAddress = addr;
}

static void unhandled(EXCEPTION_RECORD *rec)
{
    KeBugCheckEx(STATUS_KMODE_EXCEPTION_NOT_HANDLED, (uint64_t)(uint32_t)rec->ExceptionCode, (uint64_t)rec->ExceptionAddress,
                 rec->NumberParameters > 0 ? rec->ExceptionInformation[0] : 0, rec->NumberParameters > 1 ? rec->ExceptionInformation[1] : 0);
}

/* Workers of the raise thunks: `ctx` is the caller's state at entry. They return only when a handler continued execution. */
void NTAPI seh_raise_record(EXCEPTION_RECORD *rec, void *a2, void *a3, void *a4, void *a5, void *a6, CONTEXT *ctx)
{
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    rec->ExceptionAddress = (void *)ctx->Rip;
    if (!dispatch_frames(rec, ctx)) unhandled(rec);
}
void NTAPI seh_raise_status(int32_t status, void *a2, void *a3, void *a4, void *a5, void *a6, CONTEXT *ctx)
{
    EXCEPTION_RECORD rec;
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    fill_code_info(&rec, status, EXCEPTION_NONCONTINUABLE, (void *)ctx->Rip);
    if (!dispatch_frames(&rec, ctx)) unhandled(&rec);
}
void NTAPI seh_raise_access_violation(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, CONTEXT *ctx)
{
    EXCEPTION_RECORD rec;
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    fill_code_info(&rec, STATUS_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, (void *)ctx->Rip);
    rec.NumberParameters = 2;                                        /* read access, address 0 */
    if (!dispatch_frames(&rec, ctx)) unhandled(&rec);
}
void NTAPI seh_raise_misalignment(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, CONTEXT *ctx)
{
    EXCEPTION_RECORD rec;
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    fill_code_info(&rec, STATUS_DATATYPE_MISALIGNMENT_CODE, EXCEPTION_NONCONTINUABLE, (void *)ctx->Rip);
    if (!dispatch_frames(&rec, ctx)) unhandled(&rec);
}

/* ---------------------------------------------------------------- unwinding */
static void unwind_worker(void *target_frame, void *target_ip, EXCEPTION_RECORD *rec, void *return_value, CONTEXT *original,
                          CONTEXT *cap)
{
    CONTEXT c = original ? *original : *cap;
    EXCEPTION_RECORD local;
    unsigned depth = 0;
    if (!rec) {
        fill_code_info(&local, STATUS_UNWIND_CODE, 0, (void *)c.Rip);
        rec = &local;
    }
    rec->ExceptionFlags |= EXCEPTION_UNWINDING | (target_frame ? 0 : EXCEPTION_EXIT_UNWIND);
    while (depth++ < 4096) {
        uint64_t image_base = 0, establisher = 0;
        RUNTIME_FUNCTION *fe;
        CONTEXT unwound;
        void *hdata = 0;
        EXCEPTION_ROUTINE handler;
        int final;
        if (!frame_walkable(&c, depth)) break;
        fe = RtlLookupFunctionEntry(c.Rip, &image_base, 0);
        unwound = c;
        if (!fe) {
            c.Rip = *(uint64_t *)c.Rsp;
            c.Rsp += 8;
            continue;
        }
        handler = RtlVirtualUnwind(UNW_FLAG_UHANDLER, image_base, c.Rip, fe, &unwound, &hdata, &establisher, 0);
        final = target_frame && establisher == (uint64_t)target_frame;
        if (target_frame && establisher > (uint64_t)target_frame) break;              /* overshot: invalid target */
        if (final) rec->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
        if (handler) {
            DISPATCHER_CONTEXT dc;
            memset(&dc, 0, sizeof dc);
            dc.ControlPc = c.Rip; dc.ImageBase = image_base; dc.FunctionEntry = fe; dc.EstablisherFrame = establisher;
            dc.TargetIp = (uint64_t)target_ip; dc.ContextRecord = &c; dc.LanguageHandler = handler; dc.HandlerData = hdata;
            call_handler(handler, rec, (void *)establisher, &c, &dc);
        }
        if (final) break;
        c = unwound;
    }
    rec->ExceptionFlags &= ~EXCEPTION_TARGET_UNWIND;
    /* `c` is the target frame's own context (its callees were unwound), so its non-volatile registers and Rsp are what the
     * frame had at the call site; resume at the __except body with the exception code in Rax. */
    c.Rip = (uint64_t)target_ip;
    c.Rax = (uint64_t)return_value;
    c.ContextFlags = CONTEXT_ALL_X64;
    ntdrv_restore_context(&c);
}
void NTAPI seh_unwind_ex(void *target_frame, void *target_ip, EXCEPTION_RECORD *rec, void *return_value, CONTEXT *original,
                         void *history, CONTEXT *cap)
{
    (void)history;
    unwind_worker(target_frame, target_ip, rec, return_value, original, cap);
}
void NTAPI seh_unwind(void *target_frame, void *target_ip, EXCEPTION_RECORD *rec, void *return_value, void *a5, void *a6,
                      CONTEXT *cap)
{
    (void)a5; (void)a6;
    unwind_worker(target_frame, target_ip, rec, return_value, 0, cap);
}

/* ---------------------------------------------------------------- __C_specific_handler */
/* SCOPE_TABLE (RVAs from ImageBase): Count, then {BeginAddress, EndAddress, HandlerAddress, JumpTarget}. JumpTarget == 0 marks
 * a __finally (HandlerAddress is the termination handler); otherwise an __except whose HandlerAddress is the filter, or the
 * constant 1 meaning EXCEPTION_EXECUTE_HANDLER, and JumpTarget is the __except body. */
typedef struct { uint32_t Count; struct { uint32_t Begin, End, Handler, Target; } Rec[1]; } scope_table_t;
typedef int32_t (NTAPI *c_filter_t)(EXCEPTION_POINTERS *, void *frame);
typedef void (NTAPI *c_finally_t)(uint8_t abnormal, void *frame);

int32_t NTAPI __C_specific_handler(EXCEPTION_RECORD *rec, void *frame, CONTEXT *ctx, DISPATCHER_CONTEXT *dc)
{
    const scope_table_t *st = dc->HandlerData;
    const uint64_t base = dc->ImageBase;
    const uint32_t control = (uint32_t)(dc->ControlPc - base);
    uint32_t i;
    if (!st) return ExceptionContinueSearch;
    if (rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
        /* Unwind phase: run every __finally whose scope holds the control PC, except scopes that also hold the target IP
         * (those are still active after the unwind lands). */
        const uint32_t target = (uint32_t)(dc->TargetIp - base);
        for (i = 0; i < st->Count; ++i) {
            if (control < st->Rec[i].Begin || control >= st->Rec[i].End) continue;
            if (st->Rec[i].Target) continue;                                      /* an __except, not a __finally */
            if ((rec->ExceptionFlags & EXCEPTION_TARGET_UNWIND) && target >= st->Rec[i].Begin && target < st->Rec[i].End) continue;
            ((c_finally_t)(uintptr_t)(base + st->Rec[i].Handler))(1, frame);
        }
        return ExceptionContinueSearch;
    }
    for (i = 0; i < st->Count; ++i) {                                             /* search phase: evaluate the __except filters */
        int32_t r;
        if (control < st->Rec[i].Begin || control >= st->Rec[i].End || !st->Rec[i].Target) continue;
        if (st->Rec[i].Handler == 1) r = EXCEPTION_EXECUTE_HANDLER;
        else {
            EXCEPTION_POINTERS ep = { rec, ctx };
            r = ((c_filter_t)(uintptr_t)(base + st->Rec[i].Handler))(&ep, frame);
        }
        if (r == EXCEPTION_CONTINUE_EXECUTION) return ExceptionContinueExecution;
        if (r == EXCEPTION_CONTINUE_SEARCH) continue;
        /* EXCEPTION_EXECUTE_HANDLER: unwind to the __except body (does not return). */
        {
            extern void NTAPI RtlUnwindEx(void *, void *, EXCEPTION_RECORD *, void *, CONTEXT *, void *);
            RtlUnwindEx(frame, (void *)(uintptr_t)(base + st->Rec[i].Target), rec, (void *)(uintptr_t)(uint32_t)rec->ExceptionCode, ctx,
                        dc->HistoryTable);
        }
    }
    return ExceptionContinueSearch;
}

/* ---------------------------------------------------------------- CPU exceptions inside a driver */
/* Called by the CPU-exception path for a ring-0 fault. When it happened in driver code, the fault becomes an exception
 * record and goes through the driver's frames; returns 1 if a handler continued execution (the interrupted state was
 * updated in `r`), 0 to let the kernel report the fault as fatal. A handler that unwinds to an __except body resumes there
 * directly and never returns. */
int ntdrv_kernel_exception(struct regs *r)
{
    CONTEXT ctx;
    EXCEPTION_RECORD rec;
    int32_t code;
    if (r->cs & 3) return 0;
    if (!ntdrv_driver_by_address(r->rip)) {
        /* Instruction-fetch fault after a call through a bad pointer: RIP is the bad address, the driver's return address is
         * on top of the stack. */
        if (!(r->vector == 14 && r->rip == read_cr2() && stack_ok(r->rsp) && ntdrv_driver_by_address(*(uint64_t *)r->rsp))) return 0;
    }
    memset(&rec, 0, sizeof rec);
    switch (r->vector) {
    case 0: code = STATUS_INTEGER_DIVIDE_BY_ZERO; break;
    case 3: code = STATUS_BREAKPOINT_CODE; break;
    case 4: code = STATUS_INTEGER_OVERFLOW_CODE; break;
    case 5: code = STATUS_ARRAY_BOUNDS_EXCEEDED_CODE; break;
    case 6: code = STATUS_ILLEGAL_INSTRUCTION; break;
    case 13: code = STATUS_PRIVILEGED_INSTRUCTION_CODE; break;
    case 14:
        code = STATUS_ACCESS_VIOLATION;
        rec.NumberParameters = 2;
        rec.ExceptionInformation[0] = (r->error >> 1) & 1;           /* 0 = read, 1 = write */
        rec.ExceptionInformation[1] = read_cr2();
        break;
    case 17: code = STATUS_DATATYPE_MISALIGNMENT_CODE; break;
    default: return 0;
    }
    rec.ExceptionCode = code;
    rec.ExceptionAddress = (void *)r->rip;
    memset(&ctx, 0, sizeof ctx);
    ctx.ContextFlags = CONTEXT_ALL_X64;
    ctx.Rax = r->rax; ctx.Rcx = r->rcx; ctx.Rdx = r->rdx; ctx.Rbx = r->rbx; ctx.Rsp = r->rsp; ctx.Rbp = r->rbp; ctx.Rsi = r->rsi;
    ctx.Rdi = r->rdi; ctx.R8 = r->r8; ctx.R9 = r->r9; ctx.R10 = r->r10; ctx.R11 = r->r11; ctx.R12 = r->r12; ctx.R13 = r->r13;
    ctx.R14 = r->r14; ctx.R15 = r->r15; ctx.Rip = r->rip; ctx.EFlags = (uint32_t)r->rflags;
    if (!dispatch_frames(&rec, &ctx)) return 0;
    r->rax = ctx.Rax; r->rcx = ctx.Rcx; r->rdx = ctx.Rdx; r->rbx = ctx.Rbx; r->rsp = ctx.Rsp; r->rbp = ctx.Rbp; r->rsi = ctx.Rsi;
    r->rdi = ctx.Rdi; r->r8 = ctx.R8; r->r9 = ctx.R9; r->r10 = ctx.R10; r->r11 = ctx.R11; r->r12 = ctx.R12; r->r13 = ctx.R13;
    r->r14 = ctx.R14; r->r15 = ctx.R15; r->rip = ctx.Rip; r->rflags = ctx.EFlags | 2;
    return 1;
}

/* Driver Verifier hooks some drivers call: verification is never enabled in this host. */
uint8_t NTAPI VfIsVerificationEnabled(uint32_t object_type, void *object)
{
    (void)object_type; (void)object;
    return 0;
}
void NTAPI VfFailDeviceNode(void *pdo, uint32_t major, uint32_t minor, uint32_t failure_class, uint32_t *control, char *message,
                            char *format)
{
    (void)pdo; (void)major; (void)minor; (void)failure_class; (void)control; (void)format;
    kprintf("K64 ntdrv: VfFailDeviceNode(%s) ignored (Driver Verifier is not active)\n", message ? message : "");
}
