/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll: Control Flow Guard check routines and the load-configuration accessors used by the guard.
 *
 * On Windows the loader stores GuardCFCheckFunctionPointer / GuardCFDispatchFunctionPointer in each CFG-instrumented
 * image; the compiler emits `call [__guard_check_icall_fptr]` (or the dispatch variant `jmp` via the target in RAX)
 * before every indirect call. When CFG is not enforced (no kernel mitigation) those pointers reference a routine that
 * simply returns. This ntdll installs a REAL but NON-ENFORCING check: it validates the target against the
 * GuardCFFunctionTable of the image that contains it and reports violations, but always lets the call proceed - so an
 * image built with /guard:cf runs exactly as it would on a Windows machine that has CFG available but not enforced,
 * while a corrupted call target is still observable (ShzGuardViolationCount, ShzDebugLine). This is documented as
 * non-enforcing on purpose: we cannot terminate a process on a guard failure without a kernel mitigation policy, and a
 * silent no-op check would hide bugs.
 *
 * References (public): learn.microsoft.com "Control Flow Guard"; the /guard:cf image layout (GuardCFFunctionTable of
 * 4-byte RVAs plus GuardFlags's per-entry metadata stride) documented under IMAGE_LOAD_CONFIG_DIRECTORY /
 * IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK. Kernel64's loader points the image's guard pointers at ShzGuardCheckICall /
 * ShzGuardDispatchICall (kernel64/ldr.c, apply_load_config).
 */
#include "nt.h"

#define IMAGE_GUARD_CF_INSTRUMENTED 0x00000100u
#define IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT 0x00000400u
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK 0xF0000000u
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT 28

volatile LONG ShzGuardViolationCount;
volatile LONG ShzGuardCheckCount;

/* Fixed byte offsets into IMAGE_LOAD_CONFIG_DIRECTORY64 for the CFG fields (the mingw header stops at SEHandlerCount,
 * so they are read by offset; values from winnt.h of the Windows SDK). */
#define LC_GUARD_CF_FUNCTION_TABLE 0x80
#define LC_GUARD_CF_FUNCTION_COUNT 0x88
#define LC_GUARD_FLAGS 0x90

/* Load configuration of the image that maps `addr`, or 0. Walks the loader list (no allocation, safe in the guard). */
static const uint8_t *load_config_of(const void *addr, DWORD64 *image_base, DWORD *cfg_size)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList, *l;
    for (l = head->Flink; l != head; l = l->Flink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InLoadOrderLinks);
        const uint8_t *base = e->DllBase;
        const IMAGE_DOS_HEADER *dos;
        const IMAGE_NT_HEADERS64 *nt;
        const IMAGE_DATA_DIRECTORY *d;
        const uint8_t *lc;
        if ((const uint8_t *)addr < base || (const uint8_t *)addr >= base + e->SizeOfImage) continue;
        dos = (const IMAGE_DOS_HEADER *)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        nt = (const IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
        d = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (!d->VirtualAddress || d->Size < 0x94) return 0;
        lc = base + d->VirtualAddress;
        *image_base = (DWORD64)(uintptr_t)base;
        *cfg_size = *(const DWORD *)lc < d->Size ? *(const DWORD *)lc : d->Size;
        return lc;
    }
    return 0;
}

/* 1 if `target` is a call target the image declares valid (a GuardCFFunctionTable RVA), or the image is not
 * CFG-instrumented / has no table (then every target is accepted, as CFG does for non-instrumented callees). */
static int target_is_valid(DWORD64 target)
{
    DWORD64 base = 0;
    DWORD size = 0;
    const uint8_t *lc = load_config_of((const void *)(uintptr_t)target, &base, &size);
    DWORD flags, stride;
    DWORD64 count, table, rva;
    long lo, hi;
    if (!lc) return 1;                                                  /* target outside any known image, or no cfg */
    if (LC_GUARD_FLAGS + 4 > size) return 1;
    flags = *(const DWORD *)(lc + LC_GUARD_FLAGS);
    if (!(flags & IMAGE_GUARD_CF_INSTRUMENTED) || !(flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT)) return 1;
    table = *(const DWORD64 *)(lc + LC_GUARD_CF_FUNCTION_TABLE);
    count = *(const DWORD64 *)(lc + LC_GUARD_CF_FUNCTION_COUNT);
    if (!table || !count) return 1;
    stride = 4 + ((flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT);
    rva = target - base;
    /* the table is sorted by RVA; each entry begins with a 4-byte RVA followed by `stride - 4` metadata bytes */
    lo = 0; hi = (long)count - 1;
    while (lo <= hi) {
        const long mid = lo + (hi - lo) / 2;
        const DWORD entry = *(const DWORD *)(uintptr_t)(base + (table - base) + (DWORD64)mid * stride);
        if ((DWORD)rva < entry) hi = mid - 1;
        else if ((DWORD)rva > entry) lo = mid + 1;
        else return 1;
    }
    return 0;
}

/* The guard check: fast path when the target is valid; otherwise count it and report once. Never blocks the call. */
static void guard_check(DWORD64 target)
{
    __sync_add_and_fetch(&ShzGuardCheckCount, 1);
    if (target && !target_is_valid(target)) {
        if (__sync_add_and_fetch(&ShzGuardViolationCount, 1) <= 16)
            ShzDebugLine("ntdll CFG: indirect call target not in the image's guard table (non-enforcing)\n");
    }
}

/* __guard_check_icall_fptr contract: RCX = target, preserves all volatile registers except RAX/R10/R11, returns.
 * The C function follows the Microsoft x64 ABI (it may clobber the volatiles), so the exported symbol is a small
 * assembly trampoline that saves the argument-passing registers around the call. ShzGuardDispatchICall additionally
 * transfers control to the target (RAX) after the check (the /guard:cf dispatch form). */
void ShzGuardCheckICallC(DWORD64 target) { guard_check(target); }

__asm__(
    ".text\n"
    ".globl ShzGuardCheckICall\n"
    ".def ShzGuardCheckICall; .scl 2; .type 32; .endef\n"
    "ShzGuardCheckICall:\n"                 /* RCX = target; preserve RCX RDX R8 R9 and the FP arg regs */
    "    subq $0x68, %rsp\n"
    "    movq %rcx, 0x20(%rsp)\n"
    "    movq %rdx, 0x28(%rsp)\n"
    "    movq %r8,  0x30(%rsp)\n"
    "    movq %r9,  0x38(%rsp)\n"
    "    movups %xmm0, 0x40(%rsp)\n"
    "    movups %xmm1, 0x50(%rsp)\n"
    "    call ShzGuardCheckICallC\n"        /* RCX already = target */
    "    movq 0x20(%rsp), %rcx\n"
    "    movq 0x28(%rsp), %rdx\n"
    "    movq 0x30(%rsp), %r8\n"
    "    movq 0x38(%rsp), %r9\n"
    "    movups 0x40(%rsp), %xmm0\n"
    "    movups 0x50(%rsp), %xmm1\n"
    "    addq $0x68, %rsp\n"
    "    ret\n"
    ".globl ShzGuardDispatchICall\n"
    ".def ShzGuardDispatchICall; .scl 2; .type 32; .endef\n"
    "ShzGuardDispatchICall:\n"              /* RAX = target; check it, then jump */
    "    subq $0x68, %rsp\n"
    "    movq %rcx, 0x20(%rsp)\n"
    "    movq %rdx, 0x28(%rsp)\n"
    "    movq %r8,  0x30(%rsp)\n"
    "    movq %r9,  0x38(%rsp)\n"
    "    movq %rax, 0x18(%rsp)\n"
    "    movups %xmm0, 0x40(%rsp)\n"
    "    movups %xmm1, 0x50(%rsp)\n"
    "    movq %rax, %rcx\n"
    "    call ShzGuardCheckICallC\n"
    "    movq 0x20(%rsp), %rcx\n"
    "    movq 0x28(%rsp), %rdx\n"
    "    movq 0x30(%rsp), %r8\n"
    "    movq 0x38(%rsp), %r9\n"
    "    movups 0x40(%rsp), %xmm0\n"
    "    movups 0x50(%rsp), %xmm1\n"
    "    movq 0x18(%rsp), %rax\n"
    "    addq $0x68, %rsp\n"
    "    jmp *%rax\n");

/* Declarations of the two exported trampolines (so the export scanner lists them; the bodies are the asm above). */
SHZ_EXPORT void NTAPI ShzGuardCheckICall(void);
SHZ_EXPORT void NTAPI ShzGuardDispatchICall(void);
