/* SPDX-License-Identifier: GPL-2.0-only
 * __CxxFrameHandler4 (vcruntime140_1.dll) on handcrafted tables. No available compiler emits Microsoft's compressed FH4
 * exception tables (clang only produces FH3), so this test writes a function in assembly whose unwind information names
 * __CxxFrameHandler4 and whose FuncInfo4, unwind map, try map, handler arrays and ip-to-state map are encoded by hand
 * (compressed integers of one and two bytes, RVAs, a continuation address by RVA and one returned by the funclet).
 * A C++ exception thrown from inside the function (through _CxxThrowException, as compiled code does) is dispatched by
 * the system to the FH4 handler, which must pick the right catch, run the destructor actions of both kinds
 * (object in the frame, pointer in the frame) down to the try's entry, bind the catch object and resume at the
 * continuation. The encoding follows the documented FH4 layout as read by this runtime (see CRT.md): these checks prove
 * the handler's decoding and unwinding against that reading, not against an MSVC-compiled binary.
 * Also: the NoExcept bit of FH4 and the FI_EHNOEXCEPT flag of FH3 terminate the process (in child processes).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "u_check.h"

extern IMAGE_DOS_HEADER __ImageBase;
#define RVA(p) ((int32_t)((uintptr_t)(p) - (uintptr_t)&__ImageBase))

__declspec(dllimport) void _CxxThrowException(void *obj, const void *throwinfo);

struct fh4_results { int a_dtors, b_dtors, inner_cont, outer_cont, caught_all, pad; double caught_double; };
struct fh4_results g_fh4;
uint64_t g_fh4_b = 0xB;

void fh4_func(int mode);
void fh4_nx_func(void);
void fh3_nx_func(void);
void fh4_a_dtor(uint64_t *obj) { ++g_fh4.a_dtors; *obj = 0; }
void fh4_b_dtor(uint64_t *obj) { g_fh4.b_dtors += *obj == 0xB; }

/* ---- throw information for int and double (catchable types of simple types) */
typedef struct { const void *vftable; void *spare; char name[8]; } td8;
typedef struct { uint32_t properties; int32_t type, mdisp, pdisp, vdisp, size, copy; } catchable;
typedef struct { int32_t count, types[1]; } catchables;
typedef struct { uint32_t attributes; int32_t destructor, forward, catchables; } throwinfo;
static td8 td_int = { 0, 0, ".H" }, td_double = { 0, 0, ".N" };
static catchable ct_int, ct_double;
static catchables cta_int, cta_double;
static throwinfo ti_int, ti_double;
static void throw_init(void)
{
    ct_int.properties = ct_double.properties = 1;                 /* CT_IsSimpleType */
    ct_int.type = RVA(&td_int); ct_int.pdisp = -1; ct_int.size = 4;
    ct_double.type = RVA(&td_double); ct_double.pdisp = -1; ct_double.size = 8;
    cta_int.count = cta_double.count = 1;
    cta_int.types[0] = RVA(&ct_int);
    cta_double.types[0] = RVA(&ct_double);
    ti_int.catchables = RVA(&cta_int);
    ti_double.catchables = RVA(&cta_double);
}
__declspec(noinline) void fh4_raise(int mode)
{
    if (mode == 1) { int v = 7; _CxxThrowException(&v, &ti_int); }
    else { double d = 2.5; _CxxThrowException(&d, &ti_double); }
}

/* fh4_func(mode). Frame (establisher = RSP after the prologue): A object at +32, pointer to B at +40, catch object at +136.
 * States: -1; 0 outer try; 1 A alive; 2 inner try; 3 B alive; 4 inner catch; 5 outer catch.
 * try (outer) { A a; try (inner) { B b; fh4_raise(mode); } catch (double &d) { ... } ~A } catch (...) { ... } */
__asm__(
    ".text\n"
    ".globl fh4_func\n"
    ".def fh4_func; .scl 2; .type 32; .endef\n"
    ".seh_proc fh4_func\n"
    "fh4_func:\n"
    "    .seh_handler __CxxFrameHandler4, @unwind, @except\n"
    "    pushq %rbp\n"
    "    .seh_pushreg %rbp\n"
    "    subq $144, %rsp\n"
    "    .seh_stackalloc 144\n"
    "    .seh_endprologue\n"
    "    movl %ecx, 48(%rsp)\n"
    "    movq $0, 136(%rsp)\n"
    "fh4_L_s0:\n"
    "    movq $0xA, 32(%rsp)\n"
    "fh4_L_s1:\n"
    "    nop\n"
    "fh4_L_s2:\n"
    "    .fill 130, 1, 0x90\n"
    "    leaq g_fh4_b(%rip), %rax\n"
    "    movq %rax, 40(%rsp)\n"
    "fh4_L_s3:\n"
    "    movl 48(%rsp), %ecx\n"
    "    callq fh4_raise\n"
    "fh4_L_ret:\n"
    "    nop\n"
    "fh4_L_cont_inner:\n"
    "    incl g_fh4+8(%rip)\n"
    "    leaq 32(%rsp), %rcx\n"
    "    callq fh4_a_dtor\n"
    "fh4_L_a_gone:\n"
    "    jmp fh4_L_end\n"
    "fh4_L_cont_outer:\n"
    "    incl g_fh4+12(%rip)\n"
    "fh4_L_end:\n"
    "    addq $144, %rsp\n"
    "    popq %rbp\n"
    "    ret\n"
    "    .seh_handlerdata\n"
    "    .rva fh4_info\n"
    "    .text\n"
    ".seh_endproc\n"
    /* catch (double &d): binds d, returns continuation index 0 */
    ".def fh4_catch_double; .scl 3; .type 32; .endef\n"
    ".seh_proc fh4_catch_double\n"
    "fh4_catch_double:\n"
    "    movq %rdx, 16(%rsp)\n"
    "    pushq %rbp\n"
    "    .seh_pushreg %rbp\n"
    "    subq $32, %rsp\n"
    "    .seh_stackalloc 32\n"
    "    .seh_endprologue\n"
    "    movq 136(%rdx), %rax\n"
    "    movsd (%rax), %xmm0\n"
    "    movsd %xmm0, g_fh4+24(%rip)\n"
    "    xorl %eax, %eax\n"
    "    addq $32, %rsp\n"
    "    popq %rbp\n"
    "    ret\n"
    ".seh_endproc\n"
    /* catch (...): returns the continuation address itself */
    ".def fh4_catch_all; .scl 3; .type 32; .endef\n"
    ".seh_proc fh4_catch_all\n"
    "fh4_catch_all:\n"
    "    movq %rdx, 16(%rsp)\n"
    "    pushq %rbp\n"
    "    .seh_pushreg %rbp\n"
    "    subq $32, %rsp\n"
    "    .seh_stackalloc 32\n"
    "    .seh_endprologue\n"
    "    incl g_fh4+16(%rip)\n"
    "    leaq fh4_L_cont_outer(%rip), %rax\n"
    "    addq $32, %rsp\n"
    "    popq %rbp\n"
    "    ret\n"
    ".seh_endproc\n"
    /* noexcept functions without handlers: FH4 NoExcept bit, FH3 EHFlags FI_EHNOEXCEPT */
    ".globl fh4_nx_func\n"
    ".def fh4_nx_func; .scl 2; .type 32; .endef\n"
    ".seh_proc fh4_nx_func\n"
    "fh4_nx_func:\n"
    "    .seh_handler __CxxFrameHandler4, @unwind, @except\n"
    "    subq $40, %rsp\n"
    "    .seh_stackalloc 40\n"
    "    .seh_endprologue\n"
    "    movl $1, %ecx\n"
    "    callq fh4_raise\n"
    "    nop\n"
    "    addq $40, %rsp\n"
    "    ret\n"
    "    .seh_handlerdata\n"
    "    .rva fh4_nx_info\n"
    "    .text\n"
    ".seh_endproc\n"
    ".globl fh3_nx_func\n"
    ".def fh3_nx_func; .scl 2; .type 32; .endef\n"
    ".seh_proc fh3_nx_func\n"
    "fh3_nx_func:\n"
    "    .seh_handler __CxxFrameHandler3, @unwind, @except\n"
    "    subq $40, %rsp\n"
    "    .seh_stackalloc 40\n"
    "    .seh_endprologue\n"
    "    movl $1, %ecx\n"
    "    callq fh4_raise\n"
    "    nop\n"
    "    addq $40, %rsp\n"
    "    ret\n"
    "    .seh_handlerdata\n"
    "    .rva fh3_nx_info\n"
    "    .text\n"
    ".seh_endproc\n"

    ".section .rdata,\"dr\"\n"
    ".p2align 3\n"
    "fh4_td_double:\n"
    "    .quad 0, 0\n"
    "    .asciz \".N\"\n"
    "fh4_info:\n"
    "    .byte 0x18\n"                        /* UnwindMap | TryBlockMap */
    "    .rva fh4_unwind\n"
    "    .rva fh4_trymap\n"
    "    .rva fh4_ipmap\n"
    "fh4_unwind:\n"
    "    .byte 0x0C\n"                        /* 6 entries */
    "    .byte 0x00\n"                        /* e0 @1: state 0, no action, parent -1 */
    "    .byte 0x0A\n"                        /* e1 @2: (1 << 2 | 1): parent e0, destructor of frame+32 */
    "    .rva fh4_a_dtor\n"
    "    .byte 0x40\n"
    "    .byte 0x30\n"                        /* e2 @8: (6 << 2 | 0): parent e1 */
    "    .byte 0x0C\n"                        /* e3 @9: (1 << 2 | 2): parent e2, destructor of *(frame+40) */
    "    .rva fh4_b_dtor\n"
    "    .byte 0x50\n"
    "    .byte 0x68\n"                        /* e4 @15: (13 << 2 | 0): parent e1 */
    "    .byte 0x00\n"                        /* e5 @16: parent -1 */
    "fh4_trymap:\n"
    "    .byte 0x04\n"                        /* 2 try blocks, innermost first */
    "    .byte 0x04, 0x06, 0x08\n"            /* inner: 2..3, catches up to 4 */
    "    .rva fh4_handlers_inner\n"
    "    .byte 0x00, 0x08, 0x0A\n"            /* outer: 0..4, catches up to 5 */
    "    .rva fh4_handlers_outer\n"
    "fh4_handlers_inner:\n"
    "    .byte 0x02\n"                        /* 1 handler */
    "    .byte 0x1F\n"                        /* adjectives, type, catch object, continuation RVA, 1 continuation */
    "    .byte 0x10\n"                        /* HT_IsReference */
    "    .rva fh4_td_double\n"
    "    .byte 0x21, 0x02\n"                  /* catch object at 136 (two-byte encoding) */
    "    .rva fh4_catch_double\n"
    "    .rva fh4_L_cont_inner\n"
    "fh4_handlers_outer:\n"
    "    .byte 0x02\n"
    "    .byte 0x00\n"                        /* catch (...) */
    "    .rva fh4_catch_all\n"
    "fh4_ipmap:\n"
    "    .byte 0x0E\n"                        /* 7 entries: ip delta, state + 1 */
    "    .byte 0x00, 0x00\n"
    "    .byte (fh4_L_s0 - fh4_func) << 1, 0x02\n"
    "    .byte (fh4_L_s1 - fh4_L_s0) << 1, 0x04\n"
    "    .byte (fh4_L_s2 - fh4_L_s1) << 1, 0x06\n"
    "    .byte ((((fh4_L_s3 - fh4_L_s2) << 2) | 1) & 0xff), (((fh4_L_s3 - fh4_L_s2) << 2) >> 8), 0x08\n"
    "    .byte (fh4_L_cont_inner - fh4_L_s3) << 1, 0x04\n"   /* return address of the call stays in state 3 */
    "    .byte (fh4_L_a_gone - fh4_L_cont_inner) << 1, 0x00\n"
    "fh4_nx_info:\n"
    "    .byte 0x40\n"                        /* NoExcept */
    "    .rva fh4_nx_ipmap\n"
    "fh4_nx_ipmap:\n"
    "    .byte 0x02, 0x00, 0x00\n"
    ".p2align 2\n"
    "fh3_nx_info:\n"
    "    .long 0x19930522, 0, 0, 0, 0, 0, 0, 0, 0, 4\n"   /* magic 3, no tables, EHFlags = FI_EHNOEXCEPT */
    ".text\n");

int main(void)
{
    const char *cl = GetCommandLineA(), *p;
    throw_init();
    for (p = cl; *p; ++p)
        if (p[0] == 'c' && p[1] == 'h' && p[2] == 'i' && p[3] == 'l' && p[4] == 'd' && p[5] == ':') {
            if (p[6] == '1') fh4_nx_func();
            if (p[6] == '2') fh3_nx_func();
            return 0;
        }

    U_CHECK("FH4: the frame's handler is __CxxFrameHandler4 from vcruntime140_1.dll", GetModuleHandleA("vcruntime140_1.dll") != 0);
    memset(&g_fh4, 0, sizeof g_fh4);
    fh4_func(2);
    U_CHECKF("FH4: catch (double &) of the inner try binds the thrown 2.5 and resumes at its RVA continuation (index 0)",
             g_fh4.inner_cont == 1 && g_fh4.outer_cont == 0 && g_fh4.caught_double == 2.5 && !g_fh4.caught_all,
             "inner=%d outer=%d all=%d", g_fh4.inner_cont, g_fh4.outer_cont, g_fh4.caught_all);
    U_CHECKF("FH4: unwinding to the inner try destroyed B (pointer-to-object action) and not A (destroyed later by the code)",
             g_fh4.b_dtors == 1 && g_fh4.a_dtors == 1, "a=%d b=%d", g_fh4.a_dtors, g_fh4.b_dtors);
    memset(&g_fh4, 0, sizeof g_fh4);
    fh4_func(1);
    U_CHECKF("FH4: an int skips catch (double &) and reaches the outer catch (...), resuming where its funclet says",
             g_fh4.outer_cont == 1 && g_fh4.caught_all == 1 && g_fh4.inner_cont == 0, "inner=%d outer=%d all=%d",
             g_fh4.inner_cont, g_fh4.outer_cont, g_fh4.caught_all);
    U_CHECKF("FH4: unwinding to the outer try destroyed B and A (object-in-frame action)", g_fh4.b_dtors == 1 && g_fh4.a_dtors == 1,
             "a=%d b=%d", g_fh4.a_dtors, g_fh4.b_dtors);
    {
        char path[300], cmd[400];
        int mode;
        for (mode = 1; mode <= 2; ++mode) {
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            DWORD code = 0xffffffffu, n = GetModuleFileNameA(0, path, sizeof path);
            memset(&si, 0, sizeof si);
            si.cb = sizeof si;
            cmd[0] = '"';
            memcpy(cmd + 1, path, n);
            memcpy(cmd + 1 + n, "\" child:1", 10);
            cmd[1 + n + 8] = (char)('0' + mode);
            if (n && n < sizeof path && CreateProcessA(path, cmd, 0, 0, FALSE, 0, 0, 0, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 60000);
                GetExitCodeProcess(pi.hProcess, &code);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            U_CHECKF(mode == 1 ? "FH4: an exception reaching a frame with the NoExcept bit calls std::terminate (exit code 3)"
                               : "FH3: an exception reaching a frame with FI_EHNOEXCEPT calls std::terminate (exit code 3)",
                     code == 3, "exit code %u", (unsigned)code);
        }
    }
    return u_finish("t_crt_fh4");
}
