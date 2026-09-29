/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: setjmp/longjmp for x86_64 (Microsoft ABI, _JUMP_BUFFER layout of <setjmp.h>).
 * longjmp restores the non-volatile registers directly; it does not run SEH unwind handlers (no C++ in these modules).
 *   0 Frame  8 Rbx  16 Rsp  24 Rbp  32 Rsi  40 Rdi  48 R12  56 R13  64 R14  72 R15  80 Rip  88 MxCsr  92 FpCsr
 *   96.. Xmm6..Xmm15 (16 bytes each)
 */
    .text
    .globl __intrinsic_setjmpex
    .globl _setjmpex
    .globl _setjmp
    .globl __intrinsic_setjmp
    .def __intrinsic_setjmpex; .scl 2; .type 32; .endef
    .def _setjmpex; .scl 2; .type 32; .endef
    .def _setjmp; .scl 2; .type 32; .endef
    .def __intrinsic_setjmp; .scl 2; .type 32; .endef
__intrinsic_setjmpex:
_setjmpex:
_setjmp:
__intrinsic_setjmp:
    movq %rdx, 0(%rcx)
    movq %rbx, 8(%rcx)
    leaq 8(%rsp), %rax
    movq %rax, 16(%rcx)
    movq %rbp, 24(%rcx)
    movq %rsi, 32(%rcx)
    movq %rdi, 40(%rcx)
    movq %r12, 48(%rcx)
    movq %r13, 56(%rcx)
    movq %r14, 64(%rcx)
    movq %r15, 72(%rcx)
    movq (%rsp), %rax
    movq %rax, 80(%rcx)
    stmxcsr 88(%rcx)
    fnstcw 92(%rcx)
    movdqu %xmm6, 96(%rcx)
    movdqu %xmm7, 112(%rcx)
    movdqu %xmm8, 128(%rcx)
    movdqu %xmm9, 144(%rcx)
    movdqu %xmm10, 160(%rcx)
    movdqu %xmm11, 176(%rcx)
    movdqu %xmm12, 192(%rcx)
    movdqu %xmm13, 208(%rcx)
    movdqu %xmm14, 224(%rcx)
    movdqu %xmm15, 240(%rcx)
    xorl %eax, %eax
    ret

    .globl longjmp
    .def longjmp; .scl 2; .type 32; .endef
longjmp:
    movl %edx, %eax
    testl %eax, %eax
    jnz 1f
    movl $1, %eax
1:
    movq 8(%rcx), %rbx
    movq 24(%rcx), %rbp
    movq 32(%rcx), %rsi
    movq 40(%rcx), %rdi
    movq 48(%rcx), %r12
    movq 56(%rcx), %r13
    movq 64(%rcx), %r14
    movq 72(%rcx), %r15
    ldmxcsr 88(%rcx)
    fnclex
    fldcw 92(%rcx)
    movdqu 96(%rcx), %xmm6
    movdqu 112(%rcx), %xmm7
    movdqu 128(%rcx), %xmm8
    movdqu 144(%rcx), %xmm9
    movdqu 160(%rcx), %xmm10
    movdqu 176(%rcx), %xmm11
    movdqu 192(%rcx), %xmm12
    movdqu 208(%rcx), %xmm13
    movdqu 224(%rcx), %xmm14
    movdqu 240(%rcx), %xmm15
    movq 16(%rcx), %rsp
    jmpq *80(%rcx)
