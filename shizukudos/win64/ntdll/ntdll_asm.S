# SPDX-License-Identifier: GPL-2.0-only
# ntdll assembly helpers (AT&T syntax, Microsoft x64 ABI).

    .text
    .globl RtlCaptureContext
    .def RtlCaptureContext; .scl 2; .type 32; .endef
# void RtlCaptureContext(PCONTEXT ctx)   RCX = ctx
# Records the caller's non-volatile state: RSP/RIP describe the instruction after the call.
RtlCaptureContext:
    pushfq
    movq %rax, 0x78(%rcx)
    movq %rcx, 0x80(%rcx)
    movq %rdx, 0x88(%rcx)
    movq %rbx, 0x90(%rcx)
    leaq 16(%rsp), %rax            # RSP after the return
    movq %rax, 0x98(%rcx)
    movq %rbp, 0xa0(%rcx)
    movq %rsi, 0xa8(%rcx)
    movq %rdi, 0xb0(%rcx)
    movq %r8, 0xb8(%rcx)
    movq %r9, 0xc0(%rcx)
    movq %r10, 0xc8(%rcx)
    movq %r11, 0xd0(%rcx)
    movq %r12, 0xd8(%rcx)
    movq %r13, 0xe0(%rcx)
    movq %r14, 0xe8(%rcx)
    movq %r15, 0xf0(%rcx)
    movq 8(%rsp), %rax             # return address
    movq %rax, 0xf8(%rcx)
    movl (%rsp), %eax              # eflags
    movl %eax, 0x44(%rcx)
    movl $0x10001f, 0x30(%rcx)     # CONTEXT_ALL (control, integer, segments, floating point, debug flags reported)
    movw %cs, 0x38(%rcx)
    movw %ds, 0x3a(%rcx)
    movw %es, 0x3c(%rcx)
    movw %fs, 0x3e(%rcx)
    movw %gs, 0x40(%rcx)
    movw %ss, 0x42(%rcx)
    stmxcsr 0x34(%rcx)
    stmxcsr 0x118(%rcx)            # FltSave.MxCsr
    movups %xmm0, 0x1a0(%rcx)
    movups %xmm1, 0x1b0(%rcx)
    movups %xmm2, 0x1c0(%rcx)
    movups %xmm3, 0x1d0(%rcx)
    movups %xmm4, 0x1e0(%rcx)
    movups %xmm5, 0x1f0(%rcx)
    movups %xmm6, 0x200(%rcx)
    movups %xmm7, 0x210(%rcx)
    movups %xmm8, 0x220(%rcx)
    movups %xmm9, 0x230(%rcx)
    movups %xmm10, 0x240(%rcx)
    movups %xmm11, 0x250(%rcx)
    movups %xmm12, 0x260(%rcx)
    movups %xmm13, 0x270(%rcx)
    movups %xmm14, 0x280(%rcx)
    movups %xmm15, 0x290(%rcx)
    addq $8, %rsp
    ret
