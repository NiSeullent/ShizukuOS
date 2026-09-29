/* SPDX-License-Identifier: GPL-2.0-only */
.section .text.start,"ax",@progbits
.globl _start
.type _start,@function
_start:
    cld
    andl $-16, %esp
    call harness_main
    movl %eax, %ebx
    movl $1, %eax
    int $0x80
.size _start, .-_start

/* cdecl abi_call(target, arguments, count, result). Calls a real stdcall PE
 * export and checks that its return restored the pre-argument stack pointer.
 * Captures EDX:EAX before checking. Restores ESP even if the check fails. */
.text
.globl abi_call
.type abi_call,@function
abi_call:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl 8(%ebp), %edi
    movl 12(%ebp), %ebx
    movl 16(%ebp), %ecx
    movl %esp, %esi
    testl %ecx, %ecx
    jz .Lcall
.Lpush:
    pushl -4(%ebx,%ecx,4)
    decl %ecx
    jnz .Lpush
.Lcall:
    call *%edi
    movl 20(%ebp), %ecx
    movl %eax, 0(%ecx)
    movl %edx, 4(%ecx)
    xorl %eax, %eax
    cmpl %esi, %esp
    sete %al
    movl %eax, 8(%ecx)
    movl %esi, %esp
    popl %edi
    popl %esi
    popl %ebx
    leave
    ret
.size abi_call, .-abi_call
.section .note.GNU-stack,"",@progbits
