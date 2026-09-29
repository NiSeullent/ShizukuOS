/* SPDX-License-Identifier: GPL-2.0-only
 * Entry and call gates of the WIN64 subsystem end-to-end harness (w64_harness.c).
 *
 * The harness runs on a static stack inside the ELF image (below 0x80000000): NTWRAP9X.VXD's bridge accepts
 * only Win32 private-arena buffers (0x00400000..0x7fffffff), and NTW32.DLL passes stack variables to
 * DeviceIoControl, exactly as a Win98 program's stack would be. */
.section .text.start,"ax",@progbits
.globl _start
.type _start,@function
_start:
    cld
    movl $w64_stack_top, %esp
    andl $-16, %esp
    call harness_main
    movl %eax, %ebx
    movl $1, %eax
    int $0x80
.size _start, .-_start

.text
/* cdecl abi_call(target, arguments, count, result): same contract as entry.S. Pushes real stdcall arguments,
 * captures EDX:EAX and whether the callee restored ESP. */
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

/* cdecl uint32_t exe_call(entry, int *exited): runs a PE32 entry point (no arguments). A program ends with
 * ExitProcess, whose mock calls exe_exit(code): that unwinds to here with *exited = 1 and returns the code.
 * An entry point that returns yields *exited = 0 and its EAX. */
.globl exe_call
.type exe_call,@function
exe_call:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl %ebp, exe_saved_ebp
    movl %esp, exe_saved_esp
    call *8(%ebp)
    movl 12(%ebp), %ecx
    movl $0, (%ecx)
.Lexe_done:
    movl exe_saved_esp, %esp
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    ret
.size exe_call, .-exe_call

/* cdecl noreturn exe_exit(code) */
.globl exe_exit
.type exe_exit,@function
exe_exit:
    movl 4(%esp), %eax
    movl exe_saved_ebp, %ebp
    movl 12(%ebp), %ecx
    movl $1, (%ecx)
    jmp .Lexe_done
.size exe_exit, .-exe_exit

.bss
.balign 4
exe_saved_esp: .skip 4
exe_saved_ebp: .skip 4
.balign 16
w64_stack: .skip 1048576
w64_stack_top:
.section .note.GNU-stack,"",@progbits
