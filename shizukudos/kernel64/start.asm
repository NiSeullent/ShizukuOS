; SPDX-License-Identifier: GPL-2.0-only
; Kernel64 entry, interrupt/exception stubs, SYSCALL entry, context switch, ring-3 entry.
; Entered by the Supervisor in 64-bit Long Mode at 0xFFFFFFFF80100000 with boot page
; tables, RDI = bootinfo (physical), interrupts off.
bits 64
default rel

section .text.entry
global _start
extern kmain
_start:
    cli
    cld
    lea rsp, [rel kstack_top]
    xor ebp, ebp
    call kmain
.halt:
    cli
    hlt
    jmp .halt

section .text
extern isr_dispatch
extern syscall_dispatch
extern g_kstack_top
extern g_user_rsp_scratch

%macro STUB_NOERR 1
stub_%1:
    push qword 0
    push qword %1
    jmp isr_common
%endmacro
%macro STUB_ERR 1
stub_%1:
    push qword %1
    jmp isr_common
%endmacro

%assign v 0
%rep 256
  %if v == 8 || (v >= 10 && v <= 14) || v == 17 || v == 21 || v == 29 || v == 30
    STUB_ERR v
  %else
    STUB_NOERR v
  %endif
  %assign v v+1
%endrep

; Frame layout must match struct regs in k64.h (r15 lowest ... rax, vector, error, iret frame).
isr_common:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    cld
    mov rdi, rsp
    call isr_dispatch
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    iretq

; SYSCALL entry. On entry: RCX = user RIP, R11 = user RFLAGS, RSP = user stack (untouched),
; interrupts masked by SFMASK. Windows-style convention: EAX = number, R10/RDX/R8/R9 = args.
; A full struct regs is built so the dispatcher, faults and thread switching share one layout.
global syscall_entry
syscall_entry:
    mov [rel g_user_rsp_scratch], rsp
    mov rsp, [rel g_kstack_top]
    push qword 0x1b                     ; ss (user data 0x18, RPL 3)
    push qword [rel g_user_rsp_scratch] ; rsp
    push r11                            ; rflags
    push qword 0x23                     ; cs (user code 0x20, RPL 3)
    push rcx                            ; rip
    push qword 0                        ; error
    push qword 0x100                    ; vector: syscall marker
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    cld
    mov rdi, rsp
    call syscall_dispatch
    test eax, eax
    jnz .iret_exit                      ; NtContinue: restore the whole context through IRETQ
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16                         ; vector, error
    pop rcx                             ; user rip (possibly modified by the dispatcher)
    add rsp, 8                          ; cs
    pop r11                             ; rflags
    pop rsp                             ; user rsp
    o64 sysret
.iret_exit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    iretq

; void switch_stacks(uint64_t *save_rsp, uint64_t new_rsp)
global switch_stacks
extern sched_switch_complete
switch_stacks:
    pushfq
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    ; RSP%16=0 after seven saved words: SysV CALL entry is aligned at8.
    ; Old stack is now saved/inactive. No scheduler ticket spans this handoff.
    call sched_switch_complete          ; before POPFQ can enable a pending timer
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    popfq
    ret

; void enter_user(uint64_t rip, uint64_t rsp, uint64_t arg, uint64_t arg2): iretq to ring 3
; with RCX = arg, RDX = arg2 (the first two Win64 arguments) and every other register cleared
; so no kernel state leaks.
global enter_user
enter_user:
    mov rax, rcx                        ; arg2 arrives in RCX (4th SysV argument)
    mov rcx, rdx                        ; arg (3rd SysV argument)
    mov rdx, rax
    push qword 0x1b                     ; ss
    push rsi                            ; rsp
    push qword 0x202                    ; rflags: IF
    push qword 0x23                     ; cs
    push rdi                            ; rip
    xor eax, eax
    xor ebx, ebx
    xor esi, esi
    xor edi, edi
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    iretq

; New kernel threads start here: r12 = entry, r13 = argument (set by thread_create).
global thread_start
extern thread_exit
thread_start:
    sti
    mov rdi, r13
    call r12
    xor edi, edi
    call thread_exit

global load_gdt
; void load_gdt(void *gdtr, uint16_t tss_sel)
load_gdt:
    lgdt [rdi]
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    push qword 0x08
    lea rax, [rel .reload]
    push rax
    o64 retf
.reload:
    ltr si
    ret

global load_idt
load_idt:
    lidt [rdi]
    ret

section .rodata
align 8
global isr_stub_table
isr_stub_table:
%assign v 0
%rep 256
    dq stub_ %+ v
    %assign v v+1
%endrep

global user_ok_start, user_ok_end, user_fault_start, user_fault_end, user_wild_start, user_wild_end
global user_high_start, user_high_end
user_ok_start:    incbin "user_ok.bin"
user_ok_end:
user_fault_start: incbin "user_fault.bin"
user_fault_end:
user_wild_start:  incbin "user_wild.bin"
user_wild_end:
user_high_start:  incbin "user_high.bin"
user_high_end:

section .bss
align 4096
kstack: resb 32768
global kstack_top
kstack_top:
