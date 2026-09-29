/* SPDX-License-Identifier: GPL-2.0-only
 * i386 Linux entry and raw syscalls for the freestanding PE loader.
 */
.intel_syntax noprefix
.section .text
.global _start
.global ntw_open
.global ntw_read
.global ntw_write
.global ntw_close
.global ntw_lseek
.global ntw_mmap2

_start:
    mov eax, [esp]
    lea ebx, [esp+4]
    push ebx
    push eax
    call ntw_loader_main
    add esp, 8
    mov ebx, eax
    mov eax, 1
    int 0x80

ntw_open:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 5
    int 0x80
    pop ebx
    ret

ntw_read:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 3
    int 0x80
    pop ebx
    ret

ntw_write:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 4
    int 0x80
    pop ebx
    ret

ntw_close:
    push ebx
    mov ebx, [esp+8]
    mov eax, 6
    int 0x80
    pop ebx
    ret

ntw_lseek:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 19
    int 0x80
    pop ebx
    ret

/* void *ntw_mmap2(void *addr, unsigned len, int prot, int flags, int fd, unsigned pgoff) */
ntw_mmap2:
    push ebx
    push esi
    push edi
    push ebp
    mov ebx, [esp+20]
    mov ecx, [esp+24]
    mov edx, [esp+28]
    mov esi, [esp+32]
    mov edi, [esp+36]
    mov ebp, [esp+40]
    mov eax, 192
    int 0x80
    pop ebp
    pop edi
    pop esi
    pop ebx
    ret

.global ntw_munmap
ntw_munmap:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov eax, 91
    int 0x80
    pop ebx
    ret

.global ntw_set_thread_area
.global ntw_load_fs
ntw_set_thread_area:
    push ebx
    mov ebx, [esp+8]
    mov eax, 243
    int 0x80
    pop ebx
    ret

ntw_load_fs:
    mov eax, [esp+4]
    mov fs, ax
    ret

.global ntw_mprotect
ntw_mprotect:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 125
    int 0x80
    pop ebx
    ret

.global ntw_syscall0
ntw_syscall0:
    mov eax, [esp+4]
    int 0x80
    ret

.global ntw_clock_gettime
ntw_clock_gettime:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov eax, 265
    int 0x80
    pop ebx
    ret

.global ntw_llseek
ntw_llseek:
    push ebx
    push esi
    push edi
    mov ebx, [esp+16]
    mov ecx, [esp+20]
    mov edx, [esp+24]
    mov esi, [esp+28]
    mov edi, [esp+32]
    mov eax, 140
    int 0x80
    pop edi
    pop esi
    pop ebx
    ret

.global ntw_unlink
ntw_unlink:
    push ebx
    mov ebx, [esp+8]
    mov eax, 10
    int 0x80
    pop ebx
    ret

.global ntw_getdents64
ntw_getdents64:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 220
    int 0x80
    pop ebx
    ret

.global ntw_getrandom
ntw_getrandom:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 355
    int 0x80
    pop ebx
    ret

.global ntw_nanosleep
ntw_nanosleep:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov eax, 162
    int 0x80
    pop ebx
    ret

.global ntw_sigaltstack
ntw_sigaltstack:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov eax, 186
    int 0x80
    pop ebx
    ret

.global ntw_rt_sigaction
/* int ntw_rt_sigaction(int sig, const void *act, void *old, unsigned mask_bytes) */
ntw_rt_sigaction:
    push ebx
    push esi
    mov ebx, [esp+12]
    mov ecx, [esp+16]
    mov edx, [esp+20]
    mov esi, [esp+24]
    mov eax, 174
    int 0x80
    pop esi
    pop ebx
    ret

.global ntw_sigreturn
ntw_sigreturn:
    mov eax, 173
    int 0x80

.global ntw_exit_group
ntw_exit_group:
    mov ebx, [esp+4]
    mov eax, 252
    int 0x80

.global ntw_exit
ntw_exit:
    mov ebx, [esp+4]
    mov eax, 1
    int 0x80

.global ntw_chdir
ntw_chdir:
    push ebx
    mov ebx, [esp+8]
    mov eax, 12
    int 0x80
    pop ebx
    ret

.global ntw_getcwd
ntw_getcwd:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov eax, 183
    int 0x80
    pop ebx
    ret

.global ntw_resume
ntw_resume:
    mov eax, [esp+16]
    mov ebp, [esp+12]
    mov ecx, [esp+4]
    mov esp, [esp+8]
    jmp ecx

.global ntw_fiber_switch
ntw_fiber_switch:
    mov eax, [esp+4]
    mov ecx, [esp+8]
    mov [eax+24], esp
    mov [eax+28], ebp
    mov edx, fs:[0]
    mov [eax+32], edx
    mov [eax+36], ebx
    mov [eax+40], esi
    mov [eax+44], edi
    mov edx, [ecx+32]
    mov fs:[0], edx
    mov ebx, [ecx+36]
    mov esi, [ecx+40]
    mov edi, [ecx+44]
    mov esp, [ecx+24]
    mov ebp, [ecx+28]
    ret

.global ntw_fiber_bootstrap
ntw_fiber_bootstrap:
    mov eax, [esp]
    mov ecx, [esp+4]
    push ecx
    call eax
    xor ebx, ebx
    mov eax, 1
    int 0x80

.global ntw_fork
ntw_fork:
    mov eax, 2
    int 0x80
    ret

.global ntw_execve
ntw_execve:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 11
    int 0x80
    pop ebx
    ret

.global ntw_waitpid
ntw_waitpid:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 7
    int 0x80
    pop ebx
    ret

.global ntw_dup2
ntw_dup2:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov eax, 63
    int 0x80
    pop ebx
    ret

.global ntw_getpid
ntw_getpid:
    mov eax, 20
    int 0x80
    ret

.global ntw_kill
ntw_kill:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov eax, 37
    int 0x80
    pop ebx
    ret

.global ntw_mkdir
ntw_mkdir:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov eax, 39
    int 0x80
    pop ebx
    ret

.global ntw_socketcall
ntw_socketcall:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov eax, 102
    int 0x80
    pop ebx
    ret

.global ntw_clone
/* int ntw_clone(unsigned flags, void *stack, void *parent_tid, void *tls, void *child_tid)
 * The child stack starts with a function pointer and an argument. The child
 * calls that function and then exits only its own thread.
 */
ntw_clone:
    push ebx
    push esi
    push edi
    mov ebx, [esp+16]
    mov ecx, [esp+20]
    mov edx, [esp+24]
    mov esi, [esp+28]
    mov edi, [esp+32]
    mov eax, 120
    int 0x80
    test eax, eax
    jnz 1f
    pop eax
    pop edx
    push edx
    call eax
    mov ebx, eax
    mov eax, 1
    int 0x80
1:
    pop edi
    pop esi
    pop ebx
    ret

.global ntw_ftruncate64
/* int ntw_ftruncate64(int fd, uint32_t pad, uint32_t lo, uint32_t hi) — syscall 194 */
ntw_ftruncate64:
    push ebx
    push esi
    mov ebx, [esp+12]
    mov ecx, [esp+16]
    mov edx, [esp+20]
    mov esi, [esp+24]
    mov eax, 194
    int 0x80
    pop esi
    pop ebx
    ret

.global ntw_fcntl
/* int ntw_fcntl(int fd, int cmd, void *arg) — syscall 55 */
ntw_fcntl:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 55
    int 0x80
    pop ebx
    ret

.global ntw_fstat64
/* int ntw_fstat64(int fd, void *stat64) — i386 stat64, syscall 197 */
ntw_fstat64:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov eax, 197
    int 0x80
    pop ebx
    ret

.global ntw_times
ntw_times:
    push ebx
    mov ebx, [esp+8]
    mov eax, 43
    int 0x80
    pop ebx
    ret

.global ntw_readlink
ntw_readlink:
    push ebx
    mov ebx, [esp+8]
    mov ecx, [esp+12]
    mov edx, [esp+16]
    mov eax, 85
    int 0x80
    pop ebx
    ret

.section .note.GNU-stack,"",@progbits
