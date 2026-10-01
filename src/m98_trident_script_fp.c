/* SPDX-License-Identifier: GPL-2.0-only
 * Called only while the interpreter's single global entry guard is owned.
 * FNSAVE/FRSTOR are original i486 x87 instructions. Preserve the full caller
 * environment/register stack, including pending exception flags; returning
 * only its control word would leak new pending exceptions to the caller. */
#if !defined(__i386__) && !defined(__x86_64__)
#error This interpreter profile requires x87
#endif
static unsigned char caller_x87[108] __attribute__((aligned(16)));
void m98_script_fp_save(void *state){
    const unsigned short configured=0x037f; /* PC64, nearest, all six masks. */
    __asm__ volatile("fnsave %0\n\tfldcw %1":"=m"(*(unsigned char (*)[108])state):"m"(configured):"memory");
}
void m98_script_fp_restore(const void *state){
    __asm__ volatile("frstor %0"::"m"(*(const unsigned char (*)[108])state):"memory");
}
void m98_script_fp_enter(void){m98_script_fp_save(caller_x87);}
void m98_script_fp_leave(void){m98_script_fp_restore(caller_x87);}
