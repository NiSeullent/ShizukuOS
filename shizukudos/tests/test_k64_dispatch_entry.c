/* SPDX-License-Identifier: GPL-2.0-only
 * Execute actual ASM classification, never privileged entry instructions.
 */
#include <stdint.h>
#include <stdio.h>
extern int arch_entry_needs_gs_restore(uint64_t,uint64_t) __attribute__((weak));
extern char syscall_gs_window_start[] __attribute__((weak));
extern char syscall_gs_window_end[] __attribute__((weak));
void kmain(void) { }
void isr_dispatch(void *r) { (void)r; }
void syscall_dispatch(void *r) { (void)r; }
void sched_switch_complete(void) { }
void thread_exit(void) { }
uint64_t g_kstack_top,g_user_rsp_scratch;
static unsigned checks,failures;
static void check(const char *n,int okay) { ++checks;failures+=!okay;printf("%s: %s\n",okay?"PASS":"FAIL",n); }
int main(void)
{
    check("actual ASM window classifier and boundaries exist",arch_entry_needs_gs_restore && syscall_gs_window_start && syscall_gs_window_end);
    if(arch_entry_needs_gs_restore && syscall_gs_window_start && syscall_gs_window_end) {
        volatile uint64_t first=(uintptr_t)syscall_gs_window_start,end=(uintptr_t)syscall_gs_window_end;
        check("post-first-SWAPGS begins normalization range",arch_entry_needs_gs_restore(first,8)==1);
        check("last-SWAPGS instruction is inside normalization range",arch_entry_needs_gs_restore(end-3,8)==1);
        check("next instruction after last SWAPGS is ordinary GS",arch_entry_needs_gs_restore(end,8)==0);
        check("instruction before first completed SWAPGS is ordinary GS",arch_entry_needs_gs_restore(first-1,8)==0);
        check("CPL3 never supplies a trusted entry-window frame",arch_entry_needs_gs_restore(first,0x23)==0);
        check("unrelated CPL0 RIP never toggles GS",arch_entry_needs_gs_restore((uintptr_t)main,8)==0);
        check("nested classification has no persistent shared flag",arch_entry_needs_gs_restore(first,8)==1 && arch_entry_needs_gs_restore(end,8)==0 && arch_entry_needs_gs_restore(first,8)==1);
    }
    printf("checks=%u failures=%u scope=actual_ASM_classification_only\n",checks,failures);return failures?1:0;
}
