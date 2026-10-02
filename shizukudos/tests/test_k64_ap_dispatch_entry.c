/* SPDX-License-Identifier: GPL-2.0-only
 * Execute only actual AP stack transfer assembly; hardware IF/GS/IRQ are not executed. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void sched_ap_stack_enter(uint64_t *,uint64_t,unsigned) __attribute__((weak));
static unsigned checks,failures,phase;
static uint8_t idle_stack[8192] __attribute__((aligned(16)));
static uint64_t saved;
static void check(const char *name,int okay) { ++checks;failures+=!okay;printf("%s: %s\n",okay?"PASS":"FAIL",name); }
void test_idle_boundary(unsigned cpu,uint64_t sp)
{
    check("actual idle destination is active before publication callback",cpu==3 && sp>=(uintptr_t)idle_stack && sp<(uintptr_t)idle_stack+sizeof idle_stack && saved);
    check("idle destination CALL uses SysV alignment",(sp&15)==8);phase=1;
}
void test_bootstrap_boundary(unsigned cpu,uint64_t sp)
{
    check("bootstrap destination is active before withdrawal callback",cpu==3 && phase==1 && (sp<(uintptr_t)idle_stack || sp>=(uintptr_t)idle_stack+sizeof idle_stack));
    check("bootstrap destination CALL uses SysV alignment",(sp&15)==8);phase=2;
}
void __attribute__((naked)) sched_ap_stack_main(unsigned cpu __attribute__((unused)))
{
    __asm__ volatile("mov %rsp,%rsi; sub $8,%rsp; call test_idle_boundary; add $8,%rsp; ret");
}
void __attribute__((naked)) sched_ap_stack_leave_complete(unsigned cpu __attribute__((unused)))
{
    __asm__ volatile("mov %rsp,%rsi; sub $8,%rsp; call test_bootstrap_boundary; add $8,%rsp; ret");
}
void kmain(void){} void isr_dispatch(void *r){(void)r;} void syscall_dispatch(void *r){(void)r;}
void sched_switch_complete(void){} void thread_exit(void){}
int main(void)
{
    volatile uintptr_t entry=(uintptr_t)sched_ap_stack_enter;
    check("actual AP stack transfer entry exists",entry!=0);
    if(entry) {
        register uint64_t r12 __asm__("r12")=0x123456789abcdef0ull,r13 __asm__("r13")=0x3456789abcdef012ull;
        register uint64_t r14 __asm__("r14")=0x56789abcdef01234ull,r15 __asm__("r15")=0x789abcdef0123456ull;
        __asm__ volatile("":"+r"(r12),"+r"(r13),"+r"(r14),"+r"(r15));
        ((void (*)(uint64_t *,uint64_t,unsigned))entry)(&saved,(uintptr_t)idle_stack+sizeof idle_stack,3);
        __asm__ volatile("":"+r"(r12),"+r"(r13),"+r"(r14),"+r"(r15));
        check("actual transfer preserves callee-saved context",r12==0x123456789abcdef0ull && r13==0x3456789abcdef012ull && r14==0x56789abcdef01234ull && r15==0x789abcdef0123456ull);
        check("both destination boundaries complete in order",phase==2);
    }
    printf("checks=%u failures=%u scope=actual_ASM_host_stack_transfer_no_privileged_entry\n",checks,failures);return failures?1:0;
}
