/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the production hypercall dispatcher and interrupt-delivery body.
 * VMCS, interrupt injection, device polling and time are modeled here; no
 * guest code, Windows VMM or VMX instructions execute.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../src/cpu.h"
#include "../../src/domain.h"
#include "../../src/devices.h"

static unsigned checks, advance_calls, injected;
static uint64_t rip = 0x1234;
static int interruptible = 1;
static uint8_t injected_vector;
static const uint64_t now = 1000000;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(2); } } while (0)

static uint64_t host_vmread(uint64_t field)
{
    CHECK(field == VMCS_GUEST_RIP || field == VMCS_EXIT_INSTR_LEN);
    return field == VMCS_GUEST_RIP ? rip : 3;
}
static int host_vmwrite(uint64_t field, uint64_t value)
{
    CHECK(field == VMCS_GUEST_RIP && value == rip + 3);
    rip = value;
    ++advance_calls;
    return 0;
}
static uint64_t host_rdtsc(void) { return now; }
#define vmread host_vmread
#define vmwrite host_vmwrite
#define rdtsc host_rdtsc
#include "../../src/domain.c"
#undef vmread
#undef vmwrite
#undef rdtsc

void kprintf(const char *format, ...) { (void)format; }
uint8_t dev_cmos_read(uint8_t reg) { (void)reg; return 0; }
void dev_poll(uint64_t tsc) { CHECK(tsc == now); }
int dev_irq_pending(void) { return 0; }
int dev_ack_irq(void) { CHECK(0); return -1; }
int vmx_guest_interruptible(void) { return interruptible; }
void vmx_set_interrupt_window(vcpu_t *vc, int on) { vc->pending_irq_window = on; }
void vmx_inject_external(uint8_t vector)
{
    injected_vector = vector;
    ++injected;
}

static uint64_t call(domain_t *d, unsigned op, uint64_t a, uint64_t b)
{
    const unsigned before = advance_calls;
    const uint64_t calls = g_info->hypercalls;
    const uint64_t own_calls = g_info->domains[d->id].hypercalls;
    d->vc.gpr[GPR_RAX] = op;
    d->vc.gpr[GPR_RBX] = a;
    d->vc.gpr[GPR_RCX] = b;
    CHECK(hcall_vmcall(d) == 0);
    CHECK((int64_t)d->vc.gpr[GPR_RAX] == SHZ_OK);
    CHECK(advance_calls == before + 1);
    CHECK(g_info->hypercalls == calls + 1);
    CHECK(g_info->domains[d->id].hypercalls == own_calls + 1);
    return d->vc.gpr[GPR_RBX];
}

static void check_timer_preserved(domain_t *d)
{
    CHECK(d->timer_period == 10000);
    CHECK(d->timer_next == 2000000);
    CHECK(d->timer_vector == 0x20);
}

static void exercise_doorbell(dom_kind_t kind, unsigned id)
{
    shz_info_t info = {0};
    domain_t *d = &g_dom[id], *sender;
    const unsigned sender_id = id == SHZ_DOM_KERNEL64 ? SHZ_DOM_WIN98 : SHZ_DOM_KERNEL64;
    memset(g_dom, 0, sizeof g_dom);
    g_info = &info;
    g_tsc_hz = 1000000000;
    d->id = id; d->kind = kind; d->state = SHZ_DS_RUNNABLE;
    d->timer_period = 10000; d->timer_next = 2000000; d->timer_vector = 0x20;
    sender = &g_dom[sender_id];
    sender->id = sender_id; sender->state = SHZ_DS_RUNNABLE;
    interruptible = 1;
    call(d, SHZ_HC_SET_DOORBELL_VECTOR, 0x21, 0);

    /* NOTIFY before WAIT: pending work must keep its consumer runnable. */
    call(sender, SHZ_HC_NOTIFY, id, 0x1);
    CHECK(d->doorbell_pending == 0x1 && d->doorbell_signaled == 0);
    call(d, SHZ_HC_WAIT, 0, 0);
    CHECK(d->state == SHZ_DS_RUNNABLE);
    check_timer_preserved(d);

    /* The real delivery body marks injection, but only ACK consumes work. */
    unsigned before = injected;
    deliver_events(d, now);
    CHECK(injected == before + 1 && injected_vector == 0x21);
    CHECK(info.domains[id].irqs_injected == 1 && info.injected_irqs == 1);
    CHECK(d->doorbell_pending == 0x1 && d->doorbell_signaled == 1);
    deliver_events(d, now);
    CHECK(injected == before + 1);
    call(d, SHZ_HC_WAIT, 0, 0);
    CHECK(d->state == SHZ_DS_RUNNABLE);  /* regression: injected is not acknowledged */
    CHECK(d->doorbell_pending == 0x1 && d->doorbell_signaled == 1);
    CHECK(call(d, SHZ_HC_DOORBELL_ACK, 0, 0) == 0x1);
    CHECK(d->doorbell_pending == 0 && d->doorbell_signaled == 0);
    check_timer_preserved(d);

    /* WAIT before NOTIFY: a new notification satisfies the existing wake predicate. */
    call(d, SHZ_HC_WAIT, 0, 0);
    CHECK(d->state == SHZ_DS_WAITING);
    if (kind != DK_WIN98) CHECK(kernel_ready(d, now) == 0);
    call(sender, SHZ_HC_NOTIFY, id, 0x2);
    CHECK(d->state == SHZ_DS_WAITING && d->doorbell_pending == 0x2);
    if (kind != DK_WIN98) CHECK(kernel_ready(d, now) != 0);
    d->state = SHZ_DS_RUNNABLE;  /* the scheduler resumes an eligible vCPU */
    deliver_events(d, now);
    CHECK(d->doorbell_pending == 0x2 && d->doorbell_signaled == 1);
    call(d, SHZ_HC_WAIT, 0, 0);
    CHECK(d->state == SHZ_DS_RUNNABLE);

    /* Duplicate and distinct notifications coalesce until one ACK. */
    call(sender, SHZ_HC_NOTIFY, id, 0x4);
    call(sender, SHZ_HC_NOTIFY, id, 0x4);
    call(sender, SHZ_HC_NOTIFY, id, 0x80000000u);
    CHECK(d->doorbell_pending == 0x80000006u && d->doorbell_signaled == 0);
    before = injected;
    deliver_events(d, now);
    CHECK(injected == before + 1 && d->doorbell_signaled == 1);
    call(d, SHZ_HC_WAIT, 0, 0);
    CHECK(d->state == SHZ_DS_RUNNABLE);
    CHECK(call(d, SHZ_HC_DOORBELL_ACK, 0, 0) == 0x80000006u);
    CHECK(call(d, SHZ_HC_DOORBELL_ACK, 0, 0) == 0);
    call(d, SHZ_HC_WAIT, 0, 0);
    CHECK(d->state == SHZ_DS_WAITING);
    check_timer_preserved(d);

    /* Interrupt inhibition delays delivery without consuming pending work. */
    d->state = SHZ_DS_RUNNABLE;
    call(sender, SHZ_HC_NOTIFY, id, 0x8);
    interruptible = 0;
    before = injected;
    deliver_events(d, now);
    CHECK(injected == before && d->vc.pending_irq_window == 1);
    CHECK(d->doorbell_pending == 0x8 && d->doorbell_signaled == 0);
    call(d, SHZ_HC_WAIT, 0, 0);
    CHECK(d->state == SHZ_DS_RUNNABLE);
    interruptible = 1;
    deliver_events(d, now);
    CHECK(injected == before + 1 && d->vc.pending_irq_window == 0);
    CHECK(d->doorbell_pending == 0x8 && d->doorbell_signaled == 1);
    call(d, SHZ_HC_WAIT, 0, 0);
    CHECK(d->state == SHZ_DS_RUNNABLE);
    CHECK(call(d, SHZ_HC_DOORBELL_ACK, 0, 0) == 0x8);
    check_timer_preserved(d);

    /* Timer eligibility remains independent from an empty doorbell mask. */
    if (kind != DK_WIN98) {
        d->timer_next = now;
        call(d, SHZ_HC_WAIT, 0, 0);
        CHECK(d->state == SHZ_DS_WAITING && kernel_ready(d, now) != 0);
        d->state = SHZ_DS_RUNNABLE;
        before = injected;
        deliver_events(d, now);
        CHECK(injected == before + 1 && injected_vector == 0x20);
        CHECK(d->timer_period == 10000 && d->timer_next == 1010000);
        CHECK(d->doorbell_pending == 0 && d->doorbell_signaled == 0);
    }
}

int main(void)
{
    exercise_doorbell(DK_KERNEL32, SHZ_DOM_KERNEL32);
    exercise_doorbell(DK_KERNEL64, SHZ_DOM_KERNEL64);
    exercise_doorbell(DK_WIN98, SHZ_DOM_WIN98);
    printf("PASS %u actual dispatcher/delivery/wait/ACK/coalescing checks (hardware modeled, no VM)\n", checks);
    return 0;
}
