/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 "standalone" services: the hypercall ABI (abi/shz_abi.h) served by the kernel itself so the
 * Long Mode kernel and its Win64 processes can run without the Supervisor, e.g. under QEMU TCG where Intel VMX
 * does not exist. This is a test/bring-up profile: it is NOT the multikernel product path and never claims
 * Supervisor or VMX behaviour.  Devices: kcommon/standalone_dev.h.
 *
 *   console   -> COM1            exit     -> "SHZ-EXIT:<code>" on COM1, then QEMU isa-debug-exit (0xF4)
 *   evidence  -> "SHZ-EV <slot> <hex>" on COM1, parsed by tests/run_k*_standalone.py
 *   timer     -> PIT ch.0 via the 8259 (IRQ0 = VEC_TIMER)     time -> timer ticks     walltime -> CMOS RTC
 *   doorbells/notify -> SHZ_E_UNSUPPORTED (single domain, no peers)
 */
#include "k64.h"
#include "../../kcommon/standalone_dev.h"

extern uint64_t arch_timer_irqs(void);
void standalone_eoi(void) { sa_eoi(); }
void standalone_eoi_irq(unsigned vector) { sa_eoi_irq(vector - sa_irq_vector(0)); }
void standalone_irq_unmask(unsigned irq) { sa_irq_unmask(irq); }
void standalone_irq_mask(unsigned irq) { sa_irq_mask(irq); }
unsigned standalone_irq_vector(unsigned irq) { return sa_irq_vector(irq); }

long shz_standalone_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value_out)
{
    hcreg_t v = 0;
    long st = SHZ_OK;
    switch (op) {
    case SHZ_HC_CONSOLE_WRITE: {
        const char *s = (const char *)p2v(a);
        uint64_t i;
        if (b > 512) { st = SHZ_E_RANGE; break; }
        for (i = 0; i < b; ++i)
            sa_serial_putc(s[i]);
        break;
    }
    case SHZ_HC_EXIT:
        if (a <= 1) {   /* normal exit: commit + flush write-back volumes, then the driver quiesce, before the power action */
            extern void vfs_shutdown(void);
            extern int shz_driver_bringup_quiesce(void);
            int q;
            vfs_shutdown();
            q = shz_driver_bringup_quiesce();   /* IRP_MJ_SHUTDOWN to hosted drivers + whole-device flush; runs once */
            if (q) kprintf("K64 exit: driver quiesce reported %d flush failure(s)\n", q);
        }
        sa_exit((unsigned)a);
    case SHZ_HC_TIMER_SET: st = sa_timer_set((unsigned)a, (uint32_t)b); break;
    case SHZ_HC_WAIT: __asm__ volatile("sti; hlt"); break;
    case SHZ_HC_TIME: v = arch_timer_irqs() * TICK_US * 1000ull; break;
    case SHZ_HC_EVIDENCE:
        if (a > 31) { st = SHZ_E_RANGE; break; }
        sa_evidence((unsigned)a, b);
        break;
    case SHZ_HC_ABI_VERSION: v = ((hcreg_t)SHZ_ABI_MAJOR << 16) | SHZ_ABI_MINOR; break;
    case SHZ_HC_WALLTIME: v = sa_rtc_epoch(); break;
    case SHZ_HC_NOTIFY:
    case SHZ_HC_SET_DOORBELL_VECTOR:
    case SHZ_HC_DOORBELL_ACK:
    case SHZ_HC_DOMAIN_STATE:
    case SHZ_HC_CHANNEL_INFO:
        st = SHZ_E_UNSUPPORTED;
        break;
    default:
        st = SHZ_E_INVALID;
        break;
    }
    if (value_out)
        *value_out = v;
    return st;
}
