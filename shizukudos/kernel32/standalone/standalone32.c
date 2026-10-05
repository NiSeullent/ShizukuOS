/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 "standalone" services: the hypercall ABI served by the kernel itself so the Protected Mode kernel can run
 * under QEMU TCG without the Supervisor (no Intel VMX needed). Bring-up/test profile only; see
 * kernel64/standalone/standalone64.c and kcommon/standalone_dev.h. The full-width
 * helper uses the scheduler's coherent BSP tick clock; generic 32-bit hypercalls
 * retain their register-width result. Both express the same clock in nanoseconds.
 */
#include "k32.h"
#include "../../kcommon/standalone_dev.h"

void standalone_eoi(void) { sa_eoi(); }

uint64_t shz_standalone_time_ns(void)
{
    /* ticks_now masks IRQs and takes the existing runqueue lock, including
     * AP reads of the BSP-owned 64-bit clock. Preserve the caller's IRQ state. */
    return ticks_now() * (uint64_t)TICK_US * 1000u;
}

long shz_standalone_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value_out)
{
    hcreg_t v = 0;
    long st = SHZ_OK;
    switch (op) {
    case SHZ_HC_CONSOLE_WRITE: {
        const char *s = (const char *)(uintptr_t)a;                 /* identity mapped */
        hcreg_t i;
        if (b > 512) { st = SHZ_E_RANGE; break; }
        for (i = 0; i < b; ++i)
            sa_serial_putc(s[i]);
        break;
    }
    case SHZ_HC_EXIT: sa_exit((unsigned)a);
    case SHZ_HC_TIMER_SET: st = sa_timer_set((unsigned)a, (uint32_t)b); break;
    case SHZ_HC_WAIT: __asm__ volatile("sti; hlt"); break;
    case SHZ_HC_TIME: v = (hcreg_t)shz_standalone_time_ns(); break;
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
