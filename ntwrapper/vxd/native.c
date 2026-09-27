/* SPDX-License-Identifier: GPL-2.0-only -- original native callback binding. */
#include "bridge.h"
extern uintptr_t ntwv_irq_enter(void *opaque);
extern void ntwv_irq_leave(void *opaque, uintptr_t saved);
extern uint32_t ntwv_vmm_check(uint32_t, uint32_t, uint32_t);
extern uint32_t ntwv_vmm_lock(uint32_t, uint32_t, uint32_t);
extern uint32_t ntwv_vmm_unlock(uint32_t, uint32_t, uint32_t);
extern uint32_t ntwv_vmm_ptes(uint32_t, uint32_t, uint32_t *, uint32_t);

static void write_alias(uint32_t alias, const void *source, uint32_t bytes)
{
    volatile uint8_t *to = (volatile uint8_t *)(uintptr_t)alias;
    const uint8_t *from = source;
    uint32_t i;
    for (i = 0; i < bytes; ++i)
        to[i] = from[i];
}

int ntwv_native_init(void)
{
    const struct ntw_lock_ops ops = { ntwv_irq_enter, ntwv_irq_leave, 0 };
    return ntwv_initialize(&ops);
}

int ntwv_native_exit(void)
{
    return ntwv_shutdown();
}

uint32_t ntwv_native_dioc(const struct ntwv_dioc *request)
{
    const struct ntwv_pages ops = { ntwv_vmm_check, ntwv_vmm_lock,
        ntwv_vmm_unlock, ntwv_vmm_ptes, ntwv_irq_enter, ntwv_irq_leave, write_alias };
    return ntwv_dioc(request, &ops);
}
