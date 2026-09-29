/* SPDX-License-Identifier: GPL-2.0-only -- original native callback binding. */
#include "bridge.h"
extern uintptr_t ntwv_irq_enter(void *opaque);
extern void ntwv_irq_leave(void *opaque, uintptr_t saved);
extern uint32_t ntwv_vmm_check(uint32_t, uint32_t, uint32_t);
extern uint32_t ntwv_vmm_lock(uint32_t, uint32_t, uint32_t);
extern uint32_t ntwv_vmm_unlock(uint32_t, uint32_t, uint32_t);
extern uint32_t ntwv_vmm_ptes(uint32_t, uint32_t, uint32_t *, uint32_t);
extern uint32_t ntwv_vmm_map_phys(uint32_t, uint32_t, uint32_t);
extern int32_t ntwv_vmcall(uint32_t op, uint32_t a, uint32_t b, uint32_t *ebx_out, uint32_t *ecx_out);
extern void ntwv_cpuid(uint32_t leaf, uint32_t regs[4]);

static void write_alias(uint32_t alias, const void *source, uint32_t bytes)
{
    volatile uint8_t *to = (volatile uint8_t *)(uintptr_t)alias;
    const uint8_t *from = source;
    uint32_t i;
    for (i = 0; i < bytes; ++i)
        to[i] = from[i];
}

static void read_alias(void *destination, uint32_t alias, uint32_t bytes)
{
    const volatile uint8_t *from = (const volatile uint8_t *)(uintptr_t)alias;
    uint8_t *to = destination;
    uint32_t i;
    for (i = 0; i < bytes; ++i)
        to[i] = from[i];
}

/* The Shizuku Supervisor advertises itself like every hypervisor (CPUID.1:ECX[31]) and signs leaf 0x40000000
 * with "SSHZ" / "uVMM" / "v-10" (supervisor/src/domain.c). Anything else: never execute VMCALL. */
static int hypervisor_present(void)
{
    uint32_t r[4];
    ntwv_cpuid(1, r);
    if (!(r[2] & 0x80000000u))
        return 0;
    ntwv_cpuid(0x40000000u, r);
    return r[1] == 0x5a485353u && r[2] == 0x4d4d5675u && r[3] == 0x30312d76u;
}

static void *map_phys(uint32_t phys, uint32_t bytes)
{
    return (void *)(uintptr_t)ntwv_vmm_map_phys(phys, bytes, 0);
}

int ntwv_native_init(void)
{
    const struct ntw_lock_ops ops = { ntwv_irq_enter, ntwv_irq_leave, 0 };
    return ntwv_initialize(&ops);
}

int ntwv_native_exit(void)
{
    ntwv_w64_reset();
    return ntwv_shutdown();
}

uint32_t ntwv_native_dioc(const struct ntwv_dioc *request)
{
    const struct ntwv_pages ops = { ntwv_vmm_check, ntwv_vmm_lock,
        ntwv_vmm_unlock, ntwv_vmm_ptes, ntwv_irq_enter, ntwv_irq_leave, write_alias, read_alias };
    const struct ntwv_hv hv = { hypervisor_present, ntwv_vmcall, map_phys };
    return ntwv_dioc_ex(request, &ops, &hv);
}
