/* SPDX-License-Identifier: GPL-2.0-only -- original native callback binding. */
#include "bridge.h"
#include "pma_endpoint.h"
extern uintptr_t ntwv_irq_enter(void *opaque);
extern void ntwv_irq_leave(void *opaque, uintptr_t saved);
extern uint32_t ntwv_vmm_check(uint32_t, uint32_t, uint32_t);
extern uint32_t ntwv_vmm_lock(uint32_t, uint32_t, uint32_t);
extern uint32_t ntwv_vmm_unlock(uint32_t, uint32_t, uint32_t);
extern uint32_t ntwv_vmm_ptes(uint32_t, uint32_t, uint32_t *, uint32_t);
extern uint32_t ntwv_vmm_map_phys(uint32_t, uint32_t, uint32_t);
extern int32_t ntwv_vmcall(uint32_t op, uint32_t a, uint32_t b, uint32_t *ebx_out, uint32_t *ecx_out);
extern void ntwv_cpuid(uint32_t leaf, uint32_t regs[4]);
extern uint32_t ntwv_vmm_system_vm(void), ntwv_vmm_current_vm(void), ntwv_vmm_current_thread(void), ntwv_vmm_now_ms(void);
extern uint32_t ntwv_vmm_open_event(uint32_t), ntwv_vmm_schedule_event(uint32_t), ntwv_vmm_schedule_timeout(uint32_t,uint32_t);
extern int ntwv_vmm_set_event(uint32_t), ntwv_vmm_close_event(uint32_t);
extern void ntwv_vmm_cancel_event(uint32_t), ntwv_vmm_cancel_timeout(uint32_t);
extern const uint8_t ntwv_text_begin[], ntwv_text_last[], ntwv_data_begin[], ntwv_data_last[];
static uint32_t image_pages[2], image_counts[2], image_locked, runtime_stopped;

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
static const struct ntwv_hv native_hv = { hypervisor_present, ntwv_vmcall, map_phys };
static const struct ntwv_pma_services native_services = {
    ntwv_vmm_system_vm, ntwv_vmm_current_vm, ntwv_vmm_current_thread, ntwv_vmm_now_ms,
    ntwv_vmm_open_event, ntwv_vmm_set_event, ntwv_vmm_close_event,
    ntwv_vmm_schedule_event, ntwv_vmm_cancel_event, ntwv_vmm_schedule_timeout, ntwv_vmm_cancel_timeout,
    ntwv_irq_enter, ntwv_irq_leave
};
static int lock_image(void)
{
    const uintptr_t first[2] = { (uintptr_t)ntwv_text_begin, (uintptr_t)ntwv_data_begin };
    const uintptr_t last[2] = { (uintptr_t)ntwv_text_last, (uintptr_t)ntwv_data_last };
    for (uint32_t i = 0; i < 2; ++i) {
        image_pages[i] = (uint32_t)(first[i] >> 12);
        image_counts[i] = (uint32_t)((last[i] >> 12) - (first[i] >> 12) + 1);
        if (!ntwv_vmm_lock(image_pages[i], image_counts[i], 0)) {
            while (image_locked) {
                uint32_t at=image_locked-1;
                if(!ntwv_vmm_unlock(image_pages[at], image_counts[at], 0)) break;
                --image_locked;
            }
            return 0;
        }
        ++image_locked;
    }
    return 1;
}

int ntwv_native_init(void)
{
    const struct ntw_lock_ops ops = { ntwv_irq_enter, ntwv_irq_leave, 0 };
    if(image_locked) return 0;
    if (!ntwv_initialize(&ops))
        return 0;
    runtime_stopped=0;
    if (!lock_image()) {
        (void)ntwv_shutdown();
        runtime_stopped=1;
        return 0;
    }
    if (!ntwv_pma_initialize(&native_services, &native_hv)) {
        while (image_locked) {
            uint32_t at=image_locked-1;
            if(!ntwv_vmm_unlock(image_pages[at], image_counts[at], 0)) break;
            --image_locked;
        }
        (void)ntwv_shutdown();
        runtime_stopped=1;
        return 0;
    }
    return 1;
}

int ntwv_native_exit(void)
{
    if(!runtime_stopped) {
        if (!ntwv_pma_unload_safe()) return 0;
        if (!ntwv_pma_shutdown()) return 0;
        ntwv_w64_reset();
        if (!ntwv_shutdown()) {
            ntwv_pma_resume();
            return 0;
        }
        runtime_stopped=1;
    }
    while (image_locked) {
        uint32_t at=image_locked-1;
        if (!ntwv_vmm_unlock(image_pages[at], image_counts[at], 0))
            return 0;
        --image_locked;
    }
    return 1;
}

uint32_t ntwv_native_dioc(const struct ntwv_dioc *request)
{
    const struct ntwv_pages ops = { ntwv_vmm_check, ntwv_vmm_lock,
        ntwv_vmm_unlock, ntwv_vmm_ptes, ntwv_irq_enter, ntwv_irq_leave, write_alias, read_alias };
    if (request && request->code == UINT32_MAX)
        ntwv_pma_owner_departed(request->vm, 0, request->device, request->process);
    return ntwv_dioc_ex(request, &ops, &native_hv);
}

void ntwv_native_lifecycle(uint32_t code, uint32_t vm, uint32_t thread)
{
    if (code == 0x20u || code == 0x21u)
        ntwv_pma_owner_departed(0, thread, 0, 0);
    else
        ntwv_pma_owner_departed(vm, 0, 0, 0);
}
