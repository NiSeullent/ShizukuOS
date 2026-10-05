/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku Supervisor entry (UEFI x64 profile). Runs in VMX root mode after
 * ExitBootServices and hosts the DOS16 domain in virtual Real Mode.
 */
#include "caps.h"
#include "console.h"
#include "cpu.h"
#include "domain.h"
#include "core.h"
#include "platform.h"
#include "vbios_image.h"
#include "ap_start.h"

static void print_caps(const shz_caps_t *c)
{
    kprintf("SHZ-CAP: vendor=%s family=%u model=%x stepping=%u longmode=%u l1_under_hypervisor=%u\n",
            c->vendor == SHZ_VENDOR_INTEL ? "Intel" : c->vendor == SHZ_VENDOR_AMD ? "AMD" : "other",
            c->family, c->model, c->stepping, c->long_mode, c->hypervisor_bit);
    kprintf("SHZ-CAP: vmx cpuid=%u feature_control=%llx locked=%u outside_smx=%u ept=%u unrestricted=%u vpid=%u\n",
            c->vmx_cpuid, c->feature_control, c->vmx_locked, c->vmx_enabled_outside_smx, c->ept,
            c->unrestricted_guest, c->vpid);
    kprintf("SHZ-CAP: vmx_basic=%llx ept_vpid_cap=%llx true_controls=%u usable=%u%s%s\n", c->vmx_basic,
            c->ept_vpid_cap, c->vmx_true_controls, c->vmx_usable, c->vmx_usable ? "" : " why=",
            c->vmx_usable ? "" : c->vmx_why);
    kprintf("SHZ-CAP: svm cpuid=%u npt=%u disabled=%u usable=%u%s%s\n", c->svm_cpuid, c->svm_npt,
            c->svm_disabled, c->svm_usable, c->svm_usable ? "" : " why=", c->svm_usable ? "" : c->svm_why);
}

void sup_main(shz_info_t *info)
{
    static shz_core_t core;
    shz_caps_t caps;
    int rc;

    serial_init();
    kprintf("\nSHZ: ShizukuDOS 10.0-dev Supervisor (UEFI x64 profile) entered\n");
    if (info->magic != SHZ_INFO_MAGIC || info->version != SHZ_INFO_VERSION || info->size != sizeof *info)
        platform_fail(info, "handoff block rejected (magic/version/size)");
    info->stage = SHZ_STAGE_SUPERVISOR;
    info->hv_instance_id += 1;
    info->host_cr0 = read_cr0();
    platform_init(info);
    info->host_cr3 = read_cr3();
    info->host_cr4 = read_cr4();
    info->host_efer = rdmsr(MSR_IA32_EFER);
    info->host_cs = HOST_CS;

    shz_probe_caps(&caps);
    memcpy(info->cpu_vendor, caps.vendor_regs, sizeof info->cpu_vendor);
    info->cap_bits = shz_caps_bits(&caps);
    info->vmx_basic = caps.vmx_basic;
    info->vmx_ept_vpid_cap = caps.ept_vpid_cap;
    info->feature_control = caps.feature_control;
    info->stage = SHZ_STAGE_CAPS;
    print_caps(&caps);

    if (!caps.vmx_usable)
        platform_fail(info, caps.vmx_cpuid ? "Intel VMX backend unavailable on this CPU/firmware"
                                           : "no supported virtualization backend (VMX/SVM)");
    if (shz_ap_seal(info))
        platform_fail(info, "AP resource/topology sealing refused before INIT");
    if (vmx_hw_init(info, &caps))
        platform_fail(info, info->last_error[0] ? info->last_error : "VMXON failed");
    info->cap_bits |= SHZ_CAP_BACKEND_VMX;
    info->host_cr0 = read_cr0();
    info->host_cr4 = read_cr4();
    if (shz_ap_start(info))
        platform_fail(info, "AP startup/work failed; resources retained, no retry");

    if (shz_core_create(&core, info, &caps, vbios_image, sizeof vbios_image))
        platform_fail(info, info->last_error[0] ? info->last_error : "ShizukuCore child creation failed");
    rc = shz_core_run(&core, info);
    if (rc < 0)
        platform_fail(info, info->last_error[0] ? info->last_error : "ShizukuCore execution failed");
    kprintf("SHZ: scheduler ended stage=%x total_exits=%llu hypercalls=%llu irqs=%llu\n", info->stage,
            info->total_exits, info->hypercalls, info->injected_irqs);
    {
        unsigned i;
        for (i = 2; i < SHZ_MAX_DOMAINS; ++i)
            if (info->domains[i].state)
                kprintf("SHZ: domain %u state=%u exit_code=%u exits=%llu %s\n", i, info->domains[i].state,
                        info->domains[i].exit_code, info->domains[i].exits, info->domains[i].error);
    }
    kprintf("SHZ: session complete; Supervisor idle\n");
    for (;;) {
        cli();
        hlt();
    }
}
