/* SPDX-License-Identifier: GPL-2.0-only */
#include "caps.h"
#include "cpu.h"
#include "../include/shz_info.h"

static void set_why(char *dst, const char *text)
{
    unsigned i = 0;
    if (dst[0])
        return;                 /* keep the first missing requirement */
    while (text[i] && i < 95) {
        dst[i] = text[i];
        ++i;
    }
    dst[i] = 0;
}

/* Bits the VMX backend needs from the capability MSRs: (allowed-1 half).
 * These are requirements of *this implementation*, checked against hardware. */
static int allowed1(uint64_t msr, unsigned bit) { return (int)((msr >> 32) >> bit) & 1; }

void shz_probe_caps(shz_caps_t *c)
{
    struct cpuid_regs r;
    unsigned i;
    char *p = (char *)c;
    for (i = 0; i < sizeof *c; ++i)
        p[i] = 0;

    r = cpuid(0);
    c->max_leaf = r.eax;
    c->vendor_regs[0] = r.ebx;
    c->vendor_regs[1] = r.edx;
    c->vendor_regs[2] = r.ecx;
    if (r.ebx == 0x756e6547 && r.edx == 0x49656e69 && r.ecx == 0x6c65746e)
        c->vendor = SHZ_VENDOR_INTEL;       /* "GenuineIntel" */
    else if (r.ebx == 0x68747541 && r.edx == 0x69746e65 && r.ecx == 0x444d4163)
        c->vendor = SHZ_VENDOR_AMD;         /* "AuthenticAMD" */
    r = cpuid(1);
    c->family = (r.eax >> 8) & 0xf;
    c->model = (r.eax >> 4) & 0xf;
    c->stepping = r.eax & 0xf;
    if (c->family == 0xf)
        c->family += (r.eax >> 20) & 0xff;
    if (c->family >= 6)
        c->model |= ((r.eax >> 16) & 0xf) << 4;
    c->hypervisor_bit = (r.ecx >> 31) & 1;
    c->vmx_cpuid = (r.ecx >> 5) & 1;
    r = cpuid(0x80000000);
    c->max_ext_leaf = r.eax;
    if (c->max_ext_leaf >= 0x80000001) {
        r = cpuid(0x80000001);
        c->long_mode = (r.edx >> 29) & 1;
        c->pdpe1gb = (r.edx >> 26) & 1;
        c->svm_cpuid = (r.ecx >> 2) & 1;
    }

    if (!c->vmx_cpuid) {
        set_why(c->vmx_why, "CPUID does not report VMX");
    } else {
        c->feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
        c->vmx_locked = (unsigned)(c->feature_control & 1);
        c->vmx_enabled_outside_smx = (unsigned)((c->feature_control >> 2) & 1);
        if (c->vmx_locked && !c->vmx_enabled_outside_smx)
            set_why(c->vmx_why, "VMX disabled by firmware (IA32_FEATURE_CONTROL locked without bit 2)");
        c->vmx_basic = rdmsr(MSR_IA32_VMX_BASIC);
        c->vmx_true_controls = (unsigned)((c->vmx_basic >> 55) & 1);
        c->pin = rdmsr(c->vmx_true_controls ? MSR_IA32_VMX_TRUE_PINBASED : MSR_IA32_VMX_PINBASED);
        c->proc = rdmsr(c->vmx_true_controls ? MSR_IA32_VMX_TRUE_PROCBASED : MSR_IA32_VMX_PROCBASED);
        c->exitc = rdmsr(c->vmx_true_controls ? MSR_IA32_VMX_TRUE_EXIT : MSR_IA32_VMX_EXIT);
        c->entryc = rdmsr(c->vmx_true_controls ? MSR_IA32_VMX_TRUE_ENTRY : MSR_IA32_VMX_ENTRY);
        if (allowed1(c->proc, 31)) {
            c->proc2 = rdmsr(MSR_IA32_VMX_PROCBASED2);
            c->ept = allowed1(c->proc2, 1);
            c->vpid = allowed1(c->proc2, 5);
            c->unrestricted_guest = allowed1(c->proc2, 7);
            if (c->ept || c->vpid) {
                c->ept_vpid_cap = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
                c->ept_2mb = (unsigned)((c->ept_vpid_cap >> 16) & 1);
                c->ept_wb = (unsigned)((c->ept_vpid_cap >> 14) & 1);
            }
        } else {
            set_why(c->vmx_why, "secondary VM-execution controls unavailable");
        }
        if (!c->ept)
            set_why(c->vmx_why, "EPT unavailable");
        if (!c->unrestricted_guest)
            set_why(c->vmx_why, "Unrestricted Guest unavailable (real-mode guest needs a VM86 path)");
        if (!((c->ept_vpid_cap >> 6) & 1))
            set_why(c->vmx_why, "EPT capabilities lack the 4-level page walk");
        if (!c->ept_wb)
            set_why(c->vmx_why, "EPT write-back paging-structure memory type unsupported");
        if (!allowed1(c->proc, 25) || !allowed1(c->proc, 28) || !allowed1(c->proc, 7))
            set_why(c->vmx_why, "I/O bitmap, MSR bitmap or HLT exiting controls unavailable");
        if (!allowed1(c->exitc, 9) || !allowed1(c->exitc, 15))
            set_why(c->vmx_why, "host address-space-size or ack-interrupt-on-exit unavailable");
    }
    if (!c->long_mode)
        set_why(c->vmx_why, "CPU lacks Long Mode");
    if (c->vendor != SHZ_VENDOR_INTEL)
        set_why(c->vmx_why, "not an Intel CPU");
    c->vmx_usable = c->vmx_why[0] == 0;

    if (c->vendor == SHZ_VENDOR_AMD && c->svm_cpuid && c->max_ext_leaf >= 0x8000000a) {
        r = cpuid(0x8000000a);
        c->svm_rev = r.eax & 0xff;
        c->svm_asids = r.ebx;
        c->svm_npt = r.edx & 1;
        c->svm_nrip = (r.edx >> 3) & 1;
        c->vm_cr = rdmsr(MSR_VM_CR);
        c->svm_disabled = (unsigned)((c->vm_cr >> 4) & 1);
        if (c->svm_disabled)
            set_why(c->svm_why, "SVM disabled in VM_CR (firmware)");
        if (!c->svm_npt)
            set_why(c->svm_why, "NPT unavailable (backend minimum policy)");
        if (!c->long_mode)
            set_why(c->svm_why, "CPU lacks Long Mode");
    } else {
        set_why(c->svm_why, c->vendor == SHZ_VENDOR_AMD ? "CPUID does not report SVM" : "not an AMD CPU");
    }
    c->svm_usable = c->svm_why[0] == 0;
}

uint32_t shz_caps_bits(const shz_caps_t *c)
{
    uint32_t b = 0;
    if (c->long_mode) b |= SHZ_CAP_LONG_MODE;
    if (c->vmx_cpuid) b |= SHZ_CAP_VMX;
    if (c->vmx_cpuid && (!c->vmx_locked || c->vmx_enabled_outside_smx)) b |= SHZ_CAP_VMX_ENABLED;
    if (c->ept) b |= SHZ_CAP_EPT;
    if (c->unrestricted_guest) b |= SHZ_CAP_UNRESTRICTED;
    if (c->vpid) b |= SHZ_CAP_VPID;
    if (c->svm_cpuid) b |= SHZ_CAP_SVM;
    if (c->svm_cpuid && !c->svm_disabled) b |= SHZ_CAP_SVM_ENABLED;
    if (c->svm_npt) b |= SHZ_CAP_NPT;
    return b;
}
