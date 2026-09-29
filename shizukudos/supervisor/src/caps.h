/* SPDX-License-Identifier: GPL-2.0-only
 * CPU / virtualization capability probe shared by the UEFI loader (before
 * ExitBootServices, so an unusable machine can return cleanly to firmware) and by
 * the Supervisor (which re-probes and records what it actually uses).
 *
 * Nothing here is a constant: every bit comes from CPUID or a capability MSR.
 */
#ifndef SHZ_CAPS_H
#define SHZ_CAPS_H
#include <stdint.h>

enum shz_vendor { SHZ_VENDOR_UNKNOWN = 0, SHZ_VENDOR_INTEL = 1, SHZ_VENDOR_AMD = 2 };

typedef struct {
    uint32_t vendor_regs[3];    /* CPUID.0 EBX, EDX, ECX */
    uint32_t vendor;            /* enum shz_vendor */
    uint32_t max_leaf, max_ext_leaf;
    uint32_t family, model, stepping;
    uint32_t long_mode;         /* CPUID.80000001:EDX[29] */
    uint32_t pdpe1gb;
    uint32_t hypervisor_bit;    /* running under someone else's hypervisor (L1) */

    /* Intel VMX */
    uint32_t vmx_cpuid;         /* CPUID.1:ECX[5] */
    uint64_t feature_control;   /* IA32_FEATURE_CONTROL (only read if vmx_cpuid) */
    uint32_t vmx_locked, vmx_enabled_outside_smx;
    uint64_t vmx_basic;
    uint32_t vmx_true_controls;
    uint64_t pin, proc, proc2, exitc, entryc;   /* allowed-0 in low half, allowed-1 in high half */
    uint64_t ept_vpid_cap;
    uint32_t ept, unrestricted_guest, vpid, ept_2mb, ept_wb;
    uint32_t vmx_usable;        /* every requirement of the VMX backend is met */
    char vmx_why[96];           /* first missing requirement, empty when usable */

    /* AMD SVM (detected and reported; the backend itself is a separate stage) */
    uint32_t svm_cpuid;         /* CPUID.80000001:ECX[2] */
    uint32_t svm_rev, svm_asids, svm_npt, svm_nrip;
    uint64_t vm_cr;
    uint32_t svm_disabled;      /* VM_CR.SVMDIS */
    uint32_t svm_usable;
    char svm_why[96];
} shz_caps_t;

void shz_probe_caps(shz_caps_t *caps);
/* Fold caps into shz_info cap_bits for the evidence block. */
uint32_t shz_caps_bits(const shz_caps_t *caps);
#endif
