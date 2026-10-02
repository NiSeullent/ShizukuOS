/* SPDX-License-Identifier: GPL-2.0-only
 * Intel VMX backend of the Shizuku Supervisor.
 * The AMD SVM backend is a *separate* implementation behind the same hv_backend
 * interface (see hv.h); VMX and SVM share no register model.
 */
#ifndef SHZ_VMX_H
#define SHZ_VMX_H
#include <stdint.h>

/* ---- VMCS field encodings (Intel SDM Vol. 3D, Appendix B) ---- */
#define VMCS_VPID 0x0000
#define VMCS_GUEST_ES_SEL 0x0800
#define VMCS_GUEST_CS_SEL 0x0802
#define VMCS_GUEST_SS_SEL 0x0804
#define VMCS_GUEST_DS_SEL 0x0806
#define VMCS_GUEST_FS_SEL 0x0808
#define VMCS_GUEST_GS_SEL 0x080a
#define VMCS_GUEST_LDTR_SEL 0x080c
#define VMCS_GUEST_TR_SEL 0x080e
#define VMCS_HOST_ES_SEL 0x0c00
#define VMCS_HOST_CS_SEL 0x0c02
#define VMCS_HOST_SS_SEL 0x0c04
#define VMCS_HOST_DS_SEL 0x0c06
#define VMCS_HOST_FS_SEL 0x0c08
#define VMCS_HOST_GS_SEL 0x0c0a
#define VMCS_HOST_TR_SEL 0x0c0c
#define VMCS_IO_BITMAP_A 0x2000
#define VMCS_IO_BITMAP_B 0x2002
#define VMCS_MSR_BITMAP 0x2004
#define VMCS_TSC_OFFSET 0x2010
#define VMCS_EPT_POINTER 0x201a
#define VMCS_GUEST_PHYS_ADDR 0x2400
#define VMCS_LINK_POINTER 0x2800
#define VMCS_GUEST_DEBUGCTL 0x2802
#define VMCS_GUEST_PAT 0x2804
#define VMCS_GUEST_EFER 0x2806
#define VMCS_HOST_PAT 0x2c00
#define VMCS_HOST_EFER 0x2c02
#define VMCS_PIN_CONTROLS 0x4000
#define VMCS_PROC_CONTROLS 0x4002
#define VMCS_EXCEPTION_BITMAP 0x4004
#define VMCS_PF_ERRCODE_MASK 0x4006
#define VMCS_PF_ERRCODE_MATCH 0x4008
#define VMCS_CR3_TARGET_COUNT 0x400a
#define VMCS_EXIT_CONTROLS 0x400c
#define VMCS_EXIT_MSR_STORE_COUNT 0x400e
#define VMCS_EXIT_MSR_LOAD_COUNT 0x4010
#define VMCS_ENTRY_CONTROLS 0x4012
#define VMCS_ENTRY_MSR_LOAD_COUNT 0x4014
#define VMCS_ENTRY_INTR_INFO 0x4016
#define VMCS_ENTRY_EXC_ERRCODE 0x4018
#define VMCS_ENTRY_INSTR_LEN 0x401a
#define VMCS_PROC2_CONTROLS 0x401e
#define VMCS_INSTR_ERROR 0x4400
#define VMCS_EXIT_REASON 0x4402
#define VMCS_EXIT_INTR_INFO 0x4404
#define VMCS_EXIT_INTR_ERRCODE 0x4406
#define VMCS_IDT_VECTORING_INFO 0x4408
#define VMCS_IDT_VECTORING_ERR 0x440a
#define VMCS_EXIT_INSTR_LEN 0x440c
#define VMCS_EXIT_INSTR_INFO 0x440e
#define VMCS_GUEST_ES_LIMIT 0x4800
#define VMCS_GUEST_CS_LIMIT 0x4802
#define VMCS_GUEST_SS_LIMIT 0x4804
#define VMCS_GUEST_DS_LIMIT 0x4806
#define VMCS_GUEST_FS_LIMIT 0x4808
#define VMCS_GUEST_GS_LIMIT 0x480a
#define VMCS_GUEST_LDTR_LIMIT 0x480c
#define VMCS_GUEST_TR_LIMIT 0x480e
#define VMCS_GUEST_GDTR_LIMIT 0x4810
#define VMCS_GUEST_IDTR_LIMIT 0x4812
#define VMCS_GUEST_ES_AR 0x4814
#define VMCS_GUEST_CS_AR 0x4816
#define VMCS_GUEST_SS_AR 0x4818
#define VMCS_GUEST_DS_AR 0x481a
#define VMCS_GUEST_FS_AR 0x481c
#define VMCS_GUEST_GS_AR 0x481e
#define VMCS_GUEST_LDTR_AR 0x4820
#define VMCS_GUEST_TR_AR 0x4822
#define VMCS_GUEST_INTERRUPTIBILITY 0x4824
#define VMCS_GUEST_ACTIVITY 0x4826
#define VMCS_PREEMPT_TIMER_VALUE 0x482e
#define VMCS_GUEST_SYSENTER_CS 0x482a
#define VMCS_HOST_SYSENTER_CS 0x4c00
#define VMCS_CR0_GUEST_HOST_MASK 0x6000
#define VMCS_CR4_GUEST_HOST_MASK 0x6002
#define VMCS_CR0_READ_SHADOW 0x6004
#define VMCS_CR4_READ_SHADOW 0x6006
#define VMCS_EXIT_QUAL 0x6400
#define VMCS_GUEST_LINEAR_ADDR 0x640a
#define VMCS_GUEST_CR0 0x6800
#define VMCS_GUEST_CR3 0x6802
#define VMCS_GUEST_CR4 0x6804
#define VMCS_GUEST_ES_BASE 0x6806
#define VMCS_GUEST_CS_BASE 0x6808
#define VMCS_GUEST_SS_BASE 0x680a
#define VMCS_GUEST_DS_BASE 0x680c
#define VMCS_GUEST_FS_BASE 0x680e
#define VMCS_GUEST_GS_BASE 0x6810
#define VMCS_GUEST_LDTR_BASE 0x6812
#define VMCS_GUEST_TR_BASE 0x6814
#define VMCS_GUEST_GDTR_BASE 0x6816
#define VMCS_GUEST_IDTR_BASE 0x6818
#define VMCS_GUEST_DR7 0x681a
#define VMCS_GUEST_RSP 0x681c
#define VMCS_GUEST_RIP 0x681e
#define VMCS_GUEST_RFLAGS 0x6820
#define VMCS_GUEST_PENDING_DBG 0x6822
#define VMCS_GUEST_SYSENTER_ESP 0x6824
#define VMCS_GUEST_SYSENTER_EIP 0x6826
#define VMCS_HOST_CR0 0x6c00
#define VMCS_HOST_CR3 0x6c02
#define VMCS_HOST_CR4 0x6c04
#define VMCS_HOST_FS_BASE 0x6c06
#define VMCS_HOST_GS_BASE 0x6c08
#define VMCS_HOST_TR_BASE 0x6c0a
#define VMCS_HOST_GDTR_BASE 0x6c0c
#define VMCS_HOST_IDTR_BASE 0x6c0e
#define VMCS_HOST_SYSENTER_ESP 0x6c10
#define VMCS_HOST_SYSENTER_EIP 0x6c12
#define VMCS_HOST_RSP 0x6c14
#define VMCS_HOST_RIP 0x6c16

/* ---- Basic exit reasons ---- */
enum vmx_exit {
    EXIT_EXCEPTION_NMI = 0, EXIT_EXTERNAL_INTERRUPT = 1, EXIT_TRIPLE_FAULT = 2,
    EXIT_INIT = 3, EXIT_SIPI = 4, EXIT_INTERRUPT_WINDOW = 7, EXIT_NMI_WINDOW = 8,
    EXIT_TASK_SWITCH = 9, EXIT_CPUID = 10, EXIT_HLT = 12, EXIT_INVD = 13,
    EXIT_INVLPG = 14, EXIT_RDPMC = 15, EXIT_RDTSC = 16, EXIT_VMCALL = 18,
    EXIT_CR_ACCESS = 28, EXIT_DR_ACCESS = 29, EXIT_IO = 30, EXIT_RDMSR = 31,
    EXIT_WRMSR = 32, EXIT_INVALID_GUEST_STATE = 33, EXIT_MSR_LOAD_FAIL = 34,
    EXIT_MWAIT = 36, EXIT_MTF = 37, EXIT_MONITOR = 39, EXIT_PAUSE = 40,
    EXIT_MACHINE_CHECK = 41, EXIT_EPT_VIOLATION = 48, EXIT_EPT_MISCONFIG = 49,
    EXIT_RDTSCP = 51, EXIT_PREEMPTION_TIMER = 52, EXIT_WBINVD = 54, EXIT_XSETBV = 55
};

/* Guest general-purpose register save area: order fixed by vmx_asm.asm. */
enum { GPR_RAX, GPR_RCX, GPR_RDX, GPR_RBX, GPR_RSP_UNUSED, GPR_RBP, GPR_RSI, GPR_RDI,
       GPR_R8, GPR_R9, GPR_R10, GPR_R11, GPR_R12, GPR_R13, GPR_R14, GPR_R15, GPR_COUNT };

#define VCPU_EXIT_STACK_BYTES 16384

typedef struct vcpu {
    uint64_t gpr[GPR_COUNT];        /* offset 0   */
    uint64_t launched;              /* offset 128 */
    uint64_t host_rsp_saved;        /* offset 136 */
    uint64_t domain_id;
    uint64_t reserved;
    uint64_t vmcs_pa;
    uint64_t ept_pointer;
    uint64_t pending_irq_window;    /* interrupt-window exiting currently requested */
    uint32_t owner_cpu, cpu_binding_valid; /* 0 virgin, 2 retained construction, 1 ready; owner immutable */
    uint8_t exit_stack[VCPU_EXIT_STACK_BYTES] __attribute__((aligned(16)));
} vcpu_t;

_Static_assert(__builtin_offsetof(vcpu_t, launched) == 128, "asm depends on this");
_Static_assert(__builtin_offsetof(vcpu_t, host_rsp_saved) == 136, "asm depends on this");

typedef enum { VMODE_REAL = 0, VMODE_PROT32 = 1, VMODE_LONG64 = 2 } vmx_mode_t;

/* Initial guest state and per-domain VMX resources. Segment caches are derived from the
 * mode: REAL (F000:FFF0 style), PROT32 flat 4 GiB, LONG64 with CS.L = 1 and paging on. */
typedef struct {
    vmx_mode_t mode;
    uint64_t eptp;
    uint16_t vpid;
    uint64_t rip, rsp, cr3;
    uint16_t cs_sel;                    /* REAL: segment value; others: GDT selector */
    uint16_t code_sel, data_sel;        /* PROT32 / LONG64 selectors into the boot GDT */
    uint64_t gdt_base;
    uint16_t gdt_limit;
    uint8_t *vmcs;                      /* 4 KiB pool page */
    uint8_t *io_bitmap_a, *io_bitmap_b, *msr_bitmap;
} vmx_cfg_t;

int vmx_hw_prepare_cpus(const uint32_t *apic_ids, unsigned count);
int vmx_vcpu_load(vcpu_t *vc);             /* ownership checked before VMPTRLD */
void msr_bitmap_allow(uint8_t *bitmap, uint32_t msr, int read, int write);
int vmx_enter(vcpu_t *vc);                /* vmx_asm.asm: 0 = VM exit, 1/2 = VMfailInvalid/Valid */
void vmx_exit_entry(void);                /* vmx_asm.asm: VMCS HOST_RIP */

#endif
