/* SPDX-License-Identifier: GPL-2.0-only
 * Intel VMX backend: VMXON, VMCS construction for a real-mode (Unrestricted
 * Guest) domain, EPT, and event injection helpers.
 *
 * Control values are derived from the capability MSRs, never assumed: each
 * required bit must be allowed-1 by hardware, and every must-be-1 bit is forced.
 */
#include "vmx.h"
#include "caps.h"
#include "console.h"
#include "cpu.h"
#include "ept.h"
#include "platform.h"

#include "vmx_cpu_state.h"

static vmx_cpu_topology_t cpu_topology;
static uint8_t vmxon_regions[VMX_CPU_MAX][4096] __attribute__((aligned(4096)));
static struct vmx_cpu_bank {
    uint64_t basic, pin, proc, proc2, exitc, entryc;
    unsigned true_controls, vpid;
} cpu_banks[VMX_CPU_MAX];

/* Hardware identity belongs to this root processor, not to any guest's GS. */
static uint32_t current_apic_id(void)
{
    const uint32_t max = cpuid(0).eax;
    if (max >= 0x1f) {
        struct cpuid_regs r = cpuid_count(0x1f, 0);
        if (r.ebx & 0xffffu) return r.edx;
    }
    if (max >= 0xb) {
        struct cpuid_regs r = cpuid_count(0xb, 0);
        if (r.ebx & 0xffffu) return r.edx;
    }
    if (max >= 1) {
        struct cpuid_regs r = cpuid(1);
        if (r.edx & (1u << 9)) return r.ebx >> 24;
    }
    return VMX_CPU_INVALID;
}

int vmx_hw_prepare_cpus(const uint32_t *apic_ids, unsigned count)
{
    return vmx_cpu_topology_init(&cpu_topology, apic_ids, count, current_apic_id());
}

static unsigned current_cpu(void)
{
    return vmx_cpu_find(&cpu_topology, current_apic_id());
}

static struct vmx_cpu_bank *ready_bank(unsigned *cpu)
{
    *cpu = current_cpu();
    return vmx_cpu_ready(&cpu_topology, *cpu) ? 0 : &cpu_banks[*cpu];
}

/* Read the actual host descriptor registers. Never use CPU0's global tables
 * as an AP's VMCS HOST state. This platform uses fixed descriptor shapes. */
static int publish_host_tables(unsigned cpu)
{
    struct __attribute__((packed)) { uint16_t limit; uint64_t base; } gdtr, idtr;
    uint16_t tr;
    uint64_t low, high, base;
    __asm__ volatile("sgdt %0" : "=m"(gdtr));
    __asm__ volatile("sidt %0" : "=m"(idtr));
    __asm__ volatile("str %0" : "=r"(tr));
    if (gdtr.limit != 63 || idtr.limit != 4095 || tr != HOST_TR || !gdtr.base || !idtr.base ||
        gdtr.base > UINT64_MAX - 64 || idtr.base > UINT64_MAX - 4096)
        return -1;
    low = *(const uint64_t *)(uintptr_t)(gdtr.base + HOST_TR);
    high = *(const uint64_t *)(uintptr_t)(gdtr.base + HOST_TR + 8);
    if (((low >> 40) & 0xffu) != 0x8b || high >> 32 ||
        ((low & 0xffffu) | ((low >> 32) & 0xf0000u)) != 103)
        return -1;
    base = ((low >> 16) & 0xffffffu) | ((low >> 32) & 0xff000000u) | (high << 32);
    return vmx_cpu_publish_tables(&cpu_topology, cpu, gdtr.base, idtr.base, base);
}

/* Required VM-execution controls for the DOS/real-mode domain. */
#define PIN_EXT_INT_EXIT (1u << 0)
#define PIN_NMI_EXIT (1u << 3)
#define PIN_PREEMPT_TIMER (1u << 6)
#define PROC_INT_WINDOW (1u << 2)
#define PROC_HLT_EXIT (1u << 7)
#define PROC_USE_IO_BITMAPS (1u << 25)
#define PROC_USE_MSR_BITMAPS (1u << 28)
#define PROC_SECONDARY (1u << 31)
#define PROC2_EPT (1u << 1)
#define PROC2_VPID (1u << 5)
#define PROC2_UNRESTRICTED (1u << 7)
#define EXIT_HOST_64 (1u << 9)
#define EXIT_ACK_INT (1u << 15)
#define EXIT_SAVE_PAT (1u << 18)
#define EXIT_LOAD_PAT (1u << 19)
#define EXIT_SAVE_EFER (1u << 20)
#define EXIT_LOAD_EFER (1u << 21)
#define ENTRY_LOAD_PAT (1u << 14)
#define ENTRY_LOAD_EFER (1u << 15)

static int adjust(uint64_t cap, uint32_t want, uint32_t *out, const char *name, shz_info_t *info)
{
    const uint32_t must1 = (uint32_t)cap;
    const uint32_t may1 = (uint32_t)(cap >> 32);
    uint32_t v = want | must1;
    if (v & ~may1) {
        log_capture(info->last_error, sizeof info->last_error,
                    "VMX %s control bits %x not supported (allowed-1 %x)", name, v & ~may1, may1);
        return -1;
    }
    *out = v;
    return 0;
}

static uint64_t fixed_bits(uint64_t value, uint32_t fixed0_msr, uint32_t fixed1_msr)
{
    return (value | rdmsr(fixed0_msr)) & rdmsr(fixed1_msr);
}

int vmx_hw_init(shz_info_t *info, const shz_caps_t *caps)
{
    uint64_t fc, cr0, cr4;
    int err;
    unsigned cpu = current_cpu();
    struct vmx_cpu_bank *bank;
    shz_caps_t local_caps;
    if (cpu == VMX_CPU_INVALID && !__atomic_load_n(&cpu_topology.sealed, __ATOMIC_ACQUIRE)) {
        const uint32_t bsp = current_apic_id();
        if (vmx_hw_prepare_cpus(&bsp, 1)) return -1;
        cpu = current_cpu();
    }
    if (vmx_cpu_begin(&cpu_topology, cpu)) {
        log_capture(info->last_error, sizeof info->last_error, "VMX CPU identity/state refused");
        return -1;
    }
    bank = &cpu_banks[cpu];
    shz_probe_caps(&local_caps); /* each physical CPU's actual MSRs */
    caps = &local_caps;
    if (publish_host_tables(cpu)) {
        log_capture(info->last_error, sizeof info->last_error, "VMX private host tables refused");
        __atomic_store_n(&cpu_topology.state[cpu], VMX_CPU_FAILED, __ATOMIC_RELEASE);
        return -1;
    }

    if (!caps->vmx_usable) {
        log_capture(info->last_error, sizeof info->last_error, "VMX not usable: %s", caps->vmx_why);
        __atomic_store_n(&cpu_topology.state[cpu], VMX_CPU_FAILED, __ATOMIC_RELEASE);
        return -1;
    }
    fc = rdmsr(MSR_IA32_FEATURE_CONTROL);
    if (!(fc & 1)) {
        /* Unlocked by firmware: the platform owner (this Supervisor) enables and locks it. */
        wrmsr(MSR_IA32_FEATURE_CONTROL, fc | 5);
        fc = rdmsr(MSR_IA32_FEATURE_CONTROL);
        kprintf("SHZ: IA32_FEATURE_CONTROL was unlocked; set %llx\n", fc);
    }
    if ((fc & 5) != 5) {
        log_capture(info->last_error, sizeof info->last_error,
                    "VMX outside SMX not permitted: FEATURE_CONTROL=%llx", fc);
        __atomic_store_n(&cpu_topology.state[cpu], VMX_CPU_FAILED, __ATOMIC_RELEASE);
        return -1;
    }
    info->feature_control = fc;

    bank->true_controls = caps->vmx_true_controls;
    bank->basic = caps->vmx_basic;
    bank->vpid = caps->vpid;
    bank->pin = caps->pin;
    bank->proc = caps->proc;
    bank->proc2 = caps->proc2;
    bank->exitc = caps->exitc;
    bank->entryc = caps->entryc;

    cr0 = fixed_bits(read_cr0(), MSR_IA32_VMX_CR0_FIXED0, MSR_IA32_VMX_CR0_FIXED1);
    write_cr0(cr0);
    cr4 = fixed_bits(read_cr4() | CR4_VMXE, MSR_IA32_VMX_CR4_FIXED0, MSR_IA32_VMX_CR4_FIXED1);
    write_cr4(cr4);

    memset(vmxon_regions[cpu], 0, sizeof vmxon_regions[cpu]);
    *(uint32_t *)vmxon_regions[cpu] = (uint32_t)(caps->vmx_basic & 0x7fffffff);
    err = vmxon((uint64_t)(uintptr_t)vmxon_regions[cpu]);
    if (err) {
        log_capture(info->last_error, sizeof info->last_error, "VMXON failed (%d)", err);
        __atomic_store_n(&cpu_topology.state[cpu], VMX_CPU_FAILED, __ATOMIC_RELEASE);
        return -1;
    }
    if (vmx_cpu_online(&cpu_topology, cpu)) {
        vmxoff();
        return -1;
    }
    invept_all();
    info->stage = SHZ_STAGE_VMXON;
    kprintf("SHZ: VMXON ok (revision %x, true-controls=%d)\n",
            (unsigned)(caps->vmx_basic & 0x7fffffff), bank->true_controls);
    return 0;
}

void vmx_hw_shutdown(void)
{
    const unsigned cpu = current_cpu();
    if (!vmx_cpu_ready(&cpu_topology, cpu)) {
        vmxoff();
        (void)vmx_cpu_retire(&cpu_topology, cpu);
    }
}

int vmx_vcpu_load(vcpu_t *vc)
{
    const unsigned cpu = current_cpu();
    if (!vc || vc->cpu_binding_valid != 1 || !vc->vmcs_pa || (vc->vmcs_pa & 4095) ||
        vmx_cpu_bind_allowed(&cpu_topology, cpu, vc->owner_cpu, vc->domain_id))
        return -1;
    return vmptrld(vc->vmcs_pa);
}

#define W(field, value) \
    do { if (vmwrite((field), (value))) { fail = #field; goto out; } } while (0)

/* Allow guest access to one MSR without a VM exit (bitmap layout: SDM Vol. 3C 25.6.9). */
void msr_bitmap_allow(uint8_t *bitmap, uint32_t msr, int read, int write)
{
    unsigned base_read, base_write;
    if (msr <= 0x1fff) {
        base_read = 0;
        base_write = 2048;
    } else if (msr >= 0xc0000000u && msr <= 0xc0001fffu) {
        base_read = 1024;
        base_write = 3072;
        msr -= 0xc0000000u;
    } else {
        return;
    }
    if (read)
        bitmap[base_read + msr / 8] &= (uint8_t)~(1u << (msr % 8));
    if (write)
        bitmap[base_write + msr / 8] &= (uint8_t)~(1u << (msr % 8));
}

#define AR_CODE32 0xc09b        /* G, D, P, S, type = execute/read accessed */
#define AR_CODE64 0xa09b        /* G, L, P, S, type = execute/read accessed */
#define AR_DATA 0xc093          /* G, D/B, P, S, type = read/write accessed */
#define AR_TSS_BUSY 0x8b

/* Build the VMCS for one domain from `cfg`. The VMCS becomes the current one. */
int vmx_vcpu_init(vcpu_t *vc, shz_info_t *info, const shz_caps_t *caps, const vmx_cfg_t *cfg)
{
    uint32_t pin, proc, proc2, exitc, entryc, entry_want;
    const char *fail = 0;
    uint64_t cr0_host, cr4_host, guest_cr0, guest_cr4, guest_efer;
    int i;
    (void)caps;
    const int real = cfg->mode == VMODE_REAL;
    const int lm = cfg->mode == VMODE_LONG64;
    unsigned cpu;
    struct vmx_cpu_bank *bank = ready_bank(&cpu);
    if (!bank || vc->cpu_binding_valid ||
        vmx_cpu_bind_allowed(&cpu_topology, cpu, cpu, cfg->vpid)) {
        log_capture(info->last_error, sizeof info->last_error, "VMCS CPU ownership refused");
        return -1;
    }

    entry_want = ENTRY_LOAD_PAT | ENTRY_LOAD_EFER | (lm ? (1u << 9) : 0);
    if (adjust(bank->pin, PIN_EXT_INT_EXIT | PIN_NMI_EXIT | PIN_PREEMPT_TIMER, &pin, "pin-based", info) ||
        adjust(bank->proc, PROC_HLT_EXIT | PROC_USE_IO_BITMAPS | PROC_USE_MSR_BITMAPS | PROC_SECONDARY,
               &proc, "primary", info) ||
        adjust(bank->proc2, PROC2_EPT | PROC2_UNRESTRICTED | (bank->vpid ? PROC2_VPID : 0), &proc2,
               "secondary", info) ||
        adjust(bank->exitc, EXIT_HOST_64 | EXIT_ACK_INT | EXIT_SAVE_PAT | EXIT_LOAD_PAT | EXIT_SAVE_EFER |
                         EXIT_LOAD_EFER, &exitc, "exit", info) ||
        adjust(bank->entryc, entry_want, &entryc, "entry", info))
        return -1;
    if (real) {
        info->vmx_pin = pin;
        info->vmx_proc = proc;
        info->vmx_proc2 = proc2;
        info->vmx_exit = exitc;
        info->vmx_entry = entryc;
    }

    memset(cfg->vmcs, 0, 4096);
    *(uint32_t *)cfg->vmcs = (uint32_t)(bank->basic & 0x7fffffff);
    vc->vmcs_pa = (uint64_t)(uintptr_t)cfg->vmcs;
    vc->ept_pointer = cfg->eptp;
    if (vmclear(vc->vmcs_pa) || vmptrld(vc->vmcs_pa)) {
        log_capture(info->last_error, sizeof info->last_error, "VMCLEAR/VMPTRLD failed");
        return -1;
    }

    /* ---- controls ---- */
    W(VMCS_PIN_CONTROLS, pin);
    W(VMCS_PROC_CONTROLS, proc);
    W(VMCS_PROC2_CONTROLS, proc2);
    W(VMCS_EXIT_CONTROLS, exitc);
    W(VMCS_ENTRY_CONTROLS, entryc);
    W(VMCS_EXCEPTION_BITMAP, 0);            /* guests own their exception handling */
    W(VMCS_PF_ERRCODE_MASK, 0);
    W(VMCS_PF_ERRCODE_MATCH, 0);
    W(VMCS_CR3_TARGET_COUNT, 0);
    W(VMCS_EXIT_MSR_STORE_COUNT, 0);
    W(VMCS_EXIT_MSR_LOAD_COUNT, 0);
    W(VMCS_ENTRY_MSR_LOAD_COUNT, 0);
    W(VMCS_ENTRY_INTR_INFO, 0);
    W(VMCS_IO_BITMAP_A, (uint64_t)(uintptr_t)cfg->io_bitmap_a);
    W(VMCS_IO_BITMAP_B, (uint64_t)(uintptr_t)cfg->io_bitmap_b);
    W(VMCS_MSR_BITMAP, (uint64_t)(uintptr_t)cfg->msr_bitmap);
    W(VMCS_EPT_POINTER, cfg->eptp);
    if (proc2 & PROC2_VPID)
        W(VMCS_VPID, cfg->vpid);
    W(VMCS_TSC_OFFSET, 0);
    /* Host-owned CR bits: NE (forced on in VMX operation) and VMXE. The guest sees the
     * shadow (0) and may write them without effect on the real bits. */
    W(VMCS_CR0_GUEST_HOST_MASK, CR0_NE);
    W(VMCS_CR0_READ_SHADOW, 0);
    W(VMCS_CR4_GUEST_HOST_MASK, CR4_VMXE);
    W(VMCS_CR4_READ_SHADOW, 0);

    /* ---- host state ---- */
    cr0_host = read_cr0();
    cr4_host = read_cr4();
    W(VMCS_HOST_CR0, cr0_host);
    W(VMCS_HOST_CR3, read_cr3());
    W(VMCS_HOST_CR4, cr4_host);
    W(VMCS_HOST_ES_SEL, HOST_DS);
    W(VMCS_HOST_CS_SEL, HOST_CS);
    W(VMCS_HOST_SS_SEL, HOST_DS);
    W(VMCS_HOST_DS_SEL, HOST_DS);
    W(VMCS_HOST_FS_SEL, 0);
    W(VMCS_HOST_GS_SEL, 0);
    W(VMCS_HOST_TR_SEL, HOST_TR);
    W(VMCS_HOST_FS_BASE, 0);
    W(VMCS_HOST_GS_BASE, 0);
    W(VMCS_HOST_TR_BASE, cpu_topology.tss[cpu]);
    W(VMCS_HOST_GDTR_BASE, cpu_topology.gdt[cpu]);
    W(VMCS_HOST_IDTR_BASE, cpu_topology.idt[cpu]);
    W(VMCS_HOST_SYSENTER_CS, 0);
    W(VMCS_HOST_SYSENTER_ESP, 0);
    W(VMCS_HOST_SYSENTER_EIP, 0);
    W(VMCS_HOST_EFER, rdmsr(MSR_IA32_EFER));
    W(VMCS_HOST_PAT, rdmsr(MSR_IA32_PAT));
    *(uint64_t *)(vc->exit_stack + VCPU_EXIT_STACK_BYTES - 8) = (uint64_t)(uintptr_t)vc;
    W(VMCS_HOST_RSP, (uint64_t)(uintptr_t)(vc->exit_stack + VCPU_EXIT_STACK_BYTES - 8));
    W(VMCS_HOST_RIP, (uint64_t)(uintptr_t)vmx_exit_entry);

    /* ---- guest state ---- */
    guest_cr0 = CR0_NE | 0x10;              /* ET | NE */
    guest_cr4 = CR4_VMXE;
    guest_efer = 0;
    if (cfg->mode != VMODE_REAL)
        guest_cr0 |= CR0_PE;
    if (lm) {
        guest_cr0 |= CR0_PG | CR0_WP;
        guest_cr4 |= CR4_PAE;
        guest_efer = EFER_LME | EFER_LMA;
    }
    W(VMCS_GUEST_CR0, guest_cr0);
    W(VMCS_GUEST_CR3, cfg->cr3);
    W(VMCS_GUEST_CR4, guest_cr4);
    W(VMCS_GUEST_DR7, 0x400);
    W(VMCS_GUEST_RSP, cfg->rsp);
    W(VMCS_GUEST_RIP, cfg->rip);
    W(VMCS_GUEST_RFLAGS, 0x2);
    if (real) {
        const uint64_t base = (uint64_t)cfg->cs_sel << 4;
        W(VMCS_GUEST_CS_SEL, cfg->cs_sel);
        W(VMCS_GUEST_CS_BASE, base);
        W(VMCS_GUEST_CS_LIMIT, 0xffff);
        W(VMCS_GUEST_CS_AR, 0x9b);
    } else {
        W(VMCS_GUEST_CS_SEL, cfg->code_sel);
        W(VMCS_GUEST_CS_BASE, 0);
        W(VMCS_GUEST_CS_LIMIT, 0xffffffffu);
        W(VMCS_GUEST_CS_AR, lm ? AR_CODE64 : AR_CODE32);
    }
    static const struct { unsigned sel, base, limit, ar; } seg[] = {
        {VMCS_GUEST_ES_SEL, VMCS_GUEST_ES_BASE, VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_AR},
        {VMCS_GUEST_SS_SEL, VMCS_GUEST_SS_BASE, VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_AR},
        {VMCS_GUEST_DS_SEL, VMCS_GUEST_DS_BASE, VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_AR},
        {VMCS_GUEST_FS_SEL, VMCS_GUEST_FS_BASE, VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_AR},
        {VMCS_GUEST_GS_SEL, VMCS_GUEST_GS_BASE, VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_AR},
    };
    for (i = 0; i < 5; ++i) {
        W(seg[i].sel, real ? 0 : cfg->data_sel);
        W(seg[i].base, 0);
        W(seg[i].limit, real ? 0xffff : 0xffffffffu);
        W(seg[i].ar, real ? 0x93 : AR_DATA);
    }
    W(VMCS_GUEST_LDTR_SEL, 0);
    W(VMCS_GUEST_LDTR_BASE, 0);
    W(VMCS_GUEST_LDTR_LIMIT, 0xffff);
    W(VMCS_GUEST_LDTR_AR, 0x10000);         /* unusable */
    W(VMCS_GUEST_TR_SEL, 0);
    W(VMCS_GUEST_TR_BASE, 0);
    W(VMCS_GUEST_TR_LIMIT, real ? 0xffff : 0x67);
    W(VMCS_GUEST_TR_AR, AR_TSS_BUSY);
    W(VMCS_GUEST_GDTR_BASE, real ? 0 : cfg->gdt_base);
    W(VMCS_GUEST_GDTR_LIMIT, real ? 0xffff : cfg->gdt_limit);
    W(VMCS_GUEST_IDTR_BASE, 0);
    W(VMCS_GUEST_IDTR_LIMIT, real ? 0x3ff : 0);
    W(VMCS_GUEST_INTERRUPTIBILITY, 0);
    W(VMCS_GUEST_ACTIVITY, 0);
    W(VMCS_GUEST_PENDING_DBG, 0);
    W(VMCS_LINK_POINTER, ~0ull);
    W(VMCS_GUEST_DEBUGCTL, 0);
    W(VMCS_GUEST_EFER, guest_efer);
    W(VMCS_GUEST_PAT, 0x0007040600070406ull);
    W(VMCS_GUEST_SYSENTER_CS, 0);
    W(VMCS_GUEST_SYSENTER_ESP, 0);
    W(VMCS_GUEST_SYSENTER_EIP, 0);
out:
    if (fail) {
        log_capture(info->last_error, sizeof info->last_error, "VMWRITE %s failed (instr error %llu)", fail,
                    vmread(VMCS_INSTR_ERROR));
        return -1;
    }
    vc->owner_cpu = cpu;
    vc->domain_id = cfg->vpid;
    vc->cpu_binding_valid = 1;
    return 0;
}

/* Interrupt-window exiting on/off (primary control bit 2). */
void vmx_set_interrupt_window(vcpu_t *vc, int on)
{
    uint64_t proc = vmread(VMCS_PROC_CONTROLS);
    if (on)
        proc |= PROC_INT_WINDOW;
    else
        proc &= ~(uint64_t)PROC_INT_WINDOW;
    vmwrite(VMCS_PROC_CONTROLS, proc);
    vc->pending_irq_window = on;
}

/* External interrupt injection (type 0). Caller has verified RFLAGS.IF and no shadow. */
void vmx_inject_external(uint8_t vector)
{
    vmwrite(VMCS_ENTRY_INTR_INFO, 0x80000000ull | vector);
}

void vmx_inject_exception(uint8_t vector, int has_error, uint32_t error)
{
    vmwrite(VMCS_ENTRY_INTR_INFO, 0x80000000ull | (3u << 8) | (has_error ? (1u << 11) : 0) | vector);
    if (has_error)
        vmwrite(VMCS_ENTRY_EXC_ERRCODE, error);
}

int vmx_guest_interruptible(void)
{
    return (vmread(VMCS_GUEST_RFLAGS) & 0x200) && !(vmread(VMCS_GUEST_INTERRUPTIBILITY) & 3);
}

/* Snapshot for the evidence block. */
void vmx_snapshot(shz_vmcs_snapshot_t *dst)
{
    dst->rip = vmread(VMCS_GUEST_RIP);
    dst->rflags = vmread(VMCS_GUEST_RFLAGS);
    dst->cr0 = vmread(VMCS_GUEST_CR0);
    dst->cr4 = vmread(VMCS_GUEST_CR4);
    dst->efer = vmread(VMCS_GUEST_EFER);
    dst->cs_sel = vmread(VMCS_GUEST_CS_SEL);
    dst->cs_base = vmread(VMCS_GUEST_CS_BASE);
    dst->cs_ar = vmread(VMCS_GUEST_CS_AR);
    dst->exit_reason = vmread(VMCS_EXIT_REASON);
    dst->exit_qual = vmread(VMCS_EXIT_QUAL);
    dst->valid = 1;
}
