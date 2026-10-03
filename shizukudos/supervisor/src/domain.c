/* SPDX-License-Identifier: GPL-2.0-only
 * Generic domain machinery: exit dispatch shared by every guest kind, the SHZ_HC_*
 * hypercall implementation, virtual interrupt delivery and the round-robin scheduler.
 */
#include "domain.h"
#include "bios.h"
#include "console.h"
#include "cpu.h"
#include "devices.h"
#include "pool.h"
#include "video.h"
#include "../native_win98/win98.h"

domain_t g_dom[SHZ_MAX_DOMAINS];
shz_info_t *g_info;
uint64_t g_tsc_hz;
static uint64_t g_start_tsc, g_preempt_shift;
static char console_line[SHZ_MAX_DOMAINS][160];
static unsigned console_len[SHZ_MAX_DOMAINS];

static shz_domain_info_t *dinfo(const domain_t *d) { return &g_info->domains[d->id]; }

/* ------------------------------------------------------------------ helpers */
void dom_fail(domain_t *d, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    {
        char tmp[96];
        unsigned i;
        /* format through a bounded local buffer, then publish */
        log_capture_v(tmp, sizeof tmp, fmt, ap);
        for (i = 0; i < sizeof tmp && tmp[i]; ++i)
            dinfo(d)->error[i] = tmp[i];
        dinfo(d)->error[i < 95 ? i : 95] = 0;
        kprintf("SHZ: domain %s FAILED: %s\n", d->name, tmp);
    }
    va_end(ap);
    d->state = SHZ_DS_FAILED;
    dinfo(d)->state = SHZ_DS_FAILED;
    dinfo(d)->last_rip = vmread(VMCS_GUEST_RIP);
    dinfo(d)->last_cs = vmread(VMCS_GUEST_CS_SEL);
}

void dom_exit(domain_t *d, uint32_t code)
{
    d->state = SHZ_DS_EXITED;
    dinfo(d)->state = SHZ_DS_EXITED;
    dinfo(d)->exit_code = code;
    kprintf("SHZ: domain %s exited with code %u\n", d->name, code);
}

uint8_t *dom_gpa_ptr(domain_t *d, uint64_t gpa, uint64_t len)
{
    unsigned c;
    if (gpa <= d->ram_size && len <= d->ram_size - gpa)
        return (uint8_t *)(uintptr_t)(d->ram_base + gpa);
    for (c = 0; c < SHZ_MAX_CHANNELS; ++c) {
        const uint64_t base = SHZ_IPC_GPA_BASE + (uint64_t)c * SHZ_IPC_REGION_SIZE;
        if (d->chan[c].mapped && gpa >= base && gpa - base <= SHZ_IPC_REGION_SIZE &&
            len <= SHZ_IPC_REGION_SIZE - (gpa - base))
            return (uint8_t *)(uintptr_t)(d->chan[c].hpa + (gpa - base));
    }
    return 0;
}

void dom_advance_rip(void)
{
    vmwrite(VMCS_GUEST_RIP, vmread(VMCS_GUEST_RIP) + vmread(VMCS_EXIT_INSTR_LEN));
}

/* Line-buffered kernel console so concurrent domains do not interleave mid-line. */
void dom_console(domain_t *d, const uint8_t *data, unsigned len)
{
    unsigned i;
    for (i = 0; i < len; ++i) {
        const char c = (char)data[i];
        char *line = console_line[d->id];
        unsigned *n = &console_len[d->id];
        if (c == '\r')
            continue;
        if (c == '\n' || *n >= sizeof console_line[0] - 1) {
            line[*n] = 0;
            kprintf("[%s] %s\n", d->name, line);
            *n = 0;
            if (c == '\n')
                continue;
        }
        line[(*n)++] = c;
    }
    g_info->guest_console_bytes += len;
}

static uint64_t elapsed_ns(void)
{
    const uint64_t t = rdtsc() - g_start_tsc, sec = t / g_tsc_hz, rem = t % g_tsc_hz;
    return sec * 1000000000ull + rem * 1000000000ull / g_tsc_hz;
}

/* ------------------------------------------------------------------ CPUID */
/* CPUID as seen by every guest: host leaves with virtualization, topology and the
 * state-heavy ISA extensions hidden, and a hypervisor signature at 0x40000000. */
static void handle_cpuid(domain_t *d)
{
    const uint32_t leaf = (uint32_t)d->vc.gpr[GPR_RAX];
    const uint32_t sub = (uint32_t)d->vc.gpr[GPR_RCX];
    struct cpuid_regs r;
    if (leaf == 0x40000000) {
        r.eax = 0x40000001;
        r.ebx = 0x5a485353;             /* "SSHZ" */
        r.ecx = 0x4d4d5675;             /* "uVMM" */
        r.edx = 0x30312d76;             /* "v-10" */
    } else if (leaf == 0x40000001) {
        r.eax = r.ebx = r.ecx = r.edx = 0;
    } else {
        r = cpuid_count(leaf, sub);
        if (leaf == 1) {
            r.ecx &= ~((1u << 5) | (1u << 6) | (1u << 7) | (1u << 8) | (1u << 17) | (1u << 21) |
                       (1u << 26) | (1u << 27) | (1u << 28) | (1u << 3));
            r.ecx |= 1u << 31;          /* hypervisor present */
            r.edx &= ~(1u << 28);       /* no hyper-threading */
            r.ebx = (r.ebx & 0x0000ffffu) | (1u << 16);   /* one logical processor, APIC ID 0 */
            /* Native firmware must not probe unimplemented MTRR MSRs (FE,
             * fixed/variable ranges). Neither MTRRs nor PSE36 are modeled. */
            if (d->kind == DK_WIN98) r.edx &= ~((1u << 17) | (1u << 12));
            r.edx &= ~(1u << 9);        /* no local APIC is modelled */
        } else if (leaf == 4) {
            r.eax &= ~0xfc000000u;      /* single core */
        } else if (leaf == 0xb || leaf == 0x1f || leaf == 0x14 || leaf == 0x15 || leaf == 0x16) {
            r.eax = r.ebx = r.ecx = r.edx = 0;
        } else if (leaf == 7) {
            r.ebx &= ~((1u << 2) | (1u << 10) | (1u << 20));   /* SGX, INVPCID, SMAP hidden */
            r.ecx = 0;
            r.edx = 0;
        } else if (leaf == 0x80000001 && d->kind != DK_KERNEL64) {
            r.edx &= ~((1u << 29) | (1u << 11));        /* Long Mode / SYSCALL not offered to 16/32-bit guests */
        }
    }
    d->vc.gpr[GPR_RAX] = r.eax;
    d->vc.gpr[GPR_RBX] = r.ebx;
    d->vc.gpr[GPR_RCX] = r.ecx;
    d->vc.gpr[GPR_RDX] = r.edx;
    dom_advance_rip();
}

static void handle_cr_access(domain_t *d)
{
    /* Guest CR0/CR4 accesses to host-owned bits (CR0.NE, CR4.VMXE): emulate MOV to/from CR. */
    const uint64_t q = vmread(VMCS_EXIT_QUAL);
    const unsigned cr = (unsigned)(q & 15);
    const unsigned type = (unsigned)((q >> 4) & 3);
    const unsigned reg = (unsigned)((q >> 8) & 15);
    uint64_t v;
    if (type == 0) {                          /* MOV to CR */
        v = reg == 4 ? vmread(VMCS_GUEST_RSP) : d->vc.gpr[reg];
        if (cr == 0) {
            vmwrite(VMCS_CR0_READ_SHADOW, v & CR0_NE);
            vmwrite(VMCS_GUEST_CR0, (v | CR0_NE) & 0xffffffffull);
        } else if (cr == 4) {
            vmwrite(VMCS_CR4_READ_SHADOW, v & CR4_VMXE);
            vmwrite(VMCS_GUEST_CR4, v | CR4_VMXE);
        } else if (cr == 3) {
            vmwrite(VMCS_GUEST_CR3, v);
        }
    } else if (type == 1) {                   /* MOV from CR */
        v = cr == 0 ? (vmread(VMCS_GUEST_CR0) & ~CR0_NE) | vmread(VMCS_CR0_READ_SHADOW)
          : cr == 4 ? (vmread(VMCS_GUEST_CR4) & ~CR4_VMXE) | vmread(VMCS_CR4_READ_SHADOW)
          : cr == 3 ? vmread(VMCS_GUEST_CR3) : 0;
        if (reg != 4)
            d->vc.gpr[reg] = v;
    } else if (type == 2) {                   /* CLTS */
        vmwrite(VMCS_GUEST_CR0, vmread(VMCS_GUEST_CR0) & ~8ull);
    } else if (type == 3) {                   /* LMSW */
        const uint64_t src = (q >> 16) & 0xffff;
        vmwrite(VMCS_GUEST_CR0, (vmread(VMCS_GUEST_CR0) & ~0xeull) | (src & 0xe) | CR0_NE);
    }
    dom_advance_rip();
}

/* ------------------------------------------------------------------ MSRs for 32/64-bit kernels */
static void handle_msr(domain_t *d, int write)
{
    const uint32_t msr = (uint32_t)d->vc.gpr[GPR_RCX];
    const uint64_t value = ((uint64_t)(uint32_t)d->vc.gpr[GPR_RDX] << 32) | (uint32_t)d->vc.gpr[GPR_RAX];
    uint64_t out = 0;
    int ok = 1;
    switch (msr) {
    case MSR_IA32_EFER:
        if (write) {
            const uint64_t cur = vmread(VMCS_GUEST_EFER);
            const uint64_t allowed = (1ull << 0) | (1ull << 11);          /* SCE, NXE */
            if ((value & ~(allowed | EFER_LME | EFER_LMA)) || ((value ^ cur) & (EFER_LME | EFER_LMA)))
                ok = 0;                        /* mode changes go through CR0/CR4, not WRMSR */
            else
                vmwrite(VMCS_GUEST_EFER, value);
        } else {
            out = vmread(VMCS_GUEST_EFER);
        }
        break;
    case MSR_IA32_PAT:
        if (write) vmwrite(VMCS_GUEST_PAT, value); else out = vmread(VMCS_GUEST_PAT);
        break;
    case MSR_IA32_APIC_BASE:                     /* no local APIC exists for this domain */
        if (write) ok = 0; else out = 0;
        break;
    case 0x1b0: case 0x8b: case 0x179: case 0x17a: case 0xe7: case 0xe8:   /* benign probes */
        out = 0;
        break;
    default:
        ok = 0;
    }
    if (!ok) {
        vmx_inject_exception(13, 1, 0);          /* #GP(0), as hardware does for an unimplemented MSR */
        if (write)
            dinfo(d)->reserved[0] = msr;         /* remember the last rejected MSR for diagnosis */
        else
            dinfo(d)->reserved[1] = msr;
        return;
    }
    if (!write) {
        d->vc.gpr[GPR_RAX] = (uint32_t)out;
        d->vc.gpr[GPR_RDX] = (uint32_t)(out >> 32);
    }
    dom_advance_rip();
}

/* Serial port 0x3F8 as an early-boot debug console for 32/64-bit kernels. */
static void kernel_handle_io(domain_t *d)
{
    const uint64_t q = vmread(VMCS_EXIT_QUAL);
    const int size = (int)(q & 7) + 1;
    const int in = (int)((q >> 3) & 1);
    const uint16_t port = (uint16_t)(q >> 16);
    ++g_info->io_exits;
    if (in) {
        uint32_t v = 0xffffffffu;
        if (port == 0x3fd)
            v = 0x60;                            /* THR empty, transmitter idle */
        else
            ++g_info->io_unhandled;
        if (size == 1) d->vc.gpr[GPR_RAX] = (d->vc.gpr[GPR_RAX] & ~0xffull) | (v & 0xff);
        else if (size == 2) d->vc.gpr[GPR_RAX] = (d->vc.gpr[GPR_RAX] & ~0xffffull) | (v & 0xffff);
        else d->vc.gpr[GPR_RAX] = v;
    } else if (port == 0x3f8) {
        const uint8_t c = (uint8_t)d->vc.gpr[GPR_RAX];
        dom_console(d, &c, 1);
    } else {
        ++g_info->io_unhandled;
    }
    dom_advance_rip();
}

/* ------------------------------------------------------------------ hypercalls */
int hcall_vmcall(domain_t *d)
{
    uint64_t *r = d->vc.gpr;
    const uint64_t op = r[GPR_RAX];
    int64_t status = SHZ_OK;
    const uint64_t now = rdtsc();
    ++dinfo(d)->hypercalls;
    ++g_info->hypercalls;
    switch (op) {
    case SHZ_HC_CONSOLE_WRITE: {
        const uint64_t len = r[GPR_RCX];
        const uint8_t *p;
        if (len > 512) { status = SHZ_E_RANGE; break; }
        p = dom_gpa_ptr(d, r[GPR_RBX], len);
        if (!p) { status = SHZ_E_RANGE; break; }
        dom_console(d, p, (unsigned)len);
        break;
    }
    case SHZ_HC_EXIT:
        dom_exit(d, (uint32_t)r[GPR_RBX]);
        break;
    case SHZ_HC_TIMER_SET: {
        const uint64_t us = r[GPR_RCX];
        if (!us) {
            d->timer_period = 0;
        } else if (r[GPR_RBX] < 32 || r[GPR_RBX] > 255 || us > 10000000ull) {
            status = SHZ_E_INVALID;
        } else {
            d->timer_vector = (uint8_t)r[GPR_RBX];
            d->timer_period = us * (g_tsc_hz / 1000000ull);
            d->timer_next = now + d->timer_period;
        }
        break;
    }
    case SHZ_HC_NOTIFY: {
        const uint64_t target = r[GPR_RBX];
        if (target < 2 || target >= SHZ_MAX_DOMAINS || !g_dom[target].state ||
            g_dom[target].state == SHZ_DS_EXITED || g_dom[target].state == SHZ_DS_FAILED) {
            status = SHZ_E_NOENT;
            break;
        }
        g_dom[target].doorbell_pending |= (uint32_t)r[GPR_RCX];
        g_dom[target].doorbell_signaled = 0;
        break;
    }
    case SHZ_HC_WAIT:
        /* Injection only records interrupt delivery. Pending work is consumed
         * by DOORBELL_ACK, so WAIT must not park an unacknowledged notification. */
        if (!d->doorbell_pending)
            d->state = SHZ_DS_WAITING;
        break;
    case SHZ_HC_TIME:
        r[GPR_RBX] = elapsed_ns();
        break;
    case SHZ_HC_SET_DOORBELL_VECTOR:
        if (r[GPR_RBX] < 32 || r[GPR_RBX] > 255) status = SHZ_E_INVALID;
        else d->doorbell_vector = (uint8_t)r[GPR_RBX];
        break;
    case SHZ_HC_DOORBELL_ACK:
        r[GPR_RBX] = d->doorbell_pending;
        d->doorbell_pending = 0;
        d->doorbell_signaled = 0;
        break;
    case SHZ_HC_EVIDENCE:
        if (r[GPR_RBX] < SHZ_EVIDENCE_SLOTS) dinfo(d)->evidence[r[GPR_RBX]] = r[GPR_RCX];
        else status = SHZ_E_RANGE;
        break;
    case SHZ_HC_DOMAIN_STATE: {
        const uint64_t t = r[GPR_RBX];
        if (t < 2 || t >= SHZ_MAX_DOMAINS) { status = SHZ_E_NOENT; break; }
        r[GPR_RBX] = g_dom[t].state;
        r[GPR_RCX] = g_dom[t].generation;
        break;
    }
    case SHZ_HC_ABI_VERSION:
        r[GPR_RBX] = ((uint64_t)SHZ_ABI_MAJOR << 16) | SHZ_ABI_MINOR;
        break;
    case SHZ_HC_CHANNEL_INFO: {                 /* the Win98 domain's VxD has no bootinfo: it asks for its channels */
        const uint64_t c = r[GPR_RBX];
        if (c >= SHZ_MAX_CHANNELS || !d->chan[c].mapped) { status = SHZ_E_NOENT; break; }
        r[GPR_RBX] = SHZ_IPC_GPA_BASE + c * SHZ_IPC_REGION_SIZE;
        r[GPR_RCX] = d->chan[c].peer;
        break;
    }
    case SHZ_HC_NATIVE_GOP_EPOCH: {
        uint32_t word=0;
        status=win98_native_gop_epoch_word(d,r[GPR_RBX],r[GPR_RCX],&word);
        r[GPR_RBX]=status==SHZ_OK?word:0;r[GPR_RCX]=status==SHZ_OK?40:0;
        break;
    }
    case SHZ_HC_WALLTIME: {
        /* RTC registers are BCD (or binary, per register B bit 2); convert the platform clock. */
        const uint8_t regb = dev_cmos_read(0x0b), bin = (regb >> 2) & 1;
        unsigned sec = dev_cmos_read(0), min = dev_cmos_read(2), hour = dev_cmos_read(4), day = dev_cmos_read(7),
                 mon = dev_cmos_read(8), yr = dev_cmos_read(9), cent = dev_cmos_read(0x32);
        unsigned y, m, days;
        static const unsigned mdays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        if (!bin) {
#define BCD(v) ((((v) >> 4) & 15) * 10 + ((v) & 15))
            sec = BCD(sec); min = BCD(min); hour = BCD(hour & 0x7f); day = BCD(day); mon = BCD(mon);
            yr = BCD(yr); cent = BCD(cent);
#undef BCD
        }
        y = (cent ? cent : 20) * 100 + yr;
        days = 0;
        for (m = 1970; m < y; ++m)
            days += (m % 4 == 0 && (m % 100 != 0 || m % 400 == 0)) ? 366 : 365;
        for (m = 1; m < mon && m <= 12; ++m) {
            days += mdays[m - 1];
            if (m == 2 && y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ++days;
        }
        days += day ? day - 1 : 0;
        r[GPR_RBX] = (uint64_t)days * 86400 + hour * 3600 + min * 60 + sec;
        break;
    }
    default:
        status = SHZ_E_UNSUPPORTED;
    }
    r[GPR_RAX] = (uint64_t)status;
    dom_advance_rip();
    return 0;
}

/* ------------------------------------------------------------------ interrupt delivery */
static int kernel_ready(domain_t *d, uint64_t now)
{
    if (d->timer_period && now >= d->timer_next)
        return 1;
    return d->doorbell_vector && d->doorbell_pending && !d->doorbell_signaled;
}

static void deliver_events(domain_t *d, uint64_t now)
{
    int vector = -1, is_timer = 0, win98_doorbell = 0, is_dos = d->kind == DK_DOS16 || d->kind == DK_WIN98;
    if (is_dos) {
        dev_poll(now);
        if (dev_irq_pending())
            vector = -2;                       /* resolved at acceptance time */
        else if (d->kind == DK_WIN98 && d->doorbell_vector && d->doorbell_pending && !d->doorbell_signaled) {
            vector = d->doorbell_vector; win98_doorbell = 1;
        }
    } else if (d->timer_period && now >= d->timer_next) {
        vector = d->timer_vector;
        is_timer = 1;
    } else if (d->doorbell_vector && d->doorbell_pending && !d->doorbell_signaled) {
        vector = d->doorbell_vector;
    }
    if (vector == -1) {
        if (d->vc.pending_irq_window)
            vmx_set_interrupt_window(&d->vc, 0);
        return;
    }
    if (vmx_guest_interruptible()) {
        if (is_dos && !win98_doorbell)
            vector = dev_ack_irq();
        if (vector >= 0) {
            vmx_inject_external((uint8_t)vector);
            ++dinfo(d)->irqs_injected;
            ++g_info->injected_irqs;
            if (is_timer) {
                do d->timer_next += d->timer_period; while (d->timer_next <= now);
            } else if (!is_dos || win98_doorbell) {
                d->doorbell_signaled = 1;
            }
        }
        if (d->vc.pending_irq_window)
            vmx_set_interrupt_window(&d->vc, 0);
    } else if (!d->vc.pending_irq_window) {
        vmx_set_interrupt_window(&d->vc, 1);
    }
}

static void arm_preemption_timer(domain_t *d, uint64_t now)
{
    uint64_t budget = g_tsc_hz / 1000;                 /* 1 ms slice */
    uint64_t next = 0, ticks;
    if (d->kind == DK_DOS16 || d->kind == DK_WIN98)
        next = dev_next_event_tsc();
    else if (d->timer_period)
        next = d->timer_next;
    /* An event that is already due but could not be injected (guest not interruptible) is
     * delivered through interrupt-window exiting; shrinking the slice would only livelock the
     * guest, because the preemption timer can expire before any guest instruction retires. */
    if (next > now && next - now < budget)
        budget = next - now;
    if (budget < g_tsc_hz / 50000)                      /* never below ~20 us */
        budget = g_tsc_hz / 50000;
    ticks = budget >> g_preempt_shift;
    vmwrite(VMCS_PREEMPT_TIMER_VALUE, ticks ? ticks : 1);
}

/* ------------------------------------------------------------------ fx state */
static inline void fx_save(domain_t *d) { __asm__ volatile("fxsave (%0)" :: "r"(d->fx) : "memory"); }
static inline void fx_restore(domain_t *d) { __asm__ volatile("fxrstor (%0)" :: "r"(d->fx) : "memory"); }

/* ------------------------------------------------------------------ exit dispatch */
static void handle_exit(domain_t *d, uint32_t reason)
{
    switch (reason) {
    case EXIT_EXTERNAL_INTERRUPT:
    case EXIT_PREEMPTION_TIMER:
    case EXIT_INTERRUPT_WINDOW:
        return;
    case EXIT_CPUID: handle_cpuid(d); return;
    case EXIT_CR_ACCESS: handle_cr_access(d); return;
    case EXIT_EXCEPTION_NMI:
        if (((vmread(VMCS_EXIT_INTR_INFO) >> 8) & 7) == 2)
            return;                              /* NMI: not forwarded to a guest */
        dom_fail(d, "unexpected guest exception exit info=%llx", vmread(VMCS_EXIT_INTR_INFO));
        return;
    case EXIT_TRIPLE_FAULT:
        dom_fail(d, "guest triple fault at rip=%llx", vmread(VMCS_GUEST_RIP));
        return;
    case EXIT_EPT_VIOLATION:
    case EXIT_EPT_MISCONFIG:
        dom_fail(d, "EPT %s gpa=%llx qual=%llx rip=%llx",
                 reason == EXIT_EPT_VIOLATION ? "violation" : "misconfig", vmread(VMCS_GUEST_PHYS_ADDR),
                 vmread(VMCS_EXIT_QUAL), vmread(VMCS_GUEST_RIP));
        return;
    case EXIT_INVD:
    case EXIT_WBINVD:
    case EXIT_PAUSE:
    case EXIT_MWAIT:
    case EXIT_MONITOR:
        dom_advance_rip();
        return;
    default:
        break;
    }
    if (d->kind == DK_WIN98) {
        if (reason == EXIT_VMCALL) { hcall_vmcall(d); return; }
        if (win98_handle_exit(d, reason)) return;
        if (reason == EXIT_RDMSR) { handle_msr(d, 0); return; }
        if (reason == EXIT_WRMSR) { handle_msr(d, 1); return; }
    } else if (d->kind == DK_DOS16) {
        if (dos_handle_exit(d, reason))
            return;
    } else {
        switch (reason) {
        case EXIT_VMCALL: hcall_vmcall(d); return;
        case EXIT_IO: kernel_handle_io(d); return;
        case EXIT_HLT:
            dom_advance_rip();
            if (!(vmread(VMCS_GUEST_RFLAGS) & 0x200)) {
                dom_fail(d, "guest halted with interrupts disabled");
            } else {
                d->state = SHZ_DS_WAITING;
            }
            return;
        case EXIT_RDMSR: handle_msr(d, 0); return;
        case EXIT_WRMSR: handle_msr(d, 1); return;
        default: break;
        }
    }
    dom_fail(d, "unhandled VM exit reason %u qual=%llx", reason, vmread(VMCS_EXIT_QUAL));
}

static void record_state(domain_t *d, uint64_t now)
{
    shz_domain_info_t *i = dinfo(d);
    if (now - d->last_snapshot_tsc < g_tsc_hz / 100 && d->state == SHZ_DS_RUNNABLE)
        return;
    d->last_snapshot_tsc = now;
    i->state = d->state;
    i->last_cr0 = vmread(VMCS_GUEST_CR0);
    i->last_cr3 = vmread(VMCS_GUEST_CR3);
    i->last_cr4 = vmread(VMCS_GUEST_CR4);
    i->last_efer = vmread(VMCS_GUEST_EFER);
    i->last_rip = vmread(VMCS_GUEST_RIP);
    i->last_cs = vmread(VMCS_GUEST_CS_SEL);
}

/* One scheduling slice of domain `d`. Returns nonzero when the VM entry itself failed. */
static int run_slice(domain_t *d)
{
    uint64_t now = rdtsc();
    uint32_t reason;
    int rc;

    if (vmx_vcpu_load(&d->vc)) {
        dom_fail(d, "VMCS CPU ownership/load failed");
        return -1;
    }
    deliver_events(d, now);
    arm_preemption_timer(d, now);
    fx_restore(d);
    {
        const uint64_t host_cr2 = read_cr2();
        const int mixed = (g_info->loader_flags & SHZ_LOADER_NATIVE_WIN98) != 0;
        if(d->kind==DK_WIN98 && win98_execution_begin(d)){
            dom_fail(d,"native persistence execution epoch refused");return -1;
        }
        if (mixed) write_cr2(d->guest_cr2);
        rc = vmx_enter(&d->vc);
        if(d->kind==DK_WIN98 && win98_execution_end(d)){
            if(mixed)write_cr2(host_cr2);
            dom_fail(d,"native persistence returned execution epoch differs");return -1;
        }
        if (mixed) { d->guest_cr2 = read_cr2(); write_cr2(host_cr2); }
    }
    fx_save(d);
    if (rc) {
        dom_fail(d, "VM entry failed (VMfail %d, error %llu)", rc, vmread(VMCS_INSTR_ERROR));
        return -1;
    }
    d->vc.launched = 1;
    reason = (uint32_t)vmread(VMCS_EXIT_REASON);
    ++g_info->total_exits;
    ++g_info->exit_count[(reason & 0xffff) & 63];
    ++dinfo(d)->exits;
    ++dinfo(d)->run_slices;
    if (d->kind == DK_DOS16 && !g_info->first_exit.valid) {
        vmx_snapshot(&g_info->first_exit);
        kprintf("SHZ: DOS16 first VM exit reason=%u rip=%llx cr0=%llx cs=%llx\n", reason & 0xffff,
                vmread(VMCS_GUEST_RIP), vmread(VMCS_GUEST_CR0), vmread(VMCS_GUEST_CS_SEL));
    }
    if (reason & 0x80000000u) {
        vmx_snapshot(&g_info->last_exit);
        dom_fail(d, "VM entry failure exit reason=%x qual=%llx", reason & 0xffff, vmread(VMCS_EXIT_QUAL));
        return -1;
    }
    if (d->kind == DK_WIN98)
        win98_observe_exit(d, reason & 0xffff);
    handle_exit(d, reason & 0xffff);
    if (d->kind == DK_DOS16) {
        dos_housekeeping();
        if (rdtsc() - d->last_snapshot_tsc > g_tsc_hz / 100)
            vmx_snapshot(&g_info->last_exit);
    }
    if (d->kind == DK_WIN98) win98_housekeeping();
    record_state(d, rdtsc());
    return 0;
}

int sched_run(shz_info_t *info)
{
    unsigned last = 0;
    g_info = info;
    g_tsc_hz = info->tsc_hz;
    g_start_tsc = rdtsc();
    g_preempt_shift = rdmsr(MSR_IA32_VMX_MISC) & 0x1f;
    info->stage = SHZ_STAGE_LAUNCHED;
    for (;;) {
        domain_t *pick = 0;
        unsigned live = 0, n;
        const uint64_t now = rdtsc();
        for (n = 1; n <= SHZ_MAX_DOMAINS; ++n) {
            domain_t *d = &g_dom[(last + n) % SHZ_MAX_DOMAINS];
            if (d->state != SHZ_DS_RUNNABLE && d->state != SHZ_DS_WAITING)
                continue;
            ++live;
            if (!pick) {
                if (d->state == SHZ_DS_WAITING) {
                    const int ready = d->kind == DK_DOS16 ? dos_ready(d, now) : d->kind == DK_WIN98 ? win98_ready(d, now) : kernel_ready(d, now);
                    if (ready) {
                        d->state = SHZ_DS_RUNNABLE;
                        pick = d;
                    }
                } else {
                    pick = d;
                }
            }
        }
        if (!live)
            break;
        if (!pick) {
            /* everything is idle: keep the display and input alive, then spin briefly */
            if (info->loader_flags & SHZ_LOADER_NATIVE_WIN98) win98_housekeeping();
            else { dos_housekeeping(); bios_poll_input(); }
            pause_cpu();
            continue;
        }
        last = pick->id;
        run_slice(pick);
        /* Includes checked-load and VM-entry failure returns, where run_slice
         * never reaches its ordinary post-exit housekeeping. */
        if(pick->kind==DK_WIN98)win98_housekeeping();
    }
    info->stage = SHZ_STAGE_GUEST_EXIT;
    return 0;
}
