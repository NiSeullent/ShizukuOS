/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 and Kernel64 domains, plus the shared IPC channels between domains.
 *
 * The Supervisor acts as the boot loader for these guests: it copies the kernel image
 * to guest-physical 1 MiB, writes a boot GDT and a bootinfo block, and (for Long Mode)
 * a minimal set of boot page tables, then starts the vCPU directly in the guest kernel's
 * target CPU mode. Each guest replaces all of that with its own tables early on.
 */
#include "console.h"
#include "core.h"
#include "cpu.h"
#include "domain.h"
#include "pool.h"
#include "../../abi/shz_ipc.h"
#include "../../boot_profile/win98_foundation.h"
#include "../../kernel32/service_policy.h"

#define BOOT_GDT_GPA 0x6000u
#define BOOT_PML4_GPA 0x1000u
#define BOOT_PDPT_LO_GPA 0x2000u
#define BOOT_PD_GPA 0x3000u
#define BOOT_PDPT_HI_GPA 0x4000u
#define KERNEL_GPA 0x100000ull
#define INITRD_GPA 0x02000000ull
#define K64_VIRT_BASE 0xffffffff80000000ull

static const uint64_t boot_gdt[5] = {
    0,
    0x00cf9b000000ffffull,      /* 0x08 code, 32-bit flat */
    0x00cf93000000ffffull,      /* 0x10 data, flat */
    0x00af9b000000ffffull,      /* 0x18 code, 64-bit */
    0x00cf93000000ffffull,      /* 0x20 data */
};

static const shz_blob_t *find_blob(const shz_info_t *info, const char *name)
{
    unsigned i;
    for (i = 0; i < SHZ_MAX_BLOBS; ++i) {
        const char *n = info->blobs[i].name;
        unsigned k = 0;
        while (n[k] && name[k] && n[k] == name[k])
            ++k;
        if (n[k] == 0 && name[k] == 0 && info->blobs[i].size)
            return &info->blobs[i];
    }
    return 0;
}

static void build_boot_page_tables(uint8_t *ram, uint64_t ram_size)
{
    uint64_t *pml4 = (uint64_t *)(ram + BOOT_PML4_GPA), *pdpt_lo = (uint64_t *)(ram + BOOT_PDPT_LO_GPA);
    uint64_t *pd = (uint64_t *)(ram + BOOT_PD_GPA), *pdpt_hi = (uint64_t *)(ram + BOOT_PDPT_HI_GPA);
    uint64_t i;
    memset(ram + BOOT_PML4_GPA, 0, 0x4000);
    pml4[0] = BOOT_PDPT_LO_GPA | 3;
    pml4[511] = BOOT_PDPT_HI_GPA | 3;
    pdpt_lo[0] = BOOT_PD_GPA | 3;
    pdpt_hi[510] = BOOT_PD_GPA | 3;             /* 0xFFFFFFFF80000000 -> physical 0 */
    for (i = 0; i < 512 && (i << 21) < ram_size; ++i)
        pd[i] = (i << 21) | 0x83;               /* present, writable, 2 MiB */
}

int kernel_domain_create(shz_info_t *info, const shz_caps_t *caps, dom_kind_t kind)
{
    const int lm = kind == DK_KERNEL64;
    const uint32_t id = lm ? SHZ_DOM_KERNEL64 : SHZ_DOM_KERNEL32;
    const uint64_t base = lm ? info->k64_ram_base : info->k32_ram_base;
    const uint64_t size = lm ? info->k64_ram_size : info->k32_ram_size;
    const shz_blob_t *kernel = find_blob(info, lm ? "KERNEL64.BIN" : "KERNEL32.BIN");
    const shz_blob_t *initrd = lm ? find_blob(info, "WIN64.IMG") : 0;
    domain_t *d = &g_dom[id];
    vmx_cfg_t cfg;
    uint8_t *ram;
    shz_bootinfo_t *bi;

    if (!size || !kernel)
        return 1;                                   /* not configured: not an error */
    memset(d, 0, sizeof *d);
    d->id = id;
    d->name = lm ? "K64" : "K32";
    d->kind = kind;
    d->generation = 1;
    d->ram_base = base;
    d->ram_size = size;
    d->fx[24] = 0x80; d->fx[25] = 0x1f;             /* MXCSR default 0x1F80 */
    d->fx[0] = 0x7f; d->fx[1] = 0x03;              /* FCW default 0x037F */
    if ((base & 0x1fffff) || (size & 0x1fffff) || size < (16ull << 20) || kernel->size > (size - KERNEL_GPA) / 2 ||
        (initrd && (INITRD_GPA + initrd->size > size))) {
        log_capture(info->last_error, sizeof info->last_error, "%s: RAM/kernel/initrd geometry invalid", d->name);
        return -1;
    }
    ram = (uint8_t *)(uintptr_t)base;
    memset(ram, 0, size);
    memcpy(ram + KERNEL_GPA, (const void *)(uintptr_t)kernel->base, kernel->size);
    if (initrd)
        memcpy(ram + INITRD_GPA, (const void *)(uintptr_t)initrd->base, initrd->size);
    memcpy(ram + BOOT_GDT_GPA, boot_gdt, sizeof boot_gdt);
    if (lm)
        build_boot_page_tables(ram, size);

    bi = (shz_bootinfo_t *)(ram + SHZ_BOOTINFO_GPA);
    memset(bi, 0, sizeof *bi);
    bi->magic = SHZ_BOOTINFO_MAGIC;
    bi->abi_major = SHZ_ABI_MAJOR;
    bi->abi_minor = SHZ_ABI_MINOR;
    bi->size = sizeof *bi;
    bi->domain_id = id;
    bi->generation = d->generation;
    bi->ram_size = size;
    bi->kernel_gpa = KERNEL_GPA;
    bi->kernel_size = kernel->size;
    if (initrd) {
        bi->initrd_gpa = INITRD_GPA;
        bi->initrd_size = initrd->size;
    }
    bi->tsc_hz = info->tsc_hz;
    /* Installed-target identity: filled only from the creating ShizukuCore
     * root's admitted, stamped SHZBOOT.MAN; otherwise the tail stays zero
     * (historical unattested route). bi->size above covers the tail, and
     * core.c verify_kernel_load re-checks it against the manifest. */
    if (shz_core_install_identity(&bi->install))
        kprintf("SHZ: domain %s install identity attested by ShizukuCore manifest generation=%llu\n", d->name,
                (unsigned long long)bi->install.install_generation);
    else
        kprintf("SHZ: domain %s install identity unattested (no admitted stamped installed-target manifest)\n",
                d->name);
    /* Native Win98 is the explicit owner of this K32 service lifetime. The
     * existing ABI1.1 command line carries policy; default DOS/QA stays empty.
     */
    if (!lm && info->loader_flags == SHZ_LOADER_NATIVE_WIN98) {
        memcpy(bi->cmdline, K32_WIN98_SERVICE_CMDLINE, sizeof K32_WIN98_SERVICE_CMDLINE);
        bi->cmdline_size = sizeof K32_WIN98_SERVICE_CMDLINE - 1;
    }

    if (ept_init(&d->ept) || ept_map(&d->ept, 0, base, size, EPT_RWX | EPT_WB, 0)) {
        log_capture(info->last_error, sizeof info->last_error, "%s: EPT construction failed", d->name);
        return -1;
    }
    d->io_bitmap_a = pool_alloc_pages(1);
    d->io_bitmap_b = pool_alloc_pages(1);
    d->msr_bitmap = pool_alloc_pages(1);
    cfg.vmcs = pool_alloc_pages(1);
    if (!d->io_bitmap_a || !d->io_bitmap_b || !d->msr_bitmap || !cfg.vmcs) {
        log_capture(info->last_error, sizeof info->last_error, "%s: Supervisor pool exhausted", d->name);
        return -1;
    }
    memset(d->io_bitmap_a, 0xff, 4096);
    memset(d->io_bitmap_b, 0xff, 4096);
    memset(d->msr_bitmap, 0xff, 4096);
    /* MSRs whose state lives in VMCS fields or that only this domain uses are passed through.
     * SYSCALL/SYSRET and swapgs MSRs are NOT context-switched: one Long Mode domain per CPU. */
    msr_bitmap_allow(d->msr_bitmap, 0x10, 1, 0);                  /* TSC */
    msr_bitmap_allow(d->msr_bitmap, MSR_IA32_SYSENTER_CS, 1, 1);
    msr_bitmap_allow(d->msr_bitmap, MSR_IA32_SYSENTER_ESP, 1, 1);
    msr_bitmap_allow(d->msr_bitmap, MSR_IA32_SYSENTER_EIP, 1, 1);
    msr_bitmap_allow(d->msr_bitmap, 0xc0000081u, 1, 1);           /* STAR */
    msr_bitmap_allow(d->msr_bitmap, 0xc0000082u, 1, 1);           /* LSTAR */
    msr_bitmap_allow(d->msr_bitmap, 0xc0000083u, 1, 1);           /* CSTAR */
    msr_bitmap_allow(d->msr_bitmap, 0xc0000084u, 1, 1);           /* SFMASK */
    msr_bitmap_allow(d->msr_bitmap, MSR_IA32_FS_BASE, 1, 1);
    msr_bitmap_allow(d->msr_bitmap, MSR_IA32_GS_BASE, 1, 1);
    msr_bitmap_allow(d->msr_bitmap, 0xc0000102u, 1, 1);           /* KERNEL_GS_BASE */

    cfg.io_bitmap_a = d->io_bitmap_a; cfg.io_bitmap_b = d->io_bitmap_b; cfg.msr_bitmap = d->msr_bitmap;
    cfg.mode = lm ? VMODE_LONG64 : VMODE_PROT32;
    cfg.eptp = ept_pointer(&d->ept);
    cfg.vpid = (uint16_t)id;
    cfg.rip = lm ? K64_VIRT_BASE + KERNEL_GPA : KERNEL_GPA;
    cfg.rsp = 0x70000;
    cfg.cr3 = lm ? BOOT_PML4_GPA : 0;
    cfg.cs_sel = 0;
    cfg.code_sel = lm ? 0x18 : 0x08;
    cfg.data_sel = lm ? 0x20 : 0x10;
    cfg.gdt_base = BOOT_GDT_GPA;
    cfg.gdt_limit = sizeof boot_gdt - 1;
    if (vmx_vcpu_init(&d->vc, info, caps, &cfg))
        return -1;
    d->vc.gpr[GPR_RBX] = SHZ_BOOTINFO_GPA;
    d->vc.gpr[GPR_RDI] = SHZ_BOOTINFO_GPA;
    d->vc.gpr[GPR_RAX] = SHZ_BOOTINFO_MAGIC;
    d->state = SHZ_DS_RUNNABLE;
    info->domains[id].kind = kind;
    info->domains[id].generation = d->generation;
    info->domains[id].state = SHZ_DS_RUNNABLE;
    kprintf("SHZ: domain %s created: %s, %llu MiB RAM at %llx, kernel %llu bytes\n", d->name,
            lm ? "Long Mode" : "Protected Mode", size >> 20, base, kernel->size);
    return 0;
}

/* ------------------------------------------------------------------ IPC channels */
static const struct { uint32_t a, b; } channel_plan[SHZ_MAX_CHANNELS] = {
    {SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64},
    {SHZ_DOM_KERNEL32, SHZ_DOM_DOS16},
    {SHZ_DOM_KERNEL64, SHZ_DOM_WIN98},
    {0, 0},
};

static int alive(uint32_t id) { return id < SHZ_MAX_DOMAINS && g_dom[id].state && g_dom[id].id == id; }

/* Publish the runtime policy only after genuine native domains and their
 * channels exist. A configured loader bit or stale EXITED domain alone cannot
 * create a Windows owner or a worker service channel. */
static int win98_foundation_publish(shz_info_t *info)
{
    static const char command[] = "shz.foundation=win98";
    static const uint32_t ids[] = {SHZ_DOM_WIN98, SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64};
    static const dom_kind_t kinds[] = {DK_WIN98, DK_KERNEL32, DK_KERNEL64};
    shz_bootinfo_t *workers[2], candidates[2];
    unsigned i;
    if (!info->loader_flags) return 0;
    if (info->loader_flags != SHZ_LOADER_NATIVE_WIN98) goto refused;
    for (i = 0; i < 3; ++i) {
        domain_t *d = &g_dom[ids[i]];
        if (d->id != ids[i] || d->kind != kinds[i] || !d->generation ||
            (d->state != SHZ_DS_RUNNABLE && d->state != SHZ_DS_WAITING)) goto refused;
        if (i) {
            if (!d->ram_base || d->ram_size < SHZ_BOOTINFO_GPA + sizeof(shz_bootinfo_t) ||
                d->ram_base > UINT64_MAX - SHZ_BOOTINFO_GPA - sizeof(shz_bootinfo_t)) goto refused;
            workers[i - 1] = (shz_bootinfo_t *)(uintptr_t)(d->ram_base + SHZ_BOOTINFO_GPA);
            if (workers[i - 1]->size != sizeof(shz_bootinfo_t) ||
                workers[i - 1]->domain_id != d->id || workers[i - 1]->generation != d->generation)
                goto refused;
        }
    }
    if (!g_dom[SHZ_DOM_KERNEL32].chan[0].mapped ||
        g_dom[SHZ_DOM_KERNEL32].chan[0].peer != SHZ_DOM_KERNEL64 ||
        !g_dom[SHZ_DOM_KERNEL64].chan[0].mapped ||
        g_dom[SHZ_DOM_KERNEL64].chan[0].peer != SHZ_DOM_KERNEL32 ||
        !g_dom[SHZ_DOM_KERNEL64].chan[2].mapped ||
        g_dom[SHZ_DOM_KERNEL64].chan[2].peer != SHZ_DOM_WIN98 ||
        !g_dom[SHZ_DOM_WIN98].chan[2].mapped ||
        g_dom[SHZ_DOM_WIN98].chan[2].peer != SHZ_DOM_KERNEL64) goto refused;
    for (i = 0; i < 2; ++i) {
        memcpy(&candidates[i], workers[i], sizeof candidates[i]);
        memset(candidates[i].cmdline, 0, sizeof candidates[i].cmdline);
        memcpy(candidates[i].cmdline, command, sizeof command);
        candidates[i].cmdline_size = sizeof command - 1;
        if (shz_win98_foundation_policy(&candidates[i]) != 1) goto refused;
    }
    for (i = 0; i < 2; ++i) {
        memcpy(workers[i]->cmdline, candidates[i].cmdline, sizeof workers[i]->cmdline);
        workers[i]->cmdline_size = candidates[i].cmdline_size;
    }
    kprintf("SHZ: native Win98 foundation policy published after channel construction\n");
    return 0;
refused:
    log_capture(info->last_error, sizeof info->last_error,
                "native Win98 foundation lacks live owners or validated worker channels");
    return -1;
}

int ipc_channels_create(shz_info_t *info)
{
    unsigned c;
    if (!info->ipc_base || info->ipc_size < (uint64_t)SHZ_MAX_CHANNELS * SHZ_IPC_REGION_SIZE) {
        if (!info->loader_flags) return 0;
        log_capture(info->last_error, sizeof info->last_error, "native Win98 foundation lacks IPC backing");
        return -1;
    }
    for (c = 0; c < SHZ_MAX_CHANNELS; ++c) {
        const uint32_t a = channel_plan[c].a, b = channel_plan[c].b;
        const uint64_t hpa = info->ipc_base + (uint64_t)c * SHZ_IPC_REGION_SIZE;
        uint32_t peers[2] = {a, b}, i;
        if (!a || !alive(a) || !alive(b))
            continue;
        if (shz_channel_init((void *)(uintptr_t)hpa, SHZ_IPC_REGION_SIZE, c, a, b, 32, 1) != SHZ_OK) {
            log_capture(info->last_error, sizeof info->last_error, "channel %u init failed", c);
            return -1;
        }
        for (i = 0; i < 2; ++i) {
            domain_t *d = &g_dom[peers[i]];
            const uint64_t gpa = SHZ_IPC_GPA_BASE + (uint64_t)c * SHZ_IPC_REGION_SIZE;
            if (peers[i] == SHZ_DOM_DOS16)
                continue;                       /* real mode cannot address this window; see docs */
            if (ept_map(&d->ept, gpa, hpa, SHZ_IPC_REGION_SIZE, EPT_RWX | EPT_WB, 1)) {
                log_capture(info->last_error, sizeof info->last_error, "channel %u EPT map failed", c);
                return -1;
            }
            d->chan[c].hpa = hpa;
            d->chan[c].peer = peers[1 - i];
            d->chan[c].mapped = 1;
            if (d->kind != DK_WIN98) {
                shz_bootinfo_t *bi = (shz_bootinfo_t *)(uintptr_t)(d->ram_base + SHZ_BOOTINFO_GPA);
                bi->channel[bi->channel_count].gpa = gpa;
                bi->channel[bi->channel_count].size = SHZ_IPC_REGION_SIZE;
                bi->channel[bi->channel_count].peer_domain = peers[1 - i];
                bi->channel[bi->channel_count].channel_id = c;
                ++bi->channel_count;
            }
        }
        kprintf("SHZ: IPC channel %u: %s <-> %s at gpa %llx (generation 1)\n", c, g_dom[a].name, g_dom[b].name,
                SHZ_IPC_GPA_BASE + (uint64_t)c * SHZ_IPC_REGION_SIZE);
    }
    return win98_foundation_publish(info);
}
