/* SPDX-License-Identifier: GPL-2.0-only
 * Host control: loader_flags policy of the actual Supervisor kdom.c (and the actual display_grant.c), compiled
 * here unchanged. Only VMCS/EPT/pool/vCPU primitives are modeled. Cases: 0 (DOS), 2 (K64 display only),
 * 1 (native Win98), 1|2 (refused, the loader refuses it too), unknown bits (refused). No guest code, VMX or
 * Windows executes here; this is not VM evidence.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../src/cpu.h"
#include "../../src/domain.h"
#include "../../src/devices.h"

static unsigned checks, ept_init_calls, delegate_calls;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(2); } } while (0)

static uint64_t host_vmread(uint64_t field) { (void)field; return 0; }
static int host_vmwrite(uint64_t field, uint64_t value) { (void)field; (void)value; return 0; }
static uint64_t host_rdtsc(void) { return 1000000; }
#define vmread host_vmread
#define vmwrite host_vmwrite
#define rdtsc host_rdtsc
#include "../../src/domain.c"
#include "../../src/kdom.c"
#undef vmread
#undef vmwrite
#undef rdtsc

void kprintf(const char *format, ...) { (void)format; }
void log_capture(char *out, unsigned length, const char *format, ...)
{ (void)format; if (length > 1) { out[0] = 'E'; out[1] = 0; } }
uint8_t dev_cmos_read(uint8_t reg) { (void)reg; return 0; }
int ept_init(ept_t *e) { (void)e; ++ept_init_calls; return 0; }
uint64_t ept_pointer(const ept_t *e) { (void)e; return 0x1000; }
int ept_map(ept_t *e, uint64_t gpa, uint64_t hpa, uint64_t bytes, uint64_t flags, int pages)
{ (void)e; (void)gpa; (void)hpa; (void)bytes; (void)flags; (void)pages; return 0; }
static _Alignas(4096) uint8_t pool_arena[64][4096];
static unsigned pool_used;
void *pool_alloc_pages(unsigned pages)
{
    void *p;
    if (pool_used + pages > 64) pool_used = 0;          /* fixture reuse: each boot case rebuilds its domains */
    p = pool_arena[pool_used]; pool_used += pages; memset(p, 0, (size_t)pages * 4096u); return p;
}
void msr_bitmap_allow(uint8_t *bitmap, uint32_t msr, int read, int write)
{ (void)bitmap; (void)msr; (void)read; (void)write; }
int vmx_vcpu_init(vcpu_t *vc, shz_info_t *info, const shz_caps_t *caps, const vmx_cfg_t *cfg)
{ (void)vc; (void)info; (void)caps; (void)cfg; return 0; }
void video_delegate_display(uint32_t dom) { CHECK(dom == SHZ_DOM_KERNEL64); ++delegate_calls; }

#define K32_RAM_BYTES (16ull << 20)
#define K64_RAM_BYTES (64ull << 20)                       /* initrd lives at 32 MiB */
static uint8_t *k32_ram, *k64_ram, *ipc, kernel_image[4096], initrd_image[4096];

static shz_info_t base_info(uint32_t flags, int with_ipc)
{
    shz_info_t i;
    memset(&i, 0, sizeof i);
    i.loader_flags = flags;
    i.tsc_hz = 1000000000ull;
    i.fb_base = 0x80000000ull; i.fb_size = 16ull << 20;
    i.fb_width = 1280; i.fb_height = 800; i.fb_pitch_pixels = 1280; i.fb_format = 1;
    i.k32_ram_base = (uintptr_t)k32_ram; i.k32_ram_size = K32_RAM_BYTES;
    i.k64_ram_base = (uintptr_t)k64_ram; i.k64_ram_size = K64_RAM_BYTES;
    if (with_ipc) { i.ipc_base = (uintptr_t)ipc; i.ipc_size = (uint64_t)SHZ_MAX_CHANNELS * SHZ_IPC_REGION_SIZE; }
    memcpy(i.blobs[0].name, "KERNEL32.BIN", 13); i.blobs[0].base = (uintptr_t)kernel_image; i.blobs[0].size = sizeof kernel_image;
    memcpy(i.blobs[1].name, "KERNEL64.BIN", 13); i.blobs[1].base = (uintptr_t)kernel_image; i.blobs[1].size = sizeof kernel_image;
    memcpy(i.blobs[2].name, "WIN64.IMG", 10); i.blobs[2].base = (uintptr_t)initrd_image; i.blobs[2].size = sizeof initrd_image;
    return i;
}

static const shz_bootinfo_t *boot_of(const uint8_t *ram) { return (const shz_bootinfo_t *)(ram + SHZ_BOOTINFO_GPA); }

/* Full actual DOS/display boot path: K32 + K64 + IPC, no Windows baseline published. */
static void boot_without_windows(uint32_t flags, int expect_grant)
{
    shz_info_t info = base_info(flags, 1);
    shz_caps_t caps; memset(&caps, 0, sizeof caps);
    memset(g_dom, 0, sizeof g_dom); delegate_calls = 0;
    g_info = &info;
    CHECK(kernel_domain_create(&info, &caps, DK_KERNEL32) == 0);
    CHECK(kernel_domain_create(&info, &caps, DK_KERNEL64) == 0);
    CHECK(boot_of(k32_ram)->cmdline_size == 0 && boot_of(k32_ram)->cmdline[0] == 0);   /* no K32 Win98 service */
    CHECK(((boot_of(k64_ram)->flags & SHZ_BIF_FB_SUPERVISOR_GRANT) != 0) == expect_grant);
    CHECK(delegate_calls == (unsigned)expect_grant);
    if (expect_grant)
        CHECK(boot_of(k64_ram)->fb_base == info.fb_base && boot_of(k64_ram)->fb_width == 1280);
    else
        CHECK(boot_of(k64_ram)->fb_base == 0 && boot_of(k64_ram)->fb_size == 0);
    CHECK(ipc_channels_create(&info) == 0 && info.last_error[0] == 0);
    CHECK(g_dom[SHZ_DOM_KERNEL32].chan[0].mapped && g_dom[SHZ_DOM_KERNEL64].chan[0].mapped);
    CHECK(boot_of(k32_ram)->cmdline_size == 0 && boot_of(k64_ram)->cmdline_size == 0);   /* no foundation */
    CHECK(strstr(boot_of(k64_ram)->cmdline, "shz.foundation") == NULL);
    /* Missing IPC backing is not an error for the non-native profiles. */
    info = base_info(flags, 0);
    CHECK(ipc_channels_create(&info) == 0 && info.last_error[0] == 0);
}

static void refused(uint32_t flags)
{
    shz_info_t info = base_info(flags, 1);
    shz_caps_t caps; memset(&caps, 0, sizeof caps);
    memset(g_dom, 0, sizeof g_dom);
    g_info = &info; ept_init_calls = 0;
    k32_ram[SHZ_BOOTINFO_GPA] = 0x5a;
    CHECK(kernel_domain_create(&info, &caps, DK_KERNEL32) == -1 && info.last_error[0]);
    CHECK(kernel_domain_create(&info, &caps, DK_KERNEL64) == -1);
    CHECK(ept_init_calls == 0 && k32_ram[SHZ_BOOTINFO_GPA] == 0x5a);   /* refused before touching guest RAM */
    CHECK(g_dom[SHZ_DOM_KERNEL32].state == 0 && g_dom[SHZ_DOM_KERNEL64].state == 0);
    info.last_error[0] = 0;
    CHECK(ipc_channels_create(&info) == -1 && info.last_error[0]);      /* no publication, no silent DOS */
    info = base_info(flags, 0);
    CHECK(ipc_channels_create(&info) == -1 && info.last_error[0]);
}

int main(void)
{
    static const uint32_t invalid[] = {
        SHZ_LOADER_NATIVE_WIN98 | SHZ_LOADER_K64_DISPLAY, 4u, 8u, 0x80000000u,
        SHZ_LOADER_NATIVE_WIN98 | 4u, SHZ_LOADER_K64_DISPLAY | 0x80000000u, 0xffffffffu,
    };
    unsigned n;
    k32_ram = aligned_alloc(2u << 20, K32_RAM_BYTES); k64_ram = aligned_alloc(2u << 20, K64_RAM_BYTES);
    ipc = calloc(SHZ_MAX_CHANNELS, SHZ_IPC_REGION_SIZE);
    CHECK(k32_ram && k64_ram && ipc);
    memset(kernel_image, 0x90, sizeof kernel_image);

    /* The policy helper itself: each bit decided separately, unknown bits fail closed. */
    CHECK(loader_flag_policy(0) == SHZ_LFP_DOS);
    CHECK(loader_flag_policy(SHZ_LOADER_K64_DISPLAY) == SHZ_LFP_DISPLAY);
    CHECK(loader_flag_policy(SHZ_LOADER_NATIVE_WIN98) == SHZ_LFP_NATIVE);
    for (n = 0; n < sizeof invalid / sizeof invalid[0]; ++n)
        CHECK(loader_flag_policy(invalid[n]) == SHZ_LFP_INVALID);

    boot_without_windows(0, 0);                         /* flags 0: DOS profile, console keeps GOP */
    boot_without_windows(SHZ_LOADER_K64_DISPLAY, 1);    /* flags 2: IPC boots, GOP granted, no Win98 baseline */

    /* flags 1: K32 carries the Win98 service command line; the foundation stays strict. */
    {
        shz_info_t info = base_info(SHZ_LOADER_NATIVE_WIN98, 1);
        shz_caps_t caps; memset(&caps, 0, sizeof caps);
        memset(g_dom, 0, sizeof g_dom); delegate_calls = 0;
        g_info = &info;
        CHECK(kernel_domain_create(&info, &caps, DK_KERNEL32) == 0);
        CHECK(kernel_domain_create(&info, &caps, DK_KERNEL64) == 0);
        CHECK(boot_of(k32_ram)->cmdline_size == sizeof K32_WIN98_SERVICE_CMDLINE - 1);
        CHECK(memcmp(boot_of(k32_ram)->cmdline, K32_WIN98_SERVICE_CMDLINE, sizeof K32_WIN98_SERVICE_CMDLINE) == 0);
        CHECK(!(boot_of(k64_ram)->flags & SHZ_BIF_FB_SUPERVISOR_GRANT) && delegate_calls == 0);
        /* No live WIN98 owner/channel: the native foundation must refuse rather than publish. */
        CHECK(ipc_channels_create(&info) == -1 && info.last_error[0]);
        CHECK(strstr(boot_of(k64_ram)->cmdline, "shz.foundation") == NULL);
        info = base_info(SHZ_LOADER_NATIVE_WIN98, 0);
        CHECK(ipc_channels_create(&info) == -1 && info.last_error[0]);   /* native without IPC backing */
    }

    for (n = 0; n < sizeof invalid / sizeof invalid[0]; ++n)
        refused(invalid[n]);

    /* Kernel64 copy geometry (memory-layout contract b4): file must fit [1 MiB, 4 MiB) before the heap. */
    {
        static uint8_t big[SHZ_K64_KERNEL_FILE_MAX + 1];
        const uint64_t sizes[] = {SHZ_K64_KERNEL_FILE_MAX, SHZ_K64_KERNEL_FILE_MAX + 1, 0};
        shz_caps_t caps; memset(&caps, 0, sizeof caps);
        memset(big, 0xcc, sizeof big);
        for (n = 0; n < 3; ++n) {
            shz_info_t info = base_info(0, 1);
            memset(g_dom, 0, sizeof g_dom); g_info = &info;
            info.blobs[1].base = (uintptr_t)big; info.blobs[1].size = sizes[n];
            if (!sizes[n]) { memset(info.blobs[1].name, 0, sizeof info.blobs[1].name); info.blobs[1].name[0] = 'K'; }
            memset(k64_ram, 0x11, K64_RAM_BYTES);
            if (n == 0) {
                CHECK(kernel_domain_create(&info, &caps, DK_KERNEL64) == 0);
                CHECK(k64_ram[KERNEL_GPA] == 0xcc && k64_ram[SHZ_K64_KERNEL_END - 1] == 0xcc);
                CHECK(k64_ram[SHZ_K64_HEAP_GPA] == 0);       /* heap boundary untouched by the image, zeroed */
                CHECK(boot_of(k64_ram)->kernel_size == SHZ_K64_KERNEL_FILE_MAX);
            } else if (n == 1) {
                CHECK(kernel_domain_create(&info, &caps, DK_KERNEL64) == -1 && info.last_error[0]);
                CHECK(k64_ram[KERNEL_GPA] == 0x11 && k64_ram[SHZ_K64_HEAP_GPA] == 0x11);   /* refused before any write */
            } else {
                CHECK(kernel_domain_create(&info, &caps, DK_KERNEL64) == 1);   /* absent kernel: not configured */
            }
        }
        /* Kernel32 keeps its own contract: a file larger than the K64 window is still governed by K32 rules. */
        {
            shz_info_t info = base_info(0, 1);
            memset(g_dom, 0, sizeof g_dom); g_info = &info;
            info.blobs[0].base = (uintptr_t)big; info.blobs[0].size = SHZ_K64_KERNEL_FILE_MAX + 1;
            CHECK(kernel_domain_create(&info, &caps, DK_KERNEL32) == 0);
        }
    }

    free(k32_ram); free(k64_ram); free(ipc);
    printf("PASS %u actual kdom.c loader-flag policy checks (flags 0/1/2 + %u refused values; VMX/EPT modeled, no VM)\n",
           checks, (unsigned)(sizeof invalid / sizeof invalid[0]));
    return 0;
}
