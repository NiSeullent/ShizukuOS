/* SPDX-License-Identifier: GPL-2.0-only
 * Actual core.c, linked against the existing domain constructor boundaries.
 * Numeric RAM/source ranges are never dereferenced. No VMX, guest or OS boots.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "../src/core.h"
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

domain_t g_dom[SHZ_MAX_DOMAINS];
shz_info_t *g_info;
uint64_t g_tsc_hz;

static unsigned checks, scenarios, calls[16], call_count;
static const char *scenario = "startup";
static int fail_ctor, bad_ctor, bad_publish, fail_channels, bad_channels, scheduler_rc;
static int mutate_ctor, mutate_input;
static int dirty_optional;
/* Manifest controls: kernel constructors write a real kdom.c-shaped boot
 * info and image into host mappings at the fixture's numeric RAM ranges. */
static int real_ram, bad_tail, identity_rc[2];
static void (*run_hook)(void);
static shz_core_t *running_core;
static const uint8_t vbios[0x10000];
enum { CALL_CHANNELS = 100, CALL_SCHEDULER = 101 };
enum { BAD_ID = 1, BAD_KIND, BAD_GENERATION, BAD_RAM_BASE, BAD_RAM_SIZE,
       BAD_STATE, BAD_MIRROR_KIND, BAD_MIRROR_GENERATION, BAD_MIRROR_STATE };
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "FAIL %s line %d: %s\n", scenario, __LINE__, #x); exit(2); \
} } while (0)

void kprintf(const char *format, ...) { (void)format; }
void log_capture(char *dst, unsigned size, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    if (size) vsnprintf(dst, size, format, ap);
    va_end(ap);
}

static void call(unsigned id)
{
    CHECK(call_count < sizeof calls / sizeof calls[0]);
    calls[call_count++] = id;
}

static int has_blob(const shz_info_t *info, const char *name)
{
    for (unsigned i = 0; i < SHZ_MAX_BLOBS; ++i)
        if (info->blobs[i].size && !strcmp(info->blobs[i].name, name)) return 1;
    return 0;
}

static void corrupt(domain_t *d, shz_domain_info_t *mirror)
{
    if ((int)d->id != bad_ctor) return;
    switch (bad_publish) {
    case BAD_ID: ++d->id; break;
    case BAD_KIND: d->kind = (dom_kind_t)((d->kind + 1) % 4); break;
    case BAD_GENERATION: d->generation = 0; break;
    case BAD_RAM_BASE: d->ram_base += 4096; break;
    case BAD_RAM_SIZE: d->ram_size -= 4096; break;
    case BAD_STATE: d->state = SHZ_DS_EXITED; break;
    case BAD_MIRROR_KIND: ++mirror->kind; break;
    case BAD_MIRROR_GENERATION: ++mirror->generation; break;
    case BAD_MIRROR_STATE: mirror->state = SHZ_DS_FAILED; break;
    default: break;
    }
}

static void mutate(shz_info_t *info, uint32_t id)
{
    if ((int)id != mutate_ctor) return;
    switch (mutate_input) {
    case 1: info->k32_ram_base += 2ull << 20; break;
    case 2: info->k64_ram_base += 2ull << 20; break;
    case 3: info->disk_base += 4096; break;
    case 4: ++info->hv_instance_id; break;
    case 5: ++info->domain_generation; break;
    case 6: g_dom[SHZ_DOM_KERNEL32].vc.vmcs_pa = 0x1234000; break;
    case 7: g_dom[SHZ_DOM_KERNEL64].io_bitmap_a = (uint8_t *)(uintptr_t)0x1234000; break;
    default: break;
    }
}

static int publish(shz_info_t *info, uint32_t id, dom_kind_t kind,
                   uint64_t base, uint64_t size)
{
    if ((int)id == fail_ctor) return -1;
    domain_t *d = &g_dom[id];
    d->id = id; d->name = "host constructor fixture"; d->kind = kind;
    d->generation = 1; d->state = SHZ_DS_RUNNABLE;
    d->ram_base = base; d->ram_size = size;
    shz_domain_info_t *mirror = &info->domains[id];
    /* The production DOS constructor publishes only g_dom. Core retains the
     * old main.c evidence publication after validating its actual domain. */
    if (kind != DK_DOS16) {
        mirror->kind = kind; mirror->generation = 1; mirror->state = SHZ_DS_RUNNABLE;
    }
    corrupt(d, mirror);
    mutate(info, id);
    return 0;
}

int dos_domain_create(shz_info_t *info, const shz_caps_t *caps,
                      const uint8_t *rom, unsigned bytes)
{
    CHECK(caps && rom == vbios && bytes == sizeof vbios);
    call(SHZ_DOM_DOS16);
    return publish(info, SHZ_DOM_DOS16, DK_DOS16, info->guest_ram_base, info->guest_ram_size);
}

int win98_domain_create(shz_info_t *info, const shz_caps_t *caps)
{
    CHECK(caps && info->loader_flags == SHZ_LOADER_NATIVE_WIN98);
    call(SHZ_DOM_WIN98);
    return publish(info, SHZ_DOM_WIN98, DK_WIN98, info->guest_ram_base, info->guest_ram_size);
}

int kernel_domain_create(shz_info_t *info, const shz_caps_t *caps, dom_kind_t kind)
{
    CHECK(caps && (kind == DK_KERNEL32 || kind == DK_KERNEL64));
    const int lm = kind == DK_KERNEL64;
    const uint32_t id = lm ? SHZ_DOM_KERNEL64 : SHZ_DOM_KERNEL32;
    const uint64_t base = lm ? info->k64_ram_base : info->k32_ram_base;
    const uint64_t size = lm ? info->k64_ram_size : info->k32_ram_size;
    call(id);
    if ((int)id == fail_ctor) return -1;
    if (!size || !has_blob(info, lm ? "KERNEL64.BIN" : "KERNEL32.BIN")) {
        if (dirty_optional == 1) g_dom[id].chan[0].mapped = 1;
        if (dirty_optional == 2) g_dom[id].vc.vmcs_pa = 0x1234000;
        if (dirty_optional == 3) g_dom[id].io_bitmap_a = (uint8_t *)(uintptr_t)0x1234000;
        mutate(info, id);
        return 1;
    }
    if (real_ram) {
        /* Same placement and fields kdom.c writes before verify_kernel_load. */
        const shz_blob_t *k = 0, *rd = 0;
        for (unsigned i = 0; i < SHZ_MAX_BLOBS; ++i) {
            if (!info->blobs[i].size) continue;
            if (!strcmp(info->blobs[i].name, lm ? "KERNEL64.BIN" : "KERNEL32.BIN")) k = &info->blobs[i];
            if (lm && !strcmp(info->blobs[i].name, "WIN64.IMG")) rd = &info->blobs[i];
        }
        uint8_t *ram = (uint8_t *)(uintptr_t)base;
        shz_bootinfo_t *bi = (shz_bootinfo_t *)(ram + SHZ_BOOTINFO_GPA);
        memset(bi, 0x5a, sizeof *bi);   /* poison: the constructor must overwrite every byte */
        memset(bi, 0, sizeof *bi);
        bi->magic = SHZ_BOOTINFO_MAGIC; bi->size = sizeof *bi; bi->domain_id = id; bi->generation = 1;
        bi->ram_size = size; bi->kernel_gpa = 0x100000; bi->kernel_size = k->size;
        memcpy(ram + 0x100000, (const void *)(uintptr_t)k->base, k->size);
        if (rd) {
            bi->initrd_gpa = 0x2000000; bi->initrd_size = rd->size;
            memcpy(ram + 0x2000000, (const void *)(uintptr_t)rd->base, rd->size);
        }
        identity_rc[lm] = shz_core_install_identity(&bi->install);
        if (bad_tail == (int)id) bi->install.install_id[3] ^= 1;
    }
    return publish(info, id, kind, base, size);
}

int ipc_channels_create(shz_info_t *info)
{
    static const uint32_t pairs[][2] = {
        {SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64}, {SHZ_DOM_KERNEL32, SHZ_DOM_DOS16},
        {SHZ_DOM_KERNEL64, SHZ_DOM_WIN98}
    };
    call(CALL_CHANNELS);
    if (fail_channels) return -1;
    if (info->ipc_base && info->ipc_size >= SHZ_MAX_CHANNELS * SHZ_IPC_REGION_SIZE) {
        for (unsigned c = 0; c < 3; ++c) {
            if (!g_dom[pairs[c][0]].state || !g_dom[pairs[c][1]].state) continue;
            for (unsigned p = 0; p < 2; ++p) {
                domain_t *d = &g_dom[pairs[c][p]];
                if (d->kind == DK_DOS16) continue;
                d->chan[c].mapped = 1;
                d->chan[c].peer = pairs[c][1 - p];
                d->chan[c].hpa = info->ipc_base + c * SHZ_IPC_REGION_SIZE;
            }
        }
    }
    if (bad_channels == 1) g_dom[SHZ_DOM_KERNEL32].chan[0].peer = SHZ_DOM_DOS16;
    if (bad_channels == 2) g_dom[SHZ_DOM_KERNEL64].chan[0].hpa += 4096;
    if (bad_channels == 3) g_dom[SHZ_DOM_DOS16].chan[1].mapped = 1;
    if (bad_channels == 4) g_dom[SHZ_DOM_KERNEL64].chan[3].mapped = 1;
    if (bad_channels == 5) g_dom[SHZ_DOM_KERNEL32].chan[0].mapped = 0;
    if (bad_channels == 6) g_dom[SHZ_DOM_WIN98].chan[2].mapped = 0;
    mutate(info, CALL_CHANNELS);
    return 0;
}

int sched_run(shz_info_t *info)
{
    CHECK(info && running_core && running_core->phase == SHZ_CORE_RUNNING);
    call(CALL_SCHEDULER);
    if (run_hook) run_hook();
    for (unsigned i = 0; i < SHZ_MAX_DOMAINS; ++i)
        if (g_dom[i].state) {
            g_dom[i].state = scheduler_rc < 0 ? SHZ_DS_FAILED : SHZ_DS_EXITED;
            info->domains[i].state = g_dom[i].state;
        }
    return scheduler_rc;
}

static void fixture(shz_core_t *core, shz_info_t *info, shz_caps_t *caps, int native)
{
    memset(core, 0, sizeof *core); memset(info, 0, sizeof *info);
    memset(caps, 0, sizeof *caps); memset(g_dom, 0, sizeof g_dom);
    memset(calls, 0, sizeof calls); call_count = 0;
    fail_ctor = bad_ctor = bad_publish = fail_channels = bad_channels = scheduler_rc = 0;
    mutate_ctor = mutate_input = dirty_optional = 0;
    real_ram = bad_tail = 0; identity_rc[0] = identity_rc[1] = -1; run_hook = 0;
    running_core = core; g_info = info;
    caps->vmx_usable = 1; caps->long_mode = 1;
    info->magic = SHZ_INFO_MAGIC; info->version = SHZ_INFO_VERSION; info->size = sizeof *info;
    info->hv_instance_id = 7; info->domain_generation = 11; info->tsc_hz = 1000000000;
    info->region_base = SHZ_REGION_BASE; info->region_size = SHZ_REGION_SIZE;
    info->guest_ram_base = 0x10000000ull; info->guest_ram_size = 128ull << 20;
    info->k32_ram_base = 0x20000000ull; info->k32_ram_size = 32ull << 20;
    info->k64_ram_base = 0x24000000ull; info->k64_ram_size = 64ull << 20;
    info->ipc_base = 0x30000000ull; info->ipc_size = SHZ_MAX_CHANNELS * SHZ_IPC_REGION_SIZE;
    info->disk_base = 0x100000000ull; info->disk_size = 2ull << 30;
    info->memmap_base = 0x70000000ull; info->memmap_bytes = 288; info->memmap_desc_size = 48;
    const char *names[] = {"KERNEL32.BIN", "KERNEL64.BIN", "SEABIOS.BIN"};
    for (unsigned i = 0; i < 3; ++i) {
        strcpy(info->blobs[i].name, names[i]);
        info->blobs[i].base = 0x40000000ull + (uint64_t)i * 0x100000;
        info->blobs[i].size = i == 2 ? 0x40000 : 0x1000;
    }
    info->loader_flags = native ? SHZ_LOADER_NATIVE_WIN98 : 0;
}

static int create(shz_core_t *core, shz_info_t *info, const shz_caps_t *caps)
{
    return shz_core_create(core, info, caps, vbios, sizeof vbios);
}

static void no_retry(shz_core_t *core, shz_info_t *info, const shz_caps_t *caps)
{
    const unsigned previous = call_count;
    CHECK(create(core, info, caps) < 0);
    CHECK(shz_core_run(core, info) < 0);
    CHECK(call_count == previous);
}

static void reject_preflight(shz_core_t *core, shz_info_t *info, const shz_caps_t *caps)
{
    ++scenarios;
    CHECK(create(core, info, caps) < 0);
    CHECK(call_count == 0);
    no_retry(core, info, caps);
}

static void descriptors(void)
{
    scenario = "immutable four-child hierarchy"; ++scenarios;
    const char *names[] = {"ShizukuDOS", "Shizuku32", "Shizuku64", "ShizukuOS"};
    const char *modes[] = {"SZRm", "SZPrtm", "SZLm", "Windows 98"};
    const uint32_t ids[] = {SHZ_DOM_DOS16, SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98};
    const dom_kind_t kinds[] = {DK_DOS16, DK_KERNEL32, DK_KERNEL64, DK_WIN98};
    CHECK(SHZ_CORE_CHILD_COUNT == 4);
    CHECK(!strcmp(SHZ_CORE_NAME, "ShizukuCore Kernel"));
    for (unsigned i = 0; i < 4; ++i) {
        const shz_core_child_t *child = shz_core_child(i);
        CHECK(child && child == shz_core_child(i) && child == shz_core_find(ids[i]));
        CHECK(!strcmp(child->name, names[i]) && !strcmp(child->mode, modes[i]));
        CHECK(!strcmp(child->parent, SHZ_CORE_NAME));
        CHECK(child->domain_id == ids[i] && child->kind == kinds[i]);
    }
    CHECK(!shz_core_child(4) && !shz_core_child(~0u));
    CHECK(!shz_core_find(SHZ_DOM_NONE) && !shz_core_find(SHZ_DOM_SUPERVISOR));
    CHECK(!shz_core_find(SHZ_DOM_MAX) && !shz_core_find(UINT32_MAX));
}

static void normal_profiles(void)
{
    for (int native = 0; native < 2; ++native) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, native);
        scenario = native ? "native hierarchy launch" : "DOS hierarchy launch"; ++scenarios;
        CHECK(create(&core, &info, &caps) == 0);
        CHECK(core.phase == SHZ_CORE_READY && core.owner == &info);
        CHECK(core.members == (native ? 14u : 7u));
        CHECK(core.boot_epoch == 7 && info.hv_instance_id == 7);
        CHECK(core.domain_epoch == 12 && info.domain_generation == 12);
        CHECK(call_count == 4 && calls[0] == (native ? SHZ_DOM_WIN98 : SHZ_DOM_DOS16));
        CHECK(calls[1] == SHZ_DOM_KERNEL32 && calls[2] == SHZ_DOM_KERNEL64 && calls[3] == CALL_CHANNELS);
        for (unsigned i = 0; i < SHZ_CORE_CHILD_COUNT; ++i) {
            const shz_core_child_t *child = shz_core_child(i);
            if (!(core.members & (1u << i))) {
                CHECK(!g_dom[child->domain_id].state); continue;
            }
            CHECK(core.generation[i] == g_dom[child->domain_id].generation);
            CHECK(info.domains[child->domain_id].generation == 1);
            CHECK(info.domains[child->domain_id].state == SHZ_DS_RUNNABLE);
        }
        CHECK(shz_core_run(&core, &info) == 0);
        CHECK(core.phase == SHZ_CORE_FINISHED && call_count == 5 && calls[4] == CALL_SCHEDULER);
        no_retry(&core, &info, &caps);
    }
    for (unsigned present = 0; present < 4; ++present) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 0);
        scenario = "optional default kernel branches"; ++scenarios;
        if (!(present & 1)) info.k32_ram_base = info.k32_ram_size = 0;
        if (!(present & 2)) info.k64_ram_base = info.k64_ram_size = 0;
        CHECK(create(&core, &info, &caps) == 0);
        CHECK(core.members == (1u | ((present & 1) ? 2u : 0u) | ((present & 2) ? 4u : 0u)));
        CHECK(shz_core_run(&core, &info) == 0);
        no_retry(&core, &info, &caps);
    }
    /* Missing kernel source preserves the production constructor's rc=1. */
    shz_core_t core; shz_info_t info; shz_caps_t caps;
    fixture(&core, &info, &caps, 0); scenario = "optional absent source"; ++scenarios;
    memset(&info.blobs[0], 0, sizeof info.blobs[0]);
    CHECK(create(&core, &info, &caps) == 0 && core.members == 5);
    CHECK(shz_core_run(&core, &info) == 0);
    fixture(&core, &info, &caps, 0); scenario = "default no IPC"; ++scenarios;
    info.ipc_base = info.ipc_size = 0;
    CHECK(create(&core, &info, &caps) == 0 && shz_core_run(&core, &info) == 0);
    fixture(&core, &info, &caps, 0); scenario = "adjacent ranges and readonly aliases"; ++scenarios;
    info.k32_ram_base = info.guest_ram_base + info.guest_ram_size;
    info.blobs[1].base = info.blobs[0].base;
    info.memmap_base = info.blobs[0].base;
    CHECK(create(&core, &info, &caps) == 0 && shz_core_run(&core, &info) == 0);
    fixture(&core, &info, &caps, 0); scenario = "loader map inside retained host region"; ++scenarios;
    info.memmap_base = info.region_base + 0xf00000;
    CHECK(create(&core, &info, &caps) == 0 && shz_core_run(&core, &info) == 0);
}

static void invalid_ranges(void)
{
    for (unsigned defect = 0; defect < 3; ++defect) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 0); scenario = "invalid DOS VBIOS stops before constructor"; ++scenarios;
        CHECK(shz_core_create(&core, &info, &caps, defect ? vbios : NULL,
                              defect == 1 ? 0u : defect == 2 ? 0x10001u : sizeof vbios) < 0);
        CHECK(call_count == 0);
        no_retry(&core, &info, &caps);
    }
    {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 1); scenario = "native does not require DOS VBIOS"; ++scenarios;
        CHECK(shz_core_create(&core, &info, &caps, NULL, 0) == 0);
        CHECK(shz_core_run(&core, &info) == 0);
    }
    for (unsigned a = 0; a < 6; ++a) for (unsigned b = a + 1; b < 6; ++b) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 0); scenario = "all writable range overlaps";
        uint64_t *bases[] = {&info.region_base, &info.guest_ram_base, &info.k32_ram_base,
                            &info.k64_ram_base, &info.ipc_base, &info.disk_base};
        *bases[b] = *bases[a];
        reject_preflight(&core, &info, &caps);
    }
    for (unsigned target = 0; target < 6; ++target) for (unsigned source = 0; source < 2; ++source) {
        /* The retained loader map may share host-owned storage, while no
         * guest constructor may overwrite it. */
        if (source && target == 0) continue;
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 0); scenario = "writable/source alias rejected";
        const uint64_t bases[] = {info.region_base, info.guest_ram_base, info.k32_ram_base,
                                 info.k64_ram_base, info.ipc_base, info.disk_base};
        if (source) info.memmap_base = bases[target]; else info.blobs[0].base = bases[target];
        reject_preflight(&core, &info, &caps);
    }
    for (unsigned which = 0; which < 32; ++which) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 0); scenario = "malformed ranges or handoff";
        switch (which) {
        case 0: info.magic ^= 1; break;
        case 1: ++info.version; break;
        case 2: --info.size; break;
        case 3: info.loader_flags = 2; break;
        case 4: info.loader_flags = SHZ_LOADER_NATIVE_WIN98 | 2; break;
        case 5: info.region_base = 0; break;
        case 6: info.guest_ram_size = 0; break;
        case 7: ++info.region_base; break;
        case 8: ++info.guest_ram_size; break;
        case 9: info.k32_ram_base = 0; break;
        case 10: info.k64_ram_size = 0; break;
        case 11: info.k32_ram_base += 4096; break;
        case 12: info.k64_ram_size += 4096; break;
        case 13: info.ipc_base = 0; break;
        case 14: ++info.ipc_size; break;
        case 15: info.disk_base += 512; break;
        case 16: ++info.disk_size; break;
        case 17: info.memmap_base = 0; break;
        case 18: info.blobs[0].size = 0; break;
        case 19: info.guest_ram_base = UINT64_MAX - 4095; break;
        case 20: info.k64_ram_base = UINT64_MAX - ((2ull << 20) - 1); break;
        case 21: info.disk_base = UINT64_MAX - 4095; break;
        case 22: info.memmap_base = UINT64_MAX - 15; break;
        case 23: info.blobs[0].base = UINT64_MAX - 15; break;
        case 24: info.domain_generation = UINT64_MAX; break;
        case 25: info.hv_instance_id = 0; break;
        case 26: info.region_base = 0x80000000; info.guest_ram_base = SHZ_REGION_BASE; break;
        case 27: info.region_size += 4096; break;
        case 28: info.tsc_hz = 0; break;
        case 29: memset(info.blobs[0].name, 'A', sizeof info.blobs[0].name); break;
        case 30: strcpy(info.blobs[1].name, info.blobs[0].name); break;
        case 31: info.ipc_size = SHZ_IPC_REGION_SIZE; break;
        }
        reject_preflight(&core, &info, &caps);
    }
    for (unsigned which = 0; which < 4; ++which) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 1); scenario = "native required branches/backing";
        switch (which) {
        case 0: info.k32_ram_base = info.k32_ram_size = 0; break;
        case 1: memset(&info.blobs[1], 0, sizeof info.blobs[1]); break;
        case 2: info.ipc_base = info.ipc_size = 0; break;
        case 3: info.ipc_size = SHZ_IPC_REGION_SIZE; break;
        }
        reject_preflight(&core, &info, &caps);
    }
}

static void dirty_and_failures(void)
{
    for (unsigned which = 0; which < 12; ++which) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 0); scenario = "dirty Core/domain admission";
        switch (which) {
        case 0: core.members = 1; break;
        case 1: core.owner = &info; break;
        case 2: g_dom[SHZ_DOM_KERNEL32].state = SHZ_DS_RUNNABLE; break;
        case 3: g_dom[SHZ_DOM_WIN98].generation = 1; break;
        case 4: g_dom[SHZ_DOM_KERNEL32].chan[0].mapped = 1; break;
        case 5: g_dom[SHZ_DOM_KERNEL64].vc.vmcs_pa = 0x1234000; break;
        case 6: g_dom[SHZ_DOM_DOS16].io_bitmap_a = (uint8_t *)(uintptr_t)0x1234000; break;
        case 7: core.resources.guest.base = 0x10000000; break;
        case 8: core.generation[0] = 1; break;
        case 9: core.boot_epoch = 1; break;
        case 10: info.domains[SHZ_DOM_WIN98].state = SHZ_DS_EXITED; break;
        case 11: g_dom[SHZ_DOM_KERNEL64].ept.pml4_pa = 0x1234000; break;
        }
        reject_preflight(&core, &info, &caps);
    }
    for (int native = 0; native < 2; ++native) for (unsigned at = 0; at < 3; ++at) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, native); scenario = "constructor failure stops sequence"; ++scenarios;
        fail_ctor = at == 0 ? (native ? SHZ_DOM_WIN98 : SHZ_DOM_DOS16) :
                    (at == 1 ? SHZ_DOM_KERNEL32 : SHZ_DOM_KERNEL64);
        CHECK(create(&core, &info, &caps) < 0);
        CHECK(core.phase == SHZ_CORE_FAILED && call_count == at + 1);
        CHECK(info.domain_generation == 11);
        no_retry(&core, &info, &caps);
    }
    for (int retained = 1; retained <= 3; ++retained) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 0); scenario = "absent constructor retained ownership"; ++scenarios;
        info.k32_ram_base = info.k32_ram_size = 0;
        dirty_optional = retained;
        CHECK(create(&core, &info, &caps) < 0 && core.phase == SHZ_CORE_FAILED);
        CHECK(call_count == 2);
        no_retry(&core, &info, &caps);
    }
    for (int native = 0; native < 2; ++native) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, native); scenario = "channel failure prevents scheduler"; ++scenarios;
        fail_channels = 1;
        CHECK(create(&core, &info, &caps) < 0 && call_count == 4);
        CHECK(core.phase == SHZ_CORE_FAILED && info.domain_generation == 11);
        no_retry(&core, &info, &caps);
    }
    for (unsigned index = 0; index < SHZ_CORE_CHILD_COUNT; ++index) {
        const shz_core_child_t *child = shz_core_child(index);
        const int native = child->kind == DK_WIN98;
        for (int defect = BAD_ID; defect <= BAD_MIRROR_STATE; ++defect) {
            if (child->kind == DK_DOS16 && defect >= BAD_MIRROR_KIND) continue;
            shz_core_t core; shz_info_t info; shz_caps_t caps;
            fixture(&core, &info, &caps, native); scenario = "incorrect constructor publication"; ++scenarios;
            bad_ctor = (int)child->domain_id; bad_publish = defect;
            CHECK(create(&core, &info, &caps) < 0 && core.phase == SHZ_CORE_FAILED);
            CHECK(call_count == (child->kind == DK_KERNEL32 ? 2u :
                                 child->kind == DK_KERNEL64 ? 3u : 1u));
            no_retry(&core, &info, &caps);
        }
    }
    for (int defect = 1; defect <= 6; ++defect) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, defect == 6); scenario = "incorrect channel publication"; ++scenarios;
        bad_channels = defect;
        CHECK(create(&core, &info, &caps) < 0 && core.phase == SHZ_CORE_FAILED && call_count == 4);
        no_retry(&core, &info, &caps);
    }
    for (unsigned which = 0; which < 9; ++which) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 0); scenario = "constructor cannot rewrite root inputs"; ++scenarios;
        switch (which) {
        case 0: mutate_ctor = SHZ_DOM_DOS16; mutate_input = 1; break;
        case 1: mutate_ctor = SHZ_DOM_KERNEL32; mutate_input = 2; break;
        case 2: mutate_ctor = SHZ_DOM_KERNEL64; mutate_input = 3; break;
        case 3:
            info.k32_ram_base = info.k32_ram_size = 0;
            mutate_ctor = SHZ_DOM_KERNEL32; mutate_input = 2; break;
        case 4:
            info.k64_ram_base = info.k64_ram_size = 0;
            mutate_ctor = SHZ_DOM_KERNEL64; mutate_input = 4; break;
        case 5: mutate_ctor = SHZ_DOM_DOS16; mutate_input = 4; break;
        case 6: mutate_ctor = CALL_CHANNELS; mutate_input = 5; break;
        case 7: mutate_ctor = SHZ_DOM_DOS16; mutate_input = 6; break;
        case 8: mutate_ctor = SHZ_DOM_KERNEL32; mutate_input = 7; break;
        }
        CHECK(create(&core, &info, &caps) < 0 && core.phase == SHZ_CORE_FAILED);
        CHECK(call_count == (which == 0 || which == 5 || which == 7 ? 1u :
                             which == 1 || which == 3 || which == 8 ? 2u : which == 6 ? 4u : 3u));
        no_retry(&core, &info, &caps);
    }
}

static void run_admission(void)
{
    for (unsigned which = 0; which < 25; ++which) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 0); scenario = "tampered owner/epoch/role/resource before run"; ++scenarios;
        CHECK(create(&core, &info, &caps) == 0);
        shz_info_t other = info;
        shz_info_t *run_info = &info;
        switch (which) {
        case 0: ++info.hv_instance_id; break;
        case 1: ++info.domain_generation; break;
        case 2: run_info = &other; break;
        case 3: core.owner = &other; break;
        case 4: core.members &= ~2u; break;
        case 5: core.members |= 16u; break;
        case 6: ++g_dom[SHZ_DOM_KERNEL32].id; break;
        case 7: g_dom[SHZ_DOM_KERNEL32].kind = DK_DOS16; break;
        case 8: ++g_dom[SHZ_DOM_KERNEL64].generation; break;
        case 9: ++core.generation[2]; break;
        case 10: g_dom[SHZ_DOM_KERNEL64].state = SHZ_DS_FAILED; break;
        case 11: info.loader_flags = SHZ_LOADER_NATIVE_WIN98; break;
        case 12: info.k32_ram_base += 2ull << 20; break;
        case 13: info.ipc_base += 4ull << 20; break;
        case 14: info.disk_size -= 512; break;
        case 15: ++info.memmap_bytes; break;
        case 16: ++info.blobs[0].size; break;
        case 17: ++info.tsc_hz; break;
        case 18: g_dom[SHZ_DOM_KERNEL32].ram_size -= 4096; break;
        case 19: g_dom[SHZ_DOM_WIN98].state = SHZ_DS_RUNNABLE; break;
        case 20: g_dom[SHZ_DOM_KERNEL32].chan[0].peer = SHZ_DOM_DOS16; break;
        case 21: g_dom[SHZ_DOM_KERNEL64].chan[0].hpa += 4096; break;
        case 22: ++core.domain_epoch; break;
        case 23: ++info.domains[SHZ_DOM_KERNEL32].generation; break;
        case 24: info.domains[SHZ_DOM_KERNEL64].state = SHZ_DS_EXITED; break;
        }
        CHECK(shz_core_run(&core, run_info) < 0);
        CHECK(call_count == 4);
        no_retry(&core, &info, &caps);
    }
    for (unsigned phase = SHZ_CORE_NEW; phase <= SHZ_CORE_FAILED; ++phase) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        fixture(&core, &info, &caps, 0); scenario = "run bypass cannot launch"; ++scenarios;
        core.phase = phase;
        CHECK(shz_core_run(&core, &info) < 0 && call_count == 0);
    }
    shz_core_t core; shz_info_t info; shz_caps_t caps;
    fixture(&core, &info, &caps, 0); scenario = "scheduler failure has no restart"; ++scenarios;
    CHECK(create(&core, &info, &caps) == 0);
    scheduler_rc = -1;
    CHECK(shz_core_run(&core, &info) < 0 && call_count == 5);
    CHECK(core.phase == SHZ_CORE_FAILED || core.phase == SHZ_CORE_FINISHED);
    no_retry(&core, &info, &caps);
}

/* ------------------------------------------------ routing02 C1/C2/C4 controls */
#define BLOB_BASE 0x40000000ull
#define MAN_BASE (BLOB_BASE + 0x300000ull)
static shz_core_t *report_core;
static uint64_t report_expect_gen;

static void map_fixed(uint64_t base, uint64_t size)
{
    void *p = mmap((void *)(uintptr_t)base, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p != (void *)(uintptr_t)base) {
        fprintf(stderr, "FAIL host mapping at %#llx unavailable: manifest controls NOT run\n",
                (unsigned long long)base);
        exit(3);
    }
}

typedef struct { const char *comp, *parent, *blob; uint32_t kind, dom, depends, flags; } ent_t;
enum { E_KERNEL64S = 6 };
static const ent_t c1[] = {
    {"ShizukuCore", "", "", SHZ_BMAN_KIND_CORE, 0, 0, SHZ_BMAN_REQUIRED},
    {"ShizukuDOS", "ShizukuCore", "", SHZ_BMAN_KIND_CHILD, SHZ_DOM_DOS16, 1, SHZ_BMAN_REQUIRED},
    {"Shizuku32", "ShizukuCore", "KERNEL32.BIN", SHZ_BMAN_KIND_CHILD, SHZ_DOM_KERNEL32, 1, 0},
    {"Shizuku64", "ShizukuCore", "KERNEL64.BIN", SHZ_BMAN_KIND_CHILD, SHZ_DOM_KERNEL64, 1 | (1u << 5), 0},
    {"ShizukuOS", "ShizukuCore", "", SHZ_BMAN_KIND_CHILD, SHZ_DOM_WIN98, 1, 0},
    {"Win64Runtime", "Shizuku64", "WIN64.IMG", SHZ_BMAN_KIND_RESOURCE, 0, 1, 0},
    {"Kernel64S", "Shizuku64", "KERNEL64S.BIN", SHZ_BMAN_KIND_RESOURCE, 0, 1, 0},
};
static const uint8_t kernel64s_bytes[64] = "direct-route Kernel64 image, never a Supervisor blob";

/* Builds blobs + SHZBOOT.MAN (C1 table) into the fixture. Returns manifest bytes. */
static uint64_t install_manifest(shz_info_t *info, uint64_t generation, int stamp_id,
                                 uint32_t k64s_flags, int k64s_blob, int k64s_tamper, uint32_t os_flags)
{
    static const char *names[] = {"KERNEL32.BIN", "KERNEL64.BIN", "WIN64.IMG"};
    const unsigned n = sizeof c1 / sizeof c1[0];
    uint8_t *man = (uint8_t *)(uintptr_t)MAN_BASE;
    shz_bman_header_t *h = (shz_bman_header_t *)man;
    shz_bman_entry_t *e = (shz_bman_entry_t *)(man + sizeof *h);
    memset(info->blobs, 0, sizeof info->blobs);
    for (unsigned i = 0; i < 3; ++i) {
        strcpy(info->blobs[i].name, names[i]);
        info->blobs[i].base = BLOB_BASE + (uint64_t)i * 0x100000;
        info->blobs[i].size = 0x1000 + i * 0x100;
        for (unsigned b = 0; b < info->blobs[i].size; ++b)
            ((uint8_t *)(uintptr_t)info->blobs[i].base)[b] = (uint8_t)(b * 7 + i * 31 + 1);
    }
    memset(man, 0, SHZ_BMAN_MAX_BYTES);
    for (unsigned i = 0; i < n; ++i) {
        strcpy(e[i].component, c1[i].comp); strcpy(e[i].parent, c1[i].parent); strcpy(e[i].blob, c1[i].blob);
        e[i].kind = c1[i].kind; e[i].domain_id = c1[i].dom; e[i].depends = i ? c1[i].depends : 0;
        e[i].flags = c1[i].flags;
        if (i == E_KERNEL64S) e[i].flags = k64s_flags;
        if (i == 4) e[i].flags = os_flags;
        if (c1[i].blob[0]) {
            snprintf(e[i].install_path, sizeof e[i].install_path, "\\SHZDOS\\%s", c1[i].blob);
            if (i == E_KERNEL64S) {
                e[i].size = sizeof kernel64s_bytes;
                shz_sha256(kernel64s_bytes, sizeof kernel64s_bytes, e[i].sha256);
            } else {
                const shz_blob_t *b = &info->blobs[i == 2 ? 0 : i == 3 ? 1 : 2];
                e[i].size = b->size;
                shz_sha256((const void *)(uintptr_t)b->base, b->size, e[i].sha256);
            }
        }
    }
    if (k64s_blob) {
        uint8_t *dst = (uint8_t *)(uintptr_t)(BLOB_BASE + 0x200000 + 0x10000);
        memcpy(dst, kernel64s_bytes, sizeof kernel64s_bytes);
        if (k64s_tamper) dst[5] ^= 0x40;
        strcpy(info->blobs[4].name, "KERNEL64S.BIN");
        info->blobs[4].base = (uint64_t)(uintptr_t)dst; info->blobs[4].size = sizeof kernel64s_bytes;
    }
    h->magic = SHZ_BMAN_MAGIC; h->version = SHZ_BMAN_VERSION; h->header_size = sizeof *h;
    h->entry_size = sizeof *e; h->entry_count = (uint16_t)n; h->total_size = sizeof *h + n * sizeof *e;
    h->loader_profile = info->loader_flags; h->install_generation = generation;
    if (stamp_id) for (unsigned i = 0; i < 16; ++i) h->install_id[i] = (uint8_t)(0xa0 + i);
    shz_sha256(e, (uint64_t)n * sizeof *e, h->entries_sha256);
    strcpy(info->blobs[3].name, SHZ_BMAN_BLOB_NAME);
    info->blobs[3].base = MAN_BASE; info->blobs[3].size = h->total_size;
    return h->total_size;
}

static void manifest_fixture(shz_core_t *core, shz_info_t *info, shz_caps_t *caps)
{
    fixture(core, info, caps, 0);
    real_ram = 1;
    memset((void *)(uintptr_t)info->k32_ram_base, 0, 0x8000);
    memset((void *)(uintptr_t)info->k64_ram_base, 0, 0x8000);
}

static const shz_bootinfo_t *child_bootinfo(const shz_info_t *info, int lm)
{
    return (const shz_bootinfo_t *)(uintptr_t)((lm ? info->k64_ram_base : info->k32_ram_base) + SHZ_BOOTINFO_GPA);
}

static shz_drvrep_t good_report(uint64_t generation)
{
    shz_drvrep_t r;
    memset(&r, 0, sizeof r);
    r.magic = SHZ_DRVREP_MAGIC; r.version = SHZ_DRVREP_VERSION; r.size = sizeof r;
    r.flags = SHZ_DRVREP_FOUNDATION; r.install_generation = generation;
    r.rows = 9; r.running = 3; r.claimed = 1; r.not_started = 1; r.unsupported = 2; r.infrastructure = 1;
    r.linked_elsewhere = 1; r.services_considered = 2; r.services_loaded = 2;
    r.catalog_entries = 4; r.catalog_matched = 3; r.catalog_rejected = 1;
    return r;
}

/* Runs inside sched_run while the root is RUNNING, as the hypercall would. */
static void report_matrix(void)
{
    const uint64_t g = report_expect_gen;
    shz_drvrep_t r = good_report(g);
    CHECK(report_core->driver_report == 0);
    CHECK(shz_core_driver_report(SHZ_DOM_KERNEL32, 1, &r) == SHZ_E_DENIED);
    CHECK(shz_core_driver_report(SHZ_DOM_WIN98, 1, &r) == SHZ_E_DENIED);
    CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 2, &r) == SHZ_E_DENIED);      /* stale domain generation */
    r.magic ^= 1; CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_PROTO); r = good_report(g);
    r.version = 2; CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_PROTO); r = good_report(g);
    r.size = 80; CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_PROTO); r = good_report(g);
    r.reserved[1] = 1; CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_INVALID); r = good_report(g);
    r.flags = 3; CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_INVALID); r = good_report(g);
    r.flags = 8; CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_INVALID); r = good_report(g);
    r.running += 1; CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_INVALID); r = good_report(g);
    r.rows = 33; r.not_started = 25; CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_INVALID);
    r = good_report(g);
    r.running = 0xffffffffu; r.claimed = 10; r.rows = 9;   /* 32-bit wrap must not satisfy the sum */
    CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_INVALID); r = good_report(g);
    r.install_generation = g + 1; CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_STALE);
    r = good_report(g);
    CHECK(report_core->driver_report == 0 && report_core->driver_report_generation == 0);
    if (g) { r.failed = 1; r.not_started = 0; }             /* attested run reports one failed row */
    CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_OK);
    CHECK(report_core->driver_report == (g ? SHZ_CORE_DRV_REPORTED_FAILED : SHZ_CORE_DRV_REPORTED_OK));
    CHECK(report_core->driver_report_generation == 1);
    CHECK(!memcmp(&report_core->driver_report_copy, &r, sizeof r));
    r = good_report(g);
    CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &r) == SHZ_E_BUSY);         /* once per generation */
    CHECK(report_core->driver_report == (g ? SHZ_CORE_DRV_REPORTED_FAILED : SHZ_CORE_DRV_REPORTED_OK));
    CHECK(report_core->driver_state == SHZ_CORE_DRV_ABSENT);                       /* never fabricated BOUND */
}

static void manifest_routes(void)
{
    static const uint8_t abc_sha[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
                                        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    uint8_t d[32];
    char err[96];
    map_fixed(0x20000000ull, 0x08000000ull);   /* K32 [0x20000000,+32M) and K64 [0x24000000,+64M) */
    map_fixed(BLOB_BASE, 0x400000ull);
    scenario = "SHA-256 known answer"; ++scenarios;
    shz_sha256("abc", 3, d); CHECK(!memcmp(d, abc_sha, 32));

    {   /* stamped installed manifest: attested tail, report bound to generation */
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        manifest_fixture(&core, &info, &caps); scenario = "stamped C1 manifest admits and attests"; ++scenarios;
        install_manifest(&info, 5, 1, 0, 0, 0, 0);
        CHECK(shz_bman_check_table((const void *)(uintptr_t)MAN_BASE, info.blobs[3].size, err, sizeof err) == 0);
        CHECK(create(&core, &info, &caps) == 0 && core.manifest_state == SHZ_CORE_MANIFEST_ADMITTED);
        CHECK(core.members == 7u && identity_rc[0] == 1 && identity_rc[1] == 1);
        CHECK(!(core.manifest.present & (1u << E_KERNEL64S)));                 /* listed, absent, not required */
        for (int lm = 0; lm < 2; ++lm) {
            const shz_bootinfo_t *bi = child_bootinfo(&info, lm);
            CHECK(SHZ_BOOTINFO_HAS(bi, install) && bi->size == sizeof *bi);
            CHECK(bi->install.magic == SHZ_INSTID_MAGIC && bi->install.flags == SHZ_INSTID_SUPERVISOR);
            CHECK(bi->install.install_generation == 5);
            CHECK(!memcmp(bi->install.install_id, core.manifest.header->install_id, 16));
            CHECK(!memcmp(bi->install.entries_sha256, core.manifest.header->entries_sha256, 32));
        }
        shz_install_identity_t outside;
        memset(&outside, 0xee, sizeof outside);
        CHECK(shz_core_install_identity(&outside) == 0);                       /* READY: no constructor window */
        for (unsigned i = 0; i < sizeof outside; ++i) CHECK(((uint8_t *)&outside)[i] == 0);
        shz_drvrep_t early = good_report(5);
        CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &early) == SHZ_E_NOENT); /* before run */
        report_core = &core; report_expect_gen = 5; run_hook = report_matrix;
        CHECK(shz_core_run(&core, &info) == 0 && core.phase == SHZ_CORE_FINISHED);
        CHECK(core.driver_report == SHZ_CORE_DRV_REPORTED_FAILED);
        CHECK(shz_core_driver_report(SHZ_DOM_KERNEL64, 1, &early) == SHZ_E_NOENT); /* after run */
    }
    {   /* unstamped template: hash-bound, never attested */
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        manifest_fixture(&core, &info, &caps); scenario = "template manifest bound but unattested"; ++scenarios;
        install_manifest(&info, 0, 0, 0, 0, 0, 0);
        CHECK(shz_bman_check_table((const void *)(uintptr_t)MAN_BASE, info.blobs[3].size, err, sizeof err) ==
              SHZ_BMAN_TEMPLATE);
        CHECK(create(&core, &info, &caps) == 0 && core.manifest_state == SHZ_CORE_MANIFEST_TEMPLATE);
        CHECK(identity_rc[0] == 0 && identity_rc[1] == 0);
        for (int lm = 0; lm < 2; ++lm) {
            const shz_bootinfo_t *bi = child_bootinfo(&info, lm);
            const uint8_t *t = (const uint8_t *)&bi->install;
            CHECK(bi->size == sizeof *bi);
            for (unsigned i = 0; i < sizeof bi->install; ++i) CHECK(t[i] == 0);
        }
        report_core = &core; report_expect_gen = 0; run_hook = report_matrix;
        CHECK(shz_core_run(&core, &info) == 0 && core.driver_report == SHZ_CORE_DRV_REPORTED_OK);
    }
    {   /* template blob mismatch is still refused (binding not weakened) */
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        manifest_fixture(&core, &info, &caps); scenario = "template still binds blob hashes"; ++scenarios;
        install_manifest(&info, 0, 0, 0, 0, 0, 0);
        ((uint8_t *)(uintptr_t)info.blobs[1].base)[17] ^= 1;
        CHECK(create(&core, &info, &caps) < 0 && call_count == 0 && core.phase == SHZ_CORE_FAILED);
    }
    {   /* absent manifest, real constructor memory: zero tail */
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        manifest_fixture(&core, &info, &caps); scenario = "absent manifest leaves tail zero"; ++scenarios;
        install_manifest(&info, 5, 1, 0, 0, 0, 0);
        memset(&info.blobs[3], 0, sizeof info.blobs[3]);
        CHECK(create(&core, &info, &caps) == 0 && core.manifest_state == SHZ_CORE_MANIFEST_ABSENT);
        CHECK(identity_rc[0] == 0 && identity_rc[1] == 0);
        CHECK(child_bootinfo(&info, 1)->install.magic == 0 && child_bootinfo(&info, 1)->install.install_generation == 0);
        report_core = &core; report_expect_gen = 0; run_hook = report_matrix;
        CHECK(shz_core_run(&core, &info) == 0 && core.driver_report == SHZ_CORE_DRV_REPORTED_OK);
    }
    {   /* KERNEL64S.BIN delivered and matching: accepted under Shizuku64 */
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        manifest_fixture(&core, &info, &caps); scenario = "KERNEL64S present and bound"; ++scenarios;
        install_manifest(&info, 6, 1, 0, 1, 0, 0);
        CHECK(create(&core, &info, &caps) == 0 && (core.manifest.present & (1u << E_KERNEL64S)));
    }
    struct { const char *name; uint64_t gen; int id; uint32_t k64s_flags; int k64s_blob, tamper; uint32_t os_flags;
             int tail; unsigned calls; } refusals[] = {
        {"KERNEL64S tampered refused", 6, 1, 0, 1, 1, 0, 0, 0},
        {"KERNEL64S required but absent refused", 6, 1, SHZ_BMAN_REQUIRED, 0, 0, 0, 0, 0},
        {"half-stamped header refused (gen only)", 6, 0, 0, 0, 0, 0, 0, 0},
        {"half-stamped header refused (id only)", 0, 1, 0, 0, 0, 0, 0, 0},
        {"other owner required refused", 6, 1, 0, 0, 0, SHZ_BMAN_REQUIRED, 0, 0},
        {"K32 tail tampered refused", 6, 1, 0, 0, 0, 0, SHZ_DOM_KERNEL32, 2},
        {"K64 tail tampered refused", 6, 1, 0, 0, 0, 0, SHZ_DOM_KERNEL64, 3},
    };
    for (unsigned i = 0; i < sizeof refusals / sizeof refusals[0]; ++i) {
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        manifest_fixture(&core, &info, &caps); scenario = refusals[i].name; ++scenarios;
        install_manifest(&info, refusals[i].gen, refusals[i].id, refusals[i].k64s_flags, refusals[i].k64s_blob,
                         refusals[i].tamper, refusals[i].os_flags);
        bad_tail = refusals[i].tail;
        CHECK(create(&core, &info, &caps) < 0 && core.phase == SHZ_CORE_FAILED);
        CHECK(call_count == refusals[i].calls);
        CHECK(info.domain_generation == 11 && core.members == 0);
        if (refusals[i].tail) CHECK(info.domains[refusals[i].tail].state == SHZ_DS_FAILED);
        no_retry(&core, &info, &caps);
    }
    {   /* entry-table hash covers the stamp-free table only; stamping header keeps it */
        shz_core_t core; shz_info_t info; shz_caps_t caps;
        manifest_fixture(&core, &info, &caps); scenario = "pure table check rejects table tamper"; ++scenarios;
        install_manifest(&info, 7, 1, 0, 0, 0, 0);
        shz_bman_header_t *h = (shz_bman_header_t *)(uintptr_t)MAN_BASE;
        h->install_generation = 8;                                             /* re-stamp: still valid */
        CHECK(shz_bman_check_table(h, h->total_size, err, sizeof err) == 0);
        ((shz_bman_entry_t *)(h + 1))[3].depends |= 1u << 6;                   /* table byte change */
        CHECK(shz_bman_check_table(h, h->total_size, err, sizeof err) < 0 && strstr(err, "hash"));
        CHECK(shz_bman_check_table(h, h->total_size - 1, err, sizeof err) < 0);
        CHECK(shz_bman_check_table(0, 96, err, sizeof err) < 0);
    }
}

int main(void)
{
    descriptors(); normal_profiles(); invalid_ranges(); dirty_and_failures(); run_admission(); manifest_routes();
    printf("PASS %u actual Core assertions across %u scenarios "
           "(constructors/IPC/scheduler mocked; numeric ranges; no VM or integrated OS boot)\n",
           checks, scenarios);
    return 0;
}
