/* SPDX-License-Identifier: GPL-2.0-only
 * Admission and lifecycle root for the existing four guest implementations.
 * VMX, guest memory managers and sched_run remain their existing backends.
 */
#include "core.h"
#include "console.h"
#include "cpu.h"
#include "../native_win98/win98.h"

static const shz_core_child_t children[SHZ_CORE_CHILD_COUNT] = {
    {"ShizukuDOS", "SZRm", SHZ_CORE_NAME, SHZ_DOM_DOS16, DK_DOS16},
    {"Shizuku32", "SZPrtm", SHZ_CORE_NAME, SHZ_DOM_KERNEL32, DK_KERNEL32},
    {"Shizuku64", "SZLm", SHZ_CORE_NAME, SHZ_DOM_KERNEL64, DK_KERNEL64},
    {"ShizukuOS", "Windows 98", SHZ_CORE_NAME, SHZ_DOM_WIN98, DK_WIN98}
};

/* The root whose creation/run is in progress. Hypercall and constructor
 * callbacks reach Core state only through this pointer and only while that
 * root is in the phase they belong to. */
static shz_core_t *g_core_root;

const shz_core_child_t *shz_core_child(unsigned index)
{
    return index < SHZ_CORE_CHILD_COUNT ? &children[index] : 0;
}

const shz_core_child_t *shz_core_find(uint32_t domain_id)
{
    unsigned i;
    for (i = 0; i < SHZ_CORE_CHILD_COUNT; ++i)
        if (children[i].domain_id == domain_id) return &children[i];
    return 0;
}

/* Failure rollback. The Supervisor pool has no release operation, so
 * retained VMCS/EPT/bitmap allocations stay owned; rollback instead makes the
 * partial child set unlaunchable as one unit: every slot this root's
 * constructors wrote becomes FAILED in both runtime and evidence, membership
 * and generations are withdrawn, and no subset is ever offered to sched_run. */
static void quarantine(shz_core_t *core, shz_info_t *info, const char *reason)
{
    static const char tag[] = "rolled back by ShizukuCore: ";
    unsigned i, k, n;
    for (i = 0; i < SHZ_CORE_CHILD_COUNT; ++i) {
        const uint32_t id = children[i].domain_id;
        shz_domain_info_t *evidence = &info->domains[id];
        if (!((core->attempted | core->members) & (1u << i))) continue;
        if (!g_dom[id].state && !evidence->state) continue;
        g_dom[id].state = SHZ_DS_FAILED;
        evidence->state = SHZ_DS_FAILED;
        for (n = 0; n < sizeof tag - 1 && n < sizeof evidence->error - 1; ++n) evidence->error[n] = tag[n];
        for (k = 0; reason && reason[k] && n < sizeof evidence->error - 1; ++k, ++n) evidence->error[n] = reason[k];
        evidence->error[n] = 0;
        kprintf("SHZ: %s rolled back child %s domain=%u\n", SHZ_CORE_NAME, children[i].name, id);
    }
    core->members = 0;
    memset(core->generation, 0, sizeof core->generation);
}

static int refuse(shz_core_t *core, shz_info_t *info, const char *reason)
{
    if (core && info && core->phase == SHZ_CORE_CREATING && core->owner == info) quarantine(core, info, reason);
    if (core) core->phase = SHZ_CORE_FAILED;
    if (info) log_capture(info->last_error, sizeof info->last_error, "ShizukuCore: %s", reason);
    return -1;
}

static int constructor_failed(shz_core_t *core, shz_info_t *info)
{
    if (!info->last_error[0])
        log_capture(info->last_error, sizeof info->last_error, "ShizukuCore: child creation failed");
    if (core->phase == SHZ_CORE_CREATING) quarantine(core, info, info->last_error);
    core->phase = SHZ_CORE_FAILED;
    return -1;
}

static int header_valid(const shz_info_t *info)
{
    return info && info->magic == SHZ_INFO_MAGIC && info->version == SHZ_INFO_VERSION &&
           info->size == sizeof *info;
}

static void capture(shz_core_resources_t *out, const shz_info_t *info)
{
    memset(out, 0, sizeof *out);
    out->guest = (shz_core_range_t){info->guest_ram_base, info->guest_ram_size};
    out->kernel32 = (shz_core_range_t){info->k32_ram_base, info->k32_ram_size};
    out->kernel64 = (shz_core_range_t){info->k64_ram_base, info->k64_ram_size};
    out->host = (shz_core_range_t){info->region_base, info->region_size};
    out->ipc = (shz_core_range_t){info->ipc_base, info->ipc_size};
    out->disk = (shz_core_range_t){info->disk_base, info->disk_size};
    out->memmap = (shz_core_range_t){info->memmap_base, info->memmap_bytes};
    memcpy(out->blobs, info->blobs, sizeof out->blobs);
    out->tsc_hz = info->tsc_hz;
    out->loader_flags = info->loader_flags;
}

static int unchanged(const shz_core_t *core, const shz_info_t *info)
{
    shz_core_resources_t current;
    capture(&current, info);
    return info->hv_instance_id == core->boot_epoch && info->domain_generation == core->domain_epoch &&
           memcmp(&current, &core->resources, sizeof current) == 0;
}

static int range_valid(shz_core_range_t r, uint64_t base_alignment,
                       uint64_t size_alignment, int required)
{
    if (!r.base || !r.size) return !required && !r.base && !r.size;
    return r.base <= UINT64_MAX - r.size && !(r.base & (base_alignment - 1)) &&
           !(r.size & (size_alignment - 1));
}

static int overlap(shz_core_range_t a, shz_core_range_t b)
{
    return a.size && b.size && a.base < b.base + b.size && b.base < a.base + a.size;
}

static int name_equal(const char name[16], const char *expected)
{
    unsigned i;
    for (i = 0; i < 16; ++i) {
        if (name[i] != expected[i]) return 0;
        if (!name[i]) return 1;
    }
    return 0;
}

static int has_blob(const shz_core_resources_t *r, const char *name)
{
    unsigned i;
    for (i = 0; i < SHZ_MAX_BLOBS; ++i)
        if (r->blobs[i].size && name_equal(r->blobs[i].name, name)) return 1;
    return 0;
}

/* Only writable allocations need exclusive ownership. Immutable loader
 * sources may alias one another, but no child's memset/copy may overwrite
 * those sources or the retained firmware memory map.
 */
static int resources_valid(const shz_core_resources_t *r)
{
    const shz_core_range_t writable[] = {r->guest, r->kernel32, r->kernel64,
                                        r->host, r->ipc, r->disk};
    unsigned i, j;
    if (r->loader_flags != 0 && r->loader_flags != SHZ_LOADER_NATIVE_WIN98) return 0;
    /* The executing payload and its bump pool occupy this fixed allocation.
     * A substituted handoff range cannot surrender the real host image. */
    if (r->host.base != SHZ_REGION_BASE || r->host.size != SHZ_REGION_SIZE) return 0;
    if (!range_valid(r->guest, 4096, 4096, 1) ||
        !range_valid(r->kernel32, 0x200000, 0x200000, 0) ||
        !range_valid(r->kernel64, 0x200000, 0x200000, 0) ||
        !range_valid(r->host, 4096, 4096, 1) ||
        !range_valid(r->ipc, 4096, 4096, 0) ||
        !range_valid(r->disk, 4096, 512, 0) ||
        !range_valid(r->memmap, 1, 1, 0) || !r->tsc_hz) return 0;
    if (r->ipc.size && r->ipc.size < (uint64_t)SHZ_MAX_CHANNELS * SHZ_IPC_REGION_SIZE) return 0;
    for (i = 0; i < SHZ_MAX_BLOBS; ++i) {
        const shz_blob_t *b = &r->blobs[i];
        shz_core_range_t source = {b->base, b->size};
        if (!range_valid(source, 1, 1, 0)) return 0;
        if (!b->size) continue;
        for (j = 0; j < sizeof b->name && b->name[j]; ++j) { }
        if (!j || j == sizeof b->name) return 0;
        for (j = 0; j < i; ++j)
            if (r->blobs[j].size && name_equal(r->blobs[j].name, b->name)) return 0;
        for (j = 0; j < sizeof writable / sizeof writable[0]; ++j)
            if (overlap(source, writable[j])) return 0;
    }
    for (i = 0; i < sizeof writable / sizeof writable[0]; ++i) {
        /* The retained map may reside inside the host region. Every other writable allocation must
         * preserve it, including IPC and disk, while host placement remains
         * the loader's choice. */
        if (i != 3 && overlap(writable[i], r->memmap)) return 0;
        for (j = 0; j < i; ++j)
            if (overlap(writable[i], writable[j])) return 0;
    }
    if (r->loader_flags == SHZ_LOADER_NATIVE_WIN98 &&
        (!r->kernel32.size || !r->kernel64.size || !r->ipc.size ||
         !has_blob(r, "KERNEL32.BIN") || !has_blob(r, "KERNEL64.BIN"))) return 0;
    return 1;
}

static shz_core_range_t child_ram(const shz_core_t *core, unsigned index)
{
    if (index == 1) return core->resources.kernel32;
    if (index == 2) return core->resources.kernel64;
    return core->resources.guest;
}

static int empty_domain(const domain_t *d)
{
    const uint8_t *bytes = (const uint8_t *)d;
    unsigned i;
    /* No free operation exists for a VMCS, EPT or bitmap. A cleared state/ID
     * does not make a retained allocation available to another root. */
    for (i = 0; i < sizeof *d; ++i)
        if (bytes[i]) return 0;
    return 1;
}

static int fresh_context(const shz_core_t *core)
{
    const shz_core_resources_t *r = &core->resources;
    const shz_core_range_t ranges[] = {r->guest, r->kernel32, r->kernel64, r->host,
                                      r->ipc, r->disk, r->memmap};
    unsigned i, j;
    if (core->owner || core->boot_epoch || core->domain_epoch || core->members || r->tsc_hz || r->loader_flags ||
        core->manifest_state || core->attempted || core->driver_state || core->manifest.header ||
        core->manifest.entries || core->manifest.count || core->manifest.present ||
        core->driver_report || core->driver_report_generation)
        return 0;
    for (i = 0; i < SHZ_CORE_CHILD_COUNT; ++i)
        if (core->generation[i] || core->manifest_child[i]) return 0;
    for (i = 0; i < sizeof ranges / sizeof ranges[0]; ++i)
        if (ranges[i].base || ranges[i].size) return 0;
    for (i = 0; i < SHZ_MAX_BLOBS; ++i) {
        if (r->blobs[i].base || r->blobs[i].size) return 0;
        for (j = 0; j < sizeof r->blobs[i].name; ++j)
            if (r->blobs[i].name[j]) return 0;
    }
    return 1; /* Structure padding is not part of the fresh-context contract. */
}

static int admit_child(shz_core_t *core, shz_info_t *info, unsigned index)
{
    const shz_core_child_t *child = &children[index];
    const domain_t *d = &g_dom[child->domain_id];
    const shz_core_range_t ram = child_ram(core, index);
    shz_domain_info_t *evidence = &info->domains[child->domain_id];
    if (d->id != child->domain_id || d->kind != child->kind || !d->generation ||
        d->state != SHZ_DS_RUNNABLE || d->ram_base != ram.base || d->ram_size != ram.size)
        return refuse(core, info, "created child differs from its admitted role/RAM");
    /* The DOS constructor historically leaves publication to its caller. */
    if (index == 0) {
        evidence->kind = d->kind;
        evidence->generation = d->generation;
        evidence->state = d->state;
    } else if (evidence->kind != (uint32_t)d->kind || evidence->generation != d->generation ||
               evidence->state != d->state) {
        return refuse(core, info, "created child evidence differs from its runtime owner");
    }
    core->members |= 1u << index;
    core->generation[index] = d->generation;
    kprintf("SHZ: %s admitted child %s mode=%s domain=%u\n", SHZ_CORE_NAME,
            child->name, child->mode, child->domain_id);
    return 0;
}

static int member_index(const shz_core_t *core, uint32_t id)
{
    unsigned i;
    for (i = 0; i < SHZ_CORE_CHILD_COUNT; ++i)
        if ((core->members & (1u << i)) && children[i].domain_id == id) return (int)i;
    return -1;
}

static uint32_t channel_peer(uint32_t id, unsigned channel)
{
    if (channel == 0 && id == SHZ_DOM_KERNEL32) return SHZ_DOM_KERNEL64;
    if (channel == 0 && id == SHZ_DOM_KERNEL64) return SHZ_DOM_KERNEL32;
    if (channel == 1 && id == SHZ_DOM_KERNEL32) return SHZ_DOM_DOS16;
    if (channel == 2 && id == SHZ_DOM_KERNEL64) return SHZ_DOM_WIN98;
    if (channel == 2 && id == SHZ_DOM_WIN98) return SHZ_DOM_KERNEL64;
    return 0; /* DOS real mode does not map its IPC window. */
}

static int members_valid(const shz_core_t *core, int channels, int complete)
{
    const unsigned owner = core->resources.loader_flags == SHZ_LOADER_NATIVE_WIN98 ? 3u : 0u;
    const uint32_t allowed = (1u << owner) | (1u << 1) | (1u << 2);
    unsigned id;
    if (!(core->members & (1u << owner)) || (core->members & ~allowed)) return 0;
    if (complete && owner == 3 && core->members != allowed) return 0;
    for (id = 0; id < SHZ_MAX_DOMAINS; ++id) {
        const domain_t *d = &g_dom[id];
        const int index = member_index(core, id);
        unsigned c;
        if (index < 0) {
            const shz_domain_info_t *evidence = &core->owner->domains[id];
            if (!empty_domain(d) || evidence->state || evidence->kind || evidence->generation) return 0;
            continue;
        }
        {
            const shz_core_range_t ram = child_ram(core, (unsigned)index);
            const shz_domain_info_t *evidence = &core->owner->domains[id];
            if (d->id != id || d->kind != children[index].kind ||
                !core->generation[index] || d->generation != core->generation[index] ||
                d->ram_base != ram.base || d->ram_size != ram.size || d->state != SHZ_DS_RUNNABLE)
                return 0;
            /* This is publication consistency before first launch. It never
             * supplies runtime state to the scheduler or domain handlers. */
            if (evidence->kind != (uint32_t)d->kind || evidence->generation != d->generation ||
                evidence->state != d->state) return 0;
        }
        for (c = 0; c < SHZ_MAX_CHANNELS; ++c) {
            const uint32_t peer = channel_peer(id, c);
            const int mapped = channels && core->resources.ipc.size && peer && member_index(core, peer) >= 0;
            if (!!d->chan[c].mapped != !!mapped) return 0;
            if (mapped && (d->chan[c].peer != peer ||
                d->chan[c].hpa != core->resources.ipc.base + (uint64_t)c * SHZ_IPC_REGION_SIZE)) return 0;
        }
    }
    return 1;
}

/* ---------------------------------------------------------------- manifest */
static const char *const child_blob[SHZ_CORE_CHILD_COUNT] = {"", "KERNEL32.BIN", "KERNEL64.BIN", ""};
/* KERNEL64S.BIN is the direct-route (UEFI mode=kernel64 / Multiboot) Kernel64
 * image. The Supervisor route never loads it; a manifest may list it under
 * Shizuku64 (non-required here), and if the loader ever delivers it the
 * normal size/SHA-256 binding and parent admission apply. */
static const struct { const char *blob; unsigned child; } resource_owner[] = {
    {"WIN64.IMG", 2}, {"KERNEL64S.BIN", 2}, {"SEABIOS.BIN", 3}, {"VGACFG.BIN", 3}, {"VGAROM.BIN", 3},
    {"W98PERS.BIN", 3}};

static int manifest_bound(const shz_core_t *core)
{
    return core->manifest_state == SHZ_CORE_MANIFEST_ADMITTED ||
           core->manifest_state == SHZ_CORE_MANIFEST_TEMPLATE;
}

/* Identity this root attests to its kernel children: only a stamped,
 * admitted manifest produces one; everything else is all zero. */
static int build_identity(const shz_core_t *core, shz_install_identity_t *out)
{
    const shz_bman_header_t *h = core->manifest.header;
    memset(out, 0, sizeof *out);
    if (core->manifest_state != SHZ_CORE_MANIFEST_ADMITTED || !h || !h->install_generation) return 0;
    out->magic = SHZ_INSTID_MAGIC;
    out->flags = SHZ_INSTID_SUPERVISOR;
    out->install_generation = h->install_generation;
    memcpy(out->install_id, h->install_id, sizeof out->install_id);
    memcpy(out->entries_sha256, h->entries_sha256, sizeof out->entries_sha256);
    return 1;
}

int shz_core_install_identity(shz_install_identity_t *out)
{
    const shz_core_t *core = g_core_root;
    if (!out) return 0;
    if (!core || core->phase != SHZ_CORE_CREATING) {
        memset(out, 0, sizeof *out);
        return 0;
    }
    return build_identity(core, out);
}

static int str16_eq(const char f[16], const char *s)
{
    unsigned i;
    for (i = 0; i < 16; ++i) {
        if (f[i] != s[i]) return 0;
        if (!s[i]) return 1;
    }
    return 0;
}

static const shz_blob_t *core_blob(const shz_core_t *core, const char *name)
{
    unsigned i;
    for (i = 0; i < SHZ_MAX_BLOBS; ++i)
        if (core->resources.blobs[i].size && name_equal(core->resources.blobs[i].name, name))
            return &core->resources.blobs[i];
    return 0;
}

/* Binds the installed-target manifest to the exact ShizukuCore hierarchy
 * and this loader profile before any constructor writes guest memory. */
static int admit_manifest(shz_core_t *core, shz_info_t *info)
{
    const shz_blob_t *blob = core_blob(core, SHZ_BMAN_BLOB_NAME);
    const unsigned owner = core->resources.loader_flags == SHZ_LOADER_NATIVE_WIN98 ? 3u : 0u;
    unsigned i, j;
    char why[96];
    int parsed;
    if (!blob) {
        core->manifest_state = SHZ_CORE_MANIFEST_ABSENT;
        kprintf("SHZ: %s no %s: historical unmanifested route, installed-target admission NOT attested\n",
                SHZ_CORE_NAME, SHZ_BMAN_BLOB_NAME);
        return 0;
    }
    why[0] = 0;
    parsed = shz_bman_parse(info, blob, info->cap_bits, &core->manifest, why, sizeof why);
    if (parsed < 0) return refuse(core, info, why);
    if (parsed != 0 && parsed != SHZ_BMAN_TEMPLATE) return refuse(core, info, "manifest parser returned an invalid status");
    for (i = 1; i < core->manifest.count; ++i) {
        const shz_bman_entry_t *e = &core->manifest.entries[i];
        if (e->kind == SHZ_BMAN_KIND_CHILD) {
            for (j = 0; j < SHZ_CORE_CHILD_COUNT && !str16_eq(e->component, children[j].name); ++j) { }
            if (j == SHZ_CORE_CHILD_COUNT || e->domain_id != children[j].domain_id ||
                !str16_eq(e->blob, child_blob[j]) || core->manifest_child[j])
                return refuse(core, info, "manifest child differs from ShizukuCore hierarchy");
            /* DOS and Windows 98 owners are mutually exclusive profiles. One
             * installed manifest may describe both hierarchies, but the other
             * owner is never constructed on this route, so it may only be a
             * non-required, blobless listing (manifest_dependencies then keeps
             * any resource or dependency on it unsatisfied). */
            if ((j == 0 || j == 3) && j != owner && ((e->flags & SHZ_BMAN_REQUIRED) || e->blob[0]))
                return refuse(core, info, "manifest requires the other owner profile's child");
            core->manifest_child[j] = i + 1;
        } else {
            for (j = 0; j < sizeof resource_owner / sizeof resource_owner[0] &&
                        !str16_eq(e->blob, resource_owner[j].blob); ++j) { }
            if (j == sizeof resource_owner / sizeof resource_owner[0] ||
                !str16_eq(e->parent, children[resource_owner[j].child].name))
                return refuse(core, info, "manifest resource has unknown blob or wrong parent child");
        }
    }
    if (!core->manifest_child[owner] ||
        !(core->manifest.entries[core->manifest_child[owner] - 1].flags & SHZ_BMAN_REQUIRED))
        return refuse(core, info, "manifest lacks the required owner child");
    if (owner == 3)
        for (i = 1; i <= 2; ++i)
            if (!core->manifest_child[i] ||
                !(core->manifest.entries[core->manifest_child[i] - 1].flags & SHZ_BMAN_REQUIRED))
                return refuse(core, info, "native Win98 route requires manifest-required Shizuku32/Shizuku64");
    if (parsed == SHZ_BMAN_TEMPLATE) {
        /* Same binding as a stamped manifest, but no installer generation or
         * identity exists: Kernel64 receives an all-zero (unattested) tail. */
        core->manifest_state = SHZ_CORE_MANIFEST_TEMPLATE;
        kprintf("SHZ: %s bound unstamped %s template entries=%u: blobs/hierarchy verified, "
                "installed-target identity NOT attested\n", SHZ_CORE_NAME, SHZ_BMAN_BLOB_NAME, core->manifest.count);
        return 0;
    }
    core->manifest_state = SHZ_CORE_MANIFEST_ADMITTED;
    kprintf("SHZ: %s admitted %s generation=%llu entries=%u\n", SHZ_CORE_NAME, SHZ_BMAN_BLOB_NAME,
            (unsigned long long)core->manifest.header->install_generation, core->manifest.count);
    return 0;
}

/* Kernel transition proof: the image the constructor placed in the child's
 * RAM and described in its boot info is byte-identical to the installed
 * target blob, and so is the Kernel64 initial RAM image. */
static int verify_kernel_load(shz_core_t *core, shz_info_t *info, unsigned index)
{
    const domain_t *d = &g_dom[children[index].domain_id];
    const shz_bootinfo_t *bi;
    const shz_bman_entry_t *e;
    shz_install_identity_t expected;
    uint8_t digest[32];
    unsigned r;
    if (!manifest_bound(core)) return 0;
    if (!core->manifest_child[index])
        return refuse(core, info, "constructor created a child absent from the manifest");
    e = &core->manifest.entries[core->manifest_child[index] - 1];
    if (!(core->manifest.present & (1u << (core->manifest_child[index] - 1))) ||
        d->ram_size < SHZ_BOOTINFO_GPA + sizeof *bi)
        return refuse(core, info, "kernel child admitted without its verified blob");
    bi = (const shz_bootinfo_t *)(uintptr_t)(d->ram_base + SHZ_BOOTINFO_GPA);
    if (bi->magic != SHZ_BOOTINFO_MAGIC || bi->domain_id != d->id || bi->generation != d->generation ||
        bi->kernel_size != e->size || bi->kernel_gpa > d->ram_size || e->size > d->ram_size - bi->kernel_gpa)
        return refuse(core, info, "kernel boot info differs from manifest");
    /* The install tail the child will read is exactly this root's attestation. */
    build_identity(core, &expected);
    if (bi->size != sizeof *bi || memcmp(&bi->install, &expected, sizeof expected))
        return refuse(core, info, "kernel boot info install identity differs from admitted manifest");
    shz_sha256((const void *)(uintptr_t)(d->ram_base + bi->kernel_gpa), e->size, digest);
    if (memcmp(digest, e->sha256, sizeof digest))
        return refuse(core, info, "loaded kernel image differs from installed target");
    if (index != 2) return 0;
    /* Bound by blob name: C1 names the component "Win64Runtime". */
    for (r = 0; r < core->manifest.count && !str16_eq(core->manifest.entries[r].blob, "WIN64.IMG"); ++r) { }
    if (r == core->manifest.count) {
        if (bi->initrd_size) return refuse(core, info, "Kernel64 initial RAM image is not in the manifest");
        return 0;
    }
    e = &core->manifest.entries[r];
    if (!(core->manifest.present & (1u << r))) {
        if (bi->initrd_size) return refuse(core, info, "Kernel64 initial RAM image was not verified");
        return 0;
    }
    if (bi->initrd_size != e->size || bi->initrd_gpa > d->ram_size || e->size > d->ram_size - bi->initrd_gpa)
        return refuse(core, info, "Kernel64 initial RAM image geometry differs from manifest");
    shz_sha256((const void *)(uintptr_t)(d->ram_base + bi->initrd_gpa), e->size, digest);
    if (memcmp(digest, e->sha256, sizeof digest))
        return refuse(core, info, "Kernel64 initial RAM image differs from installed target");
    return 0;
}

/* Dependency and capability admission over the complete created set. */
static int manifest_dependencies(shz_core_t *core, shz_info_t *info)
{
    const shz_bman_t *m = &core->manifest;
    unsigned i, j, c;
    if (!manifest_bound(core)) return 0;
    for (c = 0; c < SHZ_CORE_CHILD_COUNT; ++c) {
        const int member = !!(core->members & (1u << c));
        if (!core->manifest_child[c]) {
            if (member) return refuse(core, info, "admitted child is not listed by the manifest");
            continue;
        }
        if (!member && (m->entries[core->manifest_child[c] - 1].flags & SHZ_BMAN_REQUIRED))
            return refuse(core, info, "manifest-required child was not created");
    }
    for (i = 1; i < m->count; ++i) {
        const shz_bman_entry_t *e = &m->entries[i];
        int live = 0;
        if (e->kind == SHZ_BMAN_KIND_CHILD) {
            for (c = 0; c < SHZ_CORE_CHILD_COUNT; ++c)
                if (core->manifest_child[c] == i + 1) live = !!(core->members & (1u << c));
        } else if (m->present & (1u << i)) {
            for (c = 0; c < SHZ_CORE_CHILD_COUNT && !str16_eq(e->parent, children[c].name); ++c) { }
            if (c == SHZ_CORE_CHILD_COUNT || !(core->members & (1u << c)))
                return refuse(core, info, "verified resource has no admitted parent child");
            live = 1;
        }
        if (!live) continue;
        for (j = 0; j < m->count; ++j) {
            const shz_bman_entry_t *dep = &m->entries[j];
            int ok = 0;
            if (!(e->depends & (1u << j))) continue;
            if (dep->kind == SHZ_BMAN_KIND_CORE) ok = 1;
            else if (dep->kind == SHZ_BMAN_KIND_RESOURCE) ok = !!(m->present & (1u << j));
            else
                for (c = 0; c < SHZ_CORE_CHILD_COUNT; ++c)
                    if (core->manifest_child[c] == j + 1) ok = !!(core->members & (1u << c));
            if (!ok) return refuse(core, info, "manifest dependency of an admitted component is unsatisfied");
        }
    }
    return 0;
}

int __attribute__((weak)) shz_core_driver_init(const shz_core_driver_view_t *view, shz_info_t *info)
{
    (void)view; (void)info;
    return SHZ_CORE_DRIVERS_ABSENT; /* no driver-binding provider linked into this payload */
}

static int drivers_admit(shz_core_t *core, shz_info_t *info)
{
    shz_core_driver_view_t view;
    int rc;
    memset(&view, 0, sizeof view);
    view.boot_epoch = core->boot_epoch;
    view.domain_epoch = core->domain_epoch;
    view.install_generation = core->manifest.header ? core->manifest.header->install_generation : 0;
    view.members = core->members;
    view.loader_flags = core->resources.loader_flags;
    view.cap_bits = info->cap_bits;
    view.manifest_state = core->manifest_state;
    view.manifest = manifest_bound(core) ? &core->manifest : 0;
    view.resources = &core->resources;
    rc = shz_core_driver_init(&view, info);
    if (rc < 0) {
        if (!info->last_error[0]) log_capture(info->last_error, sizeof info->last_error, "driver initialization refused");
        return refuse(core, info, info->last_error);
    }
    if (rc != 0 && rc != SHZ_CORE_DRIVERS_ABSENT) return refuse(core, info, "driver hook returned an invalid status");
    core->driver_state = rc ? SHZ_CORE_DRV_ABSENT : SHZ_CORE_DRV_BOUND;
    kprintf("SHZ: %s driver binding %s\n", SHZ_CORE_NAME,
            rc ? "provider absent: driver binding NOT attested" : "admitted by provider");
    return 0;
}

int shz_core_create(shz_core_t *core, shz_info_t *info, const shz_caps_t *caps,
                    const uint8_t *vbios, unsigned vbios_len)
{
    unsigned i, owner;
    int rc;
    if (!core || !header_valid(info) || !caps) return refuse(core, info, "invalid root creation context");
    if (core->phase != SHZ_CORE_NEW) {
        log_capture(info->last_error, sizeof info->last_error, "ShizukuCore: creation context already consumed");
        return -1;
    }
    if (!fresh_context(core)) return refuse(core, info, "creation requires a fresh zero-initialized root");
    core->phase = SHZ_CORE_CREATING;
    core->owner = info;
    g_core_root = core;
    core->boot_epoch = info->hv_instance_id;
    core->domain_epoch = info->domain_generation;
    core->members = 0;
    memset(core->generation, 0, sizeof core->generation);
    capture(&core->resources, info);
    if (!core->boot_epoch || !resources_valid(&core->resources) || info->domain_generation == UINT64_MAX)
        return refuse(core, info, "invalid or overlapping root resource ownership");
    if (admit_manifest(core, info)) return -1;
    for (i = 0; i < SHZ_MAX_DOMAINS; ++i)
        if (!empty_domain(&g_dom[i]) || info->domains[i].state || info->domains[i].kind ||
            info->domains[i].generation)
            return refuse(core, info, "domain ownership or stale publication already exists");
    owner = info->loader_flags == SHZ_LOADER_NATIVE_WIN98 ? 3u : 0u;
    if (!owner && (!vbios || vbios_len != 0x10000u))
        return refuse(core, info, "DOS owner requires its existing 64 KiB vBIOS");
    core->attempted |= 1u << owner;
    rc = owner == 3 ? win98_domain_create(info, caps) : dos_domain_create(info, caps, vbios, vbios_len);
    if (rc) return constructor_failed(core, info);
    if (!unchanged(core, info))
        return refuse(core, info, "owner constructor changed root resources or epoch");
    if (admit_child(core, info, owner)) return -1;
    for (i = 1; i <= 2; ++i) {
        /* Constructors must never overwrite a slot published unexpectedly by
         * an earlier child. Validate the admitted prefix before each write. */
        if (!members_valid(core, 0, 0))
            return refuse(core, info, "creation progress contains unexpected child ownership");
        core->attempted |= 1u << i;
        rc = kernel_domain_create(info, caps, children[i].kind);
        if (rc < 0) return constructor_failed(core, info);
        if (!unchanged(core, info))
            return refuse(core, info, "worker constructor changed root resources or epoch");
        if (rc == 1) {
            if (owner == 3 || !empty_domain(&g_dom[children[i].domain_id]))
                return refuse(core, info, "required or absent child ownership differs");
            kprintf("SHZ: %s child %s mode=%s absent in this profile\n", SHZ_CORE_NAME,
                    children[i].name, children[i].mode);
        } else if (rc || admit_child(core, info, i)) {
            return refuse(core, info, "child constructor returned an invalid admission");
        } else if (verify_kernel_load(core, info, i)) {
            return -1;
        }
    }
    if (!unchanged(core, info) || !members_valid(core, 0, 1))
        return refuse(core, info, "child creation changed root resources or ownership");
    if (manifest_dependencies(core, info)) return -1;
    if (ipc_channels_create(info)) return constructor_failed(core, info);
    if (!unchanged(core, info) || !members_valid(core, 1, 1))
        return refuse(core, info, "IPC publication differs from admitted child ownership");
    if (drivers_admit(core, info)) return -1;
    if (!unchanged(core, info) || !members_valid(core, 1, 1))
        return refuse(core, info, "driver initialization changed root resources or ownership");
    info->domain_generation += 1;
    core->domain_epoch = info->domain_generation;
    core->phase = SHZ_CORE_READY;
    return 0;
}

int shz_core_run(shz_core_t *core, shz_info_t *info)
{
    int rc;
    if (!core || !header_valid(info) || core->phase != SHZ_CORE_READY || core->owner != info ||
        core->boot_epoch != info->hv_instance_id || core->domain_epoch != info->domain_generation)
        return refuse(core, info, "run requires its original ready root and boot epoch");
    if (!unchanged(core, info) || !resources_valid(&core->resources) || !members_valid(core, 1, 1))
        return refuse(core, info, "run ownership differs from admitted resources/children");
    core->phase = SHZ_CORE_RUNNING;
    rc = sched_run(info);
    if (core->phase != SHZ_CORE_RUNNING)
        return refuse(core, info, "scheduler returned through a consumed root context");
    core->phase = rc < 0 ? SHZ_CORE_FAILED : SHZ_CORE_FINISHED;
    return rc; /* Domain failures stay in g_dom; return does not attest a guest boot. */
}

/* ------------------------------------------------------------ driver report */
int shz_core_drvrep_validate(const shz_drvrep_t *r, uint64_t expected_generation, const char **why)
{
    const uint32_t profiles = SHZ_DRVREP_PASSTHROUGH | SHZ_DRVREP_FOUNDATION;
    uint64_t sum;
    const char *unused;
    if (!why) why = &unused;
    *why = "report absent";
    if (!r) return SHZ_E_INVALID;
    *why = "bad magic/version/size";
    if (r->magic != SHZ_DRVREP_MAGIC || r->version != SHZ_DRVREP_VERSION || r->size != sizeof *r)
        return SHZ_E_PROTO;
    *why = "reserved words nonzero";
    if (r->reserved[0] || r->reserved[1]) return SHZ_E_INVALID;
    /* Profile bits are mutually exclusive; unknown bits are refused. */
    *why = "unknown or conflicting profile flags";
    if ((r->flags & ~profiles) || r->flags == profiles) return SHZ_E_INVALID;
    sum = (uint64_t)r->running + r->claimed + r->not_started + r->failed + r->unsupported +
          r->infrastructure + r->linked_elsewhere;
    *why = "row counters inconsistent";
    if (r->rows > SHZ_DRVREP_MAX_ROWS || sum != r->rows) return SHZ_E_INVALID;
    *why = "install generation differs from the admitted manifest";
    if (r->install_generation != expected_generation) return SHZ_E_STALE;
    *why = "ok";
    return SHZ_OK;
}

int shz_core_driver_report(uint32_t domain_id, uint32_t domain_generation, const shz_drvrep_t *copy)
{
    shz_core_t *core = g_core_root;
    const char *why = "not running";
    uint64_t expected;
    int rc;
    if (!core || core->phase != SHZ_CORE_RUNNING || !core->owner) {
        kprintf("SHZ: %s refused driver report: no running root\n", SHZ_CORE_NAME);
        return SHZ_E_NOENT;
    }
    if (domain_id != SHZ_DOM_KERNEL64 || member_index(core, domain_id) != 2 || !domain_generation ||
        core->generation[2] != domain_generation || g_dom[domain_id].generation != domain_generation) {
        kprintf("SHZ: %s refused driver report from domain %u: not the admitted Kernel64\n", SHZ_CORE_NAME, domain_id);
        return SHZ_E_DENIED;
    }
    if (core->driver_report_generation == domain_generation) {
        kprintf("SHZ: %s refused second driver report for Kernel64 generation %u\n", SHZ_CORE_NAME, domain_generation);
        return SHZ_E_BUSY;
    }
    expected = core->manifest_state == SHZ_CORE_MANIFEST_ADMITTED && core->manifest.header ?
               core->manifest.header->install_generation : 0;
    rc = shz_core_drvrep_validate(copy, expected, &why);
    if (rc != SHZ_OK) {
        kprintf("SHZ: %s refused Kernel64 driver report: %s\n", SHZ_CORE_NAME, why);
        return rc;
    }
    memcpy(&core->driver_report_copy, copy, sizeof *copy);
    core->driver_report_generation = domain_generation;
    core->driver_report = copy->failed == 0 && copy->services_failed == 0 ?
                          SHZ_CORE_DRV_REPORTED_OK : SHZ_CORE_DRV_REPORTED_FAILED;
    kprintf("SHZ: %s Kernel64 driver report %s: rows=%u running=%u claimed=%u not_started=%u failed=%u "
            "unsupported=%u infra=%u elsewhere=%u services=%u/%u failed=%u catalog=%u matched=%u rejected=%u "
            "install_generation=%llu (%s)\n", SHZ_CORE_NAME,
            core->driver_report == SHZ_CORE_DRV_REPORTED_OK ? "OK" : "FAILED",
            copy->rows, copy->running, copy->claimed, copy->not_started, copy->failed, copy->unsupported,
            copy->infrastructure, copy->linked_elsewhere, copy->services_loaded, copy->services_considered,
            copy->services_failed, copy->catalog_entries, copy->catalog_matched, copy->catalog_rejected,
            (unsigned long long)copy->install_generation, expected ? "attested" : "unattested");
    return SHZ_OK;
}
