/* SPDX-License-Identifier: GPL-2.0-only
 * Snapshot GOP, the memory map, storage, ACPI, SMBIOS and the keyboard protocol
 * while UEFI boot services still exist. After csmwrap_uefi_after_exit begins,
 * this file never calls boot services. Real mode is entered only when the
 * handoff proves both CSMWrap and KERNEL64 ran.
 */
#include "../../uefi/efi.h"
#include "../../uefi/boot.h"
#include "../include/csmwrap_abi.h"

#define CSM_ALLOCATE_ADDRESS 2u
#define CSM_BY_PROTOCOL 2u
#define CSM_CONVENTIONAL 7u
#define CSM_FILE_READ 1ull

static int low_ready;
static csmwrap_handoff high_handoff;
static csmwrap_service_table high_services;

static const EFI_GUID gop_guid = {0x9042a9de, 0x23dc, 0x4a38,
    {0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a}};
static const EFI_GUID acpi2_guid = {0x8868e871, 0xe4f1, 0x11d3,
    {0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81}};
static const EFI_GUID acpi1_guid = {0xeb9d2d30, 0x2d88, 0x11d3,
    {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}};
static const EFI_GUID smbios3_guid = {0xf2fd1544, 0x9794, 0x4a2c,
    {0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94}};
static const EFI_GUID smbios_guid = {0xeb9d2d31, 0x2d88, 0x11d3,
    {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}};
static const EFI_GUID loaded_guid = {0x5b1b31a1, 0x9562, 0x11d2,
    {0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
static const EFI_GUID fs_guid = {0x964e5b22, 0x6459, 0x11d2,
    {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
static const EFI_GUID blk_guid = {0x964e5b21, 0x6459, 0x11d2,
    {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};

typedef EFI_STATUS (EFIAPI *csm_alloc_pages)(uint32_t, uint32_t, size_t, uint64_t *);
typedef EFI_STATUS (EFIAPI *csm_handle_protocol)(EFI_HANDLE, EFI_GUID *, void **);
typedef EFI_STATUS (EFIAPI *csm_locate_handles)(uint32_t, EFI_GUID *, void *, size_t *, EFI_HANDLE **);

typedef struct {
    uint32_t revision;
    EFI_HANDLE parent;
    EFI_SYSTEM_TABLE *system;
    EFI_HANDLE device;
} csm_loaded_image;

typedef struct csm_file csm_file;
typedef struct csm_fs {
    uint64_t revision;
    EFI_STATUS (EFIAPI *open_volume)(struct csm_fs *, csm_file **);
} csm_fs;

struct csm_file {
    uint64_t revision;
    EFI_STATUS (EFIAPI *open)(csm_file *, csm_file **, CHAR16 *, uint64_t, uint64_t);
    EFI_STATUS (EFIAPI *close)(csm_file *);
    void *remove;
    EFI_STATUS (EFIAPI *read)(csm_file *, size_t *, void *);
};

typedef struct {
    uint32_t media_id;
    uint8_t removable, present, logical, readonly, caching;
    uint8_t pad[3];
    uint32_t block_size;
    uint32_t io_align;
    uint64_t last_block;
} csm_media;

typedef struct {
    uint64_t revision;
    csm_media *media;
} csm_block_io;

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    size_t i;
    for (i = 0; i < sizeof(*a); ++i)
        if (x[i] != y[i])
            return 0;
    return 1;
}

static void *table_by_guid(EFI_SYSTEM_TABLE *st, const EFI_GUID *guid)
{
    size_t i;
    if (!st->tables || st->table_count > 4096)
        return 0;
    for (i = 0; i < st->table_count; ++i)
        if (guid_equal(&st->tables[i].guid, guid))
            return st->tables[i].table;
    return 0;
}

static void note_memory(EFI_BOOT_SERVICES *bs, csmwrap_snapshot *shot, csmwrap_e820 *rows)
{
    size_t bytes = 0, key = 0, stride = 0, offset;
    uint32_t version = 0, count = 0;
    EFI_MEMORY_DESCRIPTOR *map = 0;
    EFI_STATUS status;
    status = bs->get_memory_map(&bytes, 0, &key, &stride, &version);
    if (status != EFI_BUFFER_TOO_SMALL || !stride || stride > 4096 || bytes > SD_MAP_LIMIT)
        return;
    bytes += 4096;
    if (EFI_ERROR(bs->allocate_pool(EFI_LOADER_DATA, bytes, (void **)&map)))
        return;
    status = bs->get_memory_map(&bytes, map, &key, &stride, &version);
    if (EFI_ERROR(status)) {
        bs->free_pool(map);
        return;
    }
    for (offset = 0; offset + stride <= bytes; offset += stride) {
        const EFI_MEMORY_DESCRIPTOR *desc =
            (const EFI_MEMORY_DESCRIPTOR *)((uint8_t *)map + offset);
        uint64_t kb;
        if (desc->type != CSM_CONVENTIONAL || !desc->pages)
            continue;
        kb = desc->pages * 4u;
        if (desc->physical_start < 0x100000ull) {
            if (shot->conventional_kb <= 0xffffffffu - (uint32_t)kb)
                shot->conventional_kb += (uint32_t)kb;
        } else if (shot->extended_kb <= 0xffffffffu - (uint32_t)kb) {
            shot->extended_kb += (uint32_t)kb;
        }
        if (count < 32) {
            rows[count].base = desc->physical_start;
            rows[count].length = desc->pages << 12;
            rows[count].type = 1;
            rows[count].attrs = 1;
            ++count;
        }
    }
    shot->e820 = rows;
    shot->e820_count = count;
    bs->free_pool(map);
}

static void note_storage(EFI_BOOT_SERVICES *bs, csmwrap_snapshot *shot)
{
    csm_locate_handles locate;
    csm_handle_protocol handle;
    EFI_HANDLE *handles = 0;
    size_t count = 0, i;
    EFI_STATUS status;
    if (!bs->locate_handle_buffer || !bs->handle_protocol)
        return;
    locate = (csm_locate_handles)bs->locate_handle_buffer;
    handle = (csm_handle_protocol)bs->handle_protocol;
    status = locate(CSM_BY_PROTOCOL, (EFI_GUID *)&blk_guid, 0, &count, &handles);
    if (EFI_ERROR(status) || !count)
        return;
    shot->block_io_count = count;
    for (i = 0; i < count; ++i) {
        csm_block_io *block = 0;
        if (EFI_ERROR(handle(handles[i], (EFI_GUID *)&blk_guid, (void **)&block)) || !block || !block->media)
            continue;
        if (!block->media->present || block->media->logical || !block->media->block_size)
            continue;
        shot->sector_size = block->media->block_size;
        shot->boot_disk_id = 0x80;
        if (block->media->last_block < UINT64_MAX / block->media->block_size)
            shot->disk_size = (block->media->last_block + 1u) * block->media->block_size;
        break;
    }
    if (bs->free_pool && handles)
        bs->free_pool(handles);
}

static void note_kernel(EFI_BOOT_SERVICES *bs, EFI_HANDLE image, csmwrap_snapshot *shot)
{
    static const CHAR16 path_a[] = {'\\', 'S', 'H', 'Z', 'D', 'O', 'S', '\\', 'K', 'E', 'R', 'N', 'E', 'L',
                                     '6', '4', '.', 'B', 'I', 'N', 0};
    static const CHAR16 path_b[] = {'\\', 'K', 'E', 'R', 'N', 'E', 'L', '6', '4', '.', 'B', 'I', 'N', 0};
    csm_handle_protocol handle;
    csm_loaded_image *loaded = 0;
    csm_fs *fs = 0;
    csm_file *root = 0, *file = 0;
    uint8_t *buffer = 0;
    size_t bytes = 256 * 1024;
    const CHAR16 *paths[2];
    unsigned n;
    if (!bs->handle_protocol || !bs->allocate_pool || !bs->free_pool)
        return;
    handle = (csm_handle_protocol)bs->handle_protocol;
    if (EFI_ERROR(handle(image, (EFI_GUID *)&loaded_guid, (void **)&loaded)) || !loaded)
        return;
    if (EFI_ERROR(handle(loaded->device, (EFI_GUID *)&fs_guid, (void **)&fs)) || !fs || !fs->open_volume)
        return;
    if (EFI_ERROR(fs->open_volume(fs, &root)) || !root)
        return;
    paths[0] = path_a;
    paths[1] = path_b;
    if (EFI_ERROR(bs->allocate_pool(EFI_LOADER_DATA, bytes, (void **)&buffer))) {
        root->close(root);
        return;
    }
    for (n = 0; n < 2; ++n) {
        size_t got = bytes;
        if (EFI_ERROR(root->open(root, &file, (CHAR16 *)paths[n], CSM_FILE_READ, 0)) || !file)
            continue;
        if (!EFI_ERROR(file->read(file, &got, buffer)) && got >= 64) {
            shot->kernel64 = buffer;
            shot->kernel64_bytes = (uint32_t)got;
            file->close(file);
            root->close(root);
            return;
        }
        file->close(file);
        file = 0;
    }
    bs->free_pool(buffer);
    root->close(root);
}

static void publish_low(EFI_BOOT_SERVICES *bs, csmwrap_handoff *handoff, csmwrap_service_table *services)
{
    csm_alloc_pages alloc_pages;
    uint64_t addr = CSMWRAP_HANDOFF_PHYS;
    csmwrap_service_table *low_services;
    csmwrap_handoff *low_handoff;
    const uint8_t *stub;
    unsigned stub_bytes, i;
    extern const uint8_t csmwrap_entry16_bytes[];
    extern const uint32_t csmwrap_entry16_size;
    if (!bs->allocate_pages)
        return;
    alloc_pages = (csm_alloc_pages)bs->allocate_pages;
    if (EFI_ERROR(alloc_pages(CSM_ALLOCATE_ADDRESS, EFI_LOADER_DATA, 4, &addr)) ||
        addr != CSMWRAP_HANDOFF_PHYS)
        return;
    low_handoff = (csmwrap_handoff *)(uintptr_t)CSMWRAP_HANDOFF_PHYS;
    low_services = (csmwrap_service_table *)(uintptr_t)(CSMWRAP_HANDOFF_PHYS + 0x100);
    *low_services = *services;
    *low_handoff = *handoff;
    low_handoff->service_table = (uint64_t)(uintptr_t)low_services;
    low_handoff->e820_addr = (uint64_t)(uintptr_t)low_services->e820;
    if (low_handoff->pci_info)
        low_handoff->pci_info = handoff->pci_info;
    low_handoff->flags |= CSMWRAP_F_LOWMEM;
    csmwrap_handoff_seal(low_handoff);
    stub = csmwrap_entry16_bytes;
    stub_bytes = csmwrap_entry16_size;
    if (stub_bytes > 512)
        return;
    for (i = 0; i < stub_bytes; ++i)
        ((uint8_t *)(uintptr_t)CSMWRAP_ENTRY_PHYS)[i] = stub[i];
    low_ready = 1;
    *handoff = *low_handoff;
}

int csmwrap_uefi_before_exit(void *image, void *system_table, void *gop_unused)
{
    EFI_SYSTEM_TABLE *st = system_table;
    EFI_BOOT_SERVICES *bs;
    EFI_GOP *gop = 0;
    csmwrap_snapshot shot;
    csmwrap_e820 rows[32];
    unsigned i;
    (void)gop_unused;
    csmwrap_diag_reset();
    csmwrap_diag_note("CSMWRAP uefi collect\n");
    if (!st || st->header.signature != EFI_SYSTEM_TABLE_SIGNATURE || !st->boot_services)
        return -1;
    bs = st->boot_services;
    if (bs->header.signature != EFI_BOOT_SERVICES_SIGNATURE || !bs->locate_protocol)
        return -1;
    for (i = 0; i < sizeof shot; ++i)
        ((uint8_t *)&shot)[i] = 0;
    shot.firmware.efi_signature = st->header.signature;
    shot.firmware.pointer_bits = (uint32_t)(sizeof(void *) * 8u);
    shot.uefi_system_table = (uint64_t)(uintptr_t)st;
    shot.rsdp = (uint64_t)(uintptr_t)table_by_guid(st, &acpi2_guid);
    if (!shot.rsdp)
        shot.rsdp = (uint64_t)(uintptr_t)table_by_guid(st, &acpi1_guid);
    shot.smbios = (uint64_t)(uintptr_t)table_by_guid(st, &smbios3_guid);
    if (!shot.smbios)
        shot.smbios = (uint64_t)(uintptr_t)table_by_guid(st, &smbios_guid);
    if (st->console_in) {
        shot.keyboard = (uint64_t)(uintptr_t)st->console_in;
    }
    if (!EFI_ERROR(bs->locate_protocol((EFI_GUID *)&gop_guid, 0, (void **)&gop)) && gop && gop->mode &&
        gop->mode->info) {
        shot.fb_addr = gop->mode->framebuffer_base;
        shot.fb_width = gop->mode->info->width;
        shot.fb_height = gop->mode->info->height;
        shot.fb_pitch = gop->mode->info->pixels_per_scan_line * 4u;
        shot.fb_format = gop->mode->info->pixel_format;
    }
    note_memory(bs, &shot, rows);
    note_storage(bs, &shot);
    note_kernel(bs, image, &shot);
    if (csmwrap_fill_snapshot(&high_handoff, &high_services, &shot) != 0)
        return -1;
    publish_low(bs, &high_handoff, &high_services);
    csmwrap_diag_note("CSMWRAP handoff sealed\n");
    return 0;
}

extern void csmwrap_jump_real(void);

void csmwrap_uefi_after_exit(void)
{
    const csmwrap_handoff *live;
    /* Boot services are gone. The physical page published earlier is the only source. */
    if (!low_ready)
        return;
    live = (const csmwrap_handoff *)(uintptr_t)CSMWRAP_HANDOFF_PHYS;
    if (!csmwrap_boot_allowed(live))
        return;
    csmwrap_jump_real();
}
