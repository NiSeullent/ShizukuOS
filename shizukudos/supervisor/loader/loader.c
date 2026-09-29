/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku Supervisor UEFI loader (x64 PE/COFF).
 *
 * Before ExitBootServices it can still return to firmware, so every check that can
 * refuse the machine happens here: Long Mode, VMX/SVM capability and firmware
 * enablement, the disk image, the fixed Supervisor region. Only then does it
 * exit boot services with the correct MapKey (retry loop in shizukudos/uefi/boot.c)
 * and enter the Supervisor payload with interrupts disabled. After that point no
 * UEFI service is ever called.
 */
#include "efi_ext.h"
#include "../../uefi/boot.h"
#include "../include/shz_info.h"
#include "../src/caps.h"
#include "images.h"

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st);
/* A real absolute address keeps a base-relocation section in the PE image. */
EFI_STATUS (EFIAPI *volatile shz_efi_entry_address)(EFI_HANDLE, EFI_SYSTEM_TABLE *) = efi_main;

static EFI_GUID gop_guid = {0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
static const EFI_GUID acpi2_guid = {0x8868e871,0xe4f1,0x11d3,{0xbc,0x22,0x00,0x80,0xc7,0x3c,0x88,0x81}};
static const EFI_GUID loaded_image_guid = {0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static const EFI_GUID sfs_guid = {0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static const EFI_GUID file_info_guid = {0x09576e92,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};

#define GUEST_RAM_MIB 64

static EFI_SYSTEM_TABLE *g_st;
static SD_HANDOFF g_handoff;
static shz_blob_t g_blobs[SHZ_MAX_BLOBS];
static uint64_t g_k32_ram, g_k64_ram, g_ipc;

static void say(const char *text)
{
    CHAR16 buffer[160];
    size_t n;
    if (!g_st->console_out || !g_st->console_out->output_string)
        return;
    while (*text) {
        for (n = 0; n < 158 && *text; ++n) {
            if (*text == '\n')
                buffer[n++] = '\r';
            buffer[n] = (uint8_t)*text++;
        }
        buffer[n] = 0;
        g_st->console_out->output_string(g_st->console_out, buffer);
    }
}

static void say_hex(uint64_t v)
{
    char text[19] = "0x";
    int i;
    for (i = 0; i < 16; ++i)
        text[2 + i] = "0123456789abcdef"[(v >> (60 - 4 * i)) & 15];
    text[18] = 0;
    say(text);
}

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    size_t i;
    for (i = 0; i < sizeof *a; ++i)
        if (x[i] != y[i])
            return 0;
    return 1;
}

static uint64_t rdtsc_now(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static void zero(void *p, size_t n)
{
    uint8_t *b = p;
    while (n--)
        *b++ = 0;
}

/* Reads \SHZDOS\<name> from the volume this image was loaded from into LoaderData pages. */
static EFI_STATUS load_file(EFI_HANDLE image, EFI_BOOT_SERVICES *bs, const char *name, uint64_t *base,
                            uint64_t *size, uint64_t max_bytes)
{
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_FILE_PROTOCOL *root = 0, *file = 0;
    CHAR16 path[48] = {'\\', 'S', 'H', 'Z', 'D', 'O', 'S', '\\'};
    uint8_t infobuf[512];
    size_t infosize = sizeof infobuf, done = 0, n = 8, k;
    uint64_t addr = 0;
    EFI_STATUS status;
    EFI_HANDLE_PROTOCOL_FN handle_protocol = (EFI_HANDLE_PROTOCOL_FN)bs->handle_protocol;
    EFI_ALLOCATE_PAGES_FN allocate_pages = (EFI_ALLOCATE_PAGES_FN)bs->allocate_pages;

    for (k = 0; name[k] && n < 46; ++k)
        path[n++] = (uint8_t)name[k];
    path[n] = 0;
    status = handle_protocol(image, &loaded_image_guid, (void **)&li);
    if (EFI_ERROR(status) || !li)
        return EFI_ERROR(status) ? status : EFI_UNSUPPORTED;
    status = handle_protocol(li->device_handle, &sfs_guid, (void **)&fs);
    if (EFI_ERROR(status) || !fs)
        return EFI_ERROR(status) ? status : EFI_UNSUPPORTED;
    status = fs->open_volume(fs, &root);
    if (EFI_ERROR(status))
        return status;
    status = root->open(root, &file, path, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) {
        root->close(root);
        return status;
    }
    status = file->get_info(file, &file_info_guid, &infosize, infobuf);
    if (!EFI_ERROR(status)) {
        const EFI_FILE_INFO *info = (const EFI_FILE_INFO *)infobuf;
        const uint64_t bytes = info->file_size;
        if (bytes < 16 || bytes > max_bytes) {
            status = EFI_INVALID_PARAMETER;
        } else {
            status = allocate_pages(EFI_ALLOCATE_ANY_PAGES, EFI_MEM_LOADER_DATA, (size_t)((bytes + 4095) >> 12), &addr);
            if (!EFI_ERROR(status)) {
                while (done < bytes) {
                    size_t chunk = (size_t)(bytes - done > (1u << 20) ? (1u << 20) : bytes - done);
                    status = file->read(file, &chunk, (uint8_t *)(uintptr_t)addr + done);
                    if (EFI_ERROR(status) || !chunk)
                        break;
                    done += chunk;
                }
                if (!EFI_ERROR(status) && done == bytes) {
                    *base = addr;
                    *size = bytes;
                    status = EFI_SUCCESS;
                } else if (!EFI_ERROR(status)) {
                    status = EFI_DEVICE_ERROR;
                }
            }
        }
    }
    file->close(file);
    root->close(root);
    return status;
}

/* RAM for a guest domain, aligned so the Supervisor can use 2 MiB EPT leaves. */
static EFI_STATUS alloc_guest_ram(EFI_BOOT_SERVICES *bs, uint64_t mib, uint64_t *base)
{
    EFI_ALLOCATE_PAGES_FN allocate_pages = (EFI_ALLOCATE_PAGES_FN)bs->allocate_pages;
    uint64_t raw = 0;
    EFI_STATUS status = allocate_pages(EFI_ALLOCATE_ANY_PAGES, EFI_MEM_LOADER_DATA, (size_t)((mib + 2) << 8), &raw);
    if (EFI_ERROR(status))
        return status;
    *base = (raw + 0x1fffff) & ~0x1fffffull;
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    EFI_BOOT_SERVICES *bs;
    EFI_GOP *gop = 0;
    shz_caps_t caps;
    shz_info_t *info = (shz_info_t *)(uintptr_t)SHZ_REGION_BASE;
    EFI_ALLOCATE_PAGES_FN allocate_pages;
    EFI_STALL_FN stall;
    EFI_STATUS status;
    uint64_t addr = SHZ_REGION_BASE, guest = 0, disk_base = 0, disk_size = 0, t0, t1;
    size_t i;

    if (!st || st->header.signature != EFI_SYSTEM_TABLE_SIGNATURE || !st->boot_services)
        return EFI_INVALID_PARAMETER;
    g_st = st;
    bs = st->boot_services;
    if (bs->header.signature != EFI_BOOT_SERVICES_SIGNATURE || !bs->locate_protocol || !bs->allocate_pool ||
        !bs->allocate_pages || !bs->handle_protocol || !bs->stall || !bs->set_watchdog_timer)
        return EFI_UNSUPPORTED;
    allocate_pages = (EFI_ALLOCATE_PAGES_FN)bs->allocate_pages;
    stall = (EFI_STALL_FN)bs->stall;
    say("ShizukuDOS 10.0-dev Supervisor loader (UEFI x64)\n");
    bs->set_watchdog_timer(0, 0, 0, 0);

    /* 1. Can this machine host the DOS16 domain in virtual Real Mode at all? */
    shz_probe_caps(&caps);
    if (!caps.long_mode) {
        say("REFUSED: CPU lacks Long Mode.\n");
        return EFI_UNSUPPORTED;
    }
    if (caps.vendor == SHZ_VENDOR_AMD) {
        say(caps.svm_usable ? "REFUSED: AMD SVM is usable, but the SVM backend is not implemented in this build.\n"
                            : "REFUSED: AMD SVM unusable: ");
        if (!caps.svm_usable)
            say(caps.svm_why);
        say("\nReturning to firmware. The legacy BIOS (CSM) profile does not need virtualization.\n");
        return EFI_UNSUPPORTED;
    }
    if (!caps.vmx_usable) {
        say("REFUSED: Intel VMX backend unusable: ");
        say(caps.vmx_why);
        say("\nEnable Intel VT-x in the firmware setup, or boot the legacy BIOS (CSM) profile.\nReturning to firmware.\n");
        return EFI_UNSUPPORTED;
    }
    say("Virtualization: Intel VMX with EPT and Unrestricted Guest available.\n");

    /* 2. Display. */
    if (EFI_ERROR(bs->locate_protocol(&gop_guid, 0, (void **)&gop)) || !gop ||
        EFI_ERROR(sd_framebuffer_snapshot(gop->mode, &g_handoff.framebuffer))) {
        say("REFUSED: no usable GOP framebuffer.\n");
        return EFI_UNSUPPORTED;
    }

    /* 3. Disk image and memory the Supervisor will own. */
    status = load_file(image, bs, "DISK.IMG", &disk_base, &disk_size, 256ull << 20);
    if (EFI_ERROR(status)) {
        say("REFUSED: cannot read \\SHZDOS\\DISK.IMG from the boot volume (status ");
        say_hex(status);
        say(").\n");
        return status;
    }
    status = allocate_pages(EFI_ALLOCATE_ADDRESS, EFI_MEM_LOADER_DATA, (size_t)(SHZ_REGION_SIZE >> 12), &addr);
    if (EFI_ERROR(status)) {
        say("REFUSED: fixed Supervisor region at 64 MiB is not free (status ");
        say_hex(status);
        say(").\n");
        return status;
    }
    status = allocate_pages(EFI_ALLOCATE_ANY_PAGES, EFI_MEM_LOADER_DATA, (size_t)((uint64_t)GUEST_RAM_MIB << 8), &guest);
    if (EFI_ERROR(status)) {
        say("REFUSED: cannot allocate guest RAM.\n");
        return status;
    }

    /* 3b. Optional guest kernels and their initial RAM image: each present file adds a domain. */
    {
        static const struct { const char *name; uint64_t max; } wanted[] = {
            {"KERNEL32.BIN", 8ull << 20}, {"KERNEL64.BIN", 16ull << 20}, {"WIN64.IMG", 64ull << 20}};
        size_t w, slot = 0;
        for (w = 0; w < sizeof wanted / sizeof wanted[0]; ++w) {
            uint64_t base = 0, size = 0;
            size_t k;
            status = load_file(image, bs, wanted[w].name, &base, &size, wanted[w].max);
            if (status == EFI_NOT_FOUND)
                continue;
            if (EFI_ERROR(status)) {
                say("REFUSED: cannot read guest kernel image ");
                say(wanted[w].name);
                say("\n");
                return status;
            }
            for (k = 0; wanted[w].name[k] && k < 15; ++k)
                g_blobs[slot].name[k] = wanted[w].name[k];
            g_blobs[slot].base = base;
            g_blobs[slot].size = size;
            ++slot;
        }
    }
    if (g_blobs[0].size) {
        size_t b;
        for (b = 0; b < SHZ_MAX_BLOBS && g_blobs[b].size; ++b) {
            const char *n = g_blobs[b].name;
            if (n[0] == 'K' && n[6] == '3' && n[7] == '2') {
                if (EFI_ERROR(alloc_guest_ram(bs, 32, &g_k32_ram))) { say("REFUSED: no memory for Kernel32.\n"); return EFI_OUT_OF_RESOURCES; }
            } else if (n[0] == 'K' && n[6] == '6' && n[7] == '4') {
                if (EFI_ERROR(alloc_guest_ram(bs, 64, &g_k64_ram))) { say("REFUSED: no memory for Kernel64.\n"); return EFI_OUT_OF_RESOURCES; }
            }
        }
        if (EFI_ERROR(alloc_guest_ram(bs, 4, &g_ipc))) { say("REFUSED: no memory for IPC.\n"); return EFI_OUT_OF_RESOURCES; }
    }

    /* 4. Calibrate the TSC against firmware time, once, while services still exist. */
    t0 = rdtsc_now();
    stall(100000);
    t1 = rdtsc_now();

    zero(info, SHZ_INFO_BYTES);
    info->magic = SHZ_INFO_MAGIC;
    info->version = SHZ_INFO_VERSION;
    info->size = sizeof *info;
    info->tsc_hz = (t1 - t0) * 10;
    info->fb_base = g_handoff.framebuffer.base;
    info->fb_size = g_handoff.framebuffer.size;
    info->fb_width = g_handoff.framebuffer.width;
    info->fb_height = g_handoff.framebuffer.height;
    info->fb_pitch_pixels = g_handoff.framebuffer.pitch_pixels;
    info->fb_format = g_handoff.framebuffer.pixel_format;
    info->guest_ram_base = guest;
    info->guest_ram_size = (uint64_t)GUEST_RAM_MIB << 20;
    info->disk_base = disk_base;
    info->disk_size = disk_size;
    info->region_base = SHZ_REGION_BASE;
    info->region_size = SHZ_REGION_SIZE;
    info->boot_path = 1;
    for (i = 0; i < SHZ_MAX_BLOBS; ++i)
        info->blobs[i] = g_blobs[i];
    if (g_k32_ram) { info->k32_ram_base = g_k32_ram; info->k32_ram_size = 32ull << 20; }
    if (g_k64_ram) { info->k64_ram_base = g_k64_ram; info->k64_ram_size = 64ull << 20; }
    if (g_ipc) { info->ipc_base = g_ipc; info->ipc_size = 4ull << 20; }
    if (st->tables && st->table_count <= 4096)
        for (i = 0; i < st->table_count; ++i)
            if (guid_equal(&st->tables[i].guid, &acpi2_guid))
                info->acpi_rsdp = (uint64_t)(uintptr_t)st->tables[i].table;
    {
        uint8_t *dst = (uint8_t *)(uintptr_t)SHZ_PAYLOAD_ENTRY;
        for (i = 0; i < sizeof payload_image; ++i)
            dst[i] = payload_image[i];
    }
    say("Handing over to the Supervisor (ExitBootServices).\n");

    status = sd_exit_boot_services(bs, image, &g_handoff);
    if (EFI_ERROR(status) && !g_handoff.exit_attempted) {
        say("ExitBootServices preparation failed; still in firmware.\n");
        return status;
    }
    __asm__ volatile("cli" ::: "memory");
    if (!g_handoff.boot_services_exited)
        for (;;)
            __asm__ volatile("hlt");
    info->memmap_base = (uint64_t)(uintptr_t)g_handoff.memory_map;
    info->memmap_bytes = g_handoff.map_size;
    info->memmap_desc_size = g_handoff.descriptor_size;
    info->stage = SHZ_STAGE_LOADER;
    ((void (__attribute__((sysv_abi)) *)(shz_info_t *))(uintptr_t)SHZ_PAYLOAD_ENTRY)(info);
    for (;;)
        __asm__ volatile("hlt");
}
