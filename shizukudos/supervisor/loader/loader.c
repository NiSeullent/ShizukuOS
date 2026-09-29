/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku Supervisor UEFI loader (x64 PE/COFF) and boot manager.
 *
 * Before ExitBootServices it can still return to firmware, so every check that can
 * refuse the machine happens here: Long Mode, VMX/SVM capability and firmware
 * enablement, the disk image, the fixed Supervisor region. Only then does it
 * exit boot services with the correct MapKey (retry loop in shizukudos/uefi/boot.c)
 * and enter the Supervisor payload with interrupts disabled. After that point no
 * UEFI service is ever called.
 *
 * Boot manager: the optional policy file \EFI\SHIZUKU\BOOT.INI (bootini.h) selects
 *   mode=auto        Supervisor when the VMX backend is usable, otherwise CSM (default)
 *   mode=supervisor  Supervisor only; refuse and return to firmware without VMX
 *   mode=csm         always CSM
 * "CSM" is the legacy BIOS profile: the loader chain-loads CSMWrap (LGPL-2.1,
 * https://github.com/CSMWrap/CSMWrap, which wraps the SeaBIOS CSM16 build) from the
 * same volume with LoadImage/StartImage while boot services are still up. CSMWrap
 * then exits boot services itself and SeaBIOS legacy-boots the MBR of this disk,
 * giving the DOS kernel real PC BIOS interrupt services. The loader never links or
 * copies CSMWrap code; it only starts the separately built image.
 */
#include "efi_ext.h"
#include "bootini.h"
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
static const EFI_GUID device_path_guid = {0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static EFI_GUID mp_services_guid = {0x3fdda605,0xa76e,0x4f46,{0xad,0x29,0x12,0xf4,0x53,0x1b,0x3d,0x08}};

#define GUEST_RAM_MIB 64

static EFI_SYSTEM_TABLE *g_st;
static SD_HANDOFF g_handoff;
static shz_blob_t g_blobs[SHZ_MAX_BLOBS];
static bootini_policy_t g_policy;
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

/* ------------------------------------------------------------------ boot manager */
static void say_dec(uint64_t v)
{
    char text[21];
    int i = 20;
    text[i] = 0;
    do {
        text[--i] = (char)('0' + v % 10);
        v /= 10;
    } while (v && i);
    say(text + i);
}

static void say_status(EFI_STATUS status)
{
    say(" (status ");
    say_hex(status);
    say(")");
}

/* ASCII path -> CHAR16 path; returns the number of characters (0 if it does not fit). */
static size_t ascii_to_char16(const char *in, CHAR16 *out, size_t cap)
{
    size_t n;
    for (n = 0; in[n]; ++n) {
        if (n + 1 >= cap)
            return 0;
        out[n] = (uint8_t)in[n];
    }
    out[n] = 0;
    return n;
}

/* Root directory of the volume this loader was started from. */
static EFI_STATUS open_boot_root(EFI_HANDLE image, EFI_BOOT_SERVICES *bs, EFI_LOADED_IMAGE_PROTOCOL **li_out,
                                 EFI_FILE_PROTOCOL **root)
{
    EFI_HANDLE_PROTOCOL_FN handle_protocol = (EFI_HANDLE_PROTOCOL_FN)bs->handle_protocol;
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_STATUS status = handle_protocol(image, &loaded_image_guid, (void **)&li);
    if (EFI_ERROR(status) || !li)
        return EFI_ERROR(status) ? status : EFI_UNSUPPORTED;
    status = handle_protocol(li->device_handle, &sfs_guid, (void **)&fs);
    if (EFI_ERROR(status) || !fs)
        return EFI_ERROR(status) ? status : EFI_UNSUPPORTED;
    if (li_out)
        *li_out = li;
    return fs->open_volume(fs, root);
}

/* Opens `path` read-only and reports its size; rejects directories. */
static EFI_STATUS open_regular_file(EFI_FILE_PROTOCOL *root, const CHAR16 *path, EFI_FILE_PROTOCOL **file,
                                    uint64_t *size)
{
    uint8_t infobuf[512];
    size_t infosize = sizeof infobuf;
    EFI_STATUS status;
    *file = 0;
    status = root->open(root, file, path, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status) || !*file) {
        *file = 0;
        return EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
    }
    status = (*file)->get_info(*file, &file_info_guid, &infosize, infobuf);
    if (!EFI_ERROR(status) && (((const EFI_FILE_INFO *)infobuf)->attribute & EFI_FILE_DIRECTORY))
        status = EFI_ACCESS_DENIED;
    if (EFI_ERROR(status)) {
        (*file)->close(*file);
        *file = 0;
        return status;
    }
    *size = ((const EFI_FILE_INFO *)infobuf)->file_size;
    return EFI_SUCCESS;
}

/* Reads \EFI\SHIZUKU\BOOT.INI when present. A missing file means the built-in
 * defaults; a file that exists but cannot be read or parsed stops the boot. */
static EFI_STATUS load_boot_policy(EFI_HANDLE image, EFI_BOOT_SERVICES *bs, bootini_policy_t *policy)
{
    static const CHAR16 ini_path[] = {'\\','E','F','I','\\','S','H','I','Z','U','K','U','\\',
                                      'B','O','O','T','.','I','N','I',0};
    static char text[BOOTINI_MAX_BYTES];
    char err[160];
    EFI_FILE_PROTOCOL *root = 0, *file = 0;
    uint64_t size = 0;
    size_t done = 0;
    EFI_STATUS status;
    int line;

    bootini_defaults(policy);
    status = open_boot_root(image, bs, 0, &root);
    if (EFI_ERROR(status)) {
        say("Boot manager: boot volume has no readable file system");
        say_status(status);
        say("; using mode=auto.\n");
        return EFI_SUCCESS;
    }
    status = open_regular_file(root, ini_path, &file, &size);
    if (status == EFI_NOT_FOUND) {
        root->close(root);
        say("Boot manager: no \\EFI\\SHIZUKU\\BOOT.INI; built-in policy mode=auto, csm_path=");
        say(policy->csm_path);
        say("\n");
        return EFI_SUCCESS;
    }
    if (!EFI_ERROR(status) && size > BOOTINI_MAX_BYTES)
        status = EFI_BUFFER_TOO_SMALL;
    while (!EFI_ERROR(status) && done < size) {
        size_t chunk = (size_t)size - done;
        status = file->read(file, &chunk, text + done);
        if (!EFI_ERROR(status) && !chunk)
            status = EFI_DEVICE_ERROR;
        done += chunk;
    }
    if (file)
        file->close(file);
    root->close(root);
    if (EFI_ERROR(status)) {
        say("REFUSED: \\EFI\\SHIZUKU\\BOOT.INI exists but cannot be read");
        if (status == EFI_BUFFER_TOO_SMALL)
            say(" (larger than 4096 bytes)");
        else
            say_status(status);
        say(".\nNothing was started. Returning to firmware.\n");
        return status == EFI_BUFFER_TOO_SMALL ? EFI_INVALID_PARAMETER : status;
    }
    line = bootini_parse(text, done, policy, err, sizeof err);
    if (line) {
        say("REFUSED: \\EFI\\SHIZUKU\\BOOT.INI line ");
        say_dec((uint64_t)line);
        say(": ");
        say(err);
        say("\nThe boot policy file is rejected as a whole; nothing was started. Returning to firmware.\n");
        return EFI_INVALID_PARAMETER;
    }
    say("Boot manager: \\EFI\\SHIZUKU\\BOOT.INI mode=");
    say(bootini_mode_name(policy->mode));
    say(", csm_path=");
    say(policy->csm_path);
    say(policy->csm_path_set ? "\n" : " (default)\n");
    return EFI_SUCCESS;
}

static inline void port_out8(uint16_t port, uint8_t v) { __asm__ volatile("outb %0,%1" :: "a"(v), "Nd"(port)); }
static inline uint8_t port_in8(uint16_t port) { uint8_t v; __asm__ volatile("inb %1,%0" : "=a"(v) : "Nd"(port)); return v; }

/* Boot services are gone (CSMWrap called ExitBootServices and then returned), so
 * the firmware console no longer exists: report on COM1 directly and stop. */
static __attribute__((noreturn)) void halt_after_foreign_exit(EFI_STATUS status)
{
    static const char text[] = "\r\nShizuku boot manager: CSMWrap returned after ExitBootServices; "
                               "firmware services are gone, the machine is halted.\r\n";
    const char *p;
    unsigned spin;
    (void)status;
    for (p = text; *p; ++p) {
        for (spin = 0; spin < 100000 && !(port_in8(0x3fd) & 0x20); ++spin)
            ;
        port_out8(0x3f8, (uint8_t)*p);
    }
    for (;;)
        __asm__ volatile("cli; hlt");
}

/* Legacy BIOS profile: LoadImage/StartImage of CSMWrap from the boot volume.
 * Returns only when it could not be started (or returned with boot services
 * intact); every such path says why on the console and returns to firmware. */
static EFI_STATUS csm_boot(EFI_HANDLE image, EFI_BOOT_SERVICES *bs, const bootini_policy_t *policy, const char *why)
{
    EFI_HANDLE_PROTOCOL_FN handle_protocol = (EFI_HANDLE_PROTOCOL_FN)bs->handle_protocol;
    EFI_LOAD_IMAGE_FN load_image = (EFI_LOAD_IMAGE_FN)bs->load_image;
    EFI_START_IMAGE_FN start_image = (EFI_START_IMAGE_FN)bs->start_image;
    EFI_UNLOAD_IMAGE_FN unload_image = (EFI_UNLOAD_IMAGE_FN)bs->unload_image;
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_FILE_PROTOCOL *root = 0, *file = 0;
    EFI_DEVICE_PATH_PROTOCOL *volume_path = 0, *node;
    EFI_MP_SERVICES_PROTOCOL *mp = 0;
    CHAR16 path16[BOOTINI_PATH_MAX];
    uint8_t *full = 0;
    size_t chars, prefix = 0, node_len, file_node, total, i, exit_size = 0, total_cpus = 0, enabled_cpus = 0;
    CHAR16 *exit_data = 0;
    EFI_HANDLE child = 0;
    uint64_t size = 0;
    EFI_STATUS status;

    say("CSM legacy boot (");
    say(why);
    say("): chain-loading CSMWrap ");
    say(policy->csm_path);
    say(" from this volume (SeaBIOS CSM16 legacy BIOS services for the DOS kernel).\n");
    if (!bs->load_image || !bs->start_image || !bs->unload_image) {
        say("REFUSED: firmware lacks LoadImage/StartImage. Returning to firmware.\n");
        return EFI_UNSUPPORTED;
    }

    /* CSMWrap parks one application processor as its BIOS proxy ("system thread")
     * and panics (halts) without one, after it has already taken over the machine. */
    if (!EFI_ERROR(bs->locate_protocol(&mp_services_guid, 0, (void **)&mp)) && mp &&
        !EFI_ERROR(mp->get_number_of_processors(mp, &total_cpus, &enabled_cpus))) {
        if (enabled_cpus < 2) {
            say("REFUSED: CSMWrap needs at least 2 enabled logical processors (it reserves one as its BIOS "
                "proxy); this machine reports ");
            say_dec(enabled_cpus);
            say(".\nReturning to firmware.\n");
            return EFI_UNSUPPORTED;
        }
    } else {
        say("CSM legacy boot: warning: no MP Services protocol, cannot check the 2-processor requirement.\n");
    }

    chars = ascii_to_char16(policy->csm_path, path16, sizeof path16 / sizeof path16[0]);
    if (!chars) {
        say("REFUSED: csm_path too long. Returning to firmware.\n");
        return EFI_INVALID_PARAMETER;
    }
    status = open_boot_root(image, bs, &li, &root);
    if (EFI_ERROR(status)) {
        say("REFUSED: cannot open the boot volume to find CSMWrap");
        say_status(status);
        say(".\nReturning to firmware.\n");
        return status;
    }
    status = open_regular_file(root, path16, &file, &size);
    root->close(root);
    if (EFI_ERROR(status)) {
        say("REFUSED: CSM legacy boot image ");
        say(policy->csm_path);
        say(status == EFI_NOT_FOUND ? " not found on the boot volume" :
            status == EFI_ACCESS_DENIED ? " is a directory" : " cannot be opened");
        say_status(status);
        say(".\nCopy the x64 CSMWrap image there, or point csm_path in \\EFI\\SHIZUKU\\BOOT.INI at it.\n"
            "Returning to firmware.\n");
        return status;
    }
    file->close(file);
    if (size < 64 || size > (64ull << 20)) {
        say("REFUSED: CSM legacy boot image ");
        say(policy->csm_path);
        say(" has an implausible size (");
        say_dec(size);
        say(" bytes).\nReturning to firmware.\n");
        return EFI_LOAD_ERROR;
    }

    /* Device path = the boot volume's path + one File Path media node + End. */
    status = handle_protocol(li->device_handle, &device_path_guid, (void **)&volume_path);
    if (EFI_ERROR(status) || !volume_path) {
        say("REFUSED: boot volume has no device path");
        say_status(status);
        say(".\nReturning to firmware.\n");
        return EFI_ERROR(status) ? status : EFI_UNSUPPORTED;
    }
    for (node = volume_path, i = 0; node->type != EFI_DP_TYPE_END; ++i) {
        node_len = (size_t)node->length[0] | ((size_t)node->length[1] << 8);
        if (node_len < 4 || i >= 64 || prefix + node_len > 4096) {
            say("REFUSED: malformed boot volume device path. Returning to firmware.\n");
            return EFI_UNSUPPORTED;
        }
        prefix += node_len;
        node = (EFI_DEVICE_PATH_PROTOCOL *)((uint8_t *)node + node_len);
    }
    file_node = 4 + (chars + 1) * sizeof(CHAR16);
    total = prefix + file_node + 4;
    status = bs->allocate_pool(EFI_LOADER_DATA, total, (void **)&full);
    if (EFI_ERROR(status) || !full) {
        say("REFUSED: out of pool memory for the CSMWrap device path. Returning to firmware.\n");
        return EFI_OUT_OF_RESOURCES;
    }
    for (i = 0; i < prefix; ++i)
        full[i] = ((const uint8_t *)volume_path)[i];
    full[prefix + 0] = EFI_DP_TYPE_MEDIA;
    full[prefix + 1] = EFI_DP_SUBTYPE_FILE_PATH;
    full[prefix + 2] = (uint8_t)file_node;
    full[prefix + 3] = (uint8_t)(file_node >> 8);
    for (i = 0; i <= chars; ++i) {
        full[prefix + 4 + 2 * i] = (uint8_t)path16[i];
        full[prefix + 5 + 2 * i] = (uint8_t)(path16[i] >> 8);
    }
    full[total - 4] = EFI_DP_TYPE_END;
    full[total - 3] = EFI_DP_SUBTYPE_END_ENTIRE;
    full[total - 2] = 4;
    full[total - 1] = 0;

    status = load_image(0, image, (EFI_DEVICE_PATH_PROTOCOL *)full, 0, 0, &child);
    bs->free_pool(full);
    if (EFI_ERROR(status)) {
        say("REFUSED: firmware LoadImage() rejected ");
        say(policy->csm_path);
        say_status(status);
        if (status == EFI_SECURITY_VIOLATION || status == EFI_ACCESS_DENIED)
            say(".\nSecure Boot refused the image: disable Secure Boot or enroll a signed CSMWrap");
        else
            say(".\nThe file is not a loadable x64 UEFI application");
        say(".\nReturning to firmware.\n");
        if (status == EFI_SECURITY_VIOLATION && child)
            unload_image(child);
        return status;
    }
    say("CSM legacy boot: CSMWrap loaded (");
    say_dec(size);
    say(" bytes); StartImage. CSMWrap now exits boot services and SeaBIOS boots this disk's MBR.\n");

    status = start_image(child, &exit_size, &exit_data);

    /* Still here. UEFI 2.10 7.4: a successful ExitBootServices clears these fields. */
    if (!g_st->boot_services || !g_st->console_out)
        halt_after_foreign_exit(status);
    say("CSM legacy boot: CSMWrap returned without booting");
    say_status(status);
    if (exit_data && exit_size >= sizeof(CHAR16)) {
        CHAR16 copy[80];
        for (i = 0; i < 79 && i < exit_size / sizeof(CHAR16) && exit_data[i]; ++i)
            copy[i] = exit_data[i] >= 0x20 && exit_data[i] < 0x7f ? exit_data[i] : '?';
        copy[i] = 0;
        say(": ");
        g_st->console_out->output_string(g_st->console_out, copy);
    }
    say(".\nReturning to firmware.\n");
    if (exit_data)
        bs->free_pool(exit_data);
    return EFI_ERROR(status) ? status : EFI_ABORTED;
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

    /* 0. Boot manager policy (\EFI\SHIZUKU\BOOT.INI); a malformed file stops here. */
    status = load_boot_policy(image, bs, &g_policy);
    if (EFI_ERROR(status))
        return status;
    if (g_policy.mode == BOOT_MODE_CSM)
        return csm_boot(image, bs, &g_policy, "mode=csm");

    /* 1. Can this machine host the DOS16 domain in virtual Real Mode at all? */
    shz_probe_caps(&caps);
    if (!caps.long_mode) {
        say("REFUSED: CPU lacks Long Mode.\n");
        return EFI_UNSUPPORTED;
    }
    if (g_policy.mode == BOOT_MODE_AUTO && (caps.vendor == SHZ_VENDOR_AMD || !caps.vmx_usable)) {
        /* mode=auto: the Supervisor profile is not available on this machine, so the
         * DOS kernel gets real BIOS services from the legacy (CSM) profile instead. */
        say("Supervisor profile not available: ");
        if (caps.vendor == SHZ_VENDOR_AMD) {
            say(caps.svm_usable ? "AMD SVM usable, but the SVM backend is not implemented in this build"
                                : "AMD SVM unusable: ");
            if (!caps.svm_usable)
                say(caps.svm_why);
        } else {
            say("Intel VMX backend unusable: ");
            say(caps.vmx_why);
        }
        say("\n");
        return csm_boot(image, bs, &g_policy, "mode=auto, no usable virtualization backend");
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
