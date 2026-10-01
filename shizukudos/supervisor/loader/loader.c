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
 *   mode=auto        Supervisor when the Intel VMX backend is usable; otherwise Kernel64
 *                    direct when auto_kernel64=yes and \SHZDOS\KERNEL64S.BIN exists;
 *                    otherwise CSM (default)
 *   mode=supervisor  Supervisor only; refuse and return to firmware without VMX
 *   mode=csm         always CSM
 *   mode=kernel64    the standalone Long Mode Kernel64 directly, no Supervisor, no VMX
 * "CSM" is the legacy BIOS profile: the loader chain-loads CSMWrap (LGPL-2.1,
 * https://github.com/CSMWrap/CSMWrap, which wraps the SeaBIOS CSM16 build) from the
 * same volume with LoadImage/StartImage while boot services are still up. CSMWrap
 * then exits boot services itself and SeaBIOS legacy-boots the MBR of this disk,
 * giving the DOS kernel real PC BIOS interrupt services. The loader never links or
 * copies CSMWrap code; it only starts the separately built image.
 * "Kernel64 direct" does for bare metal what kernel64/standalone/boot32.c does under a
 * Multiboot loader: \SHZDOS\KERNEL64S.BIN (built with -DSHZ_STANDALONE, so its
 * hypercalls are served in-kernel over COM1/PIT/RTC) at physical 1 MiB, \SHZDOS\WIN64.IMG
 * at 32 MiB, the boot information block (shz_abi.h, ABI 1.1 with the GOP framebuffer
 * and \SHZDOS\KERNEL64.INI command line) at 0x7000, boot page tables, then Long Mode
 * entry at 0xFFFFFFFF80100000 with RDI = 0x7000 after ExitBootServices.
 */
#include "efi_ext.h"
#include "bootini.h"
#include "../../uefi/boot.h"
#include "../../abi/shz_abi.h"
#include "../../kernel64/standalone/memholes.h"
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
        say(", auto_kernel64=no\n");
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
    say(policy->csm_path_set ? "" : " (default)");
    say(policy->auto_kernel64 ? ", auto_kernel64=yes" : ", auto_kernel64=no");
    if (policy->menu_timeout_set) {
        say(", menu_timeout=");
        say_dec((uint64_t)policy->menu_timeout);
    }
    say("\n");
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

/* ------------------------------------------------------------------ Kernel64 direct boot
 * Physical layout (identical to kernel64/standalone/boot32.c and the Supervisor's kdom.c):
 *   0x1000 PML4, 0x2000 PDPT (low), 0x3000 PD (2 MiB pages), 0x4000 PDPT (high half)
 *   0x5000 trampoline, 0x5800 GDT, 0x5820 GDTR, 0x6000-0x6fff trampoline stack
 *   0x7000 shz_bootinfo_t, 1 MiB kernel image (+ bss up to 3 MiB), 32 MiB initrd
 * Every one of those ranges is taken with AllocatePages(AllocateAddress) before any byte
 * is written, so the firmware proves nothing live (this loader, its stack, the firmware's
 * page tables) is there. Kernel64 owns guest-physical [0, ram_size), so ram_size is the end
 * of the run of memory usable after ExitBootServices that starts at 1 MiB. */
#define K64_KERNEL_PA 0x100000ull
#define K64_KERNEL_WINDOW 0x200000ull           /* zeroed [1 MiB, 3 MiB): image + bss, as boot32.c */
#define K64_KERNEL_MAX 0x100000ull              /* image file limit, as boot32.c */
#define K64_INITRD_PA 0x2000000ull
#define K64_INITRD_MAX (64ull << 20)
#define K64_LOW_PA 0x1000ull
#define K64_LOW_PAGES 7                         /* [0x1000, 0x8000) */
#define K64_TRAMP_PA 0x5000ull
#define K64_GDT_PA 0x5800ull
#define K64_GDTR_PA 0x5820ull
#define K64_RAM_MIN (64ull << 20)               /* boot32.c's minimum */
#define K64_RAM_MAX (256ull << 20)              /* Kernel64 mem.c MAX_PAGES: its page allocator limit */
#define K64_ENTRY 0xFFFFFFFF80100000ull

/* Runs from its copy at K64_TRAMP_PA, which both the firmware's identity map and the boot page
 * tables map 1:1. MS x64 call: RCX = boot PML4, RDX = GDTR, R8 = boot info, R9 = kernel entry.
 * Leaves the CPU as the Multiboot stub does: CR4 = PAE only, flat 64-bit CS 0x08, data 0x10,
 * interrupts off, RDI = boot info. Kernel64 then sets EFER/CR0/CR4 bits it needs itself. */
__asm__(".text\n"
        ".globl shz_k64_tramp_start\n"
        ".globl shz_k64_tramp_end\n"
        ".p2align 4\n"
        "shz_k64_tramp_start:\n"
        "    movq $0x7000, %rsp\n"
        "    movq %rcx, %cr3\n"
        "    movq $0x20, %rax\n"
        "    movq %rax, %cr4\n"
        "    clts\n"
        "    lgdt (%rdx)\n"
        "    pushq $0x08\n"
        "    leaq 1f(%rip), %rax\n"
        "    pushq %rax\n"
        "    lretq\n"
        "1:  movw $0x10, %ax\n"
        "    movw %ax, %ds\n"
        "    movw %ax, %es\n"
        "    movw %ax, %ss\n"
        "    xorl %eax, %eax\n"
        "    movw %ax, %fs\n"
        "    movw %ax, %gs\n"
        "    movq %r8, %rdi\n"
        "    xorl %ebp, %ebp\n"
        "    jmpq *%r9\n"
        "shz_k64_tramp_end:\n");
extern const uint8_t shz_k64_tramp_start[], shz_k64_tramp_end[];

typedef struct {
    uint64_t ksize, isize, initrd_pages, ram_size;
    int low_alloc, kernel_alloc, initrd_alloc;
    char cmdline[SHZ_CMDLINE_MAX];
    shz_memplan_result_t plan;          /* RAM and firmware holes (kernel64/standalone/memholes.h) */
} k64_state_t;
static k64_state_t g_k64;

static const char *efi_type_name(uint32_t t)
{
    static const char *const names[] = {
        "EfiReservedMemoryType", "EfiLoaderCode", "EfiLoaderData", "EfiBootServicesCode", "EfiBootServicesData",
        "EfiRuntimeServicesCode", "EfiRuntimeServicesData", "EfiConventionalMemory", "EfiUnusableMemory",
        "EfiACPIReclaimMemory", "EfiACPIMemoryNVS", "EfiMemoryMappedIO", "EfiMemoryMappedIOPortSpace",
        "EfiPalCode", "EfiPersistentMemory", "EfiUnacceptedMemoryType"};
    return t < sizeof names / sizeof names[0] ? names[t] : "OEM/OS-defined type";
}

/* Memory the OS may use once ExitBootServices has succeeded (UEFI 2.10 table 7-6). */
static int k64_usable(const EFI_MEMORY_DESCRIPTOR *d)
{
    return (d->type == EFI_LOADER_CODE_MEM || d->type == EFI_LOADER_DATA_MEM || d->type == EFI_BS_CODE ||
            d->type == EFI_BS_DATA || d->type == EFI_CONVENTIONAL) && (d->attributes & EFI_MEMORY_WB);
}

#define K64_DESC(map, i, stride) ((const EFI_MEMORY_DESCRIPTOR *)((const uint8_t *)(map) + (i) * (stride)))
#define K64_END(d) ((d)->physical_start + ((d)->pages << 12))

/* Kernel64's RAM and firmware holes from a UEFI memory map: the same plan as the Multiboot stub
 * (kernel64/standalone/memholes.h). Usable after ExitBootServices are loader and boot-services code and data and
 * conventional memory with write-back caching (k64_usable); any other descriptor overlapping them cuts them. The
 * map is not assumed sorted. OVMF with S3 on (QEMU's default) keeps EfiACPIMemoryNVS at 8-9 MiB: that becomes a
 * hole fenced off in Kernel64's heap window instead of ending its RAM at 8 MiB. */
static int k64_plan(const void *map, size_t map_size, size_t stride, uint64_t cap, uint64_t isize,
                    shz_memplan_result_t *plan)
{
    static shz_memplan_t runs;
    const size_t count = map_size / stride;
    size_t i;
    shz_memplan_init(&runs);
    for (i = 0; i < count; ++i) {
        const EFI_MEMORY_DESCRIPTOR *d = K64_DESC(map, i, stride);
        if (k64_usable(d) && d->physical_start < (1ull << 32))
            shz_memplan_add(&runs, d->physical_start, K64_END(d) < (1ull << 32) ? K64_END(d) : 1ull << 32);
    }
    for (i = 0; i < count; ++i) {
        const EFI_MEMORY_DESCRIPTOR *d = K64_DESC(map, i, stride);
        if (!k64_usable(d))
            shz_memplan_remove(&runs, d->physical_start, K64_END(d));
    }
    return shz_memplan_solve(&runs, cap, K64_RAM_MIN, K64_INITRD_PA, isize, plan);
}

static EFI_STATUS get_memory_map_copy(EFI_BOOT_SERVICES *bs, void **map, size_t *size, size_t *stride)
{
    size_t need = 0, key = 0;
    uint32_t version = 0;
    EFI_STATUS status;
    int tries;
    *map = 0;
    *stride = 0;
    status = bs->get_memory_map(&need, 0, &key, stride, &version);
    for (tries = 0; tries < 4 && status == EFI_BUFFER_TOO_SMALL; ++tries) {
        if (*map)
            bs->free_pool(*map);
        *map = 0;
        need += 16 * (*stride >= sizeof(EFI_MEMORY_DESCRIPTOR) ? *stride : 64);
        status = bs->allocate_pool(EFI_LOADER_DATA, need, map);
        if (EFI_ERROR(status)) {
            *map = 0;
            return status;
        }
        *size = need;
        status = bs->get_memory_map(size, *map, &key, stride, &version);
        need = *size;
    }
    if (!EFI_ERROR(status) && (*stride < sizeof(EFI_MEMORY_DESCRIPTOR) || version != 1 || *size % *stride))
        status = EFI_UNSUPPORTED;
    if (EFI_ERROR(status) && *map) {
        bs->free_pool(*map);
        *map = 0;
    }
    return status;
}

static void say_desc(const EFI_MEMORY_DESCRIPTOR *d)
{
    say(efi_type_name(d->type));
    say(" [");
    say_hex(d->physical_start);
    say("-");
    say_hex(K64_END(d) - 1);
    say("]");
}

/* Names what occupies [start, end) when a fixed-address allocation fails. */
static void say_owner(const void *map, size_t map_size, size_t stride, uint64_t start, uint64_t end)
{
    size_t i;
    for (i = 0; map && i < map_size / stride; ++i) {
        const EFI_MEMORY_DESCRIPTOR *d = K64_DESC(map, i, stride);
        if (d->type != EFI_CONVENTIONAL && d->physical_start < end && K64_END(d) > start) {
            say(" (occupied by ");
            say_desc(d);
            say(")");
            return;
        }
    }
}

static void k64_release(EFI_BOOT_SERVICES *bs)
{
    EFI_FREE_PAGES_FN free_pages = (EFI_FREE_PAGES_FN)bs->free_pages;
    if (g_k64.initrd_alloc)
        free_pages(K64_INITRD_PA, (size_t)g_k64.initrd_pages);
    if (g_k64.kernel_alloc)
        free_pages(K64_KERNEL_PA, (size_t)(K64_KERNEL_WINDOW >> 12));
    if (g_k64.low_alloc)
        free_pages(K64_LOW_PA, K64_LOW_PAGES);
    g_k64.initrd_alloc = g_k64.kernel_alloc = g_k64.low_alloc = 0;
}

static EFI_STATUS read_all(EFI_FILE_PROTOCOL *file, uint64_t dst, uint64_t bytes)
{
    uint64_t done = 0;
    while (done < bytes) {
        size_t chunk = (size_t)(bytes - done > (1u << 20) ? (1u << 20) : bytes - done);
        EFI_STATUS status = file->read(file, &chunk, (uint8_t *)(uintptr_t)(dst + done));
        if (EFI_ERROR(status))
            return status;
        if (!chunk)
            return EFI_DEVICE_ERROR;
        done += chunk;
    }
    return EFI_SUCCESS;
}

static inline uint64_t read_cr4(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr4, %0" : "=r"(v));
    return v;
}

/* Present but unreadable, oversized or malformed optional files refuse the boot; absent ones do not. */
static EFI_STATUS k64_refuse(const char *what, EFI_STATUS status)
{
    say("REFUSED: ");
    say(what);
    if (status != EFI_SUCCESS)
        say_status(status);
    say(".\nNothing was started. Returning to firmware.\n");
    return EFI_ERROR(status) ? status : EFI_LOAD_ERROR;
}

static int bytes_contain(const uint8_t *p, uint64_t n, const char *needle)
{
    uint64_t i, k;
    for (i = 0; i < n; ++i) {
        for (k = 0; needle[k] && i + k < n && p[i + k] == (uint8_t)needle[k]; ++k)
            ;
        if (!needle[k])
            return 1;
    }
    return 0;
}

static EFI_STATUS k64_prepare(EFI_HANDLE image, EFI_BOOT_SERVICES *bs)
{
    static const CHAR16 kpath[] = {'\\','S','H','Z','D','O','S','\\','K','E','R','N','E','L','6','4','S','.','B','I','N',0};
    static const CHAR16 ipath[] = {'\\','S','H','Z','D','O','S','\\','W','I','N','6','4','.','I','M','G',0};
    static const CHAR16 setup_path[] = {'\\','S','H','Z','\\','S','E','T','U','P','\\','I','N','S','T','A','L','L','.','I','M','G',0};
    static const CHAR16 cpath[] = {'\\','S','H','Z','D','O','S','\\','K','E','R','N','E','L','6','4','.','I','N','I',0};
    static const char setup_cmdline[] = "shz.setup=interactive shz.noapps";
    const int installer = g_policy.mode == BOOT_MODE_INSTALL;
    static char ini[BOOTINI_MAX_BYTES];
    EFI_ALLOCATE_PAGES_FN allocate_pages = (EFI_ALLOCATE_PAGES_FN)bs->allocate_pages;
    EFI_STALL_FN stall = (EFI_STALL_FN)bs->stall;
    EFI_FILE_PROTOCOL *root = 0, *kfile = 0, *ifile = 0, *cfile = 0;
    shz_bootinfo_t *bi = (shz_bootinfo_t *)(uintptr_t)SHZ_BOOTINFO_GPA;
    uint64_t *pml4 = (uint64_t *)(uintptr_t)0x1000, *pdpt_lo = (uint64_t *)(uintptr_t)0x2000,
             *pd = (uint64_t *)(uintptr_t)0x3000, *pdpt_hi = (uint64_t *)(uintptr_t)0x4000;
    uint64_t csize = 0, addr, t0, t1;
    void *map = 0;
    size_t map_size = 0, stride = 0, i;
    EFI_GOP *gop = 0;
    SD_FRAMEBUFFER fb;
    EFI_STATUS status;
    char err[160];
    int line;

    zero(&g_k64, sizeof g_k64);
    if (read_cr4() & (1ull << 12))
        return k64_refuse("the firmware runs with 5-level paging (CR4.LA57); Kernel64 uses 4-level paging and "
                          "LA57 cannot be cleared in Long Mode", EFI_UNSUPPORTED);
    status = open_boot_root(image, bs, 0, &root);
    if (EFI_ERROR(status))
        return k64_refuse("cannot open the boot volume", status);

    /* Kernel image, initial RAM image, command line. */
    status = open_regular_file(root, kpath, &kfile, &g_k64.ksize);
    if (EFI_ERROR(status)) {
        root->close(root);
        return k64_refuse(status == EFI_NOT_FOUND ? "\\SHZDOS\\KERNEL64S.BIN not found on the boot volume (build it "
                                                    "with shizukudos/kbuild.py; it is the -DSHZ_STANDALONE Kernel64)"
                                                  : "cannot open \\SHZDOS\\KERNEL64S.BIN", status);
    }
    if (g_k64.ksize < 64 || g_k64.ksize > K64_KERNEL_MAX) {
        kfile->close(kfile);
        root->close(root);
        say("REFUSED: \\SHZDOS\\KERNEL64S.BIN is ");
        say_dec(g_k64.ksize);
        say(" bytes; the kernel image (file + bss) must fit [1 MiB, 3 MiB), at most 1 MiB of file.\n"
            "Nothing was started. Returning to firmware.\n");
        return EFI_LOAD_ERROR;
    }
    status = open_regular_file(root, installer ? setup_path : ipath, &ifile, &g_k64.isize);
    if (status == EFI_NOT_FOUND && !installer) {
        g_k64.isize = 0;
        say("Kernel64 direct boot: no \\SHZDOS\\WIN64.IMG; Kernel64 starts without an initial RAM image.\n");
    } else if (EFI_ERROR(status) || !g_k64.isize || g_k64.isize > K64_INITRD_MAX) {
        if (ifile)
            ifile->close(ifile);
        kfile->close(kfile);
        root->close(root);
        return k64_refuse(installer ? (EFI_ERROR(status) ? "cannot open \\SHZ\\SETUP\\INSTALL.IMG; this boot volume has no usable installer"
                                                       : "\\SHZ\\SETUP\\INSTALL.IMG is empty or larger than 64 MiB")
                                   : (EFI_ERROR(status) ? "cannot open \\SHZDOS\\WIN64.IMG"
                                                       : "\\SHZDOS\\WIN64.IMG is empty or larger than 64 MiB"),
                          EFI_ERROR(status) ? status : EFI_SUCCESS);
    }
    /* The installer has a fixed interactive command line. A broken installed
     * desktop configuration must not turn a repair boot into unattended setup. */
    status = installer ? EFI_NOT_FOUND : open_regular_file(root, cpath, &cfile, &csize);
    if (status == EFI_NOT_FOUND) {
        csize = 0;
    } else if (EFI_ERROR(status) || csize > sizeof ini || EFI_ERROR(status = read_all(cfile, (uint64_t)(uintptr_t)ini, csize))) {
        if (cfile)
            cfile->close(cfile);
        if (ifile)
            ifile->close(ifile);
        kfile->close(kfile);
        root->close(root);
        return k64_refuse(csize > sizeof ini ? "\\SHZDOS\\KERNEL64.INI is larger than 4096 bytes"
                                             : "\\SHZDOS\\KERNEL64.INI exists but cannot be read",
                          EFI_ERROR(status) ? status : EFI_SUCCESS);
    }
    if (cfile) {
        cfile->close(cfile);
        line = k64ini_parse(ini, (size_t)csize, g_k64.cmdline, sizeof g_k64.cmdline, err, sizeof err);
        if (line) {
            if (ifile)
                ifile->close(ifile);
            kfile->close(kfile);
            root->close(root);
            say("REFUSED: \\SHZDOS\\KERNEL64.INI line ");
            say_dec((uint64_t)line);
            say(": ");
            say(err);
            say("\nThe file is rejected as a whole. Nothing was started. Returning to firmware.\n");
            return EFI_INVALID_PARAMETER;
        }
    }
    if (installer) {
        for (i = 0; i < sizeof setup_cmdline; ++i)
            g_k64.cmdline[i] = setup_cmdline[i];
    }

    /* RAM plan from the current map; recomputed from the final map after ExitBootServices. */
    status = get_memory_map_copy(bs, &map, &map_size, &stride);
    if (EFI_ERROR(status)) {
        if (ifile)
            ifile->close(ifile);
        kfile->close(kfile);
        root->close(root);
        return k64_refuse("GetMemoryMap() failed", status);
    }
    if (!k64_plan(map, map_size, stride, K64_RAM_MAX, g_k64.isize, &g_k64.plan)) {
        say("REFUSED: Kernel64 direct boot: ");
        say(g_k64.plan.why);
        say(" ");
        say_hex(g_k64.plan.at);
        if (!g_k64.plan.at_is_size)
            say_owner(map, map_size, stride, g_k64.plan.at, g_k64.plan.at + 0x1000);
        say(".\nKernel64 needs RAM usable after ExitBootServices at [0x1000, 0x8000) (boot structures), [1 MiB, 3 MiB) "
            "(kernel image) and under its initial RAM image at 32 MiB, at least 8 MiB of its heap window [3 MiB, "
            "15 MiB), and 64 MiB in all; other firmware holes are kept out of its allocators.\n"
            "Nothing was started. Returning to firmware.\n");
        bs->free_pool(map);
        if (ifile)
            ifile->close(ifile);
        kfile->close(kfile);
        root->close(root);
        return EFI_OUT_OF_RESOURCES;
    }
    g_k64.ram_size = g_k64.plan.ram;
    say("Kernel64 direct boot: RAM [0, ");
    say_dec(g_k64.ram_size >> 20);
    say(" MiB) (2 MiB aligned, at most 256 MiB), ");
    say_dec(g_k64.plan.count);
    say(" firmware hole(s) below it");
    for (i = 0; i < g_k64.plan.count; ++i) {
        say("\n  firmware hole ");
        say_hex(g_k64.plan.gpa[i]);
        say(" size ");
        say_hex(g_k64.plan.size[i]);
        say_owner(map, map_size, stride, g_k64.plan.gpa[i], g_k64.plan.gpa[i] + g_k64.plan.size[i]);
        say(g_k64.plan.gpa[i] < SHZ_K64_PMM_GPA ? ": fenced off in Kernel64's heap" :
                                                   ": kept out of Kernel64's page allocator");
    }
    if (g_k64.plan.cut) {
        say("\n  more than 16 holes: RAM ends below the hole at ");
        say_hex(g_k64.plan.cut);
    }
    say(".\n");

    /* Fixed-address ranges: the firmware guarantees nothing live is there. */
    addr = K64_LOW_PA;
    status = allocate_pages(EFI_ALLOCATE_ADDRESS, EFI_MEM_LOADER_DATA, K64_LOW_PAGES, &addr);
    g_k64.low_alloc = !EFI_ERROR(status);
    if (!EFI_ERROR(status)) {
        addr = K64_KERNEL_PA;
        status = allocate_pages(EFI_ALLOCATE_ADDRESS, EFI_MEM_LOADER_DATA, (size_t)(K64_KERNEL_WINDOW >> 12), &addr);
        g_k64.kernel_alloc = !EFI_ERROR(status);
    }
    if (!EFI_ERROR(status) && g_k64.isize) {
        addr = K64_INITRD_PA;
        g_k64.initrd_pages = (g_k64.isize + 4095) >> 12;
        status = allocate_pages(EFI_ALLOCATE_ADDRESS, EFI_MEM_LOADER_DATA, (size_t)g_k64.initrd_pages, &addr);
        g_k64.initrd_alloc = !EFI_ERROR(status);
    }
    if (EFI_ERROR(status)) {
        const uint64_t start = !g_k64.low_alloc ? K64_LOW_PA : !g_k64.kernel_alloc ? K64_KERNEL_PA : K64_INITRD_PA;
        const uint64_t end = !g_k64.low_alloc ? K64_LOW_PA + ((uint64_t)K64_LOW_PAGES << 12)
                           : !g_k64.kernel_alloc ? K64_KERNEL_PA + K64_KERNEL_WINDOW
                                                 : K64_INITRD_PA + (g_k64.initrd_pages << 12);
        say("REFUSED: the firmware still uses physical [");
        say_hex(start);
        say(", ");
        say_hex(end);
        say(")");
        say_owner(map, map_size, stride, start, end);
        say_status(status);
        say(";\nKernel64's fixed layout (boot structures 0x1000-0x7fff, kernel at 1 MiB, initrd at 32 MiB) cannot be "
            "placed.\nNothing was started. Returning to firmware.\n");
        bs->free_pool(map);
        if (ifile)
            ifile->close(ifile);
        kfile->close(kfile);
        root->close(root);
        return status;
    }
    bs->free_pool(map);

    zero((void *)(uintptr_t)K64_LOW_PA, (size_t)K64_LOW_PAGES << 12);
    zero((void *)(uintptr_t)K64_KERNEL_PA, (size_t)K64_KERNEL_WINDOW);
    status = read_all(kfile, K64_KERNEL_PA, g_k64.ksize);
    kfile->close(kfile);
    if (!EFI_ERROR(status) && ifile)
        status = read_all(ifile, K64_INITRD_PA, g_k64.isize);
    if (ifile)
        ifile->close(ifile);
    root->close(root);
    if (EFI_ERROR(status))
        return k64_refuse(installer ? "reading KERNEL64S.BIN or \\SHZ\\SETUP\\INSTALL.IMG failed"
                                   : "reading KERNEL64S.BIN or \\SHZDOS\\WIN64.IMG failed", status);
    /* A Supervisor-profile KERNEL64.BIN would issue VMCALL (#UD without VMX) on its first line of output. Only the
     * -DSHZ_STANDALONE build carries the in-kernel COM1 exit path (kcommon/standalone_dev.h). */
    if (!bytes_contain((const uint8_t *)(uintptr_t)K64_KERNEL_PA, g_k64.ksize, "SHZ-EXIT:"))
        return k64_refuse("\\SHZDOS\\KERNEL64S.BIN is not the standalone (-DSHZ_STANDALONE) Kernel64 build: its "
                          "hypercalls would need the Supervisor", EFI_SUCCESS);

    /* Boot page tables: identity [0, ram_size) and 0xFFFFFFFF80000000 -> physical 0, 2 MiB pages. */
    pml4[0] = 0x2000 | 3;
    pml4[511] = 0x4000 | 3;
    pdpt_lo[0] = 0x3000 | 3;
    pdpt_hi[510] = 0x3000 | 3;
    for (i = 0; i < 512 && ((uint64_t)i << 21) < g_k64.ram_size; ++i)
        pd[i] = ((uint64_t)i << 21) | 0x83;
    {
        volatile uint64_t *gdt = (volatile uint64_t *)(uintptr_t)K64_GDT_PA;
        volatile uint8_t *gdtr = (volatile uint8_t *)(uintptr_t)K64_GDTR_PA, *dst = (volatile uint8_t *)(uintptr_t)K64_TRAMP_PA;
        const size_t n = (size_t)(shz_k64_tramp_end - shz_k64_tramp_start);
        gdt[0] = 0;
        gdt[1] = 0x00af9b000000ffffull;         /* 0x08 code, L=1 (boot.asm) */
        gdt[2] = 0x00cf93000000ffffull;         /* 0x10 data */
        gdtr[0] = 23;
        gdtr[1] = 0;
        for (i = 0; i < 8; ++i)
            gdtr[2 + i] = (uint8_t)(K64_GDT_PA >> (8 * i));
        if (n == 0 || n > K64_GDT_PA - K64_TRAMP_PA)
            return k64_refuse("internal error: trampoline size", EFI_ABORTED);
        for (i = 0; i < n; ++i)
            dst[i] = shz_k64_tramp_start[i];
    }

    /* Boot information (ABI 1.1). ram_size is rewritten from the final memory map after ExitBootServices. */
    bi->magic = SHZ_BOOTINFO_MAGIC;
    bi->abi_major = SHZ_ABI_MAJOR;
    bi->abi_minor = SHZ_ABI_MINOR;
    bi->size = sizeof *bi;
    bi->domain_id = SHZ_DOM_KERNEL64;
    bi->generation = 1;
    bi->flags = SHZ_BIF_UEFI_DIRECT;
    bi->ram_size = g_k64.ram_size;
    bi->kernel_gpa = K64_KERNEL_PA;
    bi->kernel_size = g_k64.ksize;
    if (g_k64.isize) {
        bi->initrd_gpa = K64_INITRD_PA;
        bi->initrd_size = g_k64.isize;
    }
    for (i = 0; g_k64.cmdline[i] && i < SHZ_CMDLINE_MAX - 1; ++i)
        bi->cmdline[i] = g_k64.cmdline[i];
    bi->cmdline[i] = 0;
    bi->cmdline_size = (uint32_t)i;
    if (!EFI_ERROR(bs->locate_protocol(&gop_guid, 0, (void **)&gop)) && gop &&
        !EFI_ERROR(sd_framebuffer_snapshot(gop->mode, &fb))) {
        bi->fb_base = fb.base;
        bi->fb_size = fb.size;
        bi->fb_width = fb.width;
        bi->fb_height = fb.height;
        bi->fb_pitch = fb.pitch_pixels * 4;
        bi->fb_bpp = 32;
        bi->fb_format = fb.pixel_format == 0 ? SHZ_FB_RGBX8888 : SHZ_FB_BGRX8888;
    }
    t0 = rdtsc_now();
    stall(50000);
    t1 = rdtsc_now();
    bi->tsc_hz = (t1 - t0) * 20;

    say("Kernel64 direct boot: \\SHZDOS\\KERNEL64S.BIN ");
    say_dec(g_k64.ksize);
    say(installer ? " bytes at 1 MiB, \\SHZ\\SETUP\\INSTALL.IMG "
                  : " bytes at 1 MiB, \\SHZDOS\\WIN64.IMG ");
    say_dec(g_k64.isize);
    say(" bytes at 32 MiB, boot info ABI 1.1 at 0x7000, cmdline '");
    say(bi->cmdline);
    say("', GOP ");
    if (bi->fb_base) {
        say_dec(bi->fb_width);
        say("x");
        say_dec(bi->fb_height);
        say(bi->fb_format == SHZ_FB_BGRX8888 ? " BGRX at " : " RGBX at ");
        say_hex(bi->fb_base);
    } else {
        say("none");
    }
    say(".\n");
    return EFI_SUCCESS;
}

static void com1_say(const char *text)
{
    unsigned spin;
    for (; *text; ++text) {
        for (spin = 0; spin < 100000 && !(port_in8(0x3fd) & 0x20); ++spin)
            ;
        port_out8(0x3f8, (uint8_t)*text);
    }
}

static void com1_hex(uint64_t v)
{
    char text[19] = "0x";
    int i;
    for (i = 0; i < 16; ++i)
        text[2 + i] = "0123456789abcdef"[(v >> (60 - 4 * i)) & 15];
    text[18] = 0;
    com1_say(text);
}

static __attribute__((noreturn)) void k64_halt(const char *why)
{
    com1_say("\r\nShizuku boot manager: ");
    com1_say(why);
    com1_say("; boot services are gone, the machine is halted.\r\n");
    for (;;)
        __asm__ volatile("cli; hlt");
}

/* Returns only if ExitBootServices could not even be attempted (still in firmware). */
static EFI_STATUS k64_launch(EFI_HANDLE image, EFI_BOOT_SERVICES *bs)
{
    shz_bootinfo_t *bi = (shz_bootinfo_t *)(uintptr_t)SHZ_BOOTINFO_GPA;
    uint64_t ram;
    EFI_STATUS status;

    say("Kernel64 direct boot: ExitBootServices, then Long Mode entry at 0xffffffff80100000 with RDI=0x7000.\n");
    status = sd_exit_boot_services(bs, image, &g_handoff);
    if (EFI_ERROR(status) && !g_handoff.exit_attempted) {
        say("REFUSED: ExitBootServices preparation failed");
        say_status(status);
        say("; still in firmware. Returning to firmware.\n");
        return status;
    }
    __asm__ volatile("cli" ::: "memory");
    if (!g_handoff.boot_services_exited)
        k64_halt("ExitBootServices failed after it was attempted (Kernel64 not started)");
    /* The final map is authoritative; it can only differ in boot-services memory, but plan again (never above the
     * RAM planned before) and hand Kernel64 the holes of this final plan. */
    if (!k64_plan(g_handoff.memory_map, g_handoff.map_size, g_handoff.descriptor_size, g_k64.ram_size, g_k64.isize,
                  &g_k64.plan))
        k64_halt(g_k64.plan.why);
    ram = g_k64.plan.ram;
    bi->ram_size = ram;
    zero((void *)(uintptr_t)SHZ_MEMHOLES_GPA, sizeof(shz_memholes_t));
    shz_memholes_write((volatile shz_memholes_t *)(uintptr_t)SHZ_MEMHOLES_GPA, &g_k64.plan);
    com1_say("Shizuku boot manager: ExitBootServices done (");
    com1_hex(g_handoff.exit_calls);
    com1_say(" call(s)); Kernel64 RAM [0, ");
    com1_hex(ram);
    com1_say("); ");
    com1_hex(g_k64.plan.count);
    com1_say(" firmware hole(s) handed over at 0x6000; entering Kernel64 at 0xffffffff80100000\r\n");
    ((void (EFIAPI *)(uint64_t, uint64_t, uint64_t, uint64_t))(uintptr_t)K64_TRAMP_PA)(
        0x1000, K64_GDTR_PA, SHZ_BOOTINFO_GPA, K64_ENTRY);
    k64_halt("Kernel64 returned");
}

/* Kernel64 direct boot: returns only when nothing was started (every path says why). */
static EFI_STATUS k64_boot(EFI_HANDLE image, EFI_BOOT_SERVICES *bs, const char *why)
{
    EFI_STATUS status;
    say("Kernel64 direct boot (");
    say(why);
    say("): the standalone Long Mode Kernel64 without the Supervisor and without VMX.\n");
    status = k64_prepare(image, bs);
    if (!EFI_ERROR(status))
        status = k64_launch(image, bs);
    k64_release(bs);
    return status;
}

/* Does \SHZDOS\KERNEL64S.BIN exist (mode=auto with auto_kernel64=yes)? */
static int k64_image_present(EFI_HANDLE image, EFI_BOOT_SERVICES *bs)
{
    static const CHAR16 kpath[] = {'\\','S','H','Z','D','O','S','\\','K','E','R','N','E','L','6','4','S','.','B','I','N',0};
    EFI_FILE_PROTOCOL *root = 0, *file = 0;
    uint64_t size = 0;
    EFI_STATUS status = open_boot_root(image, bs, 0, &root);
    if (EFI_ERROR(status))
        return 0;
    status = open_regular_file(root, kpath, &file, &size);
    if (!EFI_ERROR(status))
        file->close(file);
    root->close(root);
    return status != EFI_NOT_FOUND;         /* present but unreadable: let k64_boot report it */
}

/* BOOT.INI menu_timeout: a one-key menu on the firmware console (OVMF mirrors the console to COM1 and reads COM1
 * as a keyboard). The choice applies to this boot only; no key within the timeout follows the policy file. */
static void boot_menu(bootini_policy_t *policy)
{
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL *in = (EFI_SIMPLE_TEXT_INPUT_PROTOCOL *)g_st->console_in;
    EFI_STALL_FN stall = (EFI_STALL_FN)g_st->boot_services->stall;
    EFI_INPUT_KEY key;
    uint32_t tick, ticks = (uint32_t)policy->menu_timeout * 100u;
    int mode = -1;
    CHAR16 c = 0;

    if (!in || !in->read_key_stroke) {
        say("Boot manager menu: the firmware has no console input; following BOOT.INI.\n");
        return;
    }
    if (in->reset)
        in->reset(in, 0);                           /* forget keys typed before the menu was shown */
    say("\nShizuku boot manager menu: press a key within ");
    say_dec((uint64_t)policy->menu_timeout);
    say(" seconds\n  A or Enter  BOOT.INI policy, mode=");
    say(bootini_mode_name(policy->mode));
    if (policy->mode == BOOT_MODE_AUTO)
        say(policy->auto_kernel64 ? ": Supervisor with Intel VMX, otherwise Kernel64 direct, otherwise CSM"
                                  : ": Supervisor with Intel VMX, otherwise CSM");
    say("  (default)\n"
        "  K           ShizukuDOS Kernel64 component: Long Mode, no Supervisor, no VMX\n"
        "  I           ShizukuOS installer: choose a disk, review, then confirm\n"
        "  C           CSM legacy BIOS: CSMWrap, then this medium's legacy boot menu\n"
        "  S           Supervisor (needs Intel VMX)\n");
    for (tick = 0; tick < ticks && mode < 0; ++tick) {
        if (in->read_key_stroke(in, &key) != EFI_SUCCESS) {
            stall(10000);
            continue;
        }
        c = key.unicode_char >= 'A' && key.unicode_char <= 'Z' ? (CHAR16)(key.unicode_char + 32) : key.unicode_char;
        if (c == 'a' || c == '\r' || c == '\n')
            mode = policy->mode;
        else if (c == 'k')
            mode = BOOT_MODE_KERNEL64;
        else if (c == 'i')
            mode = BOOT_MODE_INSTALL;
        else if (c == 'c')
            mode = BOOT_MODE_CSM;
        else if (c == 's')
            mode = BOOT_MODE_SUPERVISOR;
    }
    if (mode < 0) {
        say("Boot manager menu: no key within ");
        say_dec((uint64_t)policy->menu_timeout);
        say(" seconds; BOOT.INI mode=");
        say(bootini_mode_name(policy->mode));
        say(".\n");
        return;
    }
    say("Boot manager menu: key '");
    {
        char text[2] = {c == '\r' || c == '\n' ? 'A' : (char)(c - 32), 0};
        say(text);
    }
    say("': mode=");
    say(bootini_mode_name(mode));
    say(" for this boot.\n");
    policy->mode = mode;
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
    say("ShizukuOS development Supervisor loader (UEFI x64) - ShizukuDOS 10\n");
    bs->set_watchdog_timer(0, 0, 0, 0);

    /* 0. Boot manager policy (\EFI\SHIZUKU\BOOT.INI); a malformed file stops here. */
    status = load_boot_policy(image, bs, &g_policy);
    if (EFI_ERROR(status))
        return status;
    if (g_policy.menu_timeout)
        boot_menu(&g_policy);
    if (g_policy.mode == BOOT_MODE_CSM)
        return csm_boot(image, bs, &g_policy, "mode=csm");

    /* 1. Can this machine host the DOS16 domain in virtual Real Mode at all? */
    shz_probe_caps(&caps);
    if (!caps.long_mode) {
        say("REFUSED: CPU lacks Long Mode.\n");
        return EFI_UNSUPPORTED;
    }
    if (g_policy.mode == BOOT_MODE_KERNEL64)
        return k64_boot(image, bs, "mode=kernel64");
    if (g_policy.mode == BOOT_MODE_INSTALL)
        return k64_boot(image, bs, "mode=install");
    if (g_policy.mode == BOOT_MODE_AUTO && (caps.vendor == SHZ_VENDOR_AMD || !caps.vmx_usable)) {
        /* mode=auto: the Supervisor profile is not available on this machine. With
         * auto_kernel64=yes the standalone Kernel64 runs directly; otherwise (or when it
         * cannot be placed) the DOS kernel gets real BIOS services from the CSM profile. */
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
        if (g_policy.auto_kernel64) {
            if (k64_image_present(image, bs)) {
                status = k64_boot(image, bs, "mode=auto, auto_kernel64=yes, no usable virtualization backend");
                say("Kernel64 direct boot did not start");
                say_status(status);
                say("; falling back to the CSM legacy BIOS profile.\n");
            } else {
                say("auto_kernel64=yes, but \\SHZDOS\\KERNEL64S.BIN is not on the boot volume; trying CSM.\n");
            }
        }
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
        say("\nEnable Intel VT-x in the firmware setup, or set mode=csm (legacy BIOS profile) or mode=kernel64 in "
            "\\EFI\\SHIZUKU\\BOOT.INI.\nReturning to firmware.\n");
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
