/* SPDX-License-Identifier: GPL-2.0-only */
#include "boot.h"
#include "display.h"
#include "../csmwrap/include/csmwrap_abi.h"

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st);
/* A real absolute address ensures the image carries a relocatable PE section. */
EFI_STATUS (EFIAPI *volatile sd_efi_entry_address)(EFI_HANDLE, EFI_SYSTEM_TABLE *) = efi_main;
static _Alignas(16) uint8_t graphics_arena[64 * 1024];
int sd_kernel_probe(void);
#ifdef SD_UEFI_TEST_PCI
int sd_pci_probe(void);
#endif

static EFI_GUID gop_guid = {0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
static const EFI_GUID acpi2_guid = {0x8868e871,0xe4f1,0x11d3,{0xbc,0x22,0x00,0x80,0xc7,0x3c,0x88,0x81}};
static const EFI_GUID acpi1_guid = {0xeb9d2d30,0x2d88,0x11d3,{0x9a,0x16,0x00,0x90,0x27,0x3f,0xc1,0x4d}};

static void print(EFI_SYSTEM_TABLE *st, const char *text)
{
    CHAR16 buffer[128];
    size_t n;
    if (!st->console_out || !st->console_out->output_string) return;
    while (*text) {
        for (n = 0; n < 127 && *text; ++n) buffer[n] = (uint8_t)*text++;
        buffer[n] = 0;
        st->console_out->output_string(st->console_out, buffer);
    }
}

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    size_t i;
    for (i = 0; i < sizeof(*a); ++i) if (x[i] != y[i]) return 0;
    return 1;
}

static __attribute__((noreturn)) void halt(void)
{
    /* No installed IDT/scheduler yet: never accept firmware IRQ handlers. */
    __asm__ volatile("cli" ::: "memory");
    for (;;) __asm__ volatile("hlt");
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    EFI_BOOT_SERVICES *bs;
    EFI_GOP *gop = 0;
    SD_HANDOFF *h = 0;
    EFI_STATUS status;
    size_t i;
    if (!st || st->header.signature != EFI_SYSTEM_TABLE_SIGNATURE ||
        st->header.header_size < sizeof(*st) || !st->boot_services)
        return EFI_INVALID_PARAMETER;
    bs = st->boot_services;
    if (bs->header.signature != EFI_BOOT_SERVICES_SIGNATURE ||
        bs->header.header_size < sizeof(*bs) || !bs->locate_protocol ||
        !bs->allocate_pool || !bs->free_pool || !bs->set_watchdog_timer)
        return EFI_UNSUPPORTED;
    print(st, "Windows 98 Shizuku's Second Edition\r\nShizukuDOS native x64 UEFI bring-up\r\n");
    status = bs->set_watchdog_timer(0, 0, 0, 0);
    if (EFI_ERROR(status)) return status;
    status = bs->locate_protocol(&gop_guid, 0, (void **)&gop);
    if (EFI_ERROR(status) || !gop) {
        print(st, "No GOP display available; no handoff attempted.\r\n");
        return EFI_UNSUPPORTED;
    }
    status = bs->allocate_pool(EFI_LOADER_DATA, sizeof(*h), (void **)&h);
    if (EFI_ERROR(status)) return status;
    for (i = 0; i < sizeof(*h); ++i) ((uint8_t *)h)[i] = 0;
    h->magic = SD_HANDOFF_MAGIC;
    h->version = SD_HANDOFF_VERSION;
    h->size = sizeof(*h);
    status = sd_framebuffer_snapshot(gop->mode, &h->framebuffer);
    if (EFI_ERROR(status)) {
        print(st, "Unsupported GOP framebuffer; no handoff attempted.\r\n");
        bs->free_pool(h);
        return status;
    }
    if (st->tables && st->table_count <= 4096)
        for (i = 0; i < st->table_count; ++i) {
            if (guid_equal(&st->tables[i].guid, &acpi2_guid)) {
                h->acpi_rsdp = st->tables[i].table;
                break;
            }
            if (guid_equal(&st->tables[i].guid, &acpi1_guid))
                h->acpi_rsdp = st->tables[i].table;
        }
    print(st, "GOP framebuffer ready; acquiring memory map.\r\n");
    print(st, "Next: CSMWrap handoff, then ExitBootServices.\r\n");
    if (csmwrap_uefi_before_exit(image, st, gop) != 0) {
        print(st, "CSMWrap rejected the handoff; Windows 98 was not started.\r\n");
        if (h->memory_map)
            bs->free_pool(h->memory_map);
        bs->free_pool(h);
        return EFI_UNSUPPORTED;
    }
    status = sd_exit_boot_services(bs, image, h);
    if (EFI_ERROR(status) && !h->exit_attempted) {
        print(st, "Memory-map preparation failed; still in firmware.\r\n");
        if (h->memory_map) bs->free_pool(h->memory_map);
        bs->free_pool(h);
        return status;
    }
    /* This point never invokes firmware, including on partial shutdown failure. */
    __asm__ volatile("cli" ::: "memory");
    sd_framebuffer_result(h, h->boot_services_exited != 0);
    if (h->boot_services_exited) {
        /* No UEFI boot service after this call. It returns only when KERNEL64 is absent. */
        csmwrap_uefi_after_exit();
        sd_ntwddm_demo(&h->framebuffer, graphics_arena, sizeof(graphics_arena));
        sd_framebuffer_kernel_result(h, sd_kernel_probe());
#ifdef SD_UEFI_TEST_PCI
        sd_framebuffer_pci_result(h, sd_pci_probe());
#endif
    }
    halt();
}
