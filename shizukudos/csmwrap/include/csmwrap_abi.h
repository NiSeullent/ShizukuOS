/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CSMWRAP_ABI_H
#define CSMWRAP_ABI_H
#include <stddef.h>
#include <stdint.h>

/* Firmware class selected by detection. There is no fourth "boot the disk now" value. */
#define CSMWRAP_MODE_NATIVE_BIOS 1u
#define CSMWRAP_MODE_UEFI_IA32   2u
#define CSMWRAP_MODE_UEFI_X64    3u

/* flags: both KERNEL64 and CSMWRAP must be set before any Windows 98 chain. */
#define CSMWRAP_F_KERNEL64   0x00000001u
#define CSMWRAP_F_ENTERED    0x00000002u
#define CSMWRAP_F_KEYBOARD   0x00000004u
#define CSMWRAP_F_STORAGE    0x00000008u
#define CSMWRAP_F_E820       0x00000010u
#define CSMWRAP_F_LOWMEM     0x00000020u

#define CSMWRAP_SIG0 0x574D5343u /* bytes 'C','S','M','W' */
#define CSMWRAP_SIG1 0x00504152u /* bytes 'R','A','P', 0 */

#define CSMWRAP_HANDOFF_PHYS 0x7000u
#define CSMWRAP_ENTRY_PHYS   0x7E00u
#define CSMWRAP_ENTRY_SEG    0x07E0u
#define CSMWRAP_SHIZUKU_SEG  0x1000u
#define CSMWRAP_SHIZUKU_OFF  0x0000u

#define CSMWRAP_SVC_INT10 0x10u
#define CSMWRAP_SVC_INT11 0x11u
#define CSMWRAP_SVC_INT12 0x12u
#define CSMWRAP_SVC_INT13 0x13u
#define CSMWRAP_SVC_INT15 0x15u
#define CSMWRAP_SVC_INT16 0x16u
#define CSMWRAP_SVC_INT1A 0x1Au
/* PCI BIOS installation check is INT 1Ah AX=B101h, registered separately. */
#define CSMWRAP_SVC_PCI_INSTALL 0xB101u

#define CSMWRAP_EFI_SYSTEM_TABLE_SIGNATURE UINT64_C(0x5453595320494249)

typedef struct csmwrap_regs {
    uint32_t eax, ebx, ecx, edx, esi, edi, ebp;
    uint32_t eflags;       /* bit 0 is CF, the same bit BIOS services use */
    uint16_t ds, es;
    uint16_t vector;
    uint32_t passthrough;  /* 1 when native firmware keeps the original vector */
} csmwrap_regs;

typedef void (*csmwrap_service_fn)(csmwrap_regs *regs);

typedef struct csmwrap_e820 {
    uint64_t base;
    uint64_t length;
    uint32_t type;         /* 1 usable, 2 reserved, matching the public E820 contract */
    uint32_t attrs;
} csmwrap_e820;

/*
 * Packed boot contract. Offsets are part of the ABI (see the static asserts).
 * Checksum is the low byte of the last field and makes the sum of every byte
 * modulo 256 equal zero. The other three bytes of the field stay zero.
 */
typedef struct csmwrap_handoff {
    uint8_t signature[8];      /* 0: exactly "CSMWRAP" plus a NUL, eight bytes */
    uint16_t abi_major;        /* 8: 1 */
    uint16_t abi_minor;        /* 10: 0 */
    uint32_t size;             /* 12: sizeof(this structure) */
    uint32_t boot_mode;        /* 16: mode this handoff will execute */
    uint32_t firmware_mode;    /* 20: mode reported by firmware detection */
    uint64_t fb_addr;          /* 24: GOP (or native VGA) framebuffer base */
    uint32_t fb_width;         /* 32 */
    uint32_t fb_height;        /* 36 */
    uint32_t fb_pitch;         /* 40: bytes per scanline */
    uint32_t fb_format;        /* 44: 0 RGB, 1 BGR, same as the local GOP snapshot */
    uint32_t boot_disk_id;     /* 48: BIOS DL-style id; 0x80 is the first hard disk */
    uint32_t sector_size;      /* 52 */
    uint64_t disk_size;        /* 56: bytes, not sectors */
    uint32_t conventional_kb;  /* 64: memory below 1 MiB, from the map or INT 12h */
    uint32_t extended_kb;      /* 68: usable memory at or above 1 MiB, in KiB */
    uint64_t e820_addr;        /* 72: physical address of csmwrap_e820[] */
    uint32_t e820_count;       /* 80 */
    uint64_t rsdp;             /* 84: ACPI RSDP, 0 if the firmware did not publish one */
    uint64_t smbios;           /* 92: SMBIOS entry point */
    uint64_t pci_info;         /* 100: small table of mechanism-1 devices, may be 0 */
    uint64_t uefi_system_table;/* 108: diagnostic copy of the table address; not a live service */
    uint64_t service_table;    /* 116: csmwrap_service_table, recorded before ExitBootServices */
    uint32_t flags;            /* 124 */
    uint32_t checksum;         /* 128 */
} __attribute__((packed)) csmwrap_handoff;

typedef struct csmwrap_service_table {
    uint32_t abi_major;
    uint32_t registered_mask;
    uint64_t keyboard;         /* simple-text-input protocol, copied, never called after exit */
    uint64_t block_io_count;
    uint64_t pci_info;
    csmwrap_e820 e820[32];
} csmwrap_service_table;

typedef struct csmwrap_firmware_view {
    uint64_t efi_signature;
    uint32_t pointer_bits;     /* 32 or 64 when an EFI system table is live */
    int native_bios;           /* IVT/CSM is the firmware we were entered from */
} csmwrap_firmware_view;

typedef struct csmwrap_snapshot {
    csmwrap_firmware_view firmware;
    uint64_t fb_addr;
    uint32_t fb_width, fb_height, fb_pitch, fb_format;
    uint32_t boot_disk_id, sector_size;
    uint64_t disk_size;
    uint32_t conventional_kb, extended_kb;
    uint64_t rsdp, smbios, pci_info, uefi_system_table, keyboard;
    uint32_t block_io_count;
    const csmwrap_e820 *e820;
    uint32_t e820_count;
    const void *kernel64;
    uint32_t kernel64_bytes;
} csmwrap_snapshot;

_Static_assert(sizeof(csmwrap_handoff) == 132, "CSMWRAP_HANDOFF size");
_Static_assert(offsetof(csmwrap_handoff, abi_major) == 8, "abi_major");
_Static_assert(offsetof(csmwrap_handoff, size) == 12, "size");
_Static_assert(offsetof(csmwrap_handoff, fb_addr) == 24, "fb_addr");
_Static_assert(offsetof(csmwrap_handoff, boot_disk_id) == 48, "boot_disk_id");
_Static_assert(offsetof(csmwrap_handoff, conventional_kb) == 64, "conventional_kb");
_Static_assert(offsetof(csmwrap_handoff, e820_addr) == 72, "e820_addr");
_Static_assert(offsetof(csmwrap_handoff, e820_count) == 80, "e820_count");
_Static_assert(offsetof(csmwrap_handoff, rsdp) == 84, "rsdp");
_Static_assert(offsetof(csmwrap_handoff, uefi_system_table) == 108, "uefi_system_table");
_Static_assert(offsetof(csmwrap_handoff, service_table) == 116, "service_table");
_Static_assert(offsetof(csmwrap_handoff, flags) == 124, "flags");
_Static_assert(offsetof(csmwrap_handoff, checksum) == 128, "checksum");

uint32_t csmwrap_select_mode(const csmwrap_firmware_view *view);
void csmwrap_handoff_clear(csmwrap_handoff *handoff);
void csmwrap_handoff_seal(csmwrap_handoff *handoff);
int csmwrap_handoff_check(const csmwrap_handoff *handoff);
int csmwrap_bind_kernel64(csmwrap_handoff *handoff, const void *image, uint32_t bytes);
int csmwrap_fill_snapshot(csmwrap_handoff *handoff, csmwrap_service_table *services,
                          const csmwrap_snapshot *snapshot);
int csmwrap_boot_allowed(const csmwrap_handoff *handoff);

int csmwrap_register_service(uint32_t id, csmwrap_service_fn fn);
csmwrap_service_fn csmwrap_service_slot(uint8_t vector);
csmwrap_service_fn csmwrap_pci_install_fn(void);
void csmwrap_dispatch(uint32_t firmware_mode, uint8_t vector, csmwrap_regs *regs);
void csmwrap_set_cf(csmwrap_regs *regs, int failed);

void csmwrap_diag_reset(void);
void csmwrap_diag_note(const char *text);
const char *csmwrap_diag_text(void);

/* UEFI translation unit. Not used by the host test. */
struct csmwrap_uefi_result {
    int collected;
    int boot_allowed;
    uint32_t handoff_phys;
    uint32_t entry_phys;
};
int csmwrap_uefi_before_exit(void *image, void *system_table, void *gop);
void csmwrap_uefi_after_exit(void);

#endif
