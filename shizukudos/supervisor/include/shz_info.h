/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS 10.0 Supervisor: loader <-> supervisor handoff and evidence block.
 *
 * One 4 KiB page at SHZ_REGION_BASE. The UEFI loader fills the input half before
 * ExitBootServices; the Supervisor fills the evidence half while it runs. Test
 * harnesses read this page (and the guest RAM / RAM-disk regions it points at)
 * straight out of physical memory, independent of anything the guest prints.
 * All fields are fixed width and pointer free.
 */
#ifndef SHZ_INFO_H
#define SHZ_INFO_H
#include <stdint.h>

#define SHZ_INFO_MAGIC 0x3031505553485A53ull   /* "SZHSUP10" little endian bytes */
#define SHZ_INFO_VERSION 3
#define SHZ_REGION_BASE 0x04000000ull          /* 64 MiB: AllocateAddress'd by the loader */
#define SHZ_REGION_SIZE 0x01000000ull          /* 16 MiB image + stacks + tables */
#define SHZ_INFO_BYTES 8192u
#define SHZ_PAYLOAD_ENTRY (SHZ_REGION_BASE + 0x2000ull)   /* info block occupies two pages */
#define SHZ_MAX_DOMAINS 8
#define SHZ_EVIDENCE_SLOTS 32
#define SHZ_MAX_BLOBS 8
/* Explicit opt-in installed Win98/SeaBIOS profile; absent flag preserves DOS. */
#define SHZ_LOADER_NATIVE_WIN98 1u
/* Explicit BOOT.INI k64_display=yes: the Supervisor may grant the GOP framebuffer to Kernel64 (display_grant.c);
 * absent flag preserves the Supervisor DOS text console on GOP. Never combined with SHZ_LOADER_NATIVE_WIN98. */
#define SHZ_LOADER_K64_DISPLAY 2u

enum shz_stage {
    SHZ_STAGE_NONE = 0,
    SHZ_STAGE_LOADER = 1,        /* loader finished, boot services exited */
    SHZ_STAGE_SUPERVISOR = 2,    /* payload entered, own GDT/IDT/CR3 active */
    SHZ_STAGE_CAPS = 3,          /* capabilities evaluated */
    SHZ_STAGE_VMXON = 4,         /* VMXON succeeded */
    SHZ_STAGE_LAUNCHED = 5,      /* first VMLAUNCH succeeded (guest ran) */
    SHZ_STAGE_GUEST_EXIT = 6,    /* guest asked to end the session */
    SHZ_STAGE_FAILED = 0xdead
};

/* Capability reasons: why a profile is or is not available. */
enum shz_cap_bits {
    SHZ_CAP_LONG_MODE = 1u << 0,
    SHZ_CAP_VMX = 1u << 1,           /* CPUID says VMX exists */
    SHZ_CAP_VMX_ENABLED = 1u << 2,   /* IA32_FEATURE_CONTROL permits VMXON */
    SHZ_CAP_EPT = 1u << 3,
    SHZ_CAP_UNRESTRICTED = 1u << 4,  /* real-mode guest without VM86 */
    SHZ_CAP_SVM = 1u << 5,
    SHZ_CAP_SVM_ENABLED = 1u << 6,   /* VM_CR.SVMDIS clear */
    SHZ_CAP_NPT = 1u << 7,
    SHZ_CAP_VPID = 1u << 8,
    SHZ_CAP_BACKEND_VMX = 1u << 16,  /* a working VMX backend was used */
    SHZ_CAP_BACKEND_SVM = 1u << 17
};

typedef struct {
    uint64_t rip, rflags, cr0, cr4, efer, cs_sel, cs_base, cs_ar;
    uint64_t exit_reason, exit_qual, valid;
} shz_vmcs_snapshot_t;

typedef struct {
    char name[16];
    uint64_t base, size;            /* loader-allocated host-physical block holding a file */
} shz_blob_t;

/* Per-domain evidence, indexed by shz_domain_id. `evidence` slots are written by the
 * *guest kernel itself* through SHZ_HC_EVIDENCE, i.e. values the guest computed or read
 * from its own CPU state; harnesses compare them with independent expectations. */
typedef struct {
    uint32_t state, kind, generation, exit_code;
    uint64_t exits, hypercalls, irqs_injected, run_slices;
    uint64_t last_cr0, last_cr3, last_cr4, last_efer, last_rip, last_cs;
    uint64_t evidence[SHZ_EVIDENCE_SLOTS];
    char error[96];
    uint64_t reserved[4];
} shz_domain_info_t;

typedef struct {
    /* ---- written by the loader ---- */
    uint64_t magic;
    uint32_t version, size;
    uint64_t fb_base, fb_size;
    uint32_t fb_width, fb_height, fb_pitch_pixels, fb_format;
    uint64_t acpi_rsdp;
    uint64_t tsc_hz;
    uint64_t guest_ram_base, guest_ram_size;
    uint64_t disk_base, disk_size;      /* RAM-backed disk: NOT an AHCI/NVMe device */
    uint64_t memmap_base, memmap_bytes, memmap_desc_size;
    uint64_t region_base, region_size;
    uint32_t boot_path;                 /* 1 = UEFI x64, 2 = BIOS/CSM */
    uint32_t loader_flags;
    uint64_t k32_ram_base, k32_ram_size;  /* Kernel32 domain RAM (0 when not loaded) */
    uint64_t k64_ram_base, k64_ram_size;  /* Kernel64 domain RAM */
    uint64_t ipc_base, ipc_size;          /* shared channel memory: SHZ_MAX_CHANNELS x 1 MiB */
    shz_blob_t blobs[SHZ_MAX_BLOBS];      /* KERNEL32.BIN, KERNEL64.BIN, WIN64.IMG ... */
    uint64_t reserved_in[4];

    /* ---- written by the Supervisor ---- */
    uint32_t stage, status;
    uint32_t cap_bits;
    uint32_t cpu_vendor[3];             /* CPUID.0 EBX,EDX,ECX */
    uint64_t feature_control;           /* IA32_FEATURE_CONTROL */
    uint64_t vmx_basic, vmx_ept_vpid_cap;
    uint64_t vmx_pin, vmx_proc, vmx_proc2, vmx_exit, vmx_entry;   /* chosen control values */
    uint64_t host_cr0, host_cr3, host_cr4, host_efer, host_cs;    /* Supervisor state */
    uint64_t hv_instance_id;            /* incremented per run to detect stale evidence */

    /* Snapshot of the guest VMCS taken at the first exit and at the last exit. */
    shz_vmcs_snapshot_t first_exit, last_exit;

    uint64_t exit_count[64];            /* by basic exit reason (0..63) */
    uint64_t total_exits;
    uint64_t hypercalls;
    uint64_t io_exits, io_unhandled;
    uint64_t injected_irqs;
    uint64_t guest_console_bytes;
    uint32_t guest_exit_code, guest_exit_requested;
    uint64_t domain_generation;
    char last_error[128];
    shz_domain_info_t domains[SHZ_MAX_DOMAINS];
    uint32_t native_input[8];           /* W98INPT owned-i8042 status (native_input.h); zero when absent */
} shz_info_t;

_Static_assert(sizeof(shz_info_t) <= SHZ_INFO_BYTES, "info must fit the two-page block");
#endif
