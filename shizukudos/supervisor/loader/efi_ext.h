/* SPDX-License-Identifier: GPL-2.0-only
 * Additional UEFI 2.10 declarations for the Supervisor loader: paged memory,
 * SimpleFileSystem file access and LoadedImage. Original definitions from the
 * public UEFI specification; no EDK II or GNU-EFI code.
 */
#ifndef SHZ_EFI_EXT_H
#define SHZ_EFI_EXT_H
#include "../../uefi/efi.h"

#define EFI_ALLOCATE_ANY_PAGES 0
#define EFI_ALLOCATE_MAX_ADDRESS 1
#define EFI_ALLOCATE_ADDRESS 2
#define EFI_MEM_LOADER_DATA 2
#define EFI_FILE_MODE_READ 1ull
#define EFI_NOT_FOUND (EFI_ERROR_BIT | 14)

typedef EFI_STATUS (EFIAPI *EFI_ALLOCATE_PAGES_FN)(uint32_t type, uint32_t memory_type, size_t pages, uint64_t *address);
typedef EFI_STATUS (EFIAPI *EFI_FREE_PAGES_FN)(uint64_t address, size_t pages);
typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL_FN)(EFI_HANDLE handle, const EFI_GUID *protocol, void **interface);
typedef EFI_STATUS (EFIAPI *EFI_STALL_FN)(size_t microseconds);

struct EFI_FILE_PROTOCOL;
typedef struct EFI_FILE_PROTOCOL {
    uint64_t revision;
    EFI_STATUS (EFIAPI *open)(struct EFI_FILE_PROTOCOL *, struct EFI_FILE_PROTOCOL **, const CHAR16 *, uint64_t, uint64_t);
    EFI_STATUS (EFIAPI *close)(struct EFI_FILE_PROTOCOL *);
    void *delete_file;
    EFI_STATUS (EFIAPI *read)(struct EFI_FILE_PROTOCOL *, size_t *, void *);
    void *write;
    void *get_position, *set_position;
    EFI_STATUS (EFIAPI *get_info)(struct EFI_FILE_PROTOCOL *, const EFI_GUID *, size_t *, void *);
    void *set_info, *flush;
} EFI_FILE_PROTOCOL;

typedef struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
    uint64_t revision;
    EFI_STATUS (EFIAPI *open_volume)(struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *, EFI_FILE_PROTOCOL **);
} EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

typedef struct {
    uint32_t revision;
    EFI_HANDLE parent_handle;
    EFI_SYSTEM_TABLE *system_table;
    EFI_HANDLE device_handle;
    void *file_path, *reserved;
    uint32_t load_options_size;
    void *load_options;
    void *image_base;
    uint64_t image_size;
    uint32_t image_code_type, image_data_type;
    void *unload;
} EFI_LOADED_IMAGE_PROTOCOL;

typedef struct {
    uint64_t size, file_size, physical_size;
    uint8_t create_time[16], last_access_time[16], modification_time[16];
    uint64_t attribute;
    CHAR16 file_name[1];
} EFI_FILE_INFO;
#define EFI_FILE_DIRECTORY 0x10ull

/* Boot manager (CSM chain-load): device paths, image services, MP services.
 * UEFI 2.10 sections 10.2 (Device Path), 7.4 (Image Services), 13.4 (MP Services). */
#define EFI_LOAD_ERROR (EFI_ERROR_BIT | 1)
#define EFI_ACCESS_DENIED (EFI_ERROR_BIT | 15)
#define EFI_SECURITY_VIOLATION (EFI_ERROR_BIT | 26)
typedef struct {
    uint8_t type, subtype, length[2];
} EFI_DEVICE_PATH_PROTOCOL;
#define EFI_DP_TYPE_MEDIA 0x04
#define EFI_DP_SUBTYPE_FILE_PATH 0x04
#define EFI_DP_TYPE_END 0x7f
#define EFI_DP_SUBTYPE_END_ENTIRE 0xff

typedef EFI_STATUS (EFIAPI *EFI_LOAD_IMAGE_FN)(uint8_t boot_policy, EFI_HANDLE parent, EFI_DEVICE_PATH_PROTOCOL *path,
                                              void *source, size_t source_size, EFI_HANDLE *image);
typedef EFI_STATUS (EFIAPI *EFI_START_IMAGE_FN)(EFI_HANDLE image, size_t *exit_data_size, CHAR16 **exit_data);
typedef EFI_STATUS (EFIAPI *EFI_UNLOAD_IMAGE_FN)(EFI_HANDLE image);

/* UEFI 2.10 12.3 Simple Text Input (the boot manager menu, BOOT.INI menu_timeout). */
#define EFI_NOT_READY (EFI_ERROR_BIT | 6)
typedef struct {
    uint16_t scan_code;
    CHAR16 unicode_char;
} EFI_INPUT_KEY;
typedef struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
    EFI_STATUS (EFIAPI *reset)(struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL *, uint8_t extended_verification);
    EFI_STATUS (EFIAPI *read_key_stroke)(struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL *, EFI_INPUT_KEY *);
    void *wait_for_key;
} EFI_SIMPLE_TEXT_INPUT_PROTOCOL;

/* UEFI 2.10 7.2 EFI_MEMORY_TYPE and memory attributes (direct Kernel64 boot). */
enum {
    EFI_RESERVED_MEMORY = 0, EFI_LOADER_CODE_MEM = 1, EFI_LOADER_DATA_MEM = 2, EFI_BS_CODE = 3, EFI_BS_DATA = 4,
    EFI_RT_CODE = 5, EFI_RT_DATA = 6, EFI_CONVENTIONAL = 7, EFI_UNUSABLE = 8, EFI_ACPI_RECLAIM = 9,
    EFI_ACPI_NVS = 10, EFI_MMIO = 11, EFI_MMIO_PORT = 12, EFI_PAL_CODE = 13, EFI_PERSISTENT = 14,
    EFI_UNACCEPTED = 15
};
#define EFI_MEMORY_WB 0x8ull

typedef struct EFI_MP_SERVICES_PROTOCOL {
    EFI_STATUS (EFIAPI *get_number_of_processors)(struct EFI_MP_SERVICES_PROTOCOL *, size_t *total, size_t *enabled);
} EFI_MP_SERVICES_PROTOCOL;

_Static_assert(offsetof(EFI_FILE_PROTOCOL, read) == 32, "EFI_FILE_PROTOCOL.Read ABI");
_Static_assert(offsetof(EFI_FILE_PROTOCOL, get_info) == 64, "EFI_FILE_PROTOCOL.GetInfo ABI");
_Static_assert(offsetof(EFI_LOADED_IMAGE_PROTOCOL, device_handle) == 24, "LoadedImage ABI");
_Static_assert(offsetof(EFI_LOADED_IMAGE_PROTOCOL, file_path) == 32, "LoadedImage.FilePath ABI");
_Static_assert(offsetof(EFI_FILE_INFO, attribute) == 72, "EFI_FILE_INFO ABI");
_Static_assert(offsetof(EFI_BOOT_SERVICES, free_pool) == 72, "FreePool ABI");
_Static_assert(offsetof(EFI_BOOT_SERVICES, load_image) == 200, "LoadImage ABI");
_Static_assert(offsetof(EFI_BOOT_SERVICES, start_image) == 208, "StartImage ABI");
_Static_assert(offsetof(EFI_BOOT_SERVICES, unload_image) == 224, "UnloadImage ABI");
_Static_assert(sizeof(EFI_DEVICE_PATH_PROTOCOL) == 4, "device path node header");
#endif
