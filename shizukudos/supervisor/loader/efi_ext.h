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

_Static_assert(offsetof(EFI_FILE_PROTOCOL, read) == 32, "EFI_FILE_PROTOCOL.Read ABI");
_Static_assert(offsetof(EFI_FILE_PROTOCOL, get_info) == 64, "EFI_FILE_PROTOCOL.GetInfo ABI");
_Static_assert(offsetof(EFI_LOADED_IMAGE_PROTOCOL, device_handle) == 24, "LoadedImage ABI");
_Static_assert(offsetof(EFI_FILE_INFO, attribute) == 72, "EFI_FILE_INFO ABI");
#endif
