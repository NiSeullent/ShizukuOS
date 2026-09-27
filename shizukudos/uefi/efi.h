/* SPDX-License-Identifier: GPL-2.0-only
 * Original minimal x64 UEFI ABI declarations, derived from UEFI 2.10 interfaces.
 * No EDK II, GNU-EFI, Windows, FreeDOS, or KernelEx implementation is used.
 */
#ifndef SHIZUKUDOS_EFI_H
#define SHIZUKUDOS_EFI_H
#include <stddef.h>
#include <stdint.h>

#define EFIAPI __attribute__((ms_abi))
typedef uint64_t EFI_STATUS;
typedef void *EFI_HANDLE;
typedef uint16_t CHAR16;
#define EFI_SUCCESS UINT64_C(0)
#define EFI_ERROR_BIT (UINT64_C(1) << 63)
#define EFI_INVALID_PARAMETER (EFI_ERROR_BIT | 2)
#define EFI_UNSUPPORTED (EFI_ERROR_BIT | 3)
#define EFI_BUFFER_TOO_SMALL (EFI_ERROR_BIT | 5)
#define EFI_DEVICE_ERROR (EFI_ERROR_BIT | 7)
#define EFI_OUT_OF_RESOURCES (EFI_ERROR_BIT | 9)
#define EFI_ABORTED (EFI_ERROR_BIT | 21)
#define EFI_ERROR(s) (((s) & EFI_ERROR_BIT) != 0)
#define EFI_SYSTEM_TABLE_SIGNATURE UINT64_C(0x5453595320494249)
#define EFI_BOOT_SERVICES_SIGNATURE UINT64_C(0x56524553544f4f42)
#define EFI_LOADER_DATA 2

typedef struct {
    uint32_t a; uint16_t b, c; uint8_t d[8];
} EFI_GUID;
typedef struct {
    uint64_t signature;
    uint32_t revision, header_size, crc32, reserved;
} EFI_TABLE_HEADER;
typedef struct {
    uint32_t type, padding;
    uint64_t physical_start, virtual_start, pages, attributes;
} EFI_MEMORY_DESCRIPTOR;
struct EFI_TEXT_OUTPUT;
typedef struct EFI_TEXT_OUTPUT {
    void *reset;
    EFI_STATUS (EFIAPI *output_string)(struct EFI_TEXT_OUTPUT *, CHAR16 *);
    void *test_string, *query_mode, *set_mode, *set_attribute, *clear_screen;
    void *set_cursor_position, *enable_cursor, *mode;
} EFI_TEXT_OUTPUT;

typedef struct {
    EFI_TABLE_HEADER header;
    void *raise_tpl, *restore_tpl, *allocate_pages, *free_pages;
    EFI_STATUS (EFIAPI *get_memory_map)(size_t *, EFI_MEMORY_DESCRIPTOR *,
                                       size_t *, size_t *, uint32_t *);
    EFI_STATUS (EFIAPI *allocate_pool)(uint32_t, size_t, void **);
    EFI_STATUS (EFIAPI *free_pool)(void *);
    void *create_event, *set_timer, *wait_for_event, *signal_event, *close_event;
    void *check_event, *install_protocol_interface, *reinstall_protocol_interface;
    void *uninstall_protocol_interface, *handle_protocol, *reserved;
    void *register_protocol_notify, *locate_handle, *locate_device_path;
    void *install_configuration_table, *load_image, *start_image, *exit;
    void *unload_image;
    EFI_STATUS (EFIAPI *exit_boot_services)(EFI_HANDLE, size_t);
    void *get_next_monotonic_count, *stall;
    EFI_STATUS (EFIAPI *set_watchdog_timer)(size_t, uint64_t, size_t, CHAR16 *);
    void *connect_controller, *disconnect_controller, *open_protocol;
    void *close_protocol, *open_protocol_information, *protocols_per_handle;
    void *locate_handle_buffer;
    EFI_STATUS (EFIAPI *locate_protocol)(EFI_GUID *, void *, void **);
    void *install_multiple_protocol_interfaces, *uninstall_multiple_protocol_interfaces;
    void *calculate_crc32, *copy_mem, *set_mem, *create_event_ex;
} EFI_BOOT_SERVICES;

typedef struct { EFI_GUID guid; void *table; } EFI_CONFIGURATION_TABLE;
typedef struct {
    EFI_TABLE_HEADER header;
    CHAR16 *firmware_vendor;
    uint32_t firmware_revision;
    EFI_HANDLE console_in_handle; void *console_in;
    EFI_HANDLE console_out_handle; EFI_TEXT_OUTPUT *console_out;
    EFI_HANDLE standard_error_handle; EFI_TEXT_OUTPUT *standard_error;
    void *runtime_services;
    EFI_BOOT_SERVICES *boot_services;
    size_t table_count;
    EFI_CONFIGURATION_TABLE *tables;
} EFI_SYSTEM_TABLE;

typedef struct {
    uint32_t version, width, height, pixel_format;
    uint32_t red_mask, green_mask, blue_mask, reserved_mask;
    uint32_t pixels_per_scan_line;
} EFI_GOP_INFO;
typedef struct {
    uint32_t max_mode, mode;
    EFI_GOP_INFO *info;
    size_t info_size;
    uint64_t framebuffer_base;
    size_t framebuffer_size;
} EFI_GOP_MODE;
typedef struct { void *query_mode, *set_mode, *blt; EFI_GOP_MODE *mode; } EFI_GOP;

_Static_assert(sizeof(void *) == 8, "This loader requires the x64 UEFI ABI");
_Static_assert(sizeof(EFI_TABLE_HEADER) == 24, "UEFI header layout");
_Static_assert(sizeof(EFI_MEMORY_DESCRIPTOR) == 40, "UEFI descriptor prefix");
_Static_assert(offsetof(EFI_BOOT_SERVICES, get_memory_map) == 56, "GetMemoryMap ABI");
_Static_assert(offsetof(EFI_BOOT_SERVICES, exit_boot_services) == 232, "ExitBootServices ABI");
_Static_assert(offsetof(EFI_BOOT_SERVICES, locate_protocol) == 320, "LocateProtocol ABI");
_Static_assert(offsetof(EFI_SYSTEM_TABLE, boot_services) == 96, "SystemTable ABI");
_Static_assert(sizeof(EFI_GOP_INFO) == 36, "GOP information ABI");
_Static_assert(sizeof(EFI_GOP_MODE) == 40, "GOP mode ABI");
#endif
