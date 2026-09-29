/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWU_USB_DESCRIPTOR_H
#define NTWU_USB_DESCRIPTOR_H
#include <stddef.h>
#include <stdint.h>

#define NTWU_ABI_VERSION 1u
#define NTWU_MAX_BLOB 4096u
#define NTWU_MAX_INTERFACES 16u
#define NTWU_MAX_ALTERNATES 32u
#define NTWU_MAX_ENDPOINTS 64u
#define NTWU_MAX_OPAQUE 64u
#define NTWU_NO_INDEX UINT16_C(0xffff)

enum ntwu_speed { NTWU_LOW_SPEED = 1, NTWU_FULL_SPEED = 2, NTWU_HIGH_SPEED = 3,
                  NTWU_SUPER_SPEED = 4 };
enum ntwu_status { NTWU_OK = 0, NTWU_INVALID = -1, NTWU_TRUNCATED = -2,
                   NTWU_MALFORMED = -3, NTWU_UNSUPPORTED = -4,
                   NTWU_LIMIT = -5, NTWU_DUPLICATE = -6, NTWU_INCONSISTENT = -7 };
struct ntwu_result { int32_t status; uint32_t offset; };

struct ntwu_device {
    uint32_t struct_size, abi_version;
    uint16_t usb_bcd, vendor_id, product_id, device_bcd;
    uint8_t device_class, subclass, protocol, control_packet_bytes;
    uint8_t manufacturer_string, product_string, serial_string, configuration_count;
    uint8_t speed, reserved[3];
};
struct ntwu_interface {
    uint16_t offset, first_endpoint;
    uint8_t number, alternate, declared_endpoints, endpoint_count;
    uint8_t class_code, subclass, protocol, string_index;
};
struct ntwu_endpoint {
    uint16_t offset, max_packet_bytes, alternate_index;
    uint8_t address, transfer_type, interval, transactions;
    uint16_t reserved;
};
struct ntwu_opaque {
    uint16_t offset;
    uint8_t length, type;
    /* Syntactic preceding records, not a claim of class-specific ownership. */
    uint16_t preceding_alternate, preceding_endpoint;
};
struct ntwu_configuration {
    uint32_t struct_size, abi_version;
    uint16_t total_length;
    uint8_t configuration_value, interface_count;
    uint16_t alternate_count, endpoint_count, opaque_count, max_power_ma;
    uint8_t attributes, string_index, speed, reserved;
    struct ntwu_interface alternates[NTWU_MAX_ALTERNATES];
    struct ntwu_endpoint endpoints[NTWU_MAX_ENDPOINTS];
    struct ntwu_opaque opaque[NTWU_MAX_OPAQUE];
};

_Static_assert(sizeof(struct ntwu_result) == 8, "USB result ABI");
_Static_assert(sizeof(struct ntwu_device) == 28, "USB device ABI");
_Static_assert(sizeof(struct ntwu_interface) == 12, "USB alternate ABI");
_Static_assert(sizeof(struct ntwu_endpoint) == 12, "USB endpoint ABI");
_Static_assert(sizeof(struct ntwu_opaque) == 8, "USB opaque ABI");
_Static_assert(sizeof(struct ntwu_configuration) == 1688, "USB configuration ABI");

/* Complete descriptor/blob only; length must equal the declared length.
 * Input/output storage must not overlap. Output remains byte-identical on any
 * failure. Input must be stable for the call. Diagnostics are returned by value.
 * Configurations support USB2 bulk/interrupt endpoints with one transaction;
 * all opaque records are offsets into the caller's original, bounded blob.
 * No allocations, host-controller operations, transfer or class-driver calls.
 */
struct ntwu_result ntwu_parse_device(const void *bytes, size_t length,
                                    enum ntwu_speed speed, struct ntwu_device *output);
struct ntwu_result ntwu_parse_configuration(const void *bytes, size_t length,
                                           enum ntwu_speed speed,
                                           struct ntwu_configuration *output);
#endif
