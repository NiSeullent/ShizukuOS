/* SPDX-License-Identifier: GPL-2.0-only -- original bounded EP0 interface. */
#ifndef SHIZUKU_XHCI_USB_H
#define SHIZUKU_XHCI_USB_H
#include "../xhci_native/xhci.h"
#include "../usb_native/ntwu_usb.h"
#define XHCIU_ABI_VERSION 1u
#define XHCIU_INPUT_OFFSET 4096u
#define XHCIU_RING_OFFSET 8192u
#define XHCIU_RING_TRBS 16u
#define XHCIU_FIRST_OFFSET 8448u
#define XHCIU_DEVICE_OFFSET 8512u
#define XHCIU_OUTPUT_SNAPSHOT 8704u
#define XHCIU_INPUT_SNAPSHOT 8832u
#define XHCIU_CONFIGURATION_MAX 2048u
#define XHCIU_CONFIGURATION_HEADER_OFFSET 8576u
#define XHCIU_CONFIGURATION_OFFSET 9216u
#define XHCIU_PROBE_US 10000000u
#define XHCIU_DEBOUNCE_US 100000u
#define XHCIU_RESET_RECOVERY_US 10000u
#define XHCIU_ADDRESS_RECOVERY_US 2000u
enum xhciu_status {
    XHCIU_DESCRIPTOR=-100, XHCIU_DISCONNECTED=-101,
    XHCIU_TOPOLOGY=-102, XHCIU_SHORT_READ=-103,
    XHCIU_CONFIGURATION_INDEX=-104, XHCIU_CONFIGURATION_LIMIT=-105
};
enum xhciu_stage {
    XHCIU_VALIDATE=0, XHCIU_PROTOCOL, XHCIU_RESET, XHCIU_ENABLE,
    XHCIU_ADDRESS, XHCIU_FIRST_READ, XHCIU_EVALUATE, XHCIU_DEVICE_READ,
    XHCIU_PARSE, XHCIU_DISABLE, XHCIU_CLOSE, XHCIU_COMPLETE,
    XHCIU_CONFIGURATION_HEADER, XHCIU_CONFIGURATION_READ, XHCIU_CONFIGURATION_PARSE
};
struct xhciu_request {
    uint32_t struct_size,abi_version,root_port,flags;
};
struct xhciu_descriptor {
    uint32_t struct_size,abi_version,root_port,slot_id,context_bytes,port_speed_id;
    uint16_t initial_ep0_packet,final_ep0_packet;
    uint8_t first_eight[8],raw_device[18],reserved[2];
    struct ntwu_device parsed;
};
struct xhciu_result {
    int32_t status,transport_error,parser_status;
    uint32_t failed_stage,parser_offset;
};
struct xhciu_configuration_request {
    uint32_t struct_size,abi_version,root_port,configuration_index,flags;
};
struct xhciu_configuration_descriptor {
    uint32_t struct_size,abi_version,configuration_index,raw_length;
    struct xhciu_descriptor device;
    uint8_t header[9],reserved[3];
    uint8_t raw[XHCIU_CONFIGURATION_MAX];
    struct ntwu_configuration parsed;
};
_Static_assert(sizeof(struct xhciu_request)==16,"EP0 request ABI");
_Static_assert(sizeof(struct xhciu_descriptor)==84,"EP0 descriptor ABI");
_Static_assert(sizeof(struct xhciu_result)==20,"EP0 result ABI");
_Static_assert(sizeof(struct xhciu_configuration_request)==20,"Configuration request ABI");
_Static_assert(sizeof(struct xhciu_configuration_descriptor)==3848,"Configuration result ABI");
_Static_assert(offsetof(struct xhciu_configuration_descriptor,raw)==112,"Configuration raw offset");
_Static_assert(offsetof(struct xhciu_configuration_descriptor,parsed)==2160,"Configuration parser offset");
_Static_assert(XHCIU_CONFIGURATION_HEADER_OFFSET+64u<=XHCIU_OUTPUT_SNAPSHOT,"Header/snapshot separation");
_Static_assert(XHCIU_INPUT_SNAPSHOT+192u<=XHCIU_CONFIGURATION_OFFSET,"Snapshot/configuration separation");
_Static_assert(XHCIU_CONFIGURATION_OFFSET+XHCIU_CONFIGURATION_MAX+64u<=XHCI_DEVICE_DMA_BYTES,
               "Configuration allocation bound");
_Static_assert((XHCIU_CONFIGURATION_OFFSET&4095u)+XHCIU_CONFIGURATION_MAX+64u<=4096u,
               "Configuration remains inside one aligned page");
_Static_assert(4u*3u<XHCIU_RING_TRBS,"Four requests do not reach the Link TRB");
/* Trusted, disjoint, serialized storage. Requires a READY one-slot controller.
 * Operational failures and success close the entire disposable session. Invalid
 * arguments leave it untouched. Output is published only after safe close.
 * QUARANTINED means all controller/callback/DMA lifetimes must continue. */
struct xhciu_result xhciu_probe_device(struct xhci_device *,
    const struct xhciu_request *,struct xhciu_descriptor *);
/* Adds GET_DESCRIPTOR(CONFIGURATION,index) header/full reads to the same
 * terminal session. No SET_CONFIGURATION or non-EP0 operation is performed.
 * Parsed offsets refer to this result's raw[]; all unused bytes are zero. */
struct xhciu_result xhciu_probe_configuration(struct xhci_device *,
    const struct xhciu_configuration_request *,struct xhciu_configuration_descriptor *);
#endif
