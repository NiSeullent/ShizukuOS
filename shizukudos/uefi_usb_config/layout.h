/* SPDX-License-Identifier: GPL-2.0-only -- original bounded configuration proof. */
#ifndef SDUSBC_LAYOUT_H
#define SDUSBC_LAYOUT_H
#include "../uefi_usb/layout.h"
#define SDUSBC_RECORD SDUSB_RECORD
#define SDUSBC_MAGIC UINT32_C(0x43425355)
#define SDUSBC_VERSION 2u
#define SDUSBC_RESULT UINT32_C(0x0200d000)
#define SDUSBC_RESULT_PAGE 4096u
/* Reuse the compact wire layout, with versioned meanings for its final words:
 * reserved[0]=result physical address, [1]=3848 bytes, [2]=descriptor index.
 * The embedded device descriptor is a redundant independently checked copy. */
typedef SDUSB_PROOF SDUSBC_PROOF;
_Static_assert(sizeof(struct xhciu_configuration_descriptor)==3848,"Configuration result ABI");
_Static_assert(SD32_MAP+SD32_MAP_CAPACITY<=SDUSBC_RESULT,"Result must follow memory map");
_Static_assert(SDUSBC_RESULT+SDUSBC_RESULT_PAGE<=SD32_HANDOFF,"Result must precede handoff");
_Static_assert(sizeof(struct xhciu_configuration_descriptor)<=SDUSBC_RESULT_PAGE,"Result page capacity");
_Static_assert(SDUSBC_RECORD+sizeof(SDUSBC_PROOF)<=SD32_PAYLOAD,"Proof must precede payload");
#endif
