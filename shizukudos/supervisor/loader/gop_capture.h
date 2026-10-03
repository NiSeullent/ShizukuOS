/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_GOP_CAPTURE_H
#define SHZ_GOP_CAPTURE_H
#include "../../uefi/boot.h"
#define SHZ_GOP_CAPTURE_PATH_MAX 4096u
#define SHZ_GOP_CAPTURE_HANDLES_MAX 1024u
/* Value capture only: no firmware pointers, epoch/admission bit or persisted
 * authority. Retaining and admitting this observation is a separate operation. */
typedef struct {
    SD_FRAMEBUFFER framebuffer;
    uint32_t segment, bus, device, function;
    uint32_t vendor_device, class_revision, command, raw_bar[6], bar_index;
    uint64_t resource_base, resource_bytes, resource_maximum, translation, bar_supports;
    uint32_t maximum_encoding; /*1 UEFI end-address;2 EDK2 alignment mask*/
    uint32_t gop_path_bytes, pci_path_bytes;
    uint8_t gop_path[SHZ_GOP_CAPTURE_PATH_MAX];
    uint8_t pci_path[SHZ_GOP_CAPTURE_PATH_MAX];
    uint8_t random[32];
} shz_gop_observation_t;
enum shz_gop_capture_result {
    SHZ_GOP_CAPTURE_OK=0, SHZ_GOP_CAPTURE_INVALID=-1,
    SHZ_GOP_CAPTURE_UNSUPPORTED=-2, SHZ_GOP_CAPTURE_AMBIGUOUS=-3,
    SHZ_GOP_CAPTURE_FIRMWARE=-4, SHZ_GOP_CAPTURE_CHANGED=-5
};
/* Before final GetMemoryMap/EBS only. Exact selected GOP must be enumerated;
 * full device path ancestry, unique closest PCI owner, actual BAR descriptors,
 * two fresh readbacks around actual EFI RNG are required. Never changes modes,
 * BARs, attributes, maps or guest state. Failure zeroes output. */
int shz_gop_capture(EFI_BOOT_SERVICES *,EFI_GOP *,const SD_FRAMEBUFFER *,
                    shz_gop_observation_t *);
#endif
