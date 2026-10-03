/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef W98_POINTER_BRIDGE_H
#define W98_POINTER_BRIDGE_H
#include "../../../drivers/shz_laptop/laptop.h"
struct w98_pointer_bridge {
    struct shz_pointer_adapter adapter;
    struct shz_hidi2c *source;
    uint64_t owner,generation;
    uint16_t address;
    uint8_t active,pending;
    size_t report_bytes;
    uint8_t report[SHZ_HID_REPORT_MAX];
    int last_error;
};
/* Native serialized resource manager calls only AFTER production hidi2c_open
 * has enumerated a verified I2C/GPIO binding. Object/source/backing must remain
 * retained until detach AND the transport owner's real stop/drain complete.
 * No ACPI namespace/OEM MMIO guess, automatic installation or synthetic source.
 * Calibration maps descriptor units to default PS/2 resolution counts (4/mm).
 * Source lease/epoch is immutable for the whole binding. */
int w98_pointer_bind_i2c(struct w98_pointer_bridge *,struct shz_hidi2c *,uint32_t units_x,uint32_t units_y);
int w98_pointer_unbind(struct w98_pointer_bridge *);
#endif
