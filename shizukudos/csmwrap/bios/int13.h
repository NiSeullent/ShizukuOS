/* SPDX-License-Identifier: GPL-2.0-only
 * INT 13h disk services over CSMWRAP_BLOCK_DEVICE.
 * Units: 0x00 floppy, 0x80 first hard disk, 0x81 second hard disk.
 * After ExitBootServices the handler uses the attached backend only.
 */
#ifndef CSMWRAP_INT13_H
#define CSMWRAP_INT13_H
#include <stdint.h>
#include "../storage/block.h"

#define CSMWRAP_CF 0x0001u

#define INT13_OK 0x00u
#define INT13_BAD_PARAM 0x01u
#define INT13_WRITE_PROTECT 0x03u
#define INT13_SECTOR_NOT_FOUND 0x04u
#define INT13_RESET_FAILED 0x05u
#define INT13_BOUNDARY 0x09u
#define INT13_BAD_SECTOR 0x0Au
#define INT13_CONTROLLER 0x20u
#define INT13_NOT_READY 0xAAu

struct csmwrap_int13_regs {
    uint16_t ax, bx, cx, dx, si, di, es, ds;
    uint16_t flags;
};

int csmwrap_int13_attach(uint8_t unit, CSMWRAP_BLOCK_DEVICE *dev);
void csmwrap_int13_detach(uint8_t unit);
void csmwrap_int13_detach_all(void);

/* guest is a flat image of real-mode physical memory. A transfer that
 * starts at an address not multiple of the sector size, or that crosses
 * a 64 KiB boundary, returns CF=1 AH=09h and does not touch the buffer. */
void csmwrap_int13(struct csmwrap_int13_regs *regs, uint8_t *guest,
                   uint32_t guest_bytes);
#endif
