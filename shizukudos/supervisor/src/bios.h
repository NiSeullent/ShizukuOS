/* SPDX-License-Identifier: GPL-2.0-only
 * Virtual BIOS service back end. The 16-bit vBIOS ROM (guest/vbios.asm) installs
 * interrupt vectors whose stubs do `out 0xE0..0xEF, al; iret`; each such port
 * write exits to the Supervisor, which implements the service here on the
 * guest's saved registers and memory.
 *
 * The disk is the loader-provided RAM-backed image (info->disk_base): it is a
 * test/bring-up device, not an AHCI/NVMe driver.
 */
#ifndef SHZ_BIOS_H
#define SHZ_BIOS_H
#include <stdint.h>

#define BIOS_PORT_VIDEO 0xe0
#define BIOS_PORT_DISK 0xe1
#define BIOS_PORT_SYSTEM 0xe2
#define BIOS_PORT_KEYBOARD 0xe3
#define BIOS_PORT_TIME 0xe4
#define BIOS_PORT_SERIAL 0xe5
#define BIOS_PORT_PRINTER 0xe6
#define BIOS_PORT_BOOT 0xe8
#define BIOS_PORT_DEBUG 0xee
#define BIOS_PORT_EXIT 0xef

void bios_init(void);
/* Returns 1 if the port is a BIOS service port and was handled. */
int bios_hypercall(uint16_t port);
void bios_poll_input(void);
int bios_key_available(void);
/* Guest-visible memory layout prepared before the first instruction runs. */
void bios_prepare_guest_memory(void);
uint64_t bios_disk_sectors(void);
#endif
