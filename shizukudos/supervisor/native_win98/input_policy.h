/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_INPUT_POLICY_H
#define SHZ_WIN98_INPUT_POLICY_H
#include <stdint.h>
/* Separate explicit W98INPT.BIN opt-in (BOOT.INI win98_input=yes). It is NOT a
 * PCI/BAR role and grants no display: it is admitted only on top of the
 * already admitted native VGA epoch, and must carry that epoch's exact fresh
 * nonce and VGA config SHA-256 (as published by the device gate). Absent blob:
 * no outer i8042 access, inner KBC behaviour unchanged.
 * Little-endian, exactly 96 bytes:
 *   0 magic 'W9IN'   4 version(u16)=1   6 extent(u16)=96
 *   8 flags (bit0 keyboard, bit1 mouse; >=1 known bit, unknown bits refused)
 *  12 machine = 1 (fixed Q35 outer i8042 at ports 0x60/0x64, polled, outer IRQs off)
 *  16 nonce[32]   48 vga_config_sha256[32]   80 reserved[16] = 0 */
#define W98_INPUT_POLICY_MAGIC 0x4e493957u /* W9IN */
#define W98_INPUT_POLICY_VERSION 1u
#define W98_INPUT_POLICY_BYTES 96u
#define W98_INPUT_KEYBOARD 1u
#define W98_INPUT_MOUSE 2u
#define W98_INPUT_KNOWN_FLAGS (W98_INPUT_KEYBOARD|W98_INPUT_MOUSE)
#define W98_INPUT_MACHINE_Q35_I8042 1u
typedef struct {
    uint32_t magic;
    uint16_t version, extent;
    uint32_t flags, machine;
    uint8_t nonce[32];
    uint8_t vga_config_sha256[32];
    uint8_t reserved[16];
} w98_input_policy_t;
_Static_assert(sizeof(w98_input_policy_t)==W98_INPUT_POLICY_BYTES,"separate input policy extent");
#endif
