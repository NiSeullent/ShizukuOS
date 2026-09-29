/* SPDX-License-Identifier: GPL-2.0-only
 * The one keyboard layout of the GUI subsystem: US (00000409), PS/2 scan code set 1. ONE definition shared by the kernel
 * (kernel64/gfx_input.c: scan code -> virtual key for the hardware and SendInput) and user32 (user32_input.c:
 * MapVirtualKeyEx, ToUnicodeEx, VkKeyScanEx, TranslateMessage). Freestanding: fixed-width types only.
 */
#ifndef SHZ_KBD_H
#define SHZ_KBD_H
#include <stdint.h>

/* scan code (no prefix) -> virtual key; left/right modifiers are the specific VK_L* / VK_R* codes (0xA0-0xA5). The numeric
 * keypad codes 0x47-0x53 give the navigation keys here; shz_kbd_numpad has their NumLock meaning. */
static const uint8_t shz_kbd_set1[0x59] = {
    0, 0x1B, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 0xBD, 0xBB, 0x08, 0x09,                 /* 00-0F */
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', 0xDB, 0xDD, 0x0D, 0xA2, 'A', 'S',                  /* 10-1F */
    'D', 'F', 'G', 'H', 'J', 'K', 'L', 0xBA, 0xDE, 0xC0, 0xA0, 0xDC, 'Z', 'X', 'C', 'V',                 /* 20-2F */
    'B', 'N', 'M', 0xBC, 0xBE, 0xBF, 0xA1, 0x6A, 0xA4, 0x20, 0x14, 0x70, 0x71, 0x72, 0x73, 0x74,         /* 30-3F */
    0x75, 0x76, 0x77, 0x78, 0x79, 0x90, 0x91, 0x24, 0x26, 0x21, 0x6D, 0x25, 0x0C, 0x27, 0x6B, 0x23,     /* 40-4F */
    0x28, 0x22, 0x2D, 0x2E, 0, 0, 0xE2, 0x7A, 0x7B };                                                 /* 50-58 */
/* keypad scan codes 0x47..0x53 with NumLock on (and Shift up): VK_NUMPAD7.. VK_DECIMAL; 0 = same as shz_kbd_set1 */
static const uint8_t shz_kbd_numpad[0x54 - 0x47] = { 0x67, 0x68, 0x69, 0, 0x64, 0x65, 0x66, 0, 0x61, 0x62, 0x63, 0x60, 0x6E };

/* E0-prefixed scan code -> virtual key (0: none) */
static inline uint8_t shz_kbd_e0(uint8_t sc)
{
    switch (sc) {
    case 0x1C: return 0x0D;             /* keypad Enter */
    case 0x1D: return 0xA3;             /* right Ctrl */
    case 0x35: return 0x6F;             /* keypad / */
    case 0x37: return 0x2C;             /* Print Screen */
    case 0x38: return 0xA5;             /* right Alt */
    case 0x47: return 0x24; case 0x48: return 0x26; case 0x49: return 0x21; case 0x4B: return 0x25; case 0x4D: return 0x27;
    case 0x4F: return 0x23; case 0x50: return 0x28; case 0x51: return 0x22; case 0x52: return 0x2D; case 0x53: return 0x2E;
    case 0x5B: return 0x5B; case 0x5C: return 0x5C; case 0x5D: return 0x5D;   /* Windows keys, Applications */
    default: return 0;
    }
}

/* virtual key -> scan code; *ext = 1 for E0 keys. Generic Shift/Ctrl/Alt map to the left key. 0 if the key has none. */
static inline uint16_t shz_kbd_vk_to_scan(uint8_t vk, int *ext)
{
    unsigned i;
    *ext = 0;
    if (vk == 0x10) vk = 0xA0;
    if (vk == 0x11) vk = 0xA2;
    if (vk == 0x12) vk = 0xA4;
    if (vk == 0x13) return 0x45;        /* Pause (sent as E1 1D 45) */
    for (i = 1; i < sizeof shz_kbd_set1; ++i) if (shz_kbd_set1[i] == vk) return (uint16_t)i;
    for (i = 0; i < sizeof shz_kbd_numpad; ++i) if (shz_kbd_numpad[i] == vk) return (uint16_t)(0x47 + i);
    for (i = 0; i < 0x60; ++i) if (shz_kbd_e0((uint8_t)i) == vk) { *ext = 1; return (uint16_t)i; }
    return 0;
}

/* US characters of the keys that have them: [vk] = { unshifted, shifted } (0 = none). Letters are handled separately. */
static inline int shz_kbd_chars(uint8_t vk, uint16_t *plain, uint16_t *shifted)
{
    static const char digits_shifted[10] = { ')', '!', '@', '#', '$', '%', '^', '&', '*', '(' };
    *plain = *shifted = 0;
    if (vk >= '0' && vk <= '9') { *plain = vk; *shifted = (uint16_t)digits_shifted[vk - '0']; return 1; }
    if (vk >= 0x60 && vk <= 0x69) { *plain = *shifted = (uint16_t)('0' + vk - 0x60); return 1; }  /* VK_NUMPAD0..9 */
    switch (vk) {
    case 0xBA: *plain = ';'; *shifted = ':'; return 1;
    case 0xBB: *plain = '='; *shifted = '+'; return 1;
    case 0xBC: *plain = ','; *shifted = '<'; return 1;
    case 0xBD: *plain = '-'; *shifted = '_'; return 1;
    case 0xBE: *plain = '.'; *shifted = '>'; return 1;
    case 0xBF: *plain = '/'; *shifted = '?'; return 1;
    case 0xC0: *plain = '`'; *shifted = '~'; return 1;
    case 0xDB: *plain = '['; *shifted = '{'; return 1;
    case 0xDC: case 0xE2: *plain = '\\'; *shifted = '|'; return 1;
    case 0xDD: *plain = ']'; *shifted = '}'; return 1;
    case 0xDE: *plain = '\''; *shifted = '"'; return 1;
    case 0x20: *plain = *shifted = ' '; return 1;
    case 0x0D: *plain = *shifted = '\r'; return 1;
    case 0x09: *plain = *shifted = '\t'; return 1;
    case 0x08: *plain = *shifted = '\b'; return 1;
    case 0x1B: *plain = *shifted = 0x1B; return 1;
    case 0x6A: *plain = *shifted = '*'; return 1;
    case 0x6B: *plain = *shifted = '+'; return 1;
    case 0x6D: *plain = *shifted = '-'; return 1;
    case 0x6E: *plain = *shifted = '.'; return 1;
    case 0x6F: *plain = *shifted = '/'; return 1;
    default: return 0;
    }
}
#endif
