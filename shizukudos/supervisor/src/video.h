/* SPDX-License-Identifier: GPL-2.0-only
 * 80x25 text-mode display for the DOS domain. The text page lives in guest RAM
 * (B800:0000) exactly as on VGA hardware; this module implements the INT 10h text
 * services on it and draws it onto the UEFI GOP framebuffer.
 */
#ifndef SHZ_VIDEO_H
#define SHZ_VIDEO_H
#include <stdint.h>

void video_init(void);
void video_int10(void);                     /* handles the INT 10h call in the guest registers */
void video_render(void);                    /* draws the text page to the framebuffer if it changed */
void video_clear(uint8_t attr);
/* Irreversible for this Supervisor lifetime: hardware VGA owns the display. */
void video_native_vga_own(void);
/* The GOP framebuffer was granted to domain `dom` (display_grant.c): stop rendering the text page there while that
 * domain is RUNNABLE/WAITING; once it has EXITED/FAILED the console takes the framebuffer back. */
void video_delegate_display(uint32_t dom);
#endif
