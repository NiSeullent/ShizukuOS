/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_DEAD_NATIVE_H
#define SHZ_DEAD_NATIVE_H
#include "dead_screen.h"
struct regs;
void ds_native_init(void);
void ds_native_bind(volatile uint32_t *pixels,uint32_t width,uint32_t height,
                    uint32_t pitch_bytes,size_t mapped_bytes,unsigned rgbx);
void ds_native_keyboard_ready(unsigned ready);
void ds_native_timer_ready(void);
void ds_native_force_text(void); /* opt-in private control, before fatal latch only */
void ds_native_control(void);    /* normal-startup opt-in own-kernel fixture */
void ds_native_capture_begin(void);
void ds_native_capture_char(char ch);
void ds_native_panic(uint64_t caller_ip,uint64_t sp,uint64_t bp) __attribute__((noreturn));
void ds_native_exception(const struct regs *r) __attribute__((noreturn));
#endif
