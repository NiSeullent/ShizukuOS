/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CONSOLE_H
#define SHZ_CONSOLE_H
#include <stdarg.h>
#include <stdint.h>

void serial_init(void);
void serial_putc(char c);
int serial_getc_nonblock(void);           /* -1 if nothing is waiting */
void kputs(const char *s);
void kprintf(const char *fmt, ...);   /* %l/%ll/%z all mean 64-bit; not checked by the compiler */
void kvprintf(const char *fmt, va_list ap);
/* Bounded log capture so a failure reason survives in the info page. */
void log_capture(char *dst, unsigned size, const char *fmt, ...);
void log_capture_v(char *dst, unsigned size, const char *fmt, va_list ap);
#endif
