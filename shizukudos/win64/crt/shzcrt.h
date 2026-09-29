/* SPDX-License-Identifier: GPL-2.0-only
 * Minimal freestanding C runtime for Shizuku Win64 test programs (NTCRTWrapper9x stage 0).
 * It exists so the test programs depend only on kernel32/ntdll; it is NOT msvcrt/UCRT and makes
 * no compatibility claim about them. */
#ifndef SHZCRT_H
#define SHZCRT_H
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

int shz_vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap);
int shz_snprintf(char *buf, size_t cap, const char *fmt, ...);
int shz_printf(const char *fmt, ...);
void shz_puts(const char *s);
void *shz_malloc(size_t n);
void *shz_calloc(size_t n, size_t m);
void *shz_realloc(void *p, size_t n);
void shz_free(void *p);
uint32_t shz_crc32(const void *data, size_t n);
int shz_evidence(unsigned slot, unsigned long long v);
#define printf shz_printf
#define snprintf shz_snprintf
#define malloc shz_malloc
#define calloc shz_calloc
#define realloc shz_realloc
#define free shz_free
#endif
