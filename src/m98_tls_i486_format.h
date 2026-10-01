/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_TLS_I486_FORMAT_H
#define M98_TLS_I486_FORMAT_H
#include <stddef.h>
#include <stdarg.h>

/* Bounded C99 truncation/count semantics for TLS integer/string diagnostics.
 * Unsupported directives, excessive widths/counts and invalid arguments fail
 * with -1 before changing output. Byte strings may contain at most 1 MiB of
 * data plus their readable NUL terminator; the total result has the same data
 * limit. This is not a floating/wide-character CRT. */
int m98_tls_i486_vsnprintf(char *, size_t, const char *, va_list);
int m98_tls_i486_snprintf(char *, size_t, const char *, ...);
#endif
