/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWST_I486_FORMAT_H
#define NTWST_I486_FORMAT_H
#include <stdarg.h>
#include <stddef.h>
/* Bounded C99 count/truncation for byte strings/chars and integer formats.
 * No floats, wide text, %n, positional arguments, or hh. Format/width/precision
 * <=4096; input strings/output <=1 MiB. Failure preserves caller output.
 * The native implementation uses the original OS _vsnprintf, never a linked
 * modern MinGW formatter. Its Windows execution is a separate acceptance gate. */
int ntwst_i486_vsnprintf(char *, size_t, const char *, va_list);
int ntwst_i486_snprintf(char *, size_t, const char *, ...);
#endif
