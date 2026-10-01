/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_WIN64_THEME_COOKIE_H
#define M98_WIN64_THEME_COOKIE_H
#include <stdint.h>
/* A 64-bit HTHEME must not silently alias a live opaque 32-bit generation. */
static inline uint32_t m98w_cookie_value(uintptr_t value)
{
    return value > UINT32_MAX ? 0u : (uint32_t)value;
}
#endif
