/* SPDX-License-Identifier: GPL-2.0-only */
#include "strcmp.h"
int32_t ntw_lstrcmpi_a(const uint8_t *left, const uint8_t *right) {
    if (!left && !right) return 0;
    if (!left) return -1;
    if (!right) return 1;
    for (;;) {
        uint8_t a = *left++, b = *right++;
        if (a >= 'A' && a <= 'Z') a = (uint8_t)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (uint8_t)(b - 'A' + 'a');
        if (a != b || !a) return (int32_t)a - (int32_t)b;
    }
}
