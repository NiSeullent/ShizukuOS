/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded character count imported by the publisher's VC14.44 C++ runtime.
 * Signature/return values cross-checked with Wine11 msvcrt/string.c __strncnt;
 * original implementation follows the existing UCRT bounded count semantics.
 */
#include "crtint.h"
DLLAPI size_t CRTAPI __strncnt(const char *string, size_t count)
{
    size_t length = 0;
    while (length < count && string[length]) ++length;
    return length;
}
