/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_WIN64_THEME_DEFAULT_STYLE_H
#define M98_WIN64_THEME_DEFAULT_STYLE_H
#include "uxtheme_engine_core.h"
/* Called by the existing lazy enter() while its lock is held. Never call a
 * public m98e_* entrypoint here: that would recursively enter initialization.
 * No allocation, style selection or callback runs from DllMain. */
static inline ntth_status m98w_create_default(const ntth_create_desc *allocator,
                                             uint32_t style, m98_theme_engine **out)
{
    m98_theme_engine *created = NULL;
    ntth_status status;
    if (!out) return NTTH_E_INVALID;
    *out = NULL;
    if (style > M98_THEME_MODERN) return NTTH_E_INVALID;
    status = m98_theme_engine_create(allocator, &created);
    if (status != NTTH_OK) return status;
    status = m98_theme_engine_style(created, style);
    if (status != NTTH_OK) { m98_theme_engine_dispose(created); return status; }
    *out = created;
    return NTTH_OK;
}
#endif
