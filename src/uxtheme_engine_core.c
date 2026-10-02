/* SPDX-License-Identifier: GPL-2.0-only
 * Opaque 32-bit API handles wrap the painter's 64-bit generation handles.
 * Callers serialize access. A style switch invalidates drawing on old handles
 * while still allowing those handles to be closed, as WM_THEMECHANGED requires.
 */
#include "uxtheme_engine_core.h"
#include "uxtheme_shizukuos_style.h"

typedef struct m98_theme_slot {
    uint32_t generation;
    ntth_theme data;
    int live;
} m98_theme_slot;
struct m98_theme_engine {
    ntth_session *session;
    ntth_create_desc allocator;
    uint32_t style, flags;
    m98_theme_slot slots[M98_THEME_CAPACITY];
};

static m98_theme_slot *lookup(m98_theme_engine *e, m98_theme_handle h)
{
    uint32_t index = h & 255u, generation = h >> 8;
    m98_theme_slot *s;
    if (!e || !index || index > M98_THEME_CAPACITY || !generation) return NULL;
    s = &e->slots[index - 1u];
    return s->live && s->generation == generation ? s : NULL;
}

ntth_status m98_theme_engine_create(const ntth_create_desc *a, m98_theme_engine **out)
{
    m98_theme_engine *e;
    ntth_status status;
    uint32_t i;
    if (!out) return NTTH_E_INVALID;
    *out = NULL;
    if (!a || a->struct_size < sizeof(*a) || !a->allocate || !a->deallocate)
        return NTTH_E_INVALID;
    e = a->allocate(a->allocator_user, sizeof(*e));
    if (!e) return NTTH_E_NOMEM;
    e->allocator = *a; e->style = M98_THEME_OFF; e->flags = 7u; e->session = NULL;
    for (i = 0; i < M98_THEME_CAPACITY; ++i) {
        e->slots[i].generation = 1; e->slots[i].live = 0; e->slots[i].data = 0;
    }
    status = ntth_session_open(a, &e->session);
    if (status != NTTH_OK) {
        a->deallocate(a->allocator_user, e, sizeof(*e)); return status;
    }
    *out = e;
    return NTTH_OK;
}

ntth_status m98_theme_engine_destroy(m98_theme_engine *e)
{
    uint32_t i;
    ntth_status status;
    if (!e) return NTTH_E_INVALID;
    for (i = 0; i < M98_THEME_CAPACITY; ++i)
        if (e->slots[i].live) return NTTH_E_BUSY;
    status = ntth_session_close(e->session);
    if (status != NTTH_OK) return status;
    e->allocator.deallocate(e->allocator.allocator_user, e, sizeof(*e));
    return NTTH_OK;
}

void m98_theme_engine_dispose(m98_theme_engine *e)
{
    uint32_t i;
    if (!e) return;
    for (i = 0; i < M98_THEME_CAPACITY; ++i)
        if (e->slots[i].live) {
            ntth_close_data(e->session, e->slots[i].data);
            e->slots[i].live = 0;
        }
    (void)m98_theme_engine_destroy(e);
}

ntth_status m98_theme_engine_style(m98_theme_engine *e, uint32_t style)
{
    ntth_status status;
    if (!e || style > M98_THEME_SHIZUKUOS) return NTTH_E_INVALID;
    if (style == e->style) return NTTH_OK;
    /* Loading even on OFF invalidates the prior style generation. */
    status = style == M98_THEME_CLASSIC ?
        ntth_session_load(e->session, ntth_builtin_classic_text, ntth_builtin_classic_length) :
        style == M98_THEME_SHIZUKUOS ?
        ntth_session_load(e->session, m98_shizukuos_style_text, m98_shizukuos_style_length) :
        ntth_session_load(e->session, ntth_builtin_modern_text, ntth_builtin_modern_length);
    if (status == NTTH_OK) e->style = style;
    return status;
}
uint32_t m98_theme_engine_get_style(const m98_theme_engine *e) { return e ? e->style : 0; }
uint32_t m98_theme_engine_get_flags(const m98_theme_engine *e) { return e ? e->flags : 0; }
void m98_theme_engine_set_flags(m98_theme_engine *e, uint32_t f) { if (e) e->flags = f & 7u; }
int m98_theme_engine_active(const m98_theme_engine *e) { return e && e->style != 0; }
int m98_theme_engine_app_themed(const m98_theme_engine *e) { return m98_theme_engine_active(e) && (e->flags & 3u) != 0; }

ntth_status m98_theme_engine_open(m98_theme_engine *e, const char *name, m98_theme_handle *out)
{
    uint32_t i;
    ntth_status status;
    uint32_t required;
    if (!out) return NTTH_E_INVALID;
    *out = 0;
    if (!e || !name) return NTTH_E_INVALID;
    if (!m98_theme_engine_active(e)) return NTTH_E_NO_THEME;
    required = name[0] == 'W' ? M98_THEME_ALLOW_NONCLIENT : M98_THEME_ALLOW_CONTROLS;
    if (!(e->flags & required)) return NTTH_E_NO_THEME;
    for (i = 0; i < M98_THEME_CAPACITY; ++i)
        if (!e->slots[i].live && e->slots[i].generation) break;
    if (i == M98_THEME_CAPACITY) return NTTH_E_EXHAUSTED;
    status = ntth_open_data(e->session, name, &e->slots[i].data);
    if (status != NTTH_OK) return status;
    e->slots[i].live = 1;
    *out = (e->slots[i].generation << 8) | (i + 1u);
    return NTTH_OK;
}

ntth_status m98_theme_engine_close(m98_theme_engine *e, m98_theme_handle h)
{
    m98_theme_slot *s = lookup(e, h);
    ntth_status status;
    if (!s) return NTTH_E_HANDLE;
    status = ntth_close_data(e->session, s->data);
    if (status != NTTH_OK) return status;
    s->live = 0;
    s->generation = s->generation == 0xffffffu ? 0 : s->generation + 1u;
    return NTTH_OK;
}

ntth_status m98_theme_engine_query(m98_theme_engine *e, m98_theme_handle h,
                                  int32_t part, int32_t state, ntth_part_properties *out)
{
    m98_theme_slot *s = lookup(e, h);
    if (!s) return NTTH_E_HANDLE;
    if (!m98_theme_engine_active(e)) return NTTH_E_NO_THEME;
    return ntth_query_part(e->session, s->data, part, state, out);
}

ntth_status m98_theme_engine_draw(m98_theme_engine *e, m98_theme_handle h,
                                 int32_t part, int32_t state, uint8_t *pixels,
                                 uint32_t width, uint32_t height, uint32_t pitch,
                                 const ntwg_rect *rect, const ntth_draw_opts *opts)
{
    m98_theme_slot *s = lookup(e, h);
    ntth_part_properties props;
    ntth_status status = m98_theme_engine_query(e, h, part, state, &props);
    if (status != NTTH_OK) return status;
    return ntth_draw_background(e->session, s->data, part, state,
                                pixels, width, height, pitch, rect, opts);
}
