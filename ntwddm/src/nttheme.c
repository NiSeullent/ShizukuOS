/* SPDX-License-Identifier: GPL-2.0-only
 * Original in-process theme painter. Border size, border-then-fill order,
 * solid and two-color linear fills, null-handle rejection, and transparent
 * text follow the reviewed LGPL uxtheme draw.c contract. GDI pens, image
 * files, and the theme service are not linked. See ../PROVENANCE.md.
 */
#include "nttheme.h"

#define NTTH_MAX_CLASSES 8u
#define NTTH_MAX_RULES 32u
#define NTTH_MAX_THEMES 8u
#define NTTH_NAME_MAX 15u
#define NTTH_TEXT_MAX 256u

#define SEEN_BG 1u
#define SEEN_BSIZE 2u
#define SEEN_BCOLOR 4u
#define SEEN_FILL 8u
#define SEEN_FCOLOR 16u
#define SEEN_TEXT 32u
#define SEEN_G1 64u
#define SEEN_G2 128u
#define SEEN_REQUIRED (SEEN_BG | SEEN_BSIZE | SEEN_BCOLOR | SEEN_FILL | SEEN_FCOLOR | SEEN_TEXT)

typedef struct ntth_rule {
    uint32_t class_index;
    uint32_t part;
    uint32_t state;
    uint32_t bgtype;
    uint32_t bordersize;
    uint32_t bordercolor;
    uint32_t filltype;
    uint32_t fillcolor;
    uint32_t gradient1;
    uint32_t gradient2;
    uint32_t textcolor;
} ntth_rule;

typedef struct ntth_slot {
    uint32_t object_generation;
    uint32_t style_generation;
    uint32_t class_index;
    uint32_t live;
} ntth_slot;

struct ntth_session {
    ntwg_allocate_fn allocate;
    ntwg_deallocate_fn deallocate;
    void *user;
    uint32_t style_generation;
    uint32_t loaded;
    char style_name[NTTH_NAME_MAX + 1u];
    char classes[NTTH_MAX_CLASSES][NTTH_NAME_MAX + 1u];
    uint32_t class_count;
    ntth_rule rules[NTTH_MAX_RULES];
    uint32_t rule_count;
    ntth_slot themes[NTTH_MAX_THEMES];
};

typedef struct ntth_draft {
    uint32_t has_name;
    int32_t current_class;
    char style_name[NTTH_NAME_MAX + 1u];
    char classes[NTTH_MAX_CLASSES][NTTH_NAME_MAX + 1u];
    uint32_t class_count;
    ntth_rule rules[NTTH_MAX_RULES];
    uint32_t rule_count;
} ntth_draft;

/* 5x7 glyphs. Bit 4 is the left column. 'A' is the contract glyph. */
static const uint8_t k_digit[10][7] = {
    {0x0E,0x11,0x13,0x15,0x19,0x11,0x0E},
    {0x04,0x0C,0x04,0x04,0x04,0x04,0x0E},
    {0x0E,0x11,0x01,0x06,0x08,0x10,0x1F},
    {0x0E,0x11,0x01,0x06,0x01,0x11,0x0E},
    {0x02,0x06,0x0A,0x12,0x1F,0x02,0x02},
    {0x1F,0x10,0x1E,0x01,0x01,0x11,0x0E},
    {0x06,0x08,0x10,0x1E,0x11,0x11,0x0E},
    {0x1F,0x01,0x02,0x04,0x08,0x08,0x08},
    {0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E},
    {0x0E,0x11,0x11,0x0F,0x01,0x02,0x0C}
};
static const uint8_t k_letter[26][7] = {
    {0x0E,0x11,0x11,0x1F,0x11,0x11,0x11}, /* A */
    {0x1E,0x11,0x11,0x1E,0x11,0x11,0x1E},
    {0x0E,0x10,0x10,0x10,0x10,0x10,0x0E}, /* C */
    {0x1E,0x11,0x11,0x11,0x11,0x11,0x1E}, /* D */
    {0x1F,0x10,0x10,0x1E,0x10,0x10,0x1F}, /* E */
    {0x1F,0x10,0x10,0x1E,0x10,0x10,0x10},
    {0x0E,0x10,0x10,0x17,0x11,0x11,0x0F},
    {0x11,0x11,0x11,0x1F,0x11,0x11,0x11},
    {0x0E,0x04,0x04,0x04,0x04,0x04,0x0E}, /* I */
    {0x01,0x01,0x01,0x01,0x11,0x11,0x0E},
    {0x11,0x12,0x14,0x18,0x14,0x12,0x11}, /* K */
    {0x10,0x10,0x10,0x10,0x10,0x10,0x1F}, /* L */
    {0x11,0x1B,0x15,0x11,0x11,0x11,0x11}, /* M */
    {0x11,0x19,0x15,0x13,0x11,0x11,0x11}, /* N */
    {0x0E,0x11,0x11,0x11,0x11,0x11,0x0E}, /* O */
    {0x1E,0x11,0x11,0x1E,0x10,0x10,0x10},
    {0x0E,0x11,0x11,0x11,0x15,0x12,0x0D},
    {0x1E,0x11,0x11,0x1E,0x14,0x12,0x11}, /* R */
    {0x0F,0x10,0x10,0x0E,0x01,0x01,0x1E}, /* S */
    {0x1F,0x04,0x04,0x04,0x04,0x04,0x04},
    {0x11,0x11,0x11,0x11,0x11,0x11,0x0E},
    {0x11,0x11,0x11,0x11,0x11,0x0A,0x04},
    {0x11,0x11,0x11,0x15,0x15,0x15,0x0A},
    {0x11,0x11,0x0A,0x04,0x0A,0x11,0x11},
    {0x11,0x11,0x0A,0x04,0x04,0x04,0x04},
    {0x1F,0x01,0x02,0x04,0x08,0x10,0x1F}
};

static void zero_bytes(void *memory, size_t bytes)
{
    uint8_t *p = (uint8_t *)memory;
    size_t i;
    for (i = 0; i < bytes; ++i) p[i] = 0;
}

static int is_alpha(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int is_name_char(char c)
{
    return is_alpha(c) || (c >= '0' && c <= '9') || c == '_';
}

static int token_is(const char *token, size_t length, const char *literal)
{
    size_t i;
    for (i = 0; literal[i] != 0; ++i) {
        if (i >= length || token[i] != literal[i]) return 0;
    }
    return i == length;
}

static int store_name(char *dest, const char *token, size_t length)
{
    size_t i;
    if (length == 0 || length > NTTH_NAME_MAX || !is_alpha(token[0])) return 0;
    for (i = 0; i < length; ++i)
        if (!is_name_char(token[i])) return 0;
    for (i = 0; i < length; ++i) dest[i] = token[i];
    dest[length] = 0;
    return 1;
}

static int names_equal(const char *stored, const char *token, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i)
        if (stored[i] != token[i]) return 0;
    return stored[length] == 0;
}

static int parse_u32(const char *token, size_t length, uint32_t limit, uint32_t *out)
{
    uint32_t value = 0;
    size_t i;
    if (length == 0) return 0;
    for (i = 0; i < length; ++i) {
        uint32_t digit;
        if (token[i] < '0' || token[i] > '9') return 0;
        digit = (uint32_t)(token[i] - '0');
        if (value > (limit - digit) / 10u) return 0;
        value = value * 10u + digit;
    }
    *out = value;
    return 1;
}

static int parse_color(const char *token, size_t length, uint32_t *out)
{
    uint32_t value = 0;
    uint32_t i;
    if (length != 6) return 0;
    for (i = 0; i < 6; ++i) {
        char c = token[i];
        uint32_t digit;
        if (c >= '0' && c <= '9') digit = (uint32_t)(c - '0');
        else if (c >= 'A' && c <= 'F') digit = (uint32_t)(c - 'A') + 10u;
        else if (c >= 'a' && c <= 'f') digit = (uint32_t)(c - 'a') + 10u;
        else return 0;
        value = (value << 4) | digit;
    }
    *out = value;
    return 1;
}

static const char *next_token(const char *p, const char *end,
                              const char **token, size_t *length)
{
    while (p < end && (*p == ' ' || *p == '\t')) ++p;
    *token = p;
    while (p < end && *p != ' ' && *p != '\t') ++p;
    *length = (size_t)(p - *token);
    return p;
}

static int duplicate_rule(const ntth_draft *draft, uint32_t class_index,
                          uint32_t part, uint32_t state)
{
    uint32_t i;
    for (i = 0; i < draft->rule_count; ++i)
        if (draft->rules[i].class_index == class_index &&
            draft->rules[i].part == part && draft->rules[i].state == state)
            return 1;
    return 0;
}

static ntth_status parse_part(const char *line, const char *end, ntth_draft *draft)
{
    const char *token;
    size_t length;
    uint32_t part, state, seen = 0, value;
    ntth_rule rule;
    const char *cursor;
    if (draft->current_class < 0) return NTTH_E_PARSE;
    cursor = next_token(line, end, &token, &length);
    if (!token_is(token, length, "part")) return NTTH_E_PARSE;
    cursor = next_token(cursor, end, &token, &length);
    if (!parse_u32(token, length, 65535u, &part) || part == 0) return NTTH_E_PARSE;
    cursor = next_token(cursor, end, &token, &length);
    if (!token_is(token, length, "state")) return NTTH_E_PARSE;
    cursor = next_token(cursor, end, &token, &length);
    if (!parse_u32(token, length, 65535u, &state) || state == 0) return NTTH_E_PARSE;
    if (duplicate_rule(draft, (uint32_t)draft->current_class, part, state))
        return NTTH_E_PARSE;
    zero_bytes(&rule, sizeof(rule));
    rule.class_index = (uint32_t)draft->current_class;
    rule.part = part;
    rule.state = state;
    for (;;) {
        cursor = next_token(cursor, end, &token, &length);
        if (length == 0) break;
        if (token_is(token, length, "bgtype")) {
            if ((seen & SEEN_BG) != 0) return NTTH_E_PARSE;
            cursor = next_token(cursor, end, &token, &length);
            if (token_is(token, length, "borderfill")) rule.bgtype = NTTH_BG_BORDERFILL;
            else if (token_is(token, length, "imagefile")) rule.bgtype = NTTH_BG_IMAGEFILE;
            else if (token_is(token, length, "none")) rule.bgtype = NTTH_BG_NONE;
            else return NTTH_E_PARSE;
            seen |= SEEN_BG;
        } else if (token_is(token, length, "bordersize")) {
            if ((seen & SEEN_BSIZE) != 0) return NTTH_E_PARSE;
            cursor = next_token(cursor, end, &token, &length);
            if (!parse_u32(token, length, 64u, &value)) return NTTH_E_PARSE;
            rule.bordersize = value;
            seen |= SEEN_BSIZE;
        } else if (token_is(token, length, "bordercolor") ||
                   token_is(token, length, "fillcolor") ||
                   token_is(token, length, "textcolor") ||
                   token_is(token, length, "gradient1") ||
                   token_is(token, length, "gradient2")) {
            const char *key = token;
            size_t key_length = length;
            uint32_t bit = 0;
            uint32_t *slot = NULL;
            if (token_is(key, key_length, "bordercolor")) { bit = SEEN_BCOLOR; slot = &rule.bordercolor; }
            else if (token_is(key, key_length, "fillcolor")) { bit = SEEN_FCOLOR; slot = &rule.fillcolor; }
            else if (token_is(key, key_length, "textcolor")) { bit = SEEN_TEXT; slot = &rule.textcolor; }
            else if (token_is(key, key_length, "gradient1")) { bit = SEEN_G1; slot = &rule.gradient1; }
            else { bit = SEEN_G2; slot = &rule.gradient2; }
            if ((seen & bit) != 0) return NTTH_E_PARSE;
            cursor = next_token(cursor, end, &token, &length);
            if (!parse_color(token, length, slot)) return NTTH_E_PARSE;
            seen |= bit;
        } else if (token_is(token, length, "filltype")) {
            if ((seen & SEEN_FILL) != 0) return NTTH_E_PARSE;
            cursor = next_token(cursor, end, &token, &length);
            if (token_is(token, length, "solid")) rule.filltype = NTTH_FT_SOLID;
            else if (token_is(token, length, "vertgradient")) rule.filltype = NTTH_FT_VERTGRADIENT;
            else if (token_is(token, length, "horzgradient")) rule.filltype = NTTH_FT_HORZGRADIENT;
            else if (token_is(token, length, "radialgradient")) rule.filltype = NTTH_FT_RADIALGRADIENT;
            else if (token_is(token, length, "tileimage")) rule.filltype = NTTH_FT_TILEIMAGE;
            else return NTTH_E_PARSE;
            seen |= SEEN_FILL;
        } else return NTTH_E_PARSE;
    }
    if ((seen & SEEN_REQUIRED) != SEEN_REQUIRED) return NTTH_E_PARSE;
    if (rule.filltype == NTTH_FT_HORZGRADIENT || rule.filltype == NTTH_FT_VERTGRADIENT) {
        if ((seen & (SEEN_G1 | SEEN_G2)) != (SEEN_G1 | SEEN_G2)) return NTTH_E_PARSE;
    } else if ((seen & (SEEN_G1 | SEEN_G2)) != 0) return NTTH_E_PARSE;
    if (draft->rule_count == NTTH_MAX_RULES) return NTTH_E_PARSE;
    draft->rules[draft->rule_count++] = rule;
    return NTTH_OK;
}

static ntth_status parse_line(const char *line, size_t length, ntth_draft *draft)
{
    const char *end, *cursor, *token;
    size_t token_length;
    while (length > 0 && (line[0] == ' ' || line[0] == '\t')) {
        ++line;
        --length;
    }
    if (length > 0 && line[length - 1] == '\r') --length;
    if (length == 0 || line[0] == '#') return NTTH_OK;
    if (length > 240) return NTTH_E_PARSE;
    end = line + length;
    cursor = next_token(line, end, &token, &token_length);
    if (token_is(token, token_length, "name")) {
        const char *extra;
        size_t extra_length;
        if (draft->has_name || draft->class_count != 0) return NTTH_E_PARSE;
        cursor = next_token(cursor, end, &token, &token_length);
        if (!store_name(draft->style_name, token, token_length)) return NTTH_E_PARSE;
        next_token(cursor, end, &extra, &extra_length);
        if (extra_length != 0) return NTTH_E_PARSE;
        draft->has_name = 1;
        return NTTH_OK;
    }
    if (token_is(token, token_length, "class")) {
        uint32_t i;
        const char *extra;
        size_t extra_length;
        char name[NTTH_NAME_MAX + 1u];
        if (!draft->has_name) return NTTH_E_PARSE;
        cursor = next_token(cursor, end, &token, &token_length);
        if (!store_name(name, token, token_length)) return NTTH_E_PARSE;
        next_token(cursor, end, &extra, &extra_length);
        if (extra_length != 0) return NTTH_E_PARSE;
        for (i = 0; i < draft->class_count; ++i)
            if (names_equal(draft->classes[i], name, token_length)) return NTTH_E_PARSE;
        if (draft->class_count == NTTH_MAX_CLASSES) return NTTH_E_PARSE;
        for (i = 0; name[i] != 0; ++i) draft->classes[draft->class_count][i] = name[i];
        draft->classes[draft->class_count][i] = 0;
        draft->current_class = (int32_t)draft->class_count;
        draft->class_count++;
        return NTTH_OK;
    }
    if (token_is(token, token_length, "part")) return parse_part(line, end, draft);
    return NTTH_E_PARSE;
}

static ntth_status parse_style(const char *text, size_t length, ntth_draft *draft)
{
    size_t i = 0;
    zero_bytes(draft, sizeof(*draft));
    draft->current_class = -1;
    if (text == NULL) return NTTH_E_INVALID;
    if (length == 0 || length > 8192u) return length == 0 ? NTTH_E_INVALID : NTTH_E_PARSE;
    while (i < length) {
        size_t start = i;
        ntth_status status;
        while (i < length && text[i] != '\n') {
            if (text[i] == 0) return NTTH_E_PARSE;
            ++i;
        }
        status = parse_line(text + start, i - start, draft);
        if (status != NTTH_OK) return status;
        if (i < length) ++i;
    }
    if (!draft->has_name || draft->class_count == 0 || draft->rule_count == 0)
        return NTTH_E_PARSE;
    return NTTH_OK;
}

static ntth_slot *lookup_theme(ntth_session *session, ntth_theme theme)
{
    uint32_t slot = (uint32_t)theme;
    uint32_t generation = (uint32_t)(theme >> 32);
    ntth_slot *entry;
    if (session == NULL || slot == 0 || slot > NTTH_MAX_THEMES || generation == 0)
        return NULL;
    entry = &session->themes[slot - 1u];
    if (entry->live == 0 || entry->object_generation != generation) return NULL;
    return entry;
}

static int find_rule(const ntth_session *session, uint32_t class_index,
                     uint32_t part, uint32_t state, ntth_rule *out)
{
    uint32_t i;
    for (i = 0; i < session->rule_count; ++i) {
        if (session->rules[i].class_index == class_index &&
            session->rules[i].part == part && session->rules[i].state == state) {
            *out = session->rules[i];
            return 1;
        }
    }
    return 0;
}

static void default_rule(ntth_rule *rule)
{
    zero_bytes(rule, sizeof(*rule));
    rule->bgtype = NTTH_BG_BORDERFILL;
    rule->bordersize = 1;
    rule->filltype = NTTH_FT_SOLID;
    rule->fillcolor = 0x00FFFFFFu;
    rule->gradient2 = 0x00FFFFFFu;
}

static ntth_status prepare_target(ntth_session *session, ntth_theme theme,
                                  int32_t part, int32_t state, uint8_t *pixels,
                                  uint32_t width, uint32_t height, uint32_t pitch,
                                  const ntwg_rect *rect, const ntth_draw_opts *opts,
                                  ntth_slot **slot, ntth_rule *rule)
{
    ntth_slot *entry;
    if (session == NULL || pixels == NULL || rect == NULL) return NTTH_E_INVALID;
    if (width == 0 || height == 0 || part <= 0 || state <= 0) return NTTH_E_INVALID;
    if (width > UINT32_MAX / 4u || pitch < width * 4u) return NTTH_E_BOUNDS;
    if ((size_t)height > SIZE_MAX / (size_t)pitch) return NTTH_E_BOUNDS;
    if (opts != NULL && opts->struct_size < sizeof(*opts)) return NTTH_E_INVALID;
    if (opts != NULL && (opts->flags & NTTH_DRAW_CLIP) != 0 &&
        (opts->clip.width == 0 || opts->clip.height == 0))
        return NTTH_E_INVALID;
    if (rect->width == 0 || rect->height == 0) return NTTH_E_INVALID;
    if (rect->x > UINT32_MAX - rect->width || rect->y > UINT32_MAX - rect->height)
        return NTTH_E_BOUNDS;
    entry = lookup_theme(session, theme);
    if (entry == NULL || entry->style_generation != session->style_generation)
        return NTTH_E_HANDLE;
    if (!find_rule(session, entry->class_index, (uint32_t)part, (uint32_t)state, rule))
        default_rule(rule);
    *slot = entry;
    return NTTH_OK;
}

static int inside_clip(const ntth_draw_opts *opts, uint32_t x, uint32_t y)
{
    if (opts == NULL || (opts->flags & NTTH_DRAW_CLIP) == 0) return 1;
    if (x < opts->clip.x || y < opts->clip.y) return 0;
    if (x - opts->clip.x >= opts->clip.width) return 0;
    if (y - opts->clip.y >= opts->clip.height) return 0;
    return 1;
}

static void put_xrgb(uint8_t *pixels, uint32_t pitch, uint32_t x, uint32_t y,
                     uint32_t color)
{
    uint8_t *p = pixels + (size_t)y * (size_t)pitch + (size_t)x * 4u;
    p[0] = (uint8_t)color;
    p[1] = (uint8_t)(color >> 8);
    p[2] = (uint8_t)(color >> 16);
    p[3] = 255;
}

static uint32_t mix_channel(uint32_t from, uint32_t to, uint32_t t, uint32_t shift)
{
    uint32_t a = (from >> shift) & 255u;
    uint32_t b = (to >> shift) & 255u;
    return ((a * (255u - t) + b * t) / 255u) << shift;
}

static uint32_t mix_color(uint32_t from, uint32_t to, uint32_t t)
{
    return mix_channel(from, to, t, 0) | mix_channel(from, to, t, 8) |
           mix_channel(from, to, t, 16);
}

/* 64-bit / 32-bit division for i386 freestanding builds, which have no libgcc. */
static uint32_t div_wide(uint32_t hi, uint32_t lo, uint32_t den)
{
    uint32_t rem = 0;
    uint32_t quot = 0;
    int bit;
    for (bit = 63; bit >= 0; --bit) {
        uint32_t next = bit >= 32 ? (hi >> (bit - 32)) & 1u : (lo >> bit) & 1u;
        rem = (rem << 1) | next;
        quot <<= 1;
        if (rem >= den) {
            rem -= den;
            quot |= 1u;
        }
    }
    return quot;
}

static uint32_t mul255_div(uint32_t numerator, uint32_t denominator)
{
    uint32_t low = (numerator & 0xFFFFu) * 255u;
    uint32_t high = (numerator >> 16) * 255u;
    uint32_t lo = low + (high << 16);
    uint32_t carry = lo < low ? 1u : 0u;
    uint32_t hi = (high >> 16) + carry;
    return div_wide(hi, lo, denominator);
}

static uint32_t gradient_color(const ntth_rule *rule, uint32_t x, uint32_t y,
                               uint32_t origin_x, uint32_t origin_y,
                               uint32_t span_w, uint32_t span_h)
{
    uint32_t t = 0;
    if (rule->filltype == NTTH_FT_HORZGRADIENT && span_w > 1u)
        t = mul255_div(x - origin_x, span_w - 1u);
    else if (rule->filltype == NTTH_FT_VERTGRADIENT && span_h > 1u)
        t = mul255_div(y - origin_y, span_h - 1u);
    return mix_color(rule->gradient1, rule->gradient2, t);
}

ntth_status ntth_draw_background(ntth_session *session, ntth_theme theme,
                                 int32_t part, int32_t state,
                                 uint8_t *pixels, uint32_t width, uint32_t height,
                                 uint32_t pitch, const ntwg_rect *rect,
                                 const ntth_draw_opts *opts)
{
    ntth_slot *slot;
    ntth_rule rule;
    ntth_status status;
    uint32_t omit_border, omit_content, border;
    uint32_t y, x;
    status = prepare_target(session, theme, part, state, pixels, width, height,
                            pitch, rect, opts, &slot, &rule);
    if (status != NTTH_OK) return status;
    (void)slot;
    if (rule.bgtype == NTTH_BG_NONE) return NTTH_OK;
    if (rule.bgtype == NTTH_BG_IMAGEFILE || rule.filltype == NTTH_FT_RADIALGRADIENT ||
        rule.filltype == NTTH_FT_TILEIMAGE || rule.bgtype > NTTH_BG_NONE)
        return NTTH_E_UNSUPPORTED;
    omit_border = opts != NULL && (opts->flags & NTTH_DRAW_OMIT_BORDER) != 0;
    omit_content = opts != NULL && (opts->flags & NTTH_DRAW_OMIT_CONTENT) != 0;
    border = rule.bordersize;
    for (y = 0; y < rect->height; ++y) {
        uint32_t py = rect->y + y;
        if (py >= height) continue;
        for (x = 0; x < rect->width; ++x) {
            uint32_t px = rect->x + x;
            int edge;
            uint32_t color;
            if (px >= width || !inside_clip(opts, px, py)) continue;
            edge = border > 0 && (x < border || y < border ||
                                  x >= rect->width - border || y >= rect->height - border);
            if (edge) {
                if (omit_border) continue;
                color = rule.bordercolor;
            } else {
                uint32_t span_w, span_h;
                if (omit_content) continue;
                if (rule.filltype == NTTH_FT_SOLID) color = rule.fillcolor;
                else {
                    if (rect->width <= border * 2u || rect->height <= border * 2u) continue;
                    span_w = rect->width - border * 2u;
                    span_h = rect->height - border * 2u;
                    color = gradient_color(&rule, px, py, rect->x + border,
                                           rect->y + border, span_w, span_h);
                }
            }
            put_xrgb(pixels, pitch, px, py, color);
        }
    }
    return NTTH_OK;
}

static const uint8_t *glyph_rows(char c)
{
    if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    if (c >= 'A' && c <= 'Z') return k_letter[(uint32_t)(c - 'A')];
    if (c >= '0' && c <= '9') return k_digit[(uint32_t)(c - '0')];
    return NULL;
}

ntth_status ntth_draw_text(ntth_session *session, ntth_theme theme,
                           int32_t part, int32_t state,
                           const char *text, size_t text_bytes,
                           uint8_t *pixels, uint32_t width, uint32_t height,
                           uint32_t pitch, const ntwg_rect *rect,
                           const ntth_draw_opts *opts)
{
    ntth_slot *slot;
    ntth_rule rule;
    ntth_status status;
    size_t i;
    uint32_t color;
    if (text_bytes > NTTH_TEXT_MAX) return NTTH_E_INVALID;
    if (text_bytes > 0 && text == NULL) return NTTH_E_INVALID;
    status = prepare_target(session, theme, part, state, pixels, width, height,
                            pitch, rect, opts, &slot, &rule);
    if (status != NTTH_OK) return status;
    (void)slot;
    for (i = 0; i < text_bytes; ++i) {
        char c = text[i];
        if (c != ' ' && glyph_rows(c) == NULL) return NTTH_E_UNSUPPORTED;
    }
    if (text_bytes > 0 && rect->x > UINT32_MAX - 6u * (uint32_t)text_bytes)
        return NTTH_E_BOUNDS;
    color = (opts != NULL && (opts->flags & NTTH_TEXT_GRAYED) != 0)
                ? 0x00808080u : rule.textcolor;
    for (i = 0; i < text_bytes; ++i) {
        const uint8_t *rows;
        uint32_t row, col;
        char c = text[i];
        uint32_t origin = rect->x + (uint32_t)i * 6u;
        if (c == ' ') continue;
        rows = glyph_rows(c);
        for (row = 0; row < 7u; ++row) {
            uint32_t py = rect->y + row;
            if (py < rect->y || py >= rect->y + rect->height || py >= height) continue;
            for (col = 0; col < 5u; ++col) {
                uint32_t px = origin + col;
                if ((rows[row] & (uint8_t)(1u << (4u - col))) == 0) continue;
                if (px < rect->x || px >= rect->x + rect->width || px >= width) continue;
                if (!inside_clip(opts, px, py)) continue;
                put_xrgb(pixels, pitch, px, py, color);
            }
        }
    }
    return NTTH_OK;
}

ntth_status ntth_session_open(const ntth_create_desc *desc, ntth_session **out)
{
    ntth_session *session;
    uint32_t i;
    if (out == NULL) return NTTH_E_INVALID;
    *out = NULL;
    if (desc == NULL || desc->struct_size < sizeof(*desc) ||
        desc->allocate == NULL || desc->deallocate == NULL)
        return NTTH_E_INVALID;
    session = (ntth_session *)desc->allocate(desc->allocator_user, sizeof(*session));
    if (session == NULL) return NTTH_E_NOMEM;
    zero_bytes(session, sizeof(*session));
    session->allocate = desc->allocate;
    session->deallocate = desc->deallocate;
    session->user = desc->allocator_user;
    for (i = 0; i < NTTH_MAX_THEMES; ++i) session->themes[i].object_generation = 1;
    *out = session;
    return NTTH_OK;
}

ntth_status ntth_session_load(ntth_session *session, const char *text, size_t length)
{
    ntth_draft draft;
    ntth_status status;
    uint32_t i;
    if (session == NULL) return NTTH_E_INVALID;
    if (session->style_generation == UINT32_MAX) return NTTH_E_EXHAUSTED;
    status = parse_style(text, length, &draft);
    if (status != NTTH_OK) return status;
    for (i = 0; i < draft.class_count; ++i) {
        uint32_t n;
        for (n = 0; n < NTTH_NAME_MAX + 1u; ++n)
            session->classes[i][n] = draft.classes[i][n];
    }
    session->class_count = draft.class_count;
    session->rule_count = draft.rule_count;
    for (i = 0; i < draft.rule_count; ++i) session->rules[i] = draft.rules[i];
    for (i = 0; i < NTTH_NAME_MAX + 1u; ++i)
        session->style_name[i] = draft.style_name[i];
    session->loaded = 1;
    session->style_generation++;
    return NTTH_OK;
}

int ntth_theme_active(const ntth_session *session)
{
    return session != NULL && session->loaded != 0;
}

ntth_status ntth_open_data(ntth_session *session, const char *class_name,
                           ntth_theme *out)
{
    uint32_t class_index, slot, i;
    size_t length = 0;
    if (out == NULL) return NTTH_E_INVALID;
    *out = 0;
    if (session == NULL || class_name == NULL) return NTTH_E_INVALID;
    if (!session->loaded) return NTTH_E_NO_THEME;
    while (class_name[length] != 0) {
        if (length == NTTH_NAME_MAX) return NTTH_E_INVALID;
        ++length;
    }
    if (length == 0) return NTTH_E_INVALID;
    class_index = NTTH_MAX_CLASSES;
    for (i = 0; i < session->class_count; ++i)
        if (names_equal(session->classes[i], class_name, length)) class_index = i;
    if (class_index == NTTH_MAX_CLASSES) return NTTH_E_NO_THEME;
    for (slot = 0; slot < NTTH_MAX_THEMES; ++slot)
        if (session->themes[slot].live == 0 &&
            session->themes[slot].object_generation != 0)
            break;
    if (slot == NTTH_MAX_THEMES) return NTTH_E_EXHAUSTED;
    session->themes[slot].live = 1;
    session->themes[slot].class_index = class_index;
    session->themes[slot].style_generation = session->style_generation;
    *out = ((uint64_t)session->themes[slot].object_generation << 32) |
           (uint64_t)(slot + 1u);
    return NTTH_OK;
}

ntth_status ntth_close_data(ntth_session *session, ntth_theme theme)
{
    ntth_slot *entry = lookup_theme(session, theme);
    if (entry == NULL) return NTTH_E_HANDLE;
    entry->live = 0;
    if (entry->object_generation == UINT32_MAX) entry->object_generation = 0;
    else entry->object_generation++;
    return NTTH_OK;
}

ntth_status ntth_session_close(ntth_session *session)
{
    uint32_t i;
    if (session == NULL) return NTTH_E_INVALID;
    for (i = 0; i < NTTH_MAX_THEMES; ++i)
        if (session->themes[i].live != 0) return NTTH_E_BUSY;
    session->deallocate(session->user, session, sizeof(*session));
    return NTTH_OK;
}
