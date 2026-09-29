/* SPDX-License-Identifier: GPL-2.0-only
 * Original routing policy: bounded parsing, provider order and stub lookup.
 * No C runtime is used; every loop is bounded by an explicit length. */
#include "routing.h"

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c; }
static char upper(char c) { return (c >= 'a' && c <= 'z') ? (char)(c - ('a' - 'A')) : c; }
static int is_space(char c) { return c == ' ' || c == '\t' || c == '\r'; }
static int is_alpha(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
static int is_digit(char c) { return c >= '0' && c <= '9'; }

int ntw_route_name_equal(const char *left, const char *right) {
    if (!left || !right) return 0;
    while (*left && *left == *right) { ++left; ++right; }
    return *left == *right;
}
int ntw_route_name_iequal(const char *left, const char *right) {
    if (!left || !right) return 0;
    while (*left && lower(*left) == lower(*right)) { ++left; ++right; }
    return lower(*left) == lower(*right);
}

void ntw_text_start(struct ntw_text *text, char *buffer, size_t capacity) {
    text->buffer = buffer;
    text->capacity = capacity;
    text->length = 0;
    if (capacity) buffer[0] = 0;
}
static void text_put(struct ntw_text *text, char c) {
    if (text->capacity == 0 || text->length + 1 >= text->capacity) return;
    text->buffer[text->length++] = c;
    text->buffer[text->length] = 0;
}
void ntw_text_add_slice(struct ntw_text *text, const char *source, size_t length) {
    size_t i;
    if (!source) { ntw_text_add(text, "(null)"); return; }
    for (i = 0; i < length && source[i]; ++i) {
        char c = source[i];
        text_put(text, (c >= 0x20 && c <= 0x7e) ? c : '?');
    }
}
void ntw_text_add_bounded(struct ntw_text *text, const char *source, size_t limit) {
    size_t i;
    if (!source) { ntw_text_add(text, "(null)"); return; }
    ntw_text_add_slice(text, source, limit);
    for (i = 0; i < limit && source[i]; ++i) { }
    if (i == limit && source[i]) ntw_text_add(text, "...");
}
void ntw_text_add(struct ntw_text *text, const char *source) {
    size_t i;
    if (!source) source = "(null)";
    for (i = 0; source[i] && i < NTW_ROUTE_MESSAGE_MAX; ++i) text_put(text, source[i]);
}
void ntw_text_add_uint(struct ntw_text *text, unsigned value) {
    char digits[10];
    unsigned count = 0;
    do { digits[count++] = (char)('0' + value % 10u); value /= 10u; } while (value && count < 10);
    while (count) text_put(text, digits[--count]);
}

const char *ntw_route_mode_name(unsigned mode) {
    switch (mode) {
    case NTW_MODE_AUTO: return "auto";
    case NTW_MODE_OWN: return "own";
    case NTW_MODE_KERNELEX: return "kernelex";
    case NTW_MODE_NATIVE: return "native";
    default: return "invalid";
    }
}
const char *ntw_route_provider_name(unsigned provider) {
    switch (provider) {
    case NTW_PROVIDER_NATIVE: return "native";
    case NTW_PROVIDER_OWN: return "own";
    case NTW_PROVIDER_KERNELEX: return "kernelex";
    default: return "none";
    }
}
const char *ntw_route_kernelex_name(unsigned state) {
    switch (state) {
    case NTW_KERNELEX_CORE_ONLY: return "core-only";
    case NTW_KERNELEX_ACTIVE: return "active";
    default: return "not-detected";
    }
}

int ntw_route_parse_mode(const char *text, size_t length, unsigned *mode) {
    static const char *const names[4] = { "auto", "own", "kernelex", "native" };
    unsigned candidate;
    if (!text || !mode || length == 0 || length > 8) return 0;
    for (candidate = 0; candidate < 4; ++candidate) {
        const char *name = names[candidate];
        size_t i;
        for (i = 0; i < length && name[i] && lower(text[i]) == name[i]; ++i) { }
        if (i == length && name[i] == 0) { *mode = candidate; return 1; }
    }
    return 0;
}

void ntw_route_policy_init(struct ntw_route_policy *policy) {
    unsigned i, j;
    if (!policy) return;
    policy->mode = NTW_MODE_AUTO;
    policy->log = 0;
    policy->source = NTW_ROUTE_SOURCE_DEFAULT;
    policy->warnings = 0;
    policy->override_count = 0;
    for (i = 0; i < NTW_ROUTE_MAX_OVERRIDES; ++i) {
        policy->overrides[i].kind = 0;
        policy->overrides[i].mode = NTW_MODE_AUTO;
        for (j = 0; j < NTW_ROUTE_NAME_MAX; ++j) policy->overrides[i].name[j] = 0;
    }
}

struct parser {
    struct ntw_route_policy *policy;
    ntw_route_log log;
    void *context;
    unsigned line;
    unsigned warnings;
    int saw_mode, saw_log;
};

static void warn(struct parser *p, const char *what, const char *detail, size_t detail_length) {
    char buffer[NTW_ROUTE_MESSAGE_MAX];
    struct ntw_text text;
    ++p->warnings;
    ++p->policy->warnings;
    if (!p->log) return;
    ntw_text_start(&text, buffer, sizeof buffer);
    ntw_text_add(&text, "NTW32: routing config");
    if (p->line) {   /* zero: the whole configuration was rejected before any line */
        ntw_text_add(&text, " line ");
        ntw_text_add_uint(&text, p->line);
    }
    ntw_text_add(&text, ": ");
    ntw_text_add(&text, what);
    if (detail) {
        ntw_text_add(&text, " '");
        ntw_text_add_slice(&text, detail, detail_length);
        ntw_text_add(&text, "'");
    }
    p->log(p->context, buffer);
}

static int valid_module_name(const char *s, size_t n) {
    size_t i;
    if (n == 0 || n >= NTW_ROUTE_MODULE_MAX) return 0;
    for (i = 0; i < n; ++i) {
        char c = s[i];
        if (!(is_alpha(c) || is_digit(c) || c == '_' || c == '.' || c == '-')) return 0;
    }
    return 1;
}
static int valid_function_name(const char *s, size_t n) {
    size_t i;
    if (n == 0 || n >= NTW_ROUTE_NAME_MAX) return 0;
    if (!(is_alpha(s[0]) || s[0] == '_')) return 0;
    for (i = 1; i < n; ++i) {
        char c = s[i];
        if (!(is_alpha(c) || is_digit(c) || c == '_')) return 0;
    }
    return 1;
}

static void add_override(struct parser *p, unsigned kind, const char *key, size_t key_length,
                         const char *value, size_t value_length) {
    struct ntw_route_policy *policy = p->policy;
    struct ntw_route_override *slot;
    unsigned mode, i;
    size_t j;
    if (kind == NTW_OVERRIDE_MODULE ? !valid_module_name(key, key_length)
                                    : !valid_function_name(key, key_length)) {
        warn(p, kind == NTW_OVERRIDE_MODULE ? "invalid module name" : "invalid function name",
             key, key_length);
        return;
    }
    if (!ntw_route_parse_mode(value, value_length, &mode)) {
        warn(p, "unknown mode", value, value_length);
        return;
    }
    for (i = 0; i < policy->override_count; ++i) {
        const struct ntw_route_override *existing = &policy->overrides[i];
        int same = 0;
        if (existing->kind != kind) continue;
        for (j = 0; j < key_length; ++j) {
            char stored = existing->name[j];
            char given = kind == NTW_OVERRIDE_MODULE ? upper(key[j]) : key[j];
            if (stored != given) break;
        }
        same = j == key_length && existing->name[j] == 0;
        if (same) { warn(p, "duplicate override ignored", key, key_length); return; }
    }
    if (policy->override_count >= NTW_ROUTE_MAX_OVERRIDES) {
        warn(p, "override limit reached; entry ignored", key, key_length);
        return;
    }
    slot = &policy->overrides[policy->override_count];
    slot->kind = (unsigned char)kind;
    slot->mode = (unsigned char)mode;
    for (j = 0; j < key_length; ++j)
        slot->name[j] = kind == NTW_OVERRIDE_MODULE ? upper(key[j]) : key[j];
    slot->name[key_length] = 0;
    ++policy->override_count;
}

enum { SECTION_NONE, SECTION_ROUTING, SECTION_MODULES, SECTION_FUNCTIONS, SECTION_UNKNOWN };

static void parse_line(struct parser *p, const char *line, size_t length, unsigned *section) {
    size_t equals, key_end, value_start;
    while (length && is_space(line[0])) { ++line; --length; }
    while (length && is_space(line[length - 1])) --length;
    if (length == 0 || line[0] == ';' || line[0] == '#') return;
    if (length > NTW_ROUTE_LINE_MAX) { warn(p, "line too long; ignored", 0, 0); return; }
    if (line[0] == '[') {
        size_t name_end;
        if (line[length - 1] != ']') { warn(p, "unterminated section header", line, length); return; }
        line += 1; length -= 2;
        while (length && is_space(line[0])) { ++line; --length; }
        name_end = length;
        while (name_end && is_space(line[name_end - 1])) --name_end;
        if (name_end == 7 && lower(line[0]) == 'r' && lower(line[1]) == 'o' && lower(line[2]) == 'u' &&
            lower(line[3]) == 't' && lower(line[4]) == 'i' && lower(line[5]) == 'n' && lower(line[6]) == 'g')
            *section = SECTION_ROUTING;
        else if (name_end == 7 && lower(line[0]) == 'm' && lower(line[1]) == 'o' && lower(line[2]) == 'd' &&
                 lower(line[3]) == 'u' && lower(line[4]) == 'l' && lower(line[5]) == 'e' && lower(line[6]) == 's')
            *section = SECTION_MODULES;
        else if (name_end == 9 && lower(line[0]) == 'f' && lower(line[1]) == 'u' && lower(line[2]) == 'n' &&
                 lower(line[3]) == 'c' && lower(line[4]) == 't' && lower(line[5]) == 'i' && lower(line[6]) == 'o' &&
                 lower(line[7]) == 'n' && lower(line[8]) == 's')
            *section = SECTION_FUNCTIONS;
        else { *section = SECTION_UNKNOWN; warn(p, "unknown section", line, name_end); }
        return;
    }
    for (equals = 0; equals < length && line[equals] != '='; ++equals) { }
    if (equals == length) { warn(p, "expected key=value", line, length); return; }
    key_end = equals;
    while (key_end && is_space(line[key_end - 1])) --key_end;
    value_start = equals + 1;
    while (value_start < length && is_space(line[value_start])) ++value_start;
    if (key_end == 0) { warn(p, "empty key", line, length); return; }
    if (value_start == length) { warn(p, "empty value", line, key_end); return; }
    switch (*section) {
    case SECTION_ROUTING:
        if (key_end == 4 && lower(line[0]) == 'm' && lower(line[1]) == 'o' &&
            lower(line[2]) == 'd' && lower(line[3]) == 'e') {
            unsigned mode;
            if (p->saw_mode) { warn(p, "duplicate mode ignored", line + value_start, length - value_start); return; }
            p->saw_mode = 1;
            if (!ntw_route_parse_mode(line + value_start, length - value_start, &mode)) {
                warn(p, "unknown mode; Auto retained", line + value_start, length - value_start);
                return;
            }
            p->policy->mode = (unsigned char)mode;
        } else if (key_end == 3 && lower(line[0]) == 'l' && lower(line[1]) == 'o' && lower(line[2]) == 'g') {
            if (p->saw_log) { warn(p, "duplicate log ignored", line + value_start, length - value_start); return; }
            p->saw_log = 1;
            if (length - value_start == 1 && (line[value_start] == '0' || line[value_start] == '1'))
                p->policy->log = (unsigned char)(line[value_start] - '0');
            else warn(p, "log must be 0 or 1", line + value_start, length - value_start);
        } else warn(p, "unknown key", line, key_end);
        return;
    case SECTION_MODULES:
        add_override(p, NTW_OVERRIDE_MODULE, line, key_end, line + value_start, length - value_start);
        return;
    case SECTION_FUNCTIONS:
        add_override(p, NTW_OVERRIDE_FUNCTION, line, key_end, line + value_start, length - value_start);
        return;
    case SECTION_UNKNOWN:
        warn(p, "key under unknown section ignored", line, key_end);
        return;
    default:
        warn(p, "key outside any section", line, key_end);
        return;
    }
}

unsigned ntw_route_parse(struct ntw_route_policy *policy, const char *text, size_t length,
                         char separator, ntw_route_log log, void *context) {
    struct parser p;
    unsigned section = SECTION_NONE;
    size_t start, i;
    if (!policy) return 0;
    p.policy = policy; p.log = log; p.context = context;
    p.line = 0; p.warnings = 0; p.saw_mode = 0; p.saw_log = 0;
    if (!text || length > NTW_ROUTE_TEXT_MAX) {
        warn(&p, "configuration missing or longer than 4096 bytes; ignored", 0, 0);
        return p.warnings;
    }
    for (i = 0; i < length; ++i) {
        char c = text[i];
        if (!((c >= 0x20 && c <= 0x7e) || c == '\t' || c == '\r' || c == '\n' || c == separator)) {
            warn(&p, "control or non-ASCII byte; configuration ignored", 0, 0);
            return p.warnings;
        }
    }
    for (start = 0, i = 0; i <= length; ++i) {
        if (i == length || text[i] == '\n' || text[i] == separator) {
            ++p.line;
            parse_line(&p, text + start, i - start, &section);
            start = i + 1;
        }
    }
    return p.warnings;
}

unsigned ntw_route_effective_mode(const struct ntw_route_policy *policy, const char *module, const char *name) {
    unsigned i;
    if (!policy) return NTW_MODE_OWN;
    for (i = 0; i < policy->override_count && i < NTW_ROUTE_MAX_OVERRIDES; ++i) {
        const struct ntw_route_override *o = &policy->overrides[i];
        if (o->kind == NTW_OVERRIDE_FUNCTION && ntw_route_name_equal(o->name, name)) return o->mode;
    }
    for (i = 0; i < policy->override_count && i < NTW_ROUTE_MAX_OVERRIDES; ++i) {
        const struct ntw_route_override *o = &policy->overrides[i];
        if (o->kind == NTW_OVERRIDE_MODULE && ntw_route_name_iequal(o->name, module)) return o->mode;
    }
    return policy->mode;
}

unsigned ntw_route_order(unsigned mode, const struct ntw_route_table *table, const char *name) {
    unsigned i;
    switch (mode) {
    case NTW_MODE_OWN: return NTW_ORDER2(NTW_PROVIDER_OWN, NTW_PROVIDER_NATIVE);
    case NTW_MODE_KERNELEX: return NTW_ORDER3(NTW_PROVIDER_KERNELEX, NTW_PROVIDER_NATIVE, NTW_PROVIDER_OWN);
    case NTW_MODE_NATIVE: return NTW_ORDER1(NTW_PROVIDER_NATIVE);
    default: break;
    }
    if (table && table->routes) {
        for (i = 0; i < table->route_count; ++i)
            if (ntw_route_name_equal(table->routes[i].name, name)) return table->routes[i].order;
    }
    return table && table->default_order ? table->default_order : NTW_ORDER_DEFAULT;
}

int ntw_route_is_stub(const struct ntw_route_table *table, const char *module, const char *name, unsigned provider) {
    unsigned i;
    if (!table || !table->stubs) return 0;
    for (i = 0; i < table->stub_count; ++i) {
        const struct ntw_stub_entry *stub = &table->stubs[i];
        if (stub->provider == provider && ntw_route_name_iequal(stub->module, module) &&
            ntw_route_name_equal(stub->name, name)) return 1;
    }
    return 0;
}

static uint32_t read32(const unsigned char *at) {
    return (uint32_t)at[0] | ((uint32_t)at[1] << 8) | ((uint32_t)at[2] << 16) | ((uint32_t)at[3] << 24);
}
static uint16_t read16(const unsigned char *at) { return (uint16_t)(at[0] | ((uint16_t)at[1] << 8)); }

int ntw_route_image_size(const unsigned char *headers, size_t available, uint32_t *size_of_image) {
    uint32_t pe_offset, size;
    if (!headers || !size_of_image || available < 64) return 0;
    if (headers[0] != 'M' || headers[1] != 'Z') return 0;
    pe_offset = read32(headers + 60);
    /* Signature (4), file header (20) and the PE32 optional header up to
     * SizeOfImage (offset 56, 4 bytes) must all lie inside the readable span. */
    if (pe_offset < 64 || pe_offset > available || available - pe_offset < 4 + 20 + 60) return 0;
    if (read32(headers + pe_offset) != UINT32_C(0x00004550)) return 0;
    if (read16(headers + pe_offset + 4) != 0x14c) return 0;
    if (read16(headers + pe_offset + 24) != 0x10b) return 0;
    size = read32(headers + pe_offset + 24 + 56);
    if (size < 0x1000 || size > UINT32_C(0x10000000)) return 0;
    *size_of_image = size;
    return 1;
}
