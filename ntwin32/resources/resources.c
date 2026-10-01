/* SPDX-License-Identifier: GPL-2.0-only
 * Independently authored immutable PE32 resource prerequisite. Public layout:
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
 * Handle/API contracts:
 * https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-findresourceexw
 * https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource
 * https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-sizeofresource
 * No host structs overlay untrusted bytes; no allocator, OS, CRT or module DB.
 */
#include "resources.h"

static int bad(const char **error, const char *why)
{ if (error) *error = why; return 0; }
static void zero(void *v, uint32_t n)
{ uint8_t *p = v; while (n--) *p++ = 0; }
static int fits(uint32_t at, uint32_t n, uint32_t limit)
{ return at <= limit && n <= limit - at; }
static int overlap(const void *a, uintptr_t an, const void *b, uintptr_t bn)
{
    uintptr_t av = (uintptr_t)a, bv = (uintptr_t)b;
    if (!a || !b || !an || !bn) return 0;
    if (av > UINTPTR_MAX - an || bv > UINTPTR_MAX - bn) return 1;
    return av >= bv ? av - bv < bn : bv - av < an;
}
static int image_alias(const np_image *p, const void *q, uintptr_t n)
{
    return p && (overlap(q, n, p, sizeof(*p)) ||
                 overlap(q, n, p->file, p->bytes));
}
static int owner_alias(const nr_resources *s, const void *q, uintptr_t n)
{
    return s && (overlap(q, n, s, sizeof(*s)) ||
                 overlap(q, n, s->image.file, s->image.bytes));
}
static int key_alias(const nr_key *k, const void *q, uintptr_t n)
{
    uintptr_t bytes;
    if (!k) return 0;
    if (overlap(q, n, k, sizeof(*k))) return 1;
    if (k->kind != NR_KEY_NAME) return 0;
    bytes = k->units;
    if (bytes > UINTPTR_MAX/2u) return 1;
    return overlap(q, n, k->utf16, bytes*2u);
}
static int valid(const nr_resources *s)
{
    return s && s->self == s && s->count <= NR_LEAVES &&
        s->regions <= NR_REGIONS && s->image.file && s->image.bytes;
}
static int key_valid(const nr_key *k)
{
    return k && ((k->kind == NR_KEY_ID && k->id <= 0x7fffffffu &&
                  !k->units && !k->utf16) ||
        (k->kind == NR_KEY_NAME && !k->id && k->units <= 65535u &&
         (k->utf16 || !k->units) &&
         (!k->units || (uintptr_t)k->utf16 <= UINTPTR_MAX-k->units*2u)));
}
static int compare(const nr_key *a, const nr_key *b)
{
    uint32_t i, n;
    if (a->kind != b->kind) return a->kind == NR_KEY_NAME ? -1 : 1;
    if (a->kind == NR_KEY_ID) return a->id < b->id ? -1 : a->id != b->id;
    n = a->units < b->units ? a->units : b->units;
    for (i = 0; i < n; i++) {
        uint16_t av = np_u16(a->utf16+i*2u), bv = np_u16(b->utf16+i*2u);
        if (av != bv) return av < bv ? -1 : 1;
    }
    return a->units < b->units ? -1 : a->units != b->units;
}
static const uint8_t *metadata(nr_resources *s, uint32_t at, uint32_t n)
{
    if (!fits(at, n, s->directory_bytes) ||
        at > 0xffffffffu-s->directory_rva) return 0;
    return np_raw(&s->image, s->directory_rva+at, n);
}
static int claim(nr_resources *s, uint32_t at, uint32_t n, const char **error)
{
    uint32_t i;
    if (!metadata(s, at, n)) return bad(error, "NR_METADATA_BOUNDS");
    for (i = 0; i < s->regions; i++) {
        nr_region *r = &s->region[i];
        if (at >= r->offset ? at-r->offset < r->bytes : r->offset-at < n)
            return bad(error, "NR_METADATA_ALIAS_UNSUPPORTED");
    }
    if (s->regions == NR_REGIONS) return bad(error, "NR_REGION_WORK_LIMIT");
    s->region[s->regions].offset = at;
    s->region[s->regions++].bytes = n;
    return 1;
}
static int key_read(nr_resources *s, uint32_t value, int named,
                    nr_key *key, const char **error)
{
    const uint8_t *q;
    uint32_t at, units;
    zero(key, sizeof(*key));
    if (!!(value & 0x80000000u) != named)
        return bad(error, "NR_ENTRY_KEY_KIND");
    if (!named) { key->id = value; return 1; }
    at = value & 0x7fffffffu;
    if (at & 1u) return bad(error, "NR_NAME_ALIGNMENT");
    q = metadata(s, at, 2);
    if (!q) return bad(error, "NR_NAME_BOUNDS");
    units = np_u16(q);
    if (units > NR_NAME_WORK-s->name_work)
        return bad(error, "NR_NAME_WORK_LIMIT");
    if (!claim(s, at, 2u+units*2u, error)) return 0;
    s->name_work += units;
    key->kind = NR_KEY_NAME; key->units = units; key->utf16 = q+2;
    return 1;
}
static int walk(nr_resources *s, uint32_t at, unsigned depth,
                const nr_key *type, const nr_key *name, const char **error)
{
    const uint8_t *d;
    uint32_t names, ids, count, i, ancestor;
    nr_key previous;
    if (at & 3u) return bad(error, "NR_DIRECTORY_ALIGNMENT");
    for (i = 0; i < s->regions; i++) {
        nr_region *r = &s->region[i];
        if (at >= r->offset ? at-r->offset < r->bytes : r->offset-at < 16u)
            return bad(error, "NR_METADATA_ALIAS_UNSUPPORTED");
    }
    d = metadata(s, at, 16);
    if (!d) return bad(error, "NR_DIRECTORY_BOUNDS");
    if (np_u32(d)) return bad(error, "NR_CHARACTERISTICS_UNSUPPORTED");
    names = np_u16(d+12); ids = np_u16(d+14); count = names+ids;
    if (count > NR_REGIONS || !claim(s, at, 16u+count*8u, error))
        return count > NR_REGIONS ? bad(error, "NR_ENTRY_WORK_LIMIT") : 0;
    zero(&previous, sizeof(previous));
    for (i = 0; i < count; i++) {
        const uint8_t *entry = d+16+i*8u;
        uint32_t target = np_u32(entry+4), offset = target & 0x7fffffffu;
        nr_key key;
        if (!key_read(s, np_u32(entry), i < names, &key, error)) return 0;
        if (i && compare(&previous, &key) >= 0)
            return bad(error, "NR_KEY_ORDER_OR_DUPLICATE");
        previous = key;
        if (depth < 2) {
            if (!(target & 0x80000000u))
                return bad(error, "NR_LEVEL_PROFILE_UNSUPPORTED");
            /* Ancestor/shared table aliases are refused before another read. */
            for (ancestor = 0; ancestor < s->regions; ancestor++)
                if (s->region[ancestor].offset == offset)
                    return bad(error, "NR_METADATA_ALIAS_UNSUPPORTED");
            if (!walk(s, offset, depth+1, depth ? type : &key,
                      depth ? &key : name, error)) return 0;
        } else {
            nr_leaf *leaf;
            const uint8_t *record, *payload;
            uint32_t rva, bytes;
            if (target & 0x80000000u)
                return bad(error, "NR_LEVEL_PROFILE_UNSUPPORTED");
            if (key.kind != NR_KEY_ID || key.id > 65535u)
                return bad(error, "NR_LANGUAGE_PROFILE_UNSUPPORTED");
            if (offset & 3u) return bad(error, "NR_DATA_ENTRY_ALIGNMENT");
            if (!claim(s, offset, 16, error)) return 0;
            record = metadata(s, offset, 16);
            rva = np_u32(record); bytes = np_u32(record+4);
            if (np_u32(record+12)) return bad(error, "NR_DATA_RESERVED_UNSUPPORTED");
            if (!fits(rva, bytes, s->image.size))
                return bad(error, "NR_PAYLOAD_RVA_OVERFLOW_OR_BOUNDS");
            payload = np_raw(&s->image, rva, bytes);
            if (!payload)
                return bad(error, "NR_PAYLOAD_RAW_BACKING");
            if (s->count == NR_LEAVES) return bad(error, "NR_LEAF_WORK_LIMIT");
            leaf = &s->leaf[s->count++];
            leaf->type = *type; leaf->name = *name;
            leaf->entry_offset = offset; leaf->data_rva = rva;
            leaf->bytes = bytes; leaf->codepage = np_u32(record+8);
            leaf->language = (uint16_t)key.id;
        }
    }
    return 1;
}
int nr_parse(const np_image *p, nr_resources *out, const char **error)
{
    if (error && (image_alias(p, error, sizeof(*error)) ||
                  overlap(error, sizeof(*error), out, sizeof(*out)))) return 0;
    if (error) *error = 0;
    if (!out) return bad(error, "NR_OUTPUT_NULL");
    if (image_alias(p, out, sizeof(*out))) return bad(error, "NR_OUTPUT_ALIASES_INPUT");
    zero(out, sizeof(*out));
    if (!p || !p->file || !p->bytes || p->sections > NP_SECTIONS)
        return bad(error, "NR_IMAGE_NULL_OR_UNPARSED");
    out->image = *p;
    out->directory_rva = p->directory[2][0];
    out->directory_bytes = p->directory[2][1];
    if (!!out->directory_rva != !!out->directory_bytes) {
        zero(out, sizeof(*out)); return bad(error, "NR_DIRECTORY_PAIR");
    }
    if (out->directory_rva) {
        if (!np_raw(p, out->directory_rva, out->directory_bytes) ||
            !walk(out, 0, 0, 0, 0, error)) {
            if (error && !*error) *error = "NR_DIRECTORY_RAW_BACKING";
            zero(out, sizeof(*out)); return 0;
        }
        out->present = 1;
    }
    out->self = out;
    return 1;
}
int nr_lookup(const nr_resources *s, const nr_key *type, const nr_key *name,
              uint16_t language, nr_handle *out, const char **error)
{
    uint32_t i;
    if (error && (owner_alias(s, error, sizeof(*error)) ||
        key_alias(type, error, sizeof(*error)) || key_alias(name, error, sizeof(*error)) ||
        overlap(error, sizeof(*error), out, sizeof(*out)))) return 0;
    if (error) *error = 0;
    if (!out) return bad(error, "NR_OUTPUT_NULL");
    if (owner_alias(s, out, sizeof(*out)) || key_alias(type, out, sizeof(*out)) ||
        key_alias(name, out, sizeof(*out))) return bad(error, "NR_OUTPUT_ALIASES_INPUT");
    *out = 0;
    if (!valid(s)) return bad(error, "NR_OWNER_INVALID");
    if (!key_valid(type) || !key_valid(name)) return bad(error, "NR_QUERY_KEY_INVALID");
    for (i = 0; i < s->count; i++) {
        const nr_leaf *leaf = &s->leaf[i];
        if (leaf->language == language && !compare(&leaf->type, type) &&
            !compare(&leaf->name, name)) { *out = leaf; return 1; }
    }
    return bad(error, "NR_NOT_FOUND");
}
static const nr_leaf *owned(const nr_resources *s, nr_handle handle)
{
    uint32_t i;
    if (!valid(s)) return 0;
    for (i = 0; i < s->count; i++) if (handle == &s->leaf[i]) return &s->leaf[i];
    return 0;
}
int nr_load(const nr_resources *s, nr_handle handle, nr_data *out, const char **error)
{
    const nr_leaf *leaf;
    const uint8_t *raw;
    if (error && (owner_alias(s, error, sizeof(*error)) ||
        overlap(error, sizeof(*error), out, sizeof(*out)))) return 0;
    if (error) *error = 0;
    if (!out) return bad(error, "NR_OUTPUT_NULL");
    if (owner_alias(s, out, sizeof(*out))) return bad(error, "NR_OUTPUT_ALIASES_INPUT");
    zero(out, sizeof(*out));
    leaf = owned(s, handle);
    if (!leaf) return bad(error, "NR_HANDLE_NOT_OWNED");
    raw = np_raw(&s->image, leaf->data_rva, leaf->bytes);
    if (!raw) return bad(error, "NR_PAYLOAD_RAW_BACKING");
    out->data = raw; out->bytes = leaf->bytes; out->rva = leaf->data_rva;
    out->codepage = leaf->codepage; out->language = leaf->language;
    return 1;
}
int nr_sizeof(const nr_resources *s, nr_handle handle, uint32_t *out, const char **error)
{
    const nr_leaf *leaf;
    if (error && (owner_alias(s, error, sizeof(*error)) ||
        overlap(error, sizeof(*error), out, sizeof(*out)))) return 0;
    if (error) *error = 0;
    if (!out) return bad(error, "NR_OUTPUT_NULL");
    if (owner_alias(s, out, sizeof(*out))) return bad(error, "NR_OUTPUT_ALIASES_INPUT");
    *out = 0;
    leaf = owned(s, handle);
    if (!leaf) return bad(error, "NR_HANDLE_NOT_OWNED");
    *out = leaf->bytes;
    return 1;
}
