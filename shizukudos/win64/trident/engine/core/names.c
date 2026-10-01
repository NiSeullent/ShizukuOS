/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - known HTML element and attribute names (see names.h).
 */
#include "names.h"

static const struct { const char *name; unsigned flags; } tag_table[SHZ_TAG__COUNT] = {
    { "", 0 },
#define SHZ_X_(e, s, f) { s, f },
    SHZ_TAG_LIST(SHZ_X_)
#undef SHZ_X_
};

static const char *const attr_table[SHZ_ATTR__COUNT] = {
    "",
#define SHZ_X_(e, s) s,
    SHZ_ATTR_LIST(SHZ_X_)
#undef SHZ_X_
};

/* compare the UTF-16 name[0..n) (optionally folded) with an ASCII table entry */
static int cmp_name(const shz_char *name, size_t n, const char *entry, int ci)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        shz_char c = ci ? shz_lower(name[i]) : name[i];
        unsigned char e = (unsigned char)entry[i];
        if (!e) return 1;                    /* name is longer */
        if (c != e) return c < e ? -1 : 1;
    }
    return entry[n] ? -1 : 0;
}

static int lookup(const shz_char *name, size_t n, int ci, int count, const char *(*get)(int))
{
    int lo = 1, hi = count - 1;
    if (!n) return 0;
    while (lo <= hi) {
        int mid = (lo + hi) / 2, c = cmp_name(name, n, get(mid), ci);
        if (!c) return mid;
        if (c < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    return 0;
}

const char *shz_tag_name(int tag)
{
    return tag > 0 && tag < SHZ_TAG__COUNT ? tag_table[tag].name : "";
}

unsigned shz_tag_flags(int tag)
{
    return tag > 0 && tag < SHZ_TAG__COUNT ? tag_table[tag].flags : 0;
}

const char *shz_attr_name(int attr)
{
    return attr > 0 && attr < SHZ_ATTR__COUNT ? attr_table[attr] : "";
}

int shz_tag_lookup(const shz_char *name, size_t n)
{
    return lookup(name, n, 0, SHZ_TAG__COUNT, shz_tag_name);
}

int shz_tag_lookup_ci(const shz_char *name, size_t n)
{
    return lookup(name, n, 1, SHZ_TAG__COUNT, shz_tag_name);
}

int shz_attr_lookup(const shz_char *name, size_t n)
{
    return lookup(name, n, 0, SHZ_ATTR__COUNT, shz_attr_name);
}

int shz_attr_lookup_ci(const shz_char *name, size_t n)
{
    return lookup(name, n, 1, SHZ_ATTR__COUNT, shz_attr_name);
}

static int ascii_less(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (unsigned char)*a < (unsigned char)*b;
}

int shz_names_sorted(void)
{
    int i;
    for (i = 2; i < SHZ_TAG__COUNT; ++i)
        if (!ascii_less(tag_table[i - 1].name, tag_table[i].name)) return 0;
    for (i = 2; i < SHZ_ATTR__COUNT; ++i)
        if (!ascii_less(attr_table[i - 1], attr_table[i])) return 0;
    return 1;
}
