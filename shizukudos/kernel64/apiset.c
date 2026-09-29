/* SPDX-License-Identifier: GPL-2.0-only
 * API-set contract resolution (see apiset.h). Pure functions over the generated table, no allocation, no libc:
 * the same object code semantics in Kernel64 and in the host tests.
 */
#include "apiset.h"
#include "apiset_table.h"

#define APISET_NAME_MAX 128

static char lc(char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; }
static int is_digit(char c) { return c >= '0' && c <= '9'; }

static int cmp(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (unsigned char)*a - (unsigned char)*b;
}

unsigned apiset_count(void) { return APISET_TABLE_COUNT; }
const apiset_entry_t *apiset_entry(unsigned index) { return index < APISET_TABLE_COUNT ? &apiset_table[index] : 0; }

/* Reads a decimal number of at most 5 digits ending at `end` (exclusive), walking backwards; returns its start. */
static long number_before(const char *s, long end, unsigned *value)
{
    long i = end;
    unsigned v = 0, scale = 1, digits = 0;
    while (i > 0 && is_digit(s[i - 1]) && digits < 5) {
        --i;
        v += (unsigned)(s[i] - '0') * scale;
        scale *= 10;
        ++digits;
    }
    if (!digits || (i > 0 && is_digit(s[i - 1]))) return -1;
    *value = v;
    return i;
}

int apiset_parse_name(const char *name, char *contract, size_t cap, unsigned *major, unsigned *minor)
{
    char buf[APISET_NAME_MAX];
    long n = 0, p, lpos;
    unsigned level;
    if (!name) return -1;
    while (name[n]) {
        if (n + 1 >= (long)sizeof buf) return -1;
        buf[n] = lc(name[n]);
        ++n;
    }
    buf[n] = 0;
    if (n > 4 && buf[n - 4] == '.' && buf[n - 3] == 'd' && buf[n - 2] == 'l' && buf[n - 1] == 'l') buf[n -= 4] = 0;
    /* ...-l<level>-<major>-<minor> */
    p = number_before(buf, n, minor);
    if (p < 2 || buf[p - 1] != '-') return -1;
    p = number_before(buf, p - 1, major);
    if (p < 2 || buf[p - 1] != '-') return -1;
    lpos = number_before(buf, p - 1, &level);
    if (lpos < 7 || buf[lpos - 1] != 'l' || buf[lpos - 2] != '-') return -1;    /* at least "api-x-l" before the level */
    (void)level;
    if (p - 1 >= (long)cap) return -1;
    {
        long i;
        for (i = 0; i < p - 1; ++i) contract[i] = buf[i];
        contract[p - 1] = 0;
    }
    return 0;
}

int apiset_lookup(const char *name, const apiset_entry_t **entry)
{
    char contract[APISET_NAME_MAX];
    unsigned major, minor;
    long lo = 0, hi = (long)APISET_TABLE_COUNT - 1, found = -1;
    const apiset_entry_t *best;
    if (entry) *entry = 0;
    if (!name) return APISET_NOT_APISET;
    if (!((lc(name[0]) == 'a' && lc(name[1]) == 'p' && lc(name[2]) == 'i' && name[3] == '-') ||
          (lc(name[0]) == 'e' && lc(name[1]) == 'x' && lc(name[2]) == 't' && name[3] == '-')))
        return APISET_NOT_APISET;
    if (apiset_parse_name(name, contract, sizeof contract, &major, &minor)) return APISET_BAD_NAME;
    /* rows are sorted by (contract, major, minor): find any row of the contract, then its last (highest) row */
    while (lo <= hi) {
        const long mid = lo + (hi - lo) / 2;
        const int c = cmp(contract, apiset_table[mid].contract);
        if (c < 0) hi = mid - 1;
        else if (c > 0) lo = mid + 1;
        else { found = mid; break; }
    }
    if (found < 0) return APISET_UNKNOWN;
    while (found + 1 < (long)APISET_TABLE_COUNT && !cmp(apiset_table[found + 1].contract, contract)) ++found;
    best = &apiset_table[found];
    if (entry) *entry = best;
    if (best->major < major || (best->major == major && best->minor < minor)) return APISET_VERSION;
    return APISET_OK;
}
