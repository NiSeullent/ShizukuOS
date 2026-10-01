/* SPDX-License-Identifier: GPL-2.0-only */
#include "interactive_choice.h"
#include <string.h>

static int eligible(const plat_disk_t *d)
{
    size_t i;
    if (!d || d->sector_size != 512 || d->sectors < 256ull * 2048 || d->sectors > UINT64_MAX / 512 ||
        d->flags & (PLAT_DISK_PARTITION | PLAT_DISK_READONLY)) return 0;
    for (i = 0; i < sizeof d->name; ++i) {
        const unsigned char c = (unsigned char)d->name[i];
        if (!c) return i != 0;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
            return 0;
    }
    return 0;
}

static int same_name(const char *a, const char *b, size_t capacity)
{
    size_t i;
    for (i = 0; i < capacity; ++i) {
        unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'A' && x <= 'Z') x = (unsigned char)(x + 'a' - 'A');
        if (y >= 'A' && y <= 'Z') y = (unsigned char)(y + 'a' - 'A');
        if (x != y) return 0;
        if (!x) return 1;
    }
    return 0;
}

int setup_review_target(const plat_t *p, unsigned index, plat_disk_t *target)
{
    plat_disk_t candidate, other;
    unsigned i, n;
    if (!p || !p->disk_count || !p->disk_info || !target) return -1;
    n = p->disk_count(p->ctx);
    if (index >= n || p->disk_info(p->ctx, index, &candidate) || !eligible(&candidate)) return -1;
    /* Refuse duplicate names and confusing case variants, even when the other
     * occurrence is a partition or a read-only device. */
    for (i = 0; i < n; ++i) {
        if (i == index) continue;
        if (p->disk_info(p->ctx, i, &other) || same_name(candidate.name, other.name, sizeof candidate.name)) return -1;
    }
    *target = candidate;
    return 0;
}

int setup_build_interactive_answer(const plat_disk_t *d, const char *confirmation,
                                   int reserve_win98, char *answer, size_t capacity)
{
    static const char first[] = "[Setup]\nSchema=1\nConfirm=ERASE-TARGET\nReboot=none\n[Target]\nSelect=name\nName=";
    static const char middle[] = "\nAllowNonEmpty=yes\n[Layout]\nSystemMiB=0\n";
    static const char last[] = "BiosBootCode=yes\n[System]\nHostname=SHIZUKUOS\n[Drivers]\nInstall=all\n";
    const char *win98 = reserve_win98 ? "Win98MiB=512\nWin98HybridMBR=yes\n" : "Win98MiB=0\nWin98HybridMBR=no\n";
    char result[512];
    size_t n = 0, name_len, len;
    if (!eligible(d) || !confirmation || strcmp(confirmation, "ERASE") || !answer ||
        (reserve_win98 && d->sectors < 768ull * 2048)) return -1;
    name_len = strlen(d->name);
    memcpy(result + n, first, sizeof first - 1); n += sizeof first - 1;
    memcpy(result + n, d->name, name_len); n += name_len;
    memcpy(result + n, middle, sizeof middle - 1); n += sizeof middle - 1;
    len = strlen(win98); memcpy(result + n, win98, len); n += len;
    memcpy(result + n, last, sizeof last); n += sizeof last;
    if (n > capacity) return -1;
    memcpy(answer, result, n);
    return 0;
}
