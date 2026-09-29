/* SPDX-License-Identifier: GPL-2.0-only */
#include "fs.h"

static fsnode_t root;
static uint64_t total_bytes;
static fsnode_t *mounts[26];                    /* drive letters A..Z; C is the RAM root */

fsnode_t *fs_root(void) { return &root; }
uint64_t fs_total_bytes(void) { return total_bytes; }

void fs_init(void)
{
    memset(&root, 0, sizeof root);
    root.name[0] = 0;
    root.is_dir = 1;
    root.attrs = FILE_ATTRIBUTE_DIRECTORY;
    total_bytes = 0;
    memset(mounts, 0, sizeof mounts);
    mounts['C' - 'A'] = &root;
}

static char fold(char c) { return c >= 'a' && c <= 'z' ? (char)(c - 32) : c; }

int fs_mount(char letter, fsnode_t *r)
{
    const char l = fold(letter);
    if (l < 'A' || l > 'Z' || l == 'C' || !r || !r->is_dir || mounts[l - 'A']) return -1;
    mounts[l - 'A'] = r;
    return 0;
}

fsnode_t *fs_root_of(char letter)
{
    const char l = fold(letter);
    return l >= 'A' && l <= 'Z' ? mounts[l - 'A'] : 0;
}

void fs_populate(fsnode_t *dir)
{
    if (dir && dir->is_dir && dir->backing == FSB_DISK && !dir->populated && dir->vol && dir->vol->populate) {
        dir->populated = 1;                     /* set first: a failed enumeration is not retried on every lookup */
        dir->vol->populate(dir->vol, dir);
    }
}

void fs_node_times(const fsnode_t *n, uint64_t *create_ft, uint64_t *write_ft)
{
    if (n->backing == FSB_DISK) {
        *create_ft = n->ftime_c ? n->ftime_c : n->ftime_m;
        *write_ft = n->ftime_m;
    } else {
        *create_ft = 132000000000000000ull + n->ctime * 10000;
        *write_ft = 132000000000000000ull + n->mtime * 10000;
    }
}

static int name_eq(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (fold(a[i]) != fold(b[i]))
            return 0;
    return a[n] == 0;
}

static fsnode_t *child_named(fsnode_t *dir, const char *name, size_t n)
{
    fsnode_t *c;
    fs_populate(dir);
    for (c = dir->child; c; c = c->sibling)
        if (!c->delete_pending && strlen(c->name) == n && name_eq(c->name, name, n))
            return c;
    return 0;
}

/* Splits "C:\a\b" / "\??\C:\a\b" / "\a\b"; returns the component start after the drive, whose letter (0 when
 * the path has none: it then means C:) goes to *drive. */
static const char *strip_prefix(const char *p, char *drive)
{
    *drive = 0;
    if (p[0] == '\\' && p[1] == '?' && p[2] == '?' && p[3] == '\\') p += 4;
    if (p[0] && p[1] == ':') { *drive = p[0]; p += 2; }
    return p;
}

static fsnode_t *resolve(const char *path, int want_parent, char *leaf, size_t leaf_cap)
{
    char drive;
    const char *p = strip_prefix(path, &drive);
    fsnode_t *cur = drive ? fs_root_of(drive) : &root;
    if (!cur) return 0;                             /* no volume mounted at that letter */
    while (*p == '\\' || *p == '/') ++p;
    while (*p) {
        const char *s = p;
        size_t n;
        while (*p && *p != '\\' && *p != '/') ++p;
        n = (size_t)(p - s);
        while (*p == '\\' || *p == '/') ++p;
        if (n == 0 || (n == 1 && s[0] == '.'))
            continue;
        if (n == 2 && s[0] == '.' && s[1] == '.') {
            if (cur->parent) cur = cur->parent;
            continue;
        }
        if (want_parent && *p == 0) {
            if (leaf) {
                if (n >= leaf_cap) return 0;
                memcpy(leaf, s, n);
                leaf[n] = 0;
            }
            return cur;
        }
        if (!cur->is_dir) return 0;
        cur = child_named(cur, s, n);
        if (!cur) return 0;
    }
    if (want_parent) {
        if (leaf) leaf[0] = 0;
        return cur;
    }
    return cur;
}

fsnode_t *fs_lookup(const char *path) { return resolve(path, 0, 0, 0); }

fsnode_t *fs_new_child(fsnode_t *dir, const char *name, int is_dir)
{
    fsnode_t *n = kzalloc(sizeof *n), **pp;
    const size_t len = strlen(name);
    if (!n || len >= FS_NAME_MAX) { kfree(n); return 0; }
    memcpy(n->name, name, len + 1);
    n->is_dir = is_dir;
    n->attrs = is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    n->parent = dir;
    n->backing = dir->backing;
    n->vol = dir->vol;
    n->readonly = dir->backing == FSB_DISK;
    for (pp = &dir->child; *pp; pp = &(*pp)->sibling) ;   /* append: listings keep creation / on-disk order */
    *pp = n;
    n->ctime = n->mtime = ticks_now();
    return n;
}

fsnode_t *fs_create(const char *path, int is_dir, int *created)
{
    char leaf[FS_NAME_MAX];
    fsnode_t *dir = resolve(path, 1, leaf, sizeof leaf), *n;
    if (created) *created = 0;
    if (!dir || !dir->is_dir || !leaf[0] || dir->readonly) return 0;
    n = child_named(dir, leaf, strlen(leaf));
    if (n) return n;
    n = fs_new_child(dir, leaf, is_dir);
    if (!n) return 0;
    if (created) *created = 1;
    return n;
}

int fs_read(fsnode_t *n, uint64_t off, void *buf, uint64_t len, uint64_t *done)
{
    if (n->is_dir) return -1;
    if (n->backing == FSB_DISK) {
        if (!n->vol || !n->vol->read) { *done = 0; return -1; }
        return n->vol->read(n->vol, n, off, buf, len, done);
    }
    if (off >= n->size) { *done = 0; return 0; }
    if (len > n->size - off) len = n->size - off;
    memcpy(buf, n->data + off, len);
    *done = len;
    return 0;
}

static int reserve(fsnode_t *n, uint64_t need)
{
    uint8_t *nd;
    uint64_t cap;
    if (n->readonly) return -1;
    if (need <= n->cap) return 0;
    cap = n->cap ? n->cap : 256;
    while (cap < need) cap *= 2;
    if (cap > (64ull << 20)) return -2;
    nd = kmalloc(cap);
    if (!nd) return -2;
    if (n->size) memcpy(nd, n->data, n->size);
    if (cap > n->size) memset(nd + n->size, 0, cap - n->size);
    if (n->data) kfree(n->data);
    total_bytes += cap - n->cap;
    n->data = nd;
    n->cap = cap;
    return 0;
}

int fs_write(fsnode_t *n, uint64_t off, const void *buf, uint64_t len)
{
    int rc;
    if (n->is_dir || n->readonly) return -1;
    if (off + len < off) return -1;
    rc = reserve(n, off + len);
    if (rc) return rc;
    if (off > n->size) memset(n->data + n->size, 0, off - n->size);
    memcpy(n->data + off, buf, len);
    if (off + len > n->size) n->size = off + len;
    n->mtime = ticks_now();
    return 0;
}

int fs_truncate(fsnode_t *n, uint64_t size)
{
    int rc;
    if (n->is_dir || n->readonly) return -1;
    if (size > n->size) {
        rc = reserve(n, size);
        if (rc) return rc;
        memset(n->data + n->size, 0, size - n->size);
    }
    n->size = size;
    return 0;
}

void fs_remove(fsnode_t *n)
{
    fsnode_t **pp;
    if (!n->parent || n->backing == FSB_DISK) return;
    for (pp = &n->parent->child; *pp; pp = &(*pp)->sibling)
        if (*pp == n) { *pp = n->sibling; break; }
    if (n->data && !n->readonly) { total_bytes -= n->cap; kfree(n->data); }
    kfree(n);
}

/* ---------------------------------------------------------------- initrd */
struct __attribute__((packed)) arc_hdr { char magic[8]; uint32_t count, reserved; };
struct __attribute__((packed)) arc_ent { char path[120]; uint64_t offset, size; };

int fs_load_archive(const uint8_t *a, uint64_t size)
{
    const struct arc_hdr *h = (const struct arc_hdr *)a;
    const struct arc_ent *e;
    uint32_t i;
    if (size < sizeof *h || memcmp(h->magic, "SHZARC01", 8)) return -1;
    if (h->count > 4096 || sizeof *h + (uint64_t)h->count * sizeof *e > size) return -1;
    e = (const struct arc_ent *)(a + sizeof *h);
    for (i = 0; i < h->count; ++i) {
        fsnode_t *n;
        char path[128];
        size_t k;
        int created;
        if (e[i].offset > size || e[i].size > size - e[i].offset) return -1;     /* overflow-safe bounds */
        for (k = 0; k < sizeof e[i].path && e[i].path[k]; ++k) path[k] = e[i].path[k];
        if (k == sizeof e[i].path) return -1;
        path[k] = 0;
        /* create parent directories */
        {
            char partial[128];
            size_t j;
            for (j = 1; j < k; ++j)
                if (path[j] == '\\') {
                    memcpy(partial, path, j);
                    partial[j] = 0;
                    if (!fs_lookup(partial) && !fs_create(partial, 1, &created)) return -1;
                }
        }
        n = fs_create(path, 0, &created);
        if (!n) return -1;
        n->data = (uint8_t *)a + e[i].offset;                                     /* zero-copy: points into the initrd */
        n->size = n->cap = e[i].size;
        n->readonly = 1;
        n->attrs = FILE_ATTRIBUTE_READONLY;
    }
    return (int)h->count;
}

int utf16_to_utf8(const uint16_t *src, uint64_t chars, char *dst, uint64_t cap)
{
    uint64_t i, o = 0;
    for (i = 0; i < chars; ++i) {
        uint32_t c = src[i];
        if (c >= 0xd800 && c < 0xdc00 && i + 1 < chars && src[i + 1] >= 0xdc00 && src[i + 1] < 0xe000)
            c = 0x10000 + ((c - 0xd800) << 10) + (src[++i] - 0xdc00);
        if (c < 0x80) { if (o + 1 >= cap) return -1; dst[o++] = (char)c; }
        else if (c < 0x800) { if (o + 2 >= cap) return -1; dst[o++] = (char)(0xc0 | (c >> 6)); dst[o++] = (char)(0x80 | (c & 63)); }
        else if (c < 0x10000) { if (o + 3 >= cap) return -1; dst[o++] = (char)(0xe0 | (c >> 12)); dst[o++] = (char)(0x80 | ((c >> 6) & 63)); dst[o++] = (char)(0x80 | (c & 63)); }
        else { if (o + 4 >= cap) return -1; dst[o++] = (char)(0xf0 | (c >> 18)); dst[o++] = (char)(0x80 | ((c >> 12) & 63)); dst[o++] = (char)(0x80 | ((c >> 6) & 63)); dst[o++] = (char)(0x80 | (c & 63)); }
    }
    dst[o] = 0;
    return (int)o;
}

int utf8_to_utf16(const char *src, uint16_t *dst, uint64_t cap_chars)
{
    uint64_t o = 0;
    const uint8_t *s = (const uint8_t *)src;
    while (*s) {
        uint32_t c;
        unsigned extra;
        if (*s < 0x80) { c = *s++; extra = 0; }
        else if ((*s & 0xe0) == 0xc0) { c = *s++ & 0x1f; extra = 1; }
        else if ((*s & 0xf0) == 0xe0) { c = *s++ & 0x0f; extra = 2; }
        else if ((*s & 0xf8) == 0xf0) { c = *s++ & 0x07; extra = 3; }
        else { c = '?'; ++s; extra = 0; }
        while (extra--) {
            if ((*s & 0xc0) != 0x80) { c = '?'; break; }
            c = (c << 6) | (*s++ & 0x3f);
        }
        if (c >= 0x10000) {
            if (o + 2 >= cap_chars) return -1;
            c -= 0x10000;
            dst[o++] = (uint16_t)(0xd800 + (c >> 10));
            dst[o++] = (uint16_t)(0xdc00 + (c & 0x3ff));
        } else {
            if (o + 1 >= cap_chars) return -1;
            dst[o++] = (uint16_t)c;
        }
    }
    dst[o] = 0;
    return (int)o;
}
