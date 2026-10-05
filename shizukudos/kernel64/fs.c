/* SPDX-License-Identifier: GPL-2.0-only */
#include "fs.h"
#include "fs_policy.h"

static fsnode_t root;
static uint64_t total_bytes;
static uint64_t next_node_id = 2;               /* the root is node 1 */
static fsnode_t *mounts[26];                    /* drive letters A..Z; C is the RAM root */

fsnode_t *fs_root(void) { return &root; }
uint64_t fs_total_bytes(void) { return total_bytes; }

void fs_init(void)
{
    memset(&root, 0, sizeof root);
    root.name[0] = 0;
    root.is_dir = 1;
    root.attrs = FILE_ATTRIBUTE_DIRECTORY;
    root.id = 1;
    total_bytes = 0;
    memset(mounts, 0, sizeof mounts);
    mounts['C' - 'A'] = &root;
    fs_create("\\TEMP", 1, 0);                  /* C:\TEMP: the loader exports it as %TEMP% and %TMP% */
}

static char fold(char c) { return c >= 'a' && c <= 'z' ? (char)(c - 32) : c; }

int fs_mount(char letter, fsnode_t *r)
{
    const char l = fold(letter);
    if (l < 'A' || l > 'Z' || l == 'C' || !r || !r->is_dir || mounts[l - 'A']) return -1;
    mounts[l - 'A'] = r;
    if (!r->id) r->id = next_node_id++;         /* volume roots are not made by fs_new_child */
    return 0;
}

fsnode_t *fs_root_of(char letter)
{
    const char l = fold(letter);
    return l >= 'A' && l <= 'Z' ? mounts[l - 'A'] : 0;
}

/* NT device names of the volumes: C: is \Device\HarddiskVolume1, D: 2, ... Z: 24, then A: 25 and B: 26. */
unsigned fs_volume_number(char letter)
{
    const char l = fold(letter);
    if (l < 'A' || l > 'Z') return 0;
    return l >= 'C' ? (unsigned)(l - 'B') : (unsigned)(l - 'A') + 25;
}

char fs_volume_letter(unsigned number)
{
    if (number >= 1 && number <= 24) return (char)('B' + number);
    if (number == 25 || number == 26) return (char)('A' + number - 25);
    return 0;
}

char fs_letter_of(const fsnode_t *n)
{
    unsigned i;
    if (!n) return 0;
    while (n->parent) n = n->parent;
    for (i = 0; i < 26; ++i)
        if (mounts[i] == n) return (char)('A' + i);
    return 0;
}

/* ---------------------------------------------------------------- access policy hooks (fs_policy.h) */
static fs_policy_fn policies[FS_POLICY_MAX];

int fs_policy_register(fs_policy_fn fn)
{
    unsigned i;
    if (!fn) return -1;
    for (i = 0; i < FS_POLICY_MAX; ++i) {
        if (policies[i] == fn) return 0;
        if (!policies[i]) { policies[i] = fn; return 0; }
    }
    return -1;
}

int fs_policy_denied(const fsnode_t *n, unsigned op)
{
    unsigned i;
    if (!n) return 0;
    for (i = 0; i < FS_POLICY_MAX && policies[i]; ++i)
        if (policies[i](n, op)) return 1;
    return 0;
}

void fs_populate(fsnode_t *dir)
{
    if (dir && dir->is_dir && dir->backing == FSB_DISK && !dir->populated && dir->vol && dir->vol->populate) {
        if (fs_policy_denied(dir, FS_OP_LIST)) return;     /* walled-off directory: stays unenumerated */
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
    static const char device[] = "\\Device\\HarddiskVolume";            /* + the volume number (fs_volume_number): what QueryDosDevice returns */
    size_t i;
    *drive = 0;
    if (p[0] == '\\' && p[1] == '?' && p[2] == '?' && p[3] == '\\') p += 4;
    for (i = 0; device[i]; ++i)
        if (fold(p[i]) != fold(device[i])) break;
    if (!device[i] && p[i] >= '1' && p[i] <= '9') {
        unsigned num = 0;
        while (p[i] >= '0' && p[i] <= '9' && num < 1000) num = num * 10 + (unsigned)(p[i++] - '0');
        if (p[i] == 0 || p[i] == '\\') {
            const char l = fs_volume_letter(num);
            *drive = l ? l : '#';                                           /* '#': no such volume, resolve() fails */
            return p + i;
        }
    }
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

/* Directory change notification (kernel64/ipc_notify.c; no-op when it is not linked): `n` was added (1), removed (2) or
 * modified (3); `what` holds the FILE_NOTIFY_CHANGE_* bits the change matches. */
void __attribute__((weak)) fs_notify(fsnode_t *n, uint32_t action, uint32_t what) { (void)n; (void)action; (void)what; }
#define NOTIFY_NAME(n) ((n)->is_dir ? 0x2u : 0x1u)            /* FILE_NOTIFY_CHANGE_DIR_NAME / FILE_NAME */

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
    n->readonly = dir->backing == FSB_DISK && (!dir->vol || !dir->vol->write);
    for (pp = &dir->child; *pp; pp = &(*pp)->sibling) ;   /* append: listings keep creation / on-disk order */
    *pp = n;
    n->ctime = n->mtime = ticks_now();
    n->id = next_node_id++;
    return n;
}

fsnode_t *fs_create(const char *path, int is_dir, int *created)
{
    char leaf[FS_NAME_MAX];
    fsnode_t *dir = resolve(path, 1, leaf, sizeof leaf), *n;
    if (created) *created = 0;
    if (!dir || !dir->is_dir || !leaf[0] || dir->readonly) return 0;
    if (fs_policy_denied(dir, FS_OP_CREATE)) return 0;
    n = child_named(dir, leaf, strlen(leaf));
    if (n) return n;
    if (dir->backing == FSB_DISK)                   /* on-disk directory entry first; the volume adds the node */
        n = dir->vol && dir->vol->create ? dir->vol->create(dir->vol, dir, leaf, is_dir) : 0;
    else
        n = fs_new_child(dir, leaf, is_dir);
    if (!n) return 0;
    if (created) *created = 1;
    fs_notify(n, 1, NOTIFY_NAME(n) | 0x40u);                  /* FILE_ACTION_ADDED; CREATION */
    return n;
}

int fs_read(fsnode_t *n, uint64_t off, void *buf, uint64_t len, uint64_t *done)
{
    if (n->is_dir) return -1;
    if (fs_policy_denied(n, FS_OP_READ)) { *done = 0; return -1; }
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
    if (need > (64ull << 20)) return -2; /* reject before capacity doubling can overflow */
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
    if (fs_policy_denied(n, FS_OP_WRITE)) return -1;
    if (n->backing == FSB_DISK) return n->vol && n->vol->write ? n->vol->write(n->vol, n, off, buf, len) : -1;
    rc = reserve(n, off + len);
    if (rc) return rc;
    if (off > n->size) memset(n->data + n->size, 0, off - n->size);
    memcpy(n->data + off, buf, len);
    if (off + len > n->size) n->size = off + len;
    n->mtime = ticks_now();
    n->ft_write = 0;                            /* a write supersedes an explicitly set last-write time */
    fs_notify(n, 3, 0x18u);                                    /* FILE_ACTION_MODIFIED; SIZE | LAST_WRITE */
    return 0;
}

int fs_flush(fsnode_t *n)
{
    if (n->backing != FSB_DISK) return 0;           /* heap-backed: nothing below */
    return n->vol && n->vol->flush ? n->vol->flush(n->vol) : 0;
}

int fs_truncate(fsnode_t *n, uint64_t size)
{
    int rc;
    if (n->is_dir || n->readonly) return -1;
    if (fs_policy_denied(n, FS_OP_WRITE)) return -1;
    if (n->backing == FSB_DISK) return n->vol && n->vol->truncate ? n->vol->truncate(n->vol, n, size) : -1;
    if (size > n->size) {
        rc = reserve(n, size);
        if (rc) return rc;
        memset(n->data + n->size, 0, size - n->size);
    }
    n->size = size;
    n->mtime = ticks_now();
    n->ft_write = 0;
    fs_notify(n, 3, 0x18u);
    return 0;
}

static void detach(fsnode_t *n)
{
    fsnode_t **pp;
    for (pp = &n->parent->child; *pp; pp = &(*pp)->sibling)
        if (*pp == n) { *pp = n->sibling; break; }
    n->sibling = 0;
}

/* Checked companion. Existing void callers keep their ABI. Negative volume
 * errors remain intact; -4 is a local policy/root refusal, -5 unsupported. */
int fs_remove_checked(fsnode_t *n)
{
    int rc;
    if (!n) return -4;
    if (!n->parent || n->view || fs_policy_denied(n, FS_OP_DELETE)) { n->delete_pending = 0; return -4; }
    if (n->backing == FSB_DISK) {
        /* volumes that can delete (vol->remove) do it on disk first; a refused delete keeps the node visible */
        if (!n->vol || !n->vol->remove) { n->delete_pending = 0; return -5; }
        rc=n->vol->remove(n->vol,n);
        if(rc){n->delete_pending=0;return rc;}
        detach(n);
        kfree(n);
        return 0;
    }
    fs_notify(n, 2, NOTIFY_NAME(n));                           /* FILE_ACTION_REMOVED (RAM volume; ipc_notify.c) */
    detach(n);
    if (n->data && !n->readonly) { total_bytes -= n->cap; kfree(n->data); }
    kfree(n);
    return 0;
}
void fs_remove(fsnode_t *n) { (void)fs_remove_checked(n); }

int fs_rename(fsnode_t *n, const char *newpath, int replace)
{
    char leaf[FS_NAME_MAX];
    fsnode_t *dir = resolve(newpath, 1, leaf, sizeof leaf), *dst, *a;
    int rc;
    if (n->backing != FSB_DISK || !n->vol || !n->vol->rename || !n->parent) return -1;
    if (!dir || !dir->is_dir || !leaf[0] || dir->backing != FSB_DISK || dir->vol != n->vol) return -1;
    for (a = dir; a; a = a->parent) if (a == n) return -1;          /* into its own subtree */
    if (fs_policy_denied(n, FS_OP_DELETE) || fs_policy_denied(dir, FS_OP_CREATE)) return -1;
    dst = child_named(dir, leaf, strlen(leaf));
    if (dst == n && !strcmp(n->name, leaf)) return 0;
    if (dst && dst != n && (!replace || dst->open_count)) return -3;
    rc = n->vol->rename(n->vol, n, dir, leaf, replace);
    if (rc) return rc;
    if (dst && dst != n) { detach(dst); kfree(dst); }
    detach(n);
    memcpy(n->name, leaf, strlen(leaf) + 1);
    n->parent = dir;
    {
        fsnode_t **pp;
        for (pp = &dir->child; *pp; pp = &(*pp)->sibling) ;
        *pp = n;
    }
    return 0;
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
