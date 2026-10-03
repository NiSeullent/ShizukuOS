/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit private native-volume installer. All source hashes and relocation
 * preflight precede target writes. No guest device authority is fabricated. */
#include "native_install.h"
#include "gpt.h"
#include "textparse.h"
#include <string.h>
/* Single-TU build of the reviewed SZOU leaf modules and the existing accounts
 * SHA-256 core: SHZSETUP (win64/build.py setup glob of *.c) and every existing
 * host link set that names native_install.c receive exactly one copy without
 * changing their file lists. native_runtime_sha.c no longer duplicates it. */
#include "../../accounts/sha256.c"
#include "native_install/szou_manifest.c"
#include "native_install/szou_stage.c"
#include "native_install/szou_fat32.c"

#define SECTOR 512u
#define BLOCK 4096u
#define IO_BYTES (64u * 1024u)
#define MAX_CHUNKS 262144u
#define MAX_NODES 8192u
#define MIB (1024ull * 1024ull)

typedef struct chunk { uint64_t first, count, data; } chunk_t;
typedef struct member { uint64_t bytes; uint8_t sha[32]; } member_t;
typedef struct native_context {
    const plat_t *p;
    const native_setup_ops_v1_t *ops;
    const native_setup_request_v1_t *request;
    native_setup_result_v1_t *result;
    void *source[3], *claim;   /* [0] manifest, [1] SIM, [2] explicit SZOU phase only */
    uint64_t source_bytes[3], image_bytes, first, last;
    native_setup_target_v1_t target;
    native_setup_overlay_v1_t overlays[2], frozen[2];
    int plan_ready, admitted[3];
    uint8_t *buffer, *scratch;
    char *manifest;
    json_t json;
    chunk_t *chunks;
    uint32_t nchunks, reserved, fat_sectors, spc, root_cluster, clusters;
    uint64_t first_data, backup_offset, fsinfo_offset, backup_fsinfo_offset;
    member_t members[8];
    unsigned seen_files, seen_dirs, directory_work;
    const native_setup_szou_ops_v1_t *szou_ops;
    const native_setup_szou_request_v1_t *szou_request;
    native_setup_szou_result_v1_t *szou;
    szou_header_t szou_header;
    szou_entry_t *szou_entries;
    uint32_t *szou_order;
    szou_name_t *szou_names;      /* v2 SZLN records (NULL for v1) */
    uint32_t szou_name_count;
    uint8_t *szou_table;
    uint64_t szou_pin_bytes;
    uint8_t szou_pin[32];
} native_context_t;

static const char *const names[8] = {
    "EFI/BOOT/BOOTX64.EFI", "EFI/SHIZUKU/BOOT.INI", "SHZDOS/KERNEL32.BIN",
    "SHZDOS/KERNEL64.BIN", "SHZDOS/WIN64.IMG", "SHZDOS/DISK.IMG",
    "SHZDOS/SEABIOS.BIN", "SHZDOS/WIN98CFG.BIN"
};
static const char *const dirs[4] = {"EFI", "EFI/BOOT", "EFI/SHIZUKU", "SHZDOS"};
static const char boot_policy[] = "mode=supervisor\r\nmenu_timeout=0\r\n";

static uint16_t u16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1] << 8); }
static uint32_t u32(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t u64(const uint8_t *p) { return u32(p) | (uint64_t)u32(p + 4) << 32; }
static void put32(uint8_t *p, uint32_t n) { unsigned i; for (i = 0; i < 4; ++i) p[i] = (uint8_t)(n >> (8 * i)); }

static void copy_string(char *out, size_t cap, const char *s)
{
    size_t i = 0;
    if (!cap) return;
    while (s && s[i] && i + 1 < cap) { out[i] = s[i]; ++i; }
    out[i] = 0;
}

static int fail(native_context_t *c, const char *reason)
{
    if (!c->result->reason[0]) copy_string(c->result->reason, sizeof c->result->reason, reason);
    return -1;
}

static int nonzero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) if (p[i]) return 1;
    return 0;
}

static int bounded_text(const char *s, size_t maximum)
{
    size_t i;
    if (!s || !*s) return 0;
    for (i = 0; i <= maximum; ++i) {
        unsigned char ch = (unsigned char)s[i];
        if (!ch) return 1;
        if (ch < 32 || ch > 126) return 0;
    }
    return 0;
}

static int hex_sha(const char *s, uint8_t out[32])
{
    unsigned i;
    if (!s || strlen(s) != 64) return -1;
    for (i = 0; i < 32; ++i) {
        unsigned a, b;
        char x = s[2 * i], y = s[2 * i + 1];
        if (x >= '0' && x <= '9') a = (unsigned)(x - '0');
        else if (x >= 'a' && x <= 'f') a = (unsigned)(x - 'a' + 10);
        else return -1;
        if (y >= '0' && y <= '9') b = (unsigned)(y - '0');
        else if (y >= 'a' && y <= 'f') b = (unsigned)(y - 'a' + 10);
        else return -1;
        out[i] = (uint8_t)(a * 16 + b);
    }
    return nonzero(out, 32) ? 0 : -1;
}

static int disk_equal(const plat_disk_t *a, const plat_disk_t *b)
{
    return !strcmp(a->name, b->name) && !strcmp(a->serial, b->serial) &&
           a->sectors == b->sectors && a->sector_size == b->sector_size && a->flags == b->flags;
}

static int target_equal(const native_setup_target_v1_t *a, const native_setup_target_v1_t *b)
{
    return a->index == b->index && disk_equal(&a->disk, &b->disk) &&
           a->generation == b->generation && !memcmp(a->whole_id, b->whole_id, 16);
}

static int valid_disk(const plat_disk_t *d)
{
    return bounded_text(d->name, sizeof d->name - 1) && bounded_text(d->serial, sizeof d->serial - 1) &&
           d->sectors && d->sectors <= UINT64_MAX / SECTOR && d->sector_size == SECTOR &&
           !(d->flags & (PLAT_DISK_PARTITION | PLAT_DISK_READONLY)) &&
           !(d->flags & ~(PLAT_DISK_PARTITION | PLAT_DISK_READONLY | PLAT_DISK_REMOVABLE));
}

static int guard(native_context_t *c)
{
    unsigned i;
    for (i = 0; i < 3; ++i)
        if (c->source[i] && c->admitted[i] && c->ops->check_source(c->ops->ctx, c->source[i]))
            return fail(c, "native input identity, namespace or read custody changed");
    if (c->plan_ready && memcmp(c->overlays, c->frozen, sizeof c->frozen))
        return fail(c, "immutable native relocation plan changed");
    if (c->claim) {
        plat_disk_t d;
        memset(&d, 0, sizeof d);
        if (c->ops->check_target(c->ops->ctx, c->claim, &c->target) ||
            c->p->disk_info(c->p->ctx, c->target.index, &d) || !valid_disk(&d) || !disk_equal(&d, &c->target.disk))
            return fail(c, "native target claim, exclusion or reviewed identity changed");
    }
    return 0;
}

static int read_source(native_context_t *c, unsigned i, uint64_t off, void *p, uint32_t n)
{
    if (i >= 3 || !c->source[i] || off > c->source_bytes[i] || n > c->source_bytes[i] - off)
        return fail(c, "native source extent differs");
    if (guard(c) || c->p->file_read(c->p->ctx, c->source[i], off, p, n) || guard(c))
        return fail(c, "native source exact read failed");
    return 0;
}

static int hash_source(native_context_t *c, unsigned i, uint8_t out[32])
{
    uint64_t off = 0;
    void *h = c->ops->sha_begin(c->ops->ctx);
    if (!h) return fail(c, "native SHA begin failed");
    while (off < c->source_bytes[i]) {
        uint32_t n = c->source_bytes[i] - off < IO_BYTES ? (uint32_t)(c->source_bytes[i] - off) : IO_BYTES;
        if (read_source(c, i, off, c->buffer, n) || c->ops->sha_update(c->ops->ctx, h, c->buffer, n)) {
            c->ops->sha_abort(c->ops->ctx, h);
            return fail(c, "native full source SHA failed");
        }
        off += n;
    }
    if (c->ops->sha_end(c->ops->ctx, h, out) || guard(c)) return fail(c, "native SHA finalization failed");
    return 0;
}

static int fields(const jnode_t *o, const char *const *allowed, unsigned n)
{
    const jnode_t *p;
    unsigned count = 0, i;
    if (!o || o->type != J_OBJ) return -1;
    for (p = o->kid; p; p = p->next) {
        for (i = 0; i < n && strcmp(p->key, allowed[i]); ++i) {}
        if (i == n || ++count > n) return -1;
    }
    return count == n ? 0 : -1;
}

static int tree(const jnode_t *o, unsigned depth, unsigned *work)
{
    const jnode_t *a, *b;
    unsigned children = 0;
    if (!o || depth > 16 || ++*work > MAX_NODES) return -1;
    for (a = o->kid; a; a = a->next) {
        if (++children > 64 || (o->type == J_OBJ && !bounded_text(a->key, 128))) return -1;
        if (o->type == J_OBJ)
            for (b = a->next; b; b = b->next) if (!strcmp(a->key, b->key)) return -1;
        if (tree(a, depth + 1, work)) return -1;
    }
    return 0;
}

static int is_string(const jnode_t *o, const char *key, const char *expected)
{
    const char *s = json_str(o, key);
    return s && !strcmp(s, expected);
}
static int is_type(const jnode_t *o, const char *key, int type)
{
    const jnode_t *v = json_get(o, key);
    return v && v->type == type;
}

static int file_pin(const jnode_t *v, uint64_t *bytes, uint8_t sha[32])
{
    static const char *const keys[] = {"path", "bytes", "sha256"};
    return fields(v, keys, 3) || !bounded_text(json_str(v, "path"), 4095) ||
           json_u64(v, "bytes", bytes) || !*bytes || *bytes > NATIVE_SETUP_IMAGE_MAX || hex_sha(json_str(v, "sha256"), sha);
}

static int member_pin(const jnode_t *v, member_t *m)
{
    static const char *const keys[] = {"bytes", "sha256"};
    return fields(v, keys, 2) || json_u64(v, "bytes", &m->bytes) || !m->bytes ||
           m->bytes > NATIVE_SETUP_IMAGE_MAX || hex_sha(json_str(v, "sha256"), m->sha);
}

static int manifest(native_context_t *c, uint8_t sim_sha[32])
{
    static const char *const top[] = {"schema", "status", "private", "public_artifact", "redistribution",
        "boot_profile", "source_request", "lineage", "esp_sim", "ESP_geometry", "first_lba",
        "input_linux_read_leases", "inputs_before_after_full_SHA_match", "independent_expanded_ESP_readback",
        "compiler_tool_closure_verified", "VM_executed", "Windows98_boot_verified", "installer_executed",
        "installer_target_written", "coldboot_persistence_verified", "MSDOS_replacement_under_Windows98",
        "native_apps_verified", "SMP_acceptance", "ISO_built"};
    static const char *const false_keys[] = {"public_artifact", "compiler_tool_closure_verified", "VM_executed",
        "Windows98_boot_verified", "installer_executed", "installer_target_written", "coldboot_persistence_verified",
        "MSDOS_replacement_under_Windows98", "native_apps_verified", "SMP_acceptance", "ISO_built"};
    static const char *const lineage_keys[] = {"source_profile", "constructor_profile", "replacement_receipt",
        "dos_build_receipt", "native_build_receipt", "original_source_disk", "replacement_disk", "native_esp",
        "native_members", "observed_windows_path", "boot_policy", "DOS3_patch_pins"};
    static const char *const pin_keys[] = {"source_profile", "constructor_profile", "replacement_receipt",
        "dos_build_receipt", "native_build_receipt", "original_source_disk"};
    static const char *const patch_names[] = {"0001-shizukudos-branding.patch", "0002-reproducible-build-date.patch",
        "0003-cb43-win98-dos-internals.patch", "0003-dosmgr-honest-contract.patch", "0004-win-startup-chain.patch",
        "freecom-0001-reproducible-build-stamp.patch"};
    const jnode_t *root, *lineage, *members, *patches;
    uint64_t n, first;
    uint8_t pin[32];
    char err[96];
    unsigned i, work = 0;
    if (!c->source_bytes[0] || c->source_bytes[0] > NATIVE_SETUP_JSON_MAX) return fail(c, "bounded native manifest required");
    c->manifest = c->p->alloc(c->p->ctx, (size_t)c->source_bytes[0] + 1);
    if (!c->manifest) return fail(c, "native manifest allocation failed");
    if (read_source(c, 0, 0, c->manifest, (uint32_t)c->source_bytes[0])) return -1;
    c->manifest[c->source_bytes[0]] = 0;
    for (i = 0; i < c->source_bytes[0]; ++i) {
        unsigned char ch = (unsigned char)c->manifest[i];
        if ((ch < 32 && ch != '\t' && ch != '\r' && ch != '\n') || ch > 126 ||
            (ch == '\\' && i + 1 < c->source_bytes[0] && c->manifest[i + 1] == 'u'))
            return fail(c, "unsupported native manifest encoding");
    }
    if (json_parse(c->p, c->manifest, (size_t)c->source_bytes[0], &c->json, err, sizeof err))
        return fail(c, "native manifest JSON invalid");
    root = c->json.root;
    if (tree(root, 0, &work) || fields(root, top, sizeof top / sizeof top[0]) ||
        !is_string(root, "schema", "shizukuos.private-native-install-payload.v1") ||
        !is_string(root, "status", "PRIVATE_NATIVE_ESP_INPUT_EXPORTED_NOT_INSTALLED") ||
        !is_string(root, "redistribution", "PROHIBITED_PRIVATE_LICENSED_INPUT") ||
        !is_string(root, "boot_profile", "native-win98") || !is_type(root, "private", J_TRUE) ||
        !is_string(root, "ESP_geometry", "LBA0_SUPERFLOPPY_UNCHANGED_NOT_PARTITION_REBASED") ||
        json_u64(root, "first_lba", &first) || first ||
        !is_type(root, "input_linux_read_leases", J_TRUE) || !is_type(root, "inputs_before_after_full_SHA_match", J_TRUE) ||
        !is_type(root, "independent_expanded_ESP_readback", J_TRUE))
        return fail(c, "strict private native manifest policy differs");
    for (i = 0; i < sizeof false_keys / sizeof false_keys[0]; ++i)
        if (!is_type(root, false_keys[i], J_FALSE)) return fail(c, "native input invents acceptance or public authority");
    if (file_pin(json_get(root, "source_request"), &n, pin)) return fail(c, "native source request pin invalid");
    lineage = json_get(root, "lineage");
    if (fields(lineage, lineage_keys, sizeof lineage_keys / sizeof lineage_keys[0]) ||
        !is_string(lineage, "boot_policy", "shz.foundation=win98") ||
        !bounded_text(json_str(lineage, "observed_windows_path"), 15)) return fail(c, "native source lineage invalid");
    {
        const char *w = json_str(lineage, "observed_windows_path");
        size_t k;
        if (strlen(w) < 4 || w[0] < 'A' || w[0] > 'Z' || w[1] != ':' || w[2] != '\\')
            return fail(c, "native Windows directory differs");
        for (k = 3; w[k]; ++k)
            if (!((w[k] >= 'A' && w[k] <= 'Z') || (w[k] >= '0' && w[k] <= '9') || w[k] == '_' || w[k] == '~'))
                return fail(c, "native Windows short-directory policy differs");
        if (k - 3 > 8) return fail(c, "native Windows directory is not a short directory");
    }
    for (i = 0; i < sizeof pin_keys / sizeof pin_keys[0]; ++i)
        if (file_pin(json_get(lineage, pin_keys[i]), &n, pin)) return fail(c, "native receipt/source pin invalid");
    if (file_pin(json_get(root, "esp_sim"), &n, sim_sha) || n != c->source_bytes[1])
        return fail(c, "native sparse input raw extent/pin differs");
    if (file_pin(json_get(lineage, "native_esp"), &c->image_bytes, c->result->original_sha256) ||
        c->image_bytes < 32 * MIB || c->image_bytes % MIB || c->image_bytes > NATIVE_SETUP_IMAGE_MAX)
        return fail(c, "native expanded image extent/pin differs");
    members = json_get(lineage, "native_members");
    if (fields(members, names, 8)) return fail(c, "native member inventory differs");
    for (i = 0; i < 8; ++i)
        if (member_pin(json_get(members, names[i]), &c->members[i]) || c->members[i].bytes > c->image_bytes)
            return fail(c, "native member pin invalid");
    if (file_pin(json_get(lineage, "replacement_disk"), &n, pin) || n != c->members[5].bytes ||
        memcmp(pin, c->members[5].sha, 32) || c->members[1].bytes != sizeof boot_policy - 1 ||
        c->members[6].bytes != 256 * 1024 || c->members[7].bytes != 16)
        return fail(c, "native disk/firmware/config member lineage differs");
    patches = json_get(lineage, "DOS3_patch_pins");
    if (fields(patches, patch_names, 6)) return fail(c, "native DOS3 patch lineage differs");
    for (i = 0; i < 6; ++i)
        if (hex_sha(json_str(patches, patch_names[i]), pin)) return fail(c, "native DOS3 patch pin invalid");
    c->result->source_image_bytes = c->image_bytes;
    return 0;
}

static int sim_table(native_context_t *c)
{
    uint8_t h[64], e[16];
    uint64_t data, previous = 0, blocks = c->image_bytes / BLOCK;
    uint32_t i;
    if (c->source_bytes[1] < 64 || read_source(c, 1, 0, h, 64) || memcmp(h, "SHZSIMG1", 8) ||
        u32(h + 8) != BLOCK || u32(h + 12) || u32(h + 20) || u64(h + 24) != c->image_bytes ||
        memcmp(h + 32, c->result->original_sha256, 32)) return fail(c, "native sparse header differs");
    c->nchunks = u32(h + 16);
    if (!c->nchunks || c->nchunks > MAX_CHUNKS || c->nchunks > blocks ||
        64ull + 16ull * c->nchunks > c->source_bytes[1]) return fail(c, "native sparse table count invalid");
    c->chunks = c->p->alloc(c->p->ctx, (size_t)c->nchunks * sizeof *c->chunks);
    if (!c->chunks) return fail(c, "native sparse table allocation failed");
    data = 64ull + 16ull * c->nchunks;
    for (i = 0; i < c->nchunks; ++i) {
        chunk_t *x = &c->chunks[i];
        if (read_source(c, 1, 64ull + 16ull * i, e, 16)) return -1;
        x->first = u64(e); x->count = u32(e + 8); x->data = data;
        if (u32(e + 12) || !x->count || x->first < previous || x->first >= blocks ||
            x->count > blocks - x->first || x->count * BLOCK > c->source_bytes[1] - data)
            return fail(c, "native sparse table is not ordered, disjoint and bounded");
        previous = x->first + x->count;
        data += x->count * BLOCK;
    }
    return data == c->source_bytes[1] ? 0 : fail(c, "native sparse trailing or omitted extent");
}

static int image_read(native_context_t *c, uint64_t off, void *out, uint32_t n)
{
    uint8_t *dst = out;
    if (off > c->image_bytes || n > c->image_bytes - off || guard(c)) return fail(c, "native expanded read extent differs");
    while (n) {
        uint32_t lo = 0, hi = c->nchunks, take;
        uint64_t end;
        const chunk_t *x = 0;
        while (lo < hi) {
            uint32_t m = lo + (hi - lo) / 2;
            if (c->chunks[m].first * BLOCK <= off) lo = m + 1; else hi = m;
        }
        if (lo) x = &c->chunks[lo - 1];
        if (x && off < (x->first + x->count) * BLOCK) {
            end = (x->first + x->count) * BLOCK;
            take = end - off < n ? (uint32_t)(end - off) : n;
            if (read_source(c, 1, x->data + off - x->first * BLOCK, dst, take)) return -1;
        } else {
            end = lo < c->nchunks ? c->chunks[lo].first * BLOCK : c->image_bytes;
            take = end - off < n ? (uint32_t)(end - off) : n;
            if (!take) return fail(c, "native sparse decoder made no progress");
            memset(dst, 0, take);
        }
        dst += take; off += take; n -= take;
    }
    return guard(c);
}

static int fsinfo_valid(const uint8_t *b, uint32_t clusters)
{
    uint32_t free_count = u32(b + 488), next = u32(b + 492);
    return u32(b) == 0x41615252u && u32(b + 484) == 0x61417272u && u32(b + 508) == 0xaa550000u &&
           (free_count == UINT32_MAX || free_count <= clusters) &&
           (next == UINT32_MAX || (next >= 2 && next <= clusters + 1));
}

static int geometry(native_context_t *c, uint8_t sectors[4][SECTOR])
{
    const uint8_t *b = sectors[0];
    uint32_t total, info, backup, root, i;
    uint64_t first, clusters;
    if (image_read(c, 0, sectors[0], SECTOR)) return -1;
    c->spc = b[13]; c->reserved = u16(b + 14); c->fat_sectors = u32(b + 36);
    total = u32(b + 32); info = u16(b + 48); backup = u16(b + 50); root = u32(b + 44);
    if (u16(b + 11) != SECTOR || b[16] != 2 || b[21] != 0xf8 || u16(b + 17) || u16(b + 19) || u16(b + 22) ||
        u32(b + 28) || u16(b + 40) || u16(b + 42) || b[510] != 0x55 || b[511] != 0xaa ||
        !c->spc || c->spc > 128 || (c->spc & (c->spc - 1)) || c->reserved <= 1 || !c->fat_sectors ||
        total != c->image_bytes / SECTOR || !info || !backup || info == backup || info >= c->reserved ||
        backup >= c->reserved || backup + info >= c->reserved)
        return fail(c, "native FAT32 BPB/reserved positions invalid");
    for (i = 52; i < 64; ++i) if (b[i]) return fail(c, "native FAT32 reserved BPB bytes differ");
    first = c->reserved + 2ull * c->fat_sectors;
    if (first >= total || (uint64_t)c->fat_sectors * SECTOR > 32 * MIB) return fail(c, "native FAT32 FAT extent invalid");
    clusters = (total - first) / c->spc;
    if (clusters < 65525 || clusters + 1 >= 0x0ffffff0ull || (clusters + 2) * 4 > (uint64_t)c->fat_sectors * SECTOR ||
        root < 2 || root > clusters + 1) return fail(c, "native image is not supported real FAT32 geometry");
    c->clusters = (uint32_t)clusters; c->root_cluster = root; c->first_data = first * SECTOR;
    c->backup_offset = (uint64_t)backup * SECTOR; c->fsinfo_offset = (uint64_t)info * SECTOR;
    c->backup_fsinfo_offset = (uint64_t)(backup + info) * SECTOR;
    if (image_read(c, c->backup_offset, sectors[1], SECTOR) || image_read(c, c->fsinfo_offset, sectors[2], SECTOR) ||
        image_read(c, c->backup_fsinfo_offset, sectors[3], SECTOR)) return -1;
    if (memcmp(sectors[0], sectors[1], SECTOR) || !fsinfo_valid(sectors[2], c->clusters) || !fsinfo_valid(sectors[3], c->clusters))
        return fail(c, "native primary/backup VBR or actual FSInfo pair invalid");
    return 0;
}

static int fat_next(native_context_t *c, uint32_t cluster, uint32_t *next)
{
    uint8_t a[4], b[4];
    uint64_t off;
    if (cluster < 2 || cluster > c->clusters + 1) return fail(c, "native FAT chain cluster invalid");
    off = (uint64_t)c->reserved * SECTOR + (uint64_t)cluster * 4;
    if (image_read(c, off, a, 4) || image_read(c, off + (uint64_t)c->fat_sectors * SECTOR, b, 4)) return -1;
    if (memcmp(a, b, 4)) return fail(c, "native mirrored FAT entry differs");
    *next = u32(a) & 0x0fffffffu;
    return 0;
}

static int hash_member(native_context_t *c, uint32_t cluster, unsigned which, uint64_t bytes)
{
    uint64_t left = bytes;
    uint32_t count = 0, next;
    uint8_t got[32];
    void *h;
    if (bytes != c->members[which].bytes) return fail(c, "actual native member extent differs");
    h = c->ops->sha_begin(c->ops->ctx);
    if (!h) return fail(c, "native member SHA begin failed");
    while (left) {
        uint32_t n = left < (uint64_t)c->spc * SECTOR ? (uint32_t)left : c->spc * SECTOR;
        uint64_t off;
        if (++count > c->clusters || cluster < 2 || cluster > c->clusters + 1) goto bad_chain;
        off = c->first_data + (uint64_t)(cluster - 2) * c->spc * SECTOR;
        if (image_read(c, off, c->scratch, n)) goto bad;
        if (which == 1 && (bytes != sizeof boot_policy - 1 || count != 1 || memcmp(c->scratch, boot_policy, sizeof boot_policy - 1))) {
            fail(c, "actual native BOOT.INI does not launch Supervisor"); goto bad;
        }
        if (which == 7 && (count != 1 || n != 16 || u32(c->scratch) != 0x38395753u ||
            u32(c->scratch + 4) != 1 || u32(c->scratch + 8) != 128 || u32(c->scratch + 12))) {
            fail(c, "actual native Win98 config differs"); goto bad;
        }
        if (c->ops->sha_update(c->ops->ctx, h, c->scratch, n) || fat_next(c, cluster, &next)) goto bad;
        left -= n;
        if ((!left && next < 0x0ffffff8u) || (left && (next < 2 || next > c->clusters + 1))) goto bad_chain;
        cluster = next;
    }
    if (c->ops->sha_end(c->ops->ctx, h, got) || memcmp(got, c->members[which].sha, 32) || guard(c))
        return fail(c, "actual native member SHA differs");
    return 0;
bad_chain:
    fail(c, "native member chain is truncated, cyclic or has an extra extent");
bad:
    c->ops->sha_abort(c->ops->ctx, h);
    return fail(c, "actual native member read/SHA failed");
}

static int short_name(const uint8_t raw[11], char out[13])
{
    unsigned i, n = 0, end = 8;
    while (end && raw[end - 1] == ' ') --end;
    if (!end) return -1;
    for (i = 0; i < end; ++i) {
        if (!((raw[i] >= 'A' && raw[i] <= 'Z') || (raw[i] >= '0' && raw[i] <= '9') || raw[i] == '_')) return -1;
        out[n++] = (char)raw[i];
    }
    end = 3;
    while (end && raw[8 + end - 1] == ' ') --end;
    if (end) out[n++] = '.';
    for (i = 0; i < end; ++i) {
        uint8_t ch = raw[8 + i];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_')) return -1;
        out[n++] = (char)ch;
    }
    out[n] = 0;
    return 0;
}

static int inventory(native_context_t *c, uint32_t cluster, const char *prefix, unsigned depth)
{
    uint32_t chain = 0, next;
    if (depth > 3) return fail(c, "unexpected native directory depth");
    for (;;) {
        uint32_t sector;
        if (++chain > c->clusters || cluster < 2 || cluster > c->clusters + 1) return fail(c, "native directory chain invalid");
        for (sector = 0; sector < c->spc; ++sector) {
            uint8_t b[SECTOR];
            unsigned at;
            uint64_t off = c->first_data + ((uint64_t)(cluster - 2) * c->spc + sector) * SECTOR;
            if (image_read(c, off, b, SECTOR)) return -1;
            for (at = 0; at < SECTOR; at += 32) {
                const uint8_t *e = b + at;
                uint32_t child;
                char name[13], path[64];
                size_t a, z;
                unsigned i;
                if (!e[0]) return 0;
                if (e[0] == 0xe5 || e[0] == '.') continue;
                if (++c->directory_work > 8192 || e[11] == 0x0f || (e[11] & 0xc0)) return fail(c, "native directory work/entry policy invalid");
                if (e[11] & 8) continue;              /* actual FAT volume label */
                if (short_name(e, name)) return fail(c, "native file is not a supported short name");
                a = strlen(prefix); z = strlen(name);
                if (a + (a != 0) + z >= sizeof path) return fail(c, "native member path exceeds bound");
                memcpy(path, prefix, a);
                if (a) path[a++] = '/';
                memcpy(path + a, name, z + 1);
                child = ((uint32_t)u16(e + 20) << 16) | u16(e + 26);
                if (e[11] & 16) {
                    for (i = 0; i < 4 && strcmp(path, dirs[i]); ++i) {}
                    if (i == 4 || (c->seen_dirs & (1u << i)) || u32(e + 28)) return fail(c, "unexpected or duplicate native directory");
                    c->seen_dirs |= 1u << i;
                    if (inventory(c, child, path, depth + 1)) return -1;
                } else {
                    for (i = 0; i < 8 && strcmp(path, names[i]); ++i) {}
                    if (i == 8 || (c->seen_files & (1u << i))) return fail(c, "unexpected or duplicate native file");
                    c->seen_files |= 1u << i;
                    if (hash_member(c, child, i, u32(e + 28))) return -1;
                }
            }
        }
        if (fat_next(c, cluster, &next)) return -1;
        if (next >= 0x0ffffff8u) return 0;
        cluster = next;
    }
}

static int select_target(native_context_t *c)
{
    const native_setup_target_v1_t *r = &c->request->reviewed_target;
    unsigned count = c->p->disk_count(c->p->ctx), i, matches = 0;
    plat_disk_t selected;
    if (!count || count > 256 || !valid_disk(&r->disk) || !r->generation || !nonzero(r->whole_id, 16) || r->index >= count)
        return fail(c, "exact reviewed native whole target required");
    memset(&selected, 0, sizeof selected);
    for (i = 0; i < count; ++i) {
        plat_disk_t d;
        memset(&d, 0, sizeof d);
        if (c->p->disk_info(c->p->ctx, i, &d) || !bounded_text(d.name, sizeof d.name - 1) ||
            !bounded_text(d.serial, sizeof d.serial - 1)) return fail(c, "native target enumeration is incomplete or truncated");
        if (i != r->index && (text_ieq(d.name, r->disk.name) ||
            (!(d.flags & PLAT_DISK_PARTITION) && !strcmp(d.serial, r->disk.serial))))
            return fail(c, "native target name or whole serial is ambiguous");
        if (valid_disk(&d) && disk_equal(&d, &r->disk)) { ++matches; selected = d; }
    }
    if (matches != 1) return fail(c, "native target reviewed tuple no longer exists uniquely");
    memset(&c->target, 0, sizeof c->target);
    if (c->ops->review_target(c->ops->ctx, r->index, c->source, &c->target) || !target_equal(&c->target, r) ||
        !disk_equal(&selected, &c->target.disk)) return fail(c, "native source/boot/current-system whole exclusion is not admitted");
    c->first = 2048;
    if (selected.sectors < 4096 || c->image_bytes / SECTOR > selected.sectors ||
        c->image_bytes / SECTOR - 1 > UINT64_MAX - c->first) return fail(c, "native target capacity overflows");
    c->last = c->first + c->image_bytes / SECTOR - 1;
    if (c->last > gpt_last_usable(SECTOR, selected.sectors)) return fail(c, "native ESP and GPT do not fit target");
    if (c->ops->claim_target(c->ops->ctx, &c->target, c->source, &c->claim) || !c->claim)
        return fail(c, "native exclusive target claim unavailable");
    c->result->target_first_lba = c->first; c->result->target_last_lba = c->last;
    return guard(c);
}

static int relocation(native_context_t *c, uint8_t sectors[4][SECTOR])
{
    uint8_t before[4][SECTOR], replacement[4];
    unsigned i;
    memcpy(before, sectors, sizeof before);
    memset(c->overlays, 0, sizeof c->overlays);
    if (c->ops->prepare_relocation(c->ops->ctx, sectors[0], sectors[1], sectors[2], sectors[3],
                                  c->image_bytes, c->first, c->last, c->overlays) ||
        memcmp(before, sectors, sizeof before)) return fail(c, "native pure relocation adapter failed or changed inputs");
    put32(replacement, (uint32_t)c->first);
    for (i = 0; i < 2; ++i)
        if (c->overlays[i].offset != (i ? c->backup_offset + 28 : 28) ||
            memcmp(c->overlays[i].original, sectors[i] + 28, 4) ||
            memcmp(c->overlays[i].replacement, replacement, 4) || c->overlays[i].offset > c->image_bytes - 4)
            return fail(c, "native adapter requested a non-hidden-sector overlay");
    memcpy(c->frozen, c->overlays, sizeof c->frozen); c->plan_ready = 1;
    return guard(c);
}

static int overlay(native_context_t *c, uint64_t off, uint8_t *p, uint32_t n)
{
    unsigned i, k;
    if (off > c->image_bytes || n > c->image_bytes - off || guard(c)) return fail(c, "native overlay extent/custody invalid");
    for (i = 0; i < 2; ++i)
        for (k = 0; k < 4; ++k) {
            uint64_t pos = c->frozen[i].offset + k;
            if (pos >= off && pos - off < n && p[pos - off] != c->frozen[i].original[k])
                return fail(c, "actual source BPB overlay bytes drifted");
        }
    for (i = 0; i < 2; ++i)
        for (k = 0; k < 4; ++k) {
            uint64_t pos = c->frozen[i].offset + k;
            if (pos >= off && pos - off < n) p[pos - off] = c->frozen[i].replacement[k];
        }
    return guard(c);
}

static int disk_io(native_context_t *c, int write, uint64_t lba, uint32_t count, void *data)
{
    uint32_t maximum = c->p->max_io_sectors;
    uint8_t *p = data;
    if (!maximum || maximum > 2048 || lba >= c->target.disk.sectors || count > c->target.disk.sectors - lba)
        return fail(c, "native sector request exceeds admitted extent");
    while (count) {
        uint32_t n = count < maximum ? count : maximum;
        int rc;
        if (guard(c)) return -1;
        if (write) {
            c->result->target_write_attempted = 1;
            rc = c->p->disk_write(c->p->ctx, c->target.index, lba, n, p);
        } else rc = c->p->disk_read(c->p->ctx, c->target.index, lba, n, p);
        if (rc || guard(c)) return fail(c, "native actual target sector I/O failed");
        lba += n; count -= n; p += (size_t)n * SECTOR;
    }
    return 0;
}

static int flush(native_context_t *c)
{
    if (guard(c) || c->p->disk_flush(c->p->ctx, c->target.index) || guard(c))
        return fail(c, "native actual target flush failed");
    return 0;
}

static int stream_image(native_context_t *c, int write, uint8_t original[32], uint8_t relocated[32])
{
    uint64_t off = 0;
    void *s = c->ops->sha_begin(c->ops->ctx), *r = c->ops->sha_begin(c->ops->ctx);
    if (!s || !r) { fail(c, "native independent image SHA begin failed"); goto bad; }
    while (off < c->image_bytes) {
        uint32_t n = c->image_bytes - off < IO_BYTES ? (uint32_t)(c->image_bytes - off) : IO_BYTES;
        if (image_read(c, off, c->buffer, n) || c->ops->sha_update(c->ops->ctx, s, c->buffer, n) ||
            overlay(c, off, c->buffer, n) || c->ops->sha_update(c->ops->ctx, r, c->buffer, n) ||
            (write && disk_io(c, 1, c->first + off / SECTOR, n / SECTOR, c->buffer))) goto bad;
        off += n;
    }
    {
        int rc = c->ops->sha_end(c->ops->ctx, s, original); s = 0;
        if (rc) { fail(c, "native original image SHA finalize failed"); goto bad; }
        rc = c->ops->sha_end(c->ops->ctx, r, relocated); r = 0;
        if (rc) { fail(c, "native relocated image SHA finalize failed"); goto bad; }
    }
    return guard(c);
bad:
    if (s) c->ops->sha_abort(c->ops->ctx, s);
    if (r) c->ops->sha_abort(c->ops->ctx, r);
    return fail(c, "native full image stream/hash failed");
}

static int readback(native_context_t *c)
{
    uint64_t off = 0;
    uint8_t got[32];
    void *h = c->ops->sha_begin(c->ops->ctx);
    if (!h) return fail(c, "native target readback SHA begin failed");
    while (off < c->image_bytes) {
        uint32_t n = c->image_bytes - off < IO_BYTES ? (uint32_t)(c->image_bytes - off) : IO_BYTES;
        if (disk_io(c, 0, c->first + off / SECTOR, n / SECTOR, c->buffer) ||
            c->ops->sha_update(c->ops->ctx, h, c->buffer, n)) {
            c->ops->sha_abort(c->ops->ctx, h);
            return fail(c, "native actual target readback failed");
        }
        off += n;
    }
    if (c->ops->sha_end(c->ops->ctx, h, got) || memcmp(got, c->result->relocated_sha256, 32) || guard(c))
        return fail(c, "native full target readback differs from precomputed relocated SHA");
    c->result->target_readback_verified = 1;
    return 0;
}

static int gpt(native_context_t *c, int write, uint8_t *bytes)
{
    uint8_t *mbr = bytes, *primary = mbr + SECTOR, *array = primary + SECTOR, *backup = array + GPT_ARRAY_BYTES;
    uint64_t end = c->target.disk.sectors - 1;
    if (!write) {
        gpt_layout_t layout;
        memset(&layout, 0, sizeof layout);
        layout.sector_size = SECTOR; layout.sectors = c->target.disk.sectors; layout.count = 1;
        if (c->p->random(c->p->ctx, layout.disk_guid, 16) || c->p->random(c->p->ctx, layout.part[0].guid, 16) ||
            !nonzero(layout.disk_guid, 16) || !nonzero(layout.part[0].guid, 16) || !memcmp(layout.disk_guid, layout.part[0].guid, 16))
            return fail(c, "native GPT identity generation failed");
        layout.disk_guid[6] = (uint8_t)((layout.disk_guid[6] & 15) | 64); layout.disk_guid[8] = (uint8_t)((layout.disk_guid[8] & 63) | 128);
        layout.part[0].guid[6] = (uint8_t)((layout.part[0].guid[6] & 15) | 64); layout.part[0].guid[8] = (uint8_t)((layout.part[0].guid[8] & 63) | 128);
        if (!memcmp(layout.disk_guid, layout.part[0].guid, 16))
            return fail(c, "native normalized GPT identities collide");
        memcpy(layout.part[0].type, GPT_TYPE_ESP, 16);
        layout.part[0].first_lba = c->first; layout.part[0].last_lba = c->last;
        copy_string(layout.part[0].name, sizeof layout.part[0].name, "ShizukuOS native Win98 ESP");
        if (gpt_build(&layout, mbr, primary, array, backup)) return fail(c, "native single-ESP GPT layout failed");
        return guard(c);
    }
    if (disk_io(c, 1, end - GPT_ARRAY_BYTES / SECTOR, GPT_ARRAY_BYTES / SECTOR, array) ||
        disk_io(c, 1, end, 1, backup) || disk_io(c, 1, 2, GPT_ARRAY_BYTES / SECTOR, array) ||
        disk_io(c, 1, 1, 1, primary) || disk_io(c, 1, 0, 1, mbr) || flush(c)) return -1;
    if (disk_io(c, 0, 0, 2 + GPT_ARRAY_BYTES / SECTOR, c->scratch) || memcmp(c->scratch, mbr, SECTOR) ||
        memcmp(c->scratch + SECTOR, primary, SECTOR) || memcmp(c->scratch + 2 * SECTOR, array, GPT_ARRAY_BYTES) ||
        gpt_check(c->scratch + SECTOR, c->scratch + 2 * SECTOR, SECTOR, 1, c->target.disk.sectors))
        return fail(c, "native primary GPT/MBR exact readback failed");
    if (disk_io(c, 0, end - GPT_ARRAY_BYTES / SECTOR, GPT_ARRAY_BYTES / SECTOR + 1, c->scratch) ||
        memcmp(c->scratch, array, GPT_ARRAY_BYTES) || memcmp(c->scratch + GPT_ARRAY_BYTES, backup, SECTOR) ||
        gpt_check(c->scratch + GPT_ARRAY_BYTES, c->scratch, SECTOR, end, c->target.disk.sectors))
        return fail(c, "native backup GPT exact readback failed");
    c->result->GPT_readback_verified = 1;
    return guard(c);
}

static int wipe(native_context_t *c)
{
    memset(c->buffer, 0, 34 * SECTOR);
    if (disk_io(c, 1, 0, 34, c->buffer) || disk_io(c, 1, c->target.disk.sectors - 33, 33, c->buffer) || flush(c)) return -1;
    return 0;
}

/* ---- Explicit original-userland (SZOU v1) phase ---------------------------
 * Only native_install_run_original_userland/_resume reach this code; the
 * strict v1 path leaves c->szou NULL and every helper below unreachable. */
#define SZOU_STAGE_ROOT "SZSTAGE.NEW"
typedef struct szou_src { native_context_t *c; } szou_src_t;
static int szou_fail(native_context_t *c, const char *reason)
{
    if (c->szou && !c->szou->reason[0]) copy_string(c->szou->reason, sizeof c->szou->reason, reason);
    return fail(c, reason);
}
static int szou_src_read(void *ctx, uint64_t off, void *buf, uint32_t n)
{
    szou_src_t *s = ctx;
    return read_source(s->c, 2, off, buf, n) ? SZOU_E_IO : 0;
}
static int szou_guard(void *ctx) { return guard((native_context_t *)ctx); }

/* Phase admission precedes every source open and target I/O. */
static int szou_request_check(native_context_t *c)
{
    const native_setup_szou_request_v1_t *q = c->szou_request;
    const native_setup_szou_ops_v1_t *o = c->szou_ops;
    if (!q || q->version != NATIVE_SETUP_SZOU_VERSION || q->bytes != sizeof *q ||
        !bounded_text(q->szou_path, NATIVE_SETUP_PATH_MAX) || !bounded_text(q->target_root, NATIVE_SETUP_SZOU_ROOT_MAX))
        return szou_fail(c, "explicit SZOU original-userland request (version, source name, target root) required");
    if (!o || o->version != NATIVE_SETUP_SZOU_VERSION || o->bytes != sizeof *o || !o->phase_pin)
        return szou_fail(c, "SZOU original-userland phase admission provider unavailable");
    if (o->phase_pin(o->ctx, NATIVE_SETUP_SZOU_ROLE, &c->szou_pin_bytes, c->szou_pin) || !c->szou_pin_bytes ||
        c->szou_pin_bytes > NATIVE_SETUP_IMAGE_MAX || !nonzero(c->szou_pin, 32))
        return szou_fail(c, "independently admitted original-userland phase record (role 2) absent; no SZOU source opened, no target I/O");
    c->szou->phase_record_present = 1;
    return 0;
}

/* Every relocated final and staged path must be creatable by the setup-side
 * FAT32 writer (8.3 components, < 4 GiB) before the destructive pass. */
static int szou_names(native_context_t *c, const szou_plan_opts_t *o)
{
    char out[SZOU_PATH_FIELD];
    uint8_t name[11];
    uint32_t i;
    int staged;
    for (i = 0; i < c->szou_header.entry_count; ++i) {
        const szou_entry_t *e = &c->szou_entries[i];
        if (e->size > 0xFFFFFFFFull) return szou_fail(c, "SZOU entry of 4 GiB or more is unsupported by FAT32");
        for (staged = 0; staged < 2; ++staged) {
            size_t a = 0, b;
            if (szou_plan_path(o, e->path, staged, out)) return szou_fail(c, "SZOU relocated path refused");
            for (;;) {
                for (b = a; out[b] && out[b] != '\\'; ++b) {}
                if (to83(out + a, b - a, name))
                    return szou_fail(c, "SZOU short path is not a valid 8.3 alias (long names come only from SZOU v2 SZLN records)");
                if (!out[b]) break;
                a = b + 1;
            }
        }
    }
    return 0;
}

static int szou_admit(native_context_t *c)
{
    const native_setup_szou_request_v1_t *q = c->szou_request;
    szou_plan_opts_t o;
    szou_src_t src;
    uint8_t got[32];
    size_t table_bytes;
    uint32_t i;
    int rc;
    if (c->p->file_open(c->p->ctx, q->szou_path, &c->source[2], &c->source_bytes[2]) || !c->source[2] ||
        c->source_bytes[2] != c->szou_pin_bytes ||
        c->ops->admit_source(c->ops->ctx, c->source[2], q->szou_path, c->source_bytes[2], c->szou_pin))
        return szou_fail(c, "actual admitted SZOU source extent, SHA or custody differs");
    c->admitted[2] = 1;
    if (hash_source(c, 2, got) || memcmp(got, c->szou_pin, 32))
        return szou_fail(c, "actual admitted SZOU source SHA differs");
    memcpy(c->szou->szou_sha256, got, 32);
    c->szou->source_bytes = c->source_bytes[2]; c->szou->source_admitted = 1;
    if (read_source(c, 2, 0, c->buffer, SZOU_HEADER_BYTES) ||
        szou_parse_header(c->buffer, c->source_bytes[2], &c->szou_header))
        return szou_fail(c, "SZOU original-userland header refused");
    table_bytes = (size_t)c->szou_header.entry_count * SZOU_ENTRY_BYTES;
    c->szou_table = c->p->alloc(c->p->ctx, table_bytes);
    c->szou_entries = c->p->alloc(c->p->ctx, (size_t)c->szou_header.entry_count * sizeof *c->szou_entries);
    c->szou_order = c->p->alloc(c->p->ctx, (size_t)c->szou_header.entry_count * sizeof *c->szou_order);
    if (!c->szou_table || !c->szou_entries || !c->szou_order) return szou_fail(c, "SZOU bounded table allocation failed");
    if (read_source(c, 2, c->szou_header.table_offset, c->szou_table, (uint32_t)table_bytes) ||
        (rc = szou_parse_table(&c->szou_header, c->szou_table, table_bytes, c->szou_entries, c->szou_order)))
        return szou_fail(c, "SZOU original-userland entry table refused");
    if (c->szou_header.version == SZOU_VERSION_NAMES) {   /* v2: SZLN long names + directory list */
        szou_names_header_t nh;
        uint8_t *raw;
        uint32_t *scratch;
        size_t rb;
        if (read_source(c, 2, c->szou_header.names_offset, c->buffer, SZLN_HEADER_BYTES) ||
            szou_parse_names_header(&c->szou_header, c->buffer, c->source_bytes[2], &nh))
            return szou_fail(c, "SZOU v2 SZLN extension header refused");
        rb = (size_t)nh.record_count * SZLN_RECORD_BYTES;
        raw = c->p->alloc(c->p->ctx, rb);
        scratch = c->p->alloc(c->p->ctx, SZOU_NAMES_SCRATCH(c->szou_header.entry_count, nh.record_count) * sizeof *scratch);
        c->szou_names = c->p->alloc(c->p->ctx, (size_t)nh.record_count * sizeof *c->szou_names);
        if (!raw || !scratch || !c->szou_names) {
            if (raw) c->p->free(c->p->ctx, raw);
            if (scratch) c->p->free(c->p->ctx, scratch);
            return szou_fail(c, "SZOU v2 bounded name table allocation failed");
        }
        rc = read_source(c, 2, nh.records_offset, raw, (uint32_t)rb) ? SZOU_E_IO :
             szou_parse_names(&c->szou_header, &nh, raw, rb, c->szou_entries, c->szou_order, c->szou_names, scratch);
        c->p->free(c->p->ctx, raw); c->p->free(c->p->ctx, scratch);
        if (rc) return szou_fail(c, "SZOU v2 long-name/directory records refused");
        c->szou_name_count = nh.record_count;
    }
    o.target_root = q->target_root; o.stage_root = SZOU_STAGE_ROOT;
    if (szou_plan_check(&o, c->szou_entries, c->szou_header.entry_count) ||
        szou_plan_check_names(&o, c->szou_names, c->szou_name_count) || szou_names(c, &o))
        return szou_fail(c, "SZOU relocation plan refused before target writes");
    src.c = c;
    for (i = 0; i < c->szou_header.entry_count; ++i)
        if (szou_verify_entry(&c->szou_header, &c->szou_entries[i], szou_src_read, &src, c->scratch, IO_BYTES))
            return szou_fail(c, "SZOU member payload SHA differs");
    c->szou->entries = c->szou_header.entry_count;
    c->szou->preflight_verified = 1;
    return guard(c);
}

static int szou_mount(native_context_t *c, szou_fat32_t *fs, szou_sink_ops_t *sink)
{
    static szou_plat_blk_t pb;   /* referenced by dev for the mount lifetime */
    szou_blkdev_t dev;
    memset(&pb, 0, sizeof pb);
    pb.p = c->p; pb.index = c->target.index; pb.first_lba = c->first; pb.sectors = c->last - c->first + 1;
    pb.guard = szou_guard; pb.gctx = c;
    if (!c->claim || szou_blk_from_plat(&pb, &dev, c->target.disk.sector_size, c->p->max_io_sectors) ||
        szou_fat32_mount(fs, &dev, c->p->alloc, c->p->free, c->p->ctx, 0, 0))
        return szou_fail(c, "SZOU installed FAT32 partition mount refused");
    szou_fat32_sink(fs, sink);
    return 0;
}

/* Re-open every committed final file through the same guarded volume and
 * compare its content SHA with the admitted entry table. */
static int szou_final_readback(native_context_t *c, const szou_sink_ops_t *k)
{
    szou_plan_opts_t o;
    char path[SZOU_PATH_FIELD];
    uint32_t i;
    o.target_root = c->szou_request->target_root; o.stage_root = SZOU_STAGE_ROOT;
    for (i = 0; i < c->szou_header.entry_count; ++i) {
        const szou_entry_t *e = &c->szou_entries[i];
        sha256_ctx h;
        uint8_t got[32];
        uint64_t size = 0, off = 0;
        void *f = 0;
        if (szou_plan_path(&o, e->path, 0, path) || k->open(k->ctx, path, &f, &size) || !f || size != e->size) {
            if (f) k->close(k->ctx, f);
            return szou_fail(c, "SZOU committed file missing or size differs");
        }
        sha256_init(&h);
        while (off < size) {
            uint32_t n = size - off < IO_BYTES ? (uint32_t)(size - off) : IO_BYTES;
            if (k->read(k->ctx, f, off, c->scratch, n)) { k->close(k->ctx, f); return szou_fail(c, "SZOU committed file readback failed"); }
            sha256_update(&h, c->scratch, n);
            off += n;
        }
        sha256_final(&h, got);
        if (k->close(k->ctx, f) || memcmp(got, e->sha256, 32)) return szou_fail(c, "SZOU committed file SHA differs");
        c->szou->bytes_read_back += size;
    }
    c->szou->final_readback_verified = 1;
    return 0;
}

static void szou_account(native_context_t *c, const szou_stage_result_t *r)
{
    c->szou->files_staged += r->files_staged; c->szou->files_committed += r->files_committed;
    c->szou->files_already_final += r->files_already_final; c->szou->dirs_created += r->dirs_created;
    c->szou->bytes_written += r->bytes_written;
}

/* Runs only after the native image, full readback and GPT readback succeeded,
 * while the exclusive claim is held. */
static int szou_phase(native_context_t *c)
{
    static szou_fat32_t fs;      /* sector cache + handles; kept off the stack */
    szou_sink_ops_t sink;
    szou_plan_opts_t o;
    szou_stage_result_t r;
    szou_src_t src;
    uint8_t got[32];
    int rc;
    if (szou_mount(c, &fs, &sink)) return -1;
    memset(&r, 0, sizeof r);
    rc = szou_commit_pending(&sink, c->buffer, IO_BYTES, &r);     /* setup resume of an earlier marker */
    if (rc == 0) { c->szou->resumed_pending = 1; szou_account(c, &r); }
    else if (rc != SZOU_ABSENT) { (void)szou_fat32_unmount(&fs); return szou_fail(c, "SZOU pending marker roll-forward failed"); }
    o.target_root = c->szou_request->target_root; o.stage_root = SZOU_STAGE_ROOT;
    src.c = c; memset(&r, 0, sizeof r);
    if (szou_stage_named(&o, &c->szou_header, c->szou_entries, c->szou_names, c->szou_name_count,
                         szou_src_read, &src, &sink, c->buffer, IO_BYTES, &r)) {
        szou_account(c, &r); (void)szou_fat32_unmount(&fs);
        return szou_fail(c, "SZOU staging into installed FAT32 volume failed");
    }
    szou_account(c, &r); c->szou->staged = 1;
    memset(&r, 0, sizeof r);
    if (szou_commit_pending(&sink, c->buffer, IO_BYTES, &r)) { (void)szou_fat32_unmount(&fs); return szou_fail(c, "SZOU commit failed"); }
    szou_account(c, &r); c->szou->committed = 1;
    if (szou_final_readback(c, &sink)) { (void)szou_fat32_unmount(&fs); return -1; }
    if (szou_fat32_unmount(&fs) || flush(c) || hash_source(c, 2, got) || memcmp(got, c->szou->szou_sha256, 32))
        return szou_fail(c, "SZOU unmount, flush or final source SHA verification failed");
    return guard(c);
}

/* Resume: verify the exact single-ESP GPT this installer wrote at [first,last]
 * and roll a persisted marker forward. No image write, no wipe. */
static int szou_resume(native_context_t *c)
{
    static szou_fat32_t fs;
    szou_sink_ops_t sink;
    szou_stage_result_t r;
    const uint8_t *e;
    int rc;
    if (disk_io(c, 0, 1, 1 + GPT_ARRAY_BYTES / SECTOR, c->scratch) ||
        gpt_check(c->scratch, c->scratch + SECTOR, SECTOR, 1, c->target.disk.sectors))
        return szou_fail(c, "SZOU resume: installed primary GPT refused");
    e = c->scratch + SECTOR;
    if (memcmp(e, GPT_TYPE_ESP, 16) || u64(e + 32) != c->first || u64(e + 40) != c->last)
        return szou_fail(c, "SZOU resume: installed ESP interval differs from reviewed plan");
    if (szou_mount(c, &fs, &sink)) return -1;
    memset(&r, 0, sizeof r);
    rc = szou_commit_pending(&sink, c->buffer, IO_BYTES, &r);
    if (rc == SZOU_ABSENT) { (void)szou_fat32_unmount(&fs); return szou_fail(c, "SZOU resume: no pending SZOUPEND.SYS marker"); }
    if (rc) { (void)szou_fat32_unmount(&fs); return szou_fail(c, "SZOU resume: pending marker roll-forward failed"); }
    szou_account(c, &r); c->szou->resumed_pending = 1; c->szou->committed = 1;
    if (szou_fat32_unmount(&fs) || flush(c)) return szou_fail(c, "SZOU resume: unmount/flush failed");
    return guard(c);
}

enum { RUN_STRICT_V1 = 0, RUN_SZOU_INSTALL = 1, RUN_SZOU_RESUME = 2 };
static void run(const plat_t *p, const native_setup_ops_v1_t *ops, const native_setup_szou_ops_v1_t *sops,
                const native_setup_request_v1_t *request, const native_setup_szou_request_v1_t *sreq,
                native_setup_result_v1_t *result, native_setup_szou_result_v1_t *sres, int mode)
{
    native_context_t c;
    uint8_t original[32], relocated[32], sim_sha[32], got[32], sectors[4][SECTOR];
    uint8_t *gpt_bytes = 0;
    unsigned i;
    int completed = 0;
    if (!result || (mode != RUN_STRICT_V1 && !sres)) return;
    memset(result, 0, sizeof *result); memset(&c, 0, sizeof c);
    c.p = p; c.ops = ops; c.request = request; c.result = result;
    if (mode != RUN_STRICT_V1) { memset(sres, 0, sizeof *sres); c.szou = sres; c.szou_ops = sops; c.szou_request = sreq; }
    if (!p || !request || request->version != NATIVE_SETUP_VERSION || request->bytes != sizeof *request ||
        !bounded_text(request->manifest_path, NATIVE_SETUP_PATH_MAX) || !bounded_text(request->sim_path, NATIVE_SETUP_PATH_MAX) ||
        !nonzero(request->admitted_manifest_sha256, 32) || !request->confirmation || strcmp(request->confirmation, "ERASE")) {
        fail(&c, "explicit native input, admitted manifest pin and exact reviewed ERASE required"); goto out;
    }
    if (!ops || ops->version != NATIVE_SETUP_VERSION || ops->bytes != sizeof *ops ||
        !ops->admit_source || !ops->check_source || !ops->close_source || !ops->sha_begin || !ops->sha_update ||
        !ops->sha_end || !ops->sha_abort || !ops->review_target || !ops->claim_target || !ops->check_target ||
        !ops->release_target || !ops->prepare_relocation) {
        fail(&c, "native source/boot whole-device authority, exclusive claim and relocation provider unavailable"); goto out;
    }
    if (!p->alloc || !p->free || !p->file_open || !p->file_read || !p->disk_count || !p->disk_info || !p->disk_read ||
        !p->disk_write || !p->disk_flush || !p->random || !p->max_io_sectors || p->max_io_sectors > 2048) {
        fail(&c, "native platform exact I/O capability unavailable"); goto out;
    }
    if (mode == RUN_SZOU_INSTALL && szou_request_check(&c)) goto out;
    c.buffer = p->alloc(p->ctx, IO_BYTES); c.scratch = p->alloc(p->ctx, IO_BYTES);
    gpt_bytes = p->alloc(p->ctx, GPT_ARRAY_BYTES + 3 * SECTOR);
    if (!c.buffer || !c.scratch || !gpt_bytes) { fail(&c, "native bounded work allocation failed"); goto out; }
    if (p->file_open(p->ctx, request->manifest_path, &c.source[0], &c.source_bytes[0]) || !c.source[0] ||
        !c.source_bytes[0] || c.source_bytes[0] > NATIVE_SETUP_JSON_MAX ||
        ops->admit_source(ops->ctx, c.source[0], request->manifest_path, c.source_bytes[0], request->admitted_manifest_sha256)) {
        fail(&c, "actual admitted native manifest extent, SHA or custody differs"); goto out;
    }
    c.admitted[0] = 1;
    if (hash_source(&c, 0, got) || memcmp(got, request->admitted_manifest_sha256, 32)) {
        fail(&c, "actual admitted native manifest SHA differs"); goto out;
    }
    memcpy(result->manifest_sha256, got, 32);
    if (p->file_open(p->ctx, request->sim_path, &c.source[1], &c.source_bytes[1]) || !c.source[1] ||
        !c.source_bytes[1] || c.source_bytes[1] > NATIVE_SETUP_IMAGE_MAX) {
        fail(&c, "actual native sparse source unavailable or unbounded"); goto out;
    }
    /* The raw SIM SHA is bound by parsed, already authenticated manifest bytes.
     * No SIM read occurs until its independent provider admits the handle. */
    if (manifest(&c, sim_sha) || ops->admit_source(ops->ctx, c.source[1], request->sim_path, c.source_bytes[1], sim_sha)) {
        fail(&c, "actual native sparse source SHA or custody differs"); goto out;
    }
    c.admitted[1] = 1;
    if (hash_source(&c, 1, got) || memcmp(got, sim_sha, 32)) {
        fail(&c, "actual native sparse source SHA differs"); goto out;
    }
    memcpy(result->sim_sha256, got, 32);
    if (mode == RUN_SZOU_INSTALL && szou_admit(&c)) goto out;
    if (sim_table(&c) || geometry(&c, sectors) || inventory(&c, c.root_cluster, "", 0) ||
        c.seen_files != 255 || c.seen_dirs != 15 || select_target(&c) || relocation(&c, sectors)) {
        fail(&c, "native complete input/member/target preflight failed"); goto out;
    }
    if (mode == RUN_SZOU_RESUME) {
        if (szou_resume(&c) || hash_source(&c, 0, got) || memcmp(got, result->manifest_sha256, 32) ||
            hash_source(&c, 1, got) || memcmp(got, result->sim_sha256, 32) || guard(&c)) {
            szou_fail(&c, "SZOU resume or final source verification failed"); goto out;
        }
        completed = 1; goto out;
    }
    if (stream_image(&c, 0, original, relocated) || memcmp(original, result->original_sha256, 32) ||
        !memcmp(original, relocated, 32) || gpt(&c, 0, gpt_bytes)) {
        fail(&c, "native original or precomputed relocated image SHA differs"); goto out;
    }
    memcpy(result->relocated_sha256, relocated, 32);
    /* Every source/raw/expanded hash, BPB plan, actual member and target claim
     * above is validated before the first destructive sector call. */
    if (guard(&c) || wipe(&c) || stream_image(&c, 1, original, relocated) ||
        memcmp(original, result->original_sha256, 32) || memcmp(relocated, result->relocated_sha256, 32) ||
        flush(&c) || readback(&c) || hash_source(&c, 0, got) || memcmp(got, result->manifest_sha256, 32) ||
        hash_source(&c, 1, got) || memcmp(got, result->sim_sha256, 32) || guard(&c) || gpt(&c, 1, gpt_bytes)) {
        fail(&c, "native second pass, full target readback or final source/GPT verification failed"); goto out;
    }
    if (mode == RUN_SZOU_INSTALL && szou_phase(&c)) goto out;
    completed = 1;
out:
    if (ops && ops->check_source && ops->close_source) {
        for (i = 0; i < 3; ++i) {
            if (!c.source[i]) continue;
            if (ops->check_source(ops->ctx, c.source[i])) { fail(&c, "native final source custody check failed"); completed = 0; }
            if (ops->close_source(ops->ctx, c.source[i])) { fail(&c, "native mandatory source close/finalization failed"); completed = 0; }
            c.source[i] = 0;
        }
    }
    if (c.claim && ops && ops->release_target) {
        if (ops->check_target(ops->ctx, c.claim, &c.target)) { fail(&c, "native final target authority check failed"); completed = 0; }
        if (ops->release_target(ops->ctx, c.claim)) { fail(&c, "native mandatory target claim release failed"); completed = 0; }
    }
    if (p && p->free) {
        json_free(p, &c.json);
        if (c.manifest) p->free(p->ctx, c.manifest);
        if (c.chunks) p->free(p->ctx, c.chunks);
        if (c.buffer) p->free(p->ctx, c.buffer);
        if (c.scratch) p->free(p->ctx, c.scratch);
        if (gpt_bytes) p->free(p->ctx, gpt_bytes);
        if (c.szou_table) p->free(p->ctx, c.szou_table);
        if (c.szou_names) p->free(p->ctx, c.szou_names);
        if (c.szou_entries) p->free(p->ctx, c.szou_entries);
        if (c.szou_order) p->free(p->ctx, c.szou_order);
    }
    result->ok = completed && !result->reason[0];
    if (mode != RUN_STRICT_V1) {
        if (!sres->reason[0] && result->reason[0]) copy_string(sres->reason, sizeof sres->reason, result->reason);
        sres->ok = result->ok && !sres->reason[0] &&
                   (mode == RUN_SZOU_RESUME ? sres->committed : sres->final_readback_verified);
        if (p && p->out) {
            p->out(p->ctx, sres->ok ? (mode == RUN_SZOU_RESUME ? "NATIVE-SZOU-RESULT: PENDING_MARKER_ROLLED_FORWARD_NOT_BOOTED\n" :
                                       "NATIVE-SZOU-RESULT: ORIGINAL_USERLAND_STAGED_COMMITTED_READBACK_VERIFIED_NOT_BOOTED\n")
                                    : "NATIVE-SZOU-RESULT: FAIL ");
            if (!sres->ok) { p->out(p->ctx, sres->reason); p->out(p->ctx, "\n"); }
        }
    }
    if (p && p->out) {
        if (result->ok) p->out(p->ctx, "NATIVE-SETUP-RESULT: TARGET_WRITTEN_READBACK_VERIFIED_NOT_BOOTED\n");
        else { p->out(p->ctx, "NATIVE-SETUP-RESULT: FAIL "); p->out(p->ctx, result->reason); p->out(p->ctx, "\n"); }
    }
}

/* Reachable versioned entry; old setup_run host link set stays unchanged. */
void setup_run_native(const plat_t *p, const native_setup_ops_v1_t *ops,
                      const native_setup_request_v1_t *request, native_setup_result_v1_t *result)
{
    native_install_run(p, ops, request, result);
}

void native_install_run(const plat_t *p, const native_setup_ops_v1_t *ops,
                        const native_setup_request_v1_t *request, native_setup_result_v1_t *result)
{
    run(p, ops, 0, request, 0, result, 0, RUN_STRICT_V1);
}

void native_install_run_original_userland(const plat_t *p, const native_setup_ops_v1_t *ops,
    const native_setup_szou_ops_v1_t *sops, const native_setup_request_v1_t *request,
    const native_setup_szou_request_v1_t *sreq, native_setup_result_v1_t *result, native_setup_szou_result_v1_t *sres)
{
    run(p, ops, sops, request, sreq, result, sres, RUN_SZOU_INSTALL);
}

void native_install_resume_original_userland(const plat_t *p, const native_setup_ops_v1_t *ops,
    const native_setup_request_v1_t *request, native_setup_result_v1_t *result, native_setup_szou_result_v1_t *sres)
{
    run(p, ops, 0, request, 0, result, sres, RUN_SZOU_RESUME);
}
