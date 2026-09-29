/* SPDX-License-Identifier: GPL-2.0-only
 * Original read-only FAT32 boot-file reader. Public layout provenance is in
 * REFERENCES.md; no filesystem, firmware or operating-system code is imported.
 */
#include "fat.h"

struct operation {
    struct ntwf_io io;
    struct ntwf_request request;
    struct ntwf_workspace *work;
    struct ntwf_file_info info;
    uint64_t started, last_time, cache_lba[2];
    uint32_t cache_valid[2], first_data, maximum_cluster;
    uint32_t found, attributes, ended;
    uint8_t media;
};

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Volatile byte accesses deliberately prevent compiler-generated libc calls. */
static void zero(void *destination, size_t bytes)
{
    volatile uint8_t *p = destination;
    while (bytes--) *p++ = 0;
}

static void copy(void *destination, const void *source, size_t bytes)
{
    volatile uint8_t *d = destination;
    const volatile uint8_t *s = source;
    while (bytes--) *d++ = *s++;
}

static int valid_range(const void *p, size_t bytes)
{
    return p && bytes && bytes - 1u <= UINTPTR_MAX - (uintptr_t)p;
}

static int overlap(const void *a, size_t na, const void *b, size_t nb)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return x <= y ? y - x < na : x - y < nb;
}

static int separate(const struct ntwf_io *io, const struct ntwf_request *request,
                    struct ntwf_workspace *work, void *destination, size_t capacity,
                    struct ntwf_file_info *info)
{
    const void *p[5] = {io, request, work, destination, info};
    size_t n[5] = {sizeof(*io), sizeof(*request), sizeof(*work), capacity, sizeof(*info)};
    unsigned i, j;
    for (i = 0; i < 5; ++i) {
        if (!valid_range(p[i], n[i])) return 0;
        for (j = 0; j < i; ++j)
            if (overlap(p[i], n[i], p[j], n[j])) return 0;
    }
    return 1;
}

static int name_character(uint8_t c)
{
    static const char punctuation[] = "$%'-_@~`!(){}^#&";
    unsigned i;
    if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return 1;
    for (i = 0; i < sizeof(punctuation) - 1u; ++i)
        if (c == (uint8_t)punctuation[i]) return 1;
    return 0;
}

static int valid_name(const uint8_t name[11])
{
    unsigned i, padding = 0;
    if (name[0] == ' ') return 0;
    for (i = 0; i < 11; ++i) {
        if (i == 8) padding = 0;
        if (name[i] == ' ') padding = 1;
        else if (padding || !name_character(name[i])) return 0;
    }
    return 1;
}

static int clock_remaining(struct operation *o, uint32_t *remaining)
{
    uint64_t now, elapsed;
    if (o->io.now_us(o->io.user, &now) || now < o->last_time) return NTWF_CLOCK;
    o->last_time = now;
    elapsed = now - o->started;
    if (elapsed >= o->request.time_budget_us) return NTWF_TIMEOUT;
    *remaining = o->request.time_budget_us - (uint32_t)elapsed;
    return NTWF_OK;
}

static int read_sector(struct operation *o, uint64_t lba, uint8_t *sector)
{
    uint32_t remaining;
    int result, read_result;
    if (lba >= o->io.sector_count) return NTWF_CORRUPT;
    if (o->info.sector_reads >= o->request.read_budget) return NTWF_LIMIT;
    result = clock_remaining(o, &remaining);
    if (result) return result;
    ++o->info.sector_reads;
    read_result = o->io.read_sector(o->io.user, lba, sector, remaining);
    result = clock_remaining(o, &remaining);
    if (result) return result;
    return read_result ? NTWF_IO : NTWF_OK;
}

static int volume_lba(const struct operation *o, uint64_t offset, uint64_t *lba)
{
    if (offset >= o->info.volume_sectors || offset >= o->info.partition_sectors ||
        offset > UINT64_MAX - o->info.partition_lba) return NTWF_CORRUPT;
    *lba = o->info.partition_lba + offset;
    return *lba < o->io.sector_count ? NTWF_OK : NTWF_CORRUPT;
}

static int partition(struct operation *o)
{
    uint64_t starts[4], ends[4];
    uint32_t counts[4], i, j, selected = o->request.partition_index;
    uint8_t *sector = o->work->sector;
    int result = read_sector(o, 0, sector);
    if (result) return result;
    if (get16(sector + 510) != 0xaa55u) return NTWF_CORRUPT;
    for (i = 0; i < 4; ++i) {
        const uint8_t *entry = sector + 446u + 16u * i;
        uint8_t type = entry[4];
        starts[i] = get32(entry + 8);
        counts[i] = get32(entry + 12);
        if (entry[0] != 0 && entry[0] != 0x80u) return NTWF_CORRUPT;
        if (type == 0xeeu) return NTWF_UNSUPPORTED;
        if (!type) {
            if (starts[i] || counts[i] || entry[0]) return NTWF_CORRUPT;
            ends[i] = 0;
            continue;
        }
        if (!starts[i] || !counts[i]) return NTWF_CORRUPT;
        /* Both operands are on-disk uint32 fields, promoted BEFORE addition. */
        ends[i] = starts[i] + (uint64_t)counts[i];
        if (ends[i] > o->io.sector_count) return NTWF_CORRUPT;
        for (j = 0; j < i; ++j)
            if (counts[j] && starts[i] < ends[j] && starts[j] < ends[i])
                return NTWF_CORRUPT;
    }
    if (!counts[selected]) return NTWF_NOT_FOUND;
    if (sector[446u + 16u * selected + 4u] != 0x0bu &&
        sector[446u + 16u * selected + 4u] != 0x0cu) return NTWF_UNSUPPORTED;
    o->info.partition_lba = starts[selected];
    o->info.partition_sectors = counts[selected];
    return NTWF_OK;
}

static int boot_record(struct operation *o)
{
    uint8_t *p = o->work->sector;
    uint32_t reserved, spc, fats, total, fat_sectors, clusters, root;
    uint16_t flags;
    uint64_t first_data, fat_entries;
    int result = read_sector(o, o->info.partition_lba, p);
    if (result) return result;
    if (get16(p + 510) != 0xaa55u) return NTWF_CORRUPT;
    spc = p[13]; fats = p[16]; reserved = get16(p + 14);
    if (get16(p + 11) != NTWF_SECTOR_BYTES || !spc || spc > 64u || (spc & (spc - 1u)) ||
        !fats || fats > 2u || get16(p + 42)) return NTWF_UNSUPPORTED;
    if (!reserved || get16(p + 17) || get16(p + 19) || get16(p + 22) ||
        get32(p + 28) != o->info.partition_lba) return NTWF_CORRUPT;
    total = get32(p + 32); fat_sectors = get32(p + 36);
    if (!total || !fat_sectors || total > o->info.partition_sectors) return NTWF_CORRUPT;
    first_data = (uint64_t)reserved + (uint64_t)fats * fat_sectors;
    if (first_data >= total) return NTWF_CORRUPT;
    clusters = (total - (uint32_t)first_data) / spc;
    if (clusters < 65525u) return NTWF_UNSUPPORTED;
    if (clusters >= 0x0ffffff6u) return NTWF_CORRUPT;
    fat_entries = (uint64_t)fat_sectors * (NTWF_SECTOR_BYTES / 4u);
    if (fat_entries < (uint64_t)clusters + 2u) return NTWF_CORRUPT;
    root = get32(p + 44);
    if (root < 2u || root > clusters + 1u || root >= 0x0ffffff0u) return NTWF_CORRUPT;
    flags = get16(p + 40);
    if (flags & 0xff70u) return NTWF_UNSUPPORTED;
    o->info.mirrored = (flags & 0x80u) ? 0u : 1u;
    o->info.active_fat = o->info.mirrored ? 0u : flags & 15u;
    if (o->info.active_fat >= fats) return NTWF_CORRUPT;
    o->media = p[21];
    if (o->media != 0xf0u && o->media < 0xf8u) return NTWF_CORRUPT;
    o->info.volume_sectors = total; o->info.sectors_per_cluster = spc;
    o->info.cluster_count = clusters; o->info.root_cluster = root;
    o->info.fat_sectors = fat_sectors; o->info.fat_count = fats;
    o->first_data = (uint32_t)first_data; o->maximum_cluster = clusters + 1u;
    /* The reserved-sector count is recovered from first_data - fats*FATSz,
     * avoiding a second public geometry field or dependence on a stale sector. */
    return NTWF_OK;
}

static int fat_copy_entry(struct operation *o, uint32_t copy_index,
                          uint32_t cluster, uint32_t *value)
{
    uint64_t reserved = (uint64_t)o->first_data -
                        (uint64_t)o->info.fat_count * o->info.fat_sectors;
    uint64_t relative = reserved + (uint64_t)copy_index * o->info.fat_sectors +
                        (cluster >> 7);
    uint64_t lba;
    int result;
    if ((cluster >> 7) >= o->info.fat_sectors) return NTWF_CORRUPT;
    result = volume_lba(o, relative, &lba);
    if (result) return result;
    if (!o->cache_valid[copy_index] || o->cache_lba[copy_index] != lba) {
        result = read_sector(o, lba, o->work->fat_sector[copy_index]);
        if (result) return result;
        o->cache_valid[copy_index] = 1; o->cache_lba[copy_index] = lba;
    }
    *value = get32(o->work->fat_sector[copy_index] + (cluster & 127u) * 4u) & 0x0fffffffu;
    return NTWF_OK;
}

static int fat_entry(struct operation *o, uint32_t cluster, uint32_t *value)
{
    uint32_t other;
    int result = fat_copy_entry(o, o->info.active_fat, cluster, value);
    if (result) return result;
    if (o->info.mirrored && o->info.fat_count == 2u) {
        result = fat_copy_entry(o, 1, cluster, &other);
        if (result) return result;
        if (other != *value) return NTWF_CORRUPT;
    }
    return NTWF_OK;
}

static int next_cluster(struct operation *o, uint32_t cluster, uint32_t *next)
{
    int result = fat_entry(o, cluster, next);
    if (result) return result;
    if (*next >= 0x0ffffff8u) { *next = 0; return NTWF_OK; }
    if (*next < 2u || *next > o->maximum_cluster || *next >= 0x0ffffff0u)
        return NTWF_CORRUPT;
    return NTWF_OK;
}

static int seen(const uint32_t *list, uint32_t count, uint32_t cluster)
{
    uint32_t i;
    for (i = 0; i < count; ++i) if (list[i] == cluster) return 1;
    return 0;
}

static int cluster_sector(struct operation *o, uint32_t cluster, uint32_t index,
                          uint8_t *out)
{
    uint64_t offset, lba;
    int result;
    if (cluster < 2u || cluster > o->maximum_cluster ||
        index >= o->info.sectors_per_cluster) return NTWF_CORRUPT;
    offset = (uint64_t)(cluster - 2u) * o->info.sectors_per_cluster + o->first_data + index;
    result = volume_lba(o, offset, &lba);
    if (result) return result;
    return read_sector(o, lba, out);
}

static int directory_sector(struct operation *o)
{
    uint32_t offset, i;
    for (offset = 0; offset < NTWF_SECTOR_BYTES; offset += 32u) {
        const uint8_t *entry = o->work->sector + offset;
        uint8_t attributes;
        if (!entry[0]) { o->ended = 1; break; }
        if (entry[0] == 0xe5u) continue;
        attributes = entry[11];
        if (attributes == 0x0fu || (attributes & 8u)) continue;
        for (i = 0; i < 11; ++i)
            if (entry[i] != o->request.name[i]) break;
        if (i != 11) continue;
        if (o->found || (attributes & 0xc0u)) return NTWF_CORRUPT;
        o->found = 1; o->attributes = attributes;
        o->info.first_cluster = ((uint32_t)get16(entry + 20) << 16) | get16(entry + 26);
        o->info.file_bytes = get32(entry + 28);
    }
    return NTWF_OK;
}

static int root_directory(struct operation *o)
{
    uint32_t cluster = o->info.root_cluster, following, sector;
    int result;
    while (cluster) {
        if (seen(o->work->root_seen, o->info.root_clusters, cluster)) return NTWF_CORRUPT;
        if (o->info.root_clusters == NTWF_MAX_ROOT_CLUSTERS) return NTWF_LIMIT;
        o->work->root_seen[o->info.root_clusters++] = cluster;
        result = next_cluster(o, cluster, &following);
        if (result) return result;
        for (sector = 0; !o->ended && sector < o->info.sectors_per_cluster; ++sector) {
            result = cluster_sector(o, cluster, sector, o->work->sector);
            if (result) return result;
            result = directory_sector(o);
            if (result) return result;
        }
        /* Even after a directory terminator, validate the complete root chain
         * and retain its ownership set before examining the file's chain. */
        cluster = following;
    }
    if (!o->found) return NTWF_NOT_FOUND;
    return (o->attributes & 0x10u) ? NTWF_UNSUPPORTED : NTWF_OK;
}

static int load_file(struct operation *o, size_t capacity)
{
    uint32_t cluster = o->info.first_cluster, following, sector, remaining;
    uint32_t cluster_bytes = o->info.sectors_per_cluster * NTWF_SECTOR_BYTES;
    uint32_t needed, copied = 0;
    int result;
    if (o->info.file_bytes > NTWF_MAX_FILE_BYTES || o->info.file_bytes > capacity)
        return NTWF_LIMIT;
    if (!o->info.file_bytes) return cluster ? NTWF_CORRUPT : NTWF_OK;
    needed = (o->info.file_bytes - 1u) / cluster_bytes + 1u;
    if (needed > NTWF_MAX_FILE_CLUSTERS) return NTWF_LIMIT;
    remaining = o->info.file_bytes;
    while (remaining) {
        if (cluster < 2u || cluster > o->maximum_cluster || cluster >= 0x0ffffff0u ||
            seen(o->work->root_seen, o->info.root_clusters, cluster) ||
            seen(o->work->file_seen, o->info.file_clusters, cluster)) return NTWF_CORRUPT;
        if (o->info.file_clusters >= needed) return NTWF_CORRUPT;
        o->work->file_seen[o->info.file_clusters++] = cluster;
        result = next_cluster(o, cluster, &following);
        if (result) return result;
        if ((o->info.file_clusters == needed) != (following == 0u)) return NTWF_CORRUPT;
        for (sector = 0; remaining && sector < o->info.sectors_per_cluster; ++sector) {
            uint32_t bytes = remaining < NTWF_SECTOR_BYTES ? remaining : NTWF_SECTOR_BYTES;
            result = cluster_sector(o, cluster, sector, o->work->sector);
            if (result) return result;
            copy(o->work->staging + copied, o->work->sector, bytes);
            copied += bytes; remaining -= bytes;
        }
        cluster = following;
    }
    return NTWF_OK;
}

int ntwf_read_root83(const struct ntwf_io *io, const struct ntwf_request *request,
                     struct ntwf_workspace *work, void *destination, size_t capacity,
                     struct ntwf_file_info *info)
{
    struct operation operation, *o = &operation;
    uint32_t value, remaining;
    int result;
    if (!separate(io, request, work, destination, capacity, info)) return NTWF_INVALID;
    if (io->struct_size != sizeof(*io) || io->abi_version != NTWF_ABI_VERSION ||
        io->reserved || !io->sector_count || !io->read_sector || !io->now_us ||
        request->struct_size != sizeof(*request) || request->abi_version != NTWF_ABI_VERSION ||
        request->partition_index > 3u || !request->read_budget || request->read_budget > NTWF_MAX_READS ||
        !request->time_budget_us || request->time_budget_us > NTWF_MAX_TIME_US ||
        request->reserved || request->padding || !valid_name(request->name)) return NTWF_INVALID;
    if (io->sector_bytes != NTWF_SECTOR_BYTES) return NTWF_UNSUPPORTED;
    zero(o, sizeof(*o));
    copy(&o->io, io, sizeof(*io)); copy(&o->request, request, sizeof(*request));
    o->work = work;
    o->info.struct_size = sizeof(o->info); o->info.abi_version = NTWF_ABI_VERSION;
    o->info.partition_index = request->partition_index;
    if (o->io.now_us(o->io.user, &o->started)) return NTWF_CLOCK;
    o->last_time = o->started;
    result = partition(o);
    if (!result) result = boot_record(o);
    if (!result) {
        result = fat_entry(o, 0, &value);
        if (!result && value != (UINT32_C(0x0fffff00) | o->media)) result = NTWF_CORRUPT;
    }
    if (!result) {
        result = fat_entry(o, 1, &value);
        if (!result && (value & UINT32_C(0x03ffffff)) != UINT32_C(0x03ffffff))
            result = NTWF_CORRUPT;
    }
    if (!result) result = root_directory(o);
    if (!result) result = load_file(o, capacity);
    if (!result) result = clock_remaining(o, &remaining);
    if (result) return result;
    /* No fallible operation follows publication; the caller owns both outputs. */
    copy(destination, work->staging, o->info.file_bytes);
    copy(info, &o->info, sizeof(*info));
    return NTWF_OK;
}
