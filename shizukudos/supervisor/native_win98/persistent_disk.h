/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_PERSISTENT_DISK_H
#define SHZ_WIN98_PERSISTENT_DISK_H
#include "disk_backend.h"
#define W98_PERSIST_ESP_SECTORS 4718592u
#define W98_PERSIST_DISK_SECTORS 4194304u
#define W98_PERSIST_VOLUME_ID 0x53485739u
#define W98_PERSIST_MAX_CLUSTERS (1u << 20)
#define W98_PERSIST_MAX_EXTENTS 4096u
#define W98_PERSIST_MAX_DIRS 128u
/* Raw owned Supervisor device, always512B sectors; unlike Kernel64 blk_flush,
 * a missing persistence barrier never means successful durable completion. */
typedef struct {
    uint64_t sectors;
    void *opaque;
    int (*read)(void *, uint64_t, unsigned, void *);
    int (*write)(void *, uint64_t, unsigned, const void *);
    int (*flush)(void *);
} w98_owned_block_t;
typedef struct { uint32_t first, count; uint64_t device_lba; } w98_disk_extent_t;
typedef struct { uint32_t first, parent; uint8_t depth, shzdos; } w98_disk_dir_t;
typedef struct { uint8_t name[11], directory; } w98_disk_name_t;
typedef struct {
    w98_owned_block_t block;
    uint32_t clusters, spc, reserved, fat_sectors, data_lba, root;
    uint32_t extents, dirs, entries_seen, names_seen, fat_cache_sector;
    uint64_t metadata_observation_fnv64;
    uint8_t admitted, failed, busy, fat_cache_valid;
    uint8_t seen[W98_PERSIST_MAX_CLUSTERS / 8];
    uint8_t fat_cache[512], sector[512], mirror[512];
    w98_disk_extent_t extent[W98_PERSIST_MAX_EXTENTS];
    w98_disk_dir_t directory[W98_PERSIST_MAX_DIRS];
    w98_disk_name_t name[4096];
} w98_persist_disk_t;
/* Explicit opt-in. Reads/validates existing metadata only; no allocation or FAT
 * writes. Caller owns/excludes the selected device and map for their lifetime.
 * Admission never authenticates an arbitrary physical device on its own. */
int w98_persist_disk_init(w98_persist_disk_t *, uint32_t, const w98_owned_block_t *);
int w98_persist_disk_backend(w98_persist_disk_t *, w98_disk_backend_t *);
#endif
