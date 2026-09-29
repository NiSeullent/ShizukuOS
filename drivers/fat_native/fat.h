/* SPDX-License-Identifier: GPL-2.0-only -- original bounded FAT32 reader. */
#ifndef NTW_FAT_NATIVE_H
#define NTW_FAT_NATIVE_H
#include <stddef.h>
#include <stdint.h>

#define NTWF_ABI_VERSION 1u
#define NTWF_SECTOR_BYTES 512u
#define NTWF_MAX_FILE_BYTES 524288u
#define NTWF_MAX_FILE_CLUSTERS 1024u
#define NTWF_MAX_ROOT_CLUSTERS 64u
#define NTWF_MAX_READS 8192u
#define NTWF_MAX_TIME_US 5000000u

enum ntwf_status {
    NTWF_OK = 0, NTWF_INVALID = -1, NTWF_UNSUPPORTED = -2,
    NTWF_IO = -3, NTWF_CORRUPT = -4, NTWF_NOT_FOUND = -5,
    NTWF_LIMIT = -6, NTWF_TIMEOUT = -7, NTWF_CLOCK = -8
};

struct ntwf_io {
    uint32_t struct_size, abi_version, sector_bytes, reserved;
    uint64_t sector_count;
    void *user;
    /* Return 0 only after supplying exactly 512 bytes. Failure may modify out.
     * The callback MUST return within remaining_us, including device recovery,
     * and must not retain out, reenter this reader, or modify other arguments.
     * A hardware binding still needs an independent watchdog: this C interface
     * cannot preempt a hung callback. No write capability is requested. */
    int (*read_sector)(void *user, uint64_t lba, uint8_t out[512],
                       uint32_t remaining_us);
    /* Return 0 and a monotonic microsecond reading. Must return promptly and
     * must not retain out or modify other arguments. Clock failure/backwards
     * movement is an error; a frozen clock is bounded by the read budget. */
    int (*now_us)(void *user, uint64_t *out);
};

struct ntwf_request {
    uint32_t struct_size, abi_version, partition_index;
    uint32_t read_budget, time_budget_us, reserved;
    /* Exact uppercase ASCII 8+3 bytes with trailing space padding, no dot or
     * path. A-Z, 0-9 and $%'-_@~`!(){}^#& are supported. Base is nonempty. */
    uint8_t name[11];
    uint8_t padding;
};

/* Caller-owned private scratch: no initialization required; never copy or
 * access it during a call. Partial sectors/file bytes may remain after error.
 * Keep this large object off the boot stack. No allocation or libc is used. */
struct ntwf_workspace {
    uint8_t staging[NTWF_MAX_FILE_BYTES];
    uint8_t sector[NTWF_SECTOR_BYTES];
    uint8_t fat_sector[2][NTWF_SECTOR_BYTES];
    uint32_t root_seen[NTWF_MAX_ROOT_CLUSTERS];
    uint32_t file_seen[NTWF_MAX_FILE_CLUSTERS];
};

/* Pointer-free metadata, zeroed padding/reserved fields on success. */
struct ntwf_file_info {
    uint32_t struct_size, abi_version, partition_index, file_bytes;
    uint64_t partition_lba;
    uint32_t partition_sectors, volume_sectors, sectors_per_cluster;
    uint32_t cluster_count, root_cluster, first_cluster;
    uint32_t fat_sectors, fat_count, active_fat, mirrored;
    uint32_t root_clusters, file_clusters, sector_reads, reserved;
};

/* Requires stable, exclusively owned/read-only media for the entire call.
 * Supports one explicit primary MBR partition (type 0b/0c), FAT32 revision 0,
 * 512-byte sectors, 1..64 power-of-two sectors/cluster, and one/two FATs.
 * Root short-name regular files only; hidden/system/read-only are accepted.
 * No GPT/extended partition, subdirectory/LFN lookup, repair, write or execute.
 * Inputs, workspace, full destination capacity, and info must be pairwise
 * disjoint valid objects. Numeric overlap checks assume flat x86 addresses.
 * destination must be nonnull, capacity nonzero; an empty file writes no bytes.
 * read_budget=1..8192 and time_budget_us=1..5000000. These are cooperative
 * budgets, not a wall-clock guarantee across an unbounded external callback.
 * On ANY failure, destination and info remain byte-for-byte unchanged.
 * On success, only file_bytes destination bytes change; the tail is untouched.
 * A validated full file is published only after directory/chain validation.
 * This is a boot-file reader, not a filesystem consistency checker or loader.
 */
int ntwf_read_root83(const struct ntwf_io *, const struct ntwf_request *,
                     struct ntwf_workspace *, void *destination, size_t capacity,
                     struct ntwf_file_info *);

_Static_assert(sizeof(struct ntwf_request) == 36, "Request ABI");
_Static_assert(sizeof(struct ntwf_file_info) == 80, "Result ABI");
#endif
