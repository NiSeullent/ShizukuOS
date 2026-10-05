/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: empty FAT32 volume formatter for the optional Windows 98 partition (p3). The partition is created empty:
 * no Microsoft file is ever bundled; the user installs their own Windows 98 there. Parameters follow Microsoft's
 * "FAT: General Overview of On-Disk Format" 1.03 (BPB, FAT size formula, FSInfo, backup boot sector).
 */
#ifndef SHZ_FAT32FMT_H
#define SHZ_FAT32FMT_H
#include <stdint.h>

typedef struct fat32_io {
    void *ctx;
    int (*write)(void *ctx, uint64_t sector, uint32_t count, const void *buf);    /* 512-byte sectors, volume-relative */
} fat32_io;

typedef struct fat32_params {
    uint64_t sectors;           /* volume size in 512-byte sectors */
    uint32_t hidden;            /* sectors before the volume on the disk (partition start LBA) */
    uint32_t volume_id;
    char label[11];             /* space padded */
} fat32_params;

/* Returns 0, or -1 (too small/large for FAT32), -2 (I/O). *clusters_out receives the data cluster count. */
int fat32_format(const fat32_io *io, const fat32_params *p, uint32_t *clusters_out);

/* Independent read-only FAT32 decoder used by SHZSETUP to read the installed ESP back from the target disk (it shares
 * no state with the host-built image or with the formatter above). Every sector is fetched through `read` with a
 * volume-relative LBA that is checked against `sectors` first. Cluster chains are bounded by the volume's cluster
 * count and by the exact file size; a chain that is too short, too long, loops or leaves the volume is corrupt.
 * Directory names match their long (VFAT, checksum-verified) or short 8.3 names, ASCII case-insensitively. */
enum { FAT32R_OK = 0, FAT32R_EBPB = -1, FAT32R_EIO = -2, FAT32R_ENOENT = -3, FAT32R_ECORRUPT = -4, FAT32R_ESINK = -5 };
typedef struct fat32_rio {
    void *ctx;
    int (*read)(void *ctx, uint64_t sector, uint32_t count, void *buf);           /* 512-byte sectors, volume-relative */
    uint64_t sectors;                                                             /* volume (partition) size bound */
} fat32_rio;
typedef struct fat32_vol {
    fat32_rio io;
    uint32_t hidden, spc, rsvd, nfats, fat_sectors, root, clusters;
    uint64_t data_start;
    uint32_t fat_cached;                        /* FAT sector held in `fat` (0xffffffff = none) */
    uint8_t fat[512], dir[512];
} fat32_vol;
typedef int (*fat32_sink)(void *ctx, const void *data, uint32_t len);      /* nonzero stops with FAT32R_ESINK */
int fat32_mount(fat32_vol *v, const fat32_rio *io);
/* path: '/'-separated, absolute. *first = first cluster (0 for an empty file). */
int fat32_lookup(fat32_vol *v, const char *path, uint32_t *first, uint32_t *size, int *is_dir);
/* Streams exactly `size` bytes of the chain at `first` through `sink`; `cbuf` must hold spc*512 bytes. */
int fat32_stream(fat32_vol *v, uint32_t first, uint32_t size, uint8_t *cbuf, fat32_sink sink, void *sink_ctx);
const char *fat32_rstrerror(int err);

/* Bounded same-size in-place overwrite of an existing file's data (installer stamping of \SHZDOS\SHZBOOT.MAN).
 * Looks `path` up through the reader above, refuses a directory, an empty file or a size other than `size`, walks the
 * whole cluster chain first (every link valid, no loop, at most ceil(size / cluster) clusters, then end-of-chain) and
 * only then writes: each data cluster is read, the file bytes inside it replaced (slack after the end of file kept)
 * and written back through `write`, with the same volume-relative bound check as reads. No FAT entry, directory entry
 * or FSInfo sector is written and nothing is allocated. Returns FAT32R_* (FAT32R_ESIZE on size/type mismatch).
 * `cbuf` must hold spc*512 bytes. A failed write may leave the file partly overwritten; callers re-read and verify. */
enum { FAT32R_ESIZE = -6, FAT32R_EWRITE = -7 };
typedef int (*fat32_wfn)(void *ctx, uint64_t sector, uint32_t count, const void *buf);  /* volume-relative */
int fat32_overwrite_file(fat32_vol *v, fat32_wfn write, void *wctx, const char *path, const void *data, uint32_t size,
                         uint8_t *cbuf);
#endif
