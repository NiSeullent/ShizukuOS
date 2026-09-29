/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP platform interface. The installer core (install.c, sfsw.c, gpt.c, fat32fmt.c, ini.c, json.c) is portable
 * C99 and reaches the outside world only through this table:
 *   - setup_main.c + blkio.c: SHZSETUP.EXE on Kernel64 (kernel32 files, bcrypt SHA-256/RNG, setup syscalls);
 *   - install/tests/host_install.c: the same core on a Linux host against disk image files (host tests).
 */
#ifndef SHZ_PLAT_H
#define SHZ_PLAT_H
#include <stddef.h>
#include <stdint.h>

#define PLAT_DISK_PARTITION 1u
#define PLAT_DISK_READONLY 2u
#define PLAT_DISK_REMOVABLE 4u

typedef struct plat_disk {
    char name[16];
    char serial[32];
    uint64_t sectors;
    uint32_t sector_size;
    uint32_t flags;                 /* PLAT_DISK_* */
} plat_disk_t;

typedef struct plat {
    void *ctx;
    void (*out)(void *ctx, const char *text);                                   /* console, text as given */
    void *(*alloc)(void *ctx, size_t bytes);                                    /* zeroed, NULL on failure */
    void (*free)(void *ctx, void *p);
    /* files of the install medium (answer file, payload), by path as written in the answer file / manifest */
    int (*file_open)(void *ctx, const char *path, void **handle, uint64_t *size);   /* 0 = ok */
    int (*file_read)(void *ctx, void *handle, uint64_t off, void *buf, uint32_t len);   /* exactly len bytes, 0 = ok */
    void (*file_close)(void *ctx, void *handle);
    /* SHA-256 */
    void *(*sha_begin)(void *ctx);
    void (*sha_update)(void *ctx, void *s, const void *buf, uint32_t len);
    void (*sha_end)(void *ctx, void *s, uint8_t out[32]);
    int (*random)(void *ctx, void *buf, uint32_t len);                          /* 0 = ok */
    uint64_t (*now)(void *ctx);                                                 /* seconds since 1970 UTC */
    /* block devices: whole devices and partitions, stable indices for the run */
    unsigned (*disk_count)(void *ctx);
    int (*disk_info)(void *ctx, unsigned index, plat_disk_t *out);
    int (*disk_read)(void *ctx, unsigned index, uint64_t lba, uint32_t count, void *buf);         /* 0 = ok */
    int (*disk_write)(void *ctx, unsigned index, uint64_t lba, uint32_t count, const void *buf);  /* 0 = ok */
    int (*disk_flush)(void *ctx, unsigned index);
    uint32_t max_io_sectors;                                                    /* per disk_read/disk_write call */
} plat_t;

/* install.c */
enum { SETUP_POWER_NONE = 0, SETUP_POWER_SHUTDOWN = 1, SETUP_POWER_REBOOT = 2 };
typedef struct setup_result {
    int ok;
    int power;                      /* SETUP_POWER_* from the answer file */
    char reason[160];
} setup_result_t;
/* Runs the whole installation. `answer` is the answer file path, `payload_dir` the directory holding manifest.json
 * and the files it names (both as understood by plat->file_open). Prints SETUP-RESULT: OK or FAIL. */
void setup_run(const plat_t *plat, const char *answer, const char *payload_dir, setup_result_t *result);
#endif
