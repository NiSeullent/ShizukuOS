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
/* Interactive installer contract, separate from the portable platform table.
 * Identity is supplied by the kernel authority, never synthesized from an ordinal,
 * name or serial. A plan is a read-only snapshot; its check must succeed again
 * immediately before the first destructive write. */
#define SETUP_PLAN_VERSION 1u
#define SETUP_LANGUAGE_KO 1u
#define SETUP_LANGUAGE_EN 2u
#define SETUP_KEYBOARD_US 1u
#define SETUP_PREFS_MAGIC 0x46505a53u /* SZPF, little endian */
#define SETUP_PREFS_PATH "/SHZ/SETUP/FIRSTBOOT.CFG"
typedef struct setup_preferences {
    uint32_t magic, version, language, keyboard;
} setup_preferences_t;
_Static_assert(sizeof(setup_preferences_t) == 16, "FIRSTBOOT.CFG v1 wire size");

typedef struct setup_target {
    plat_disk_t disk;
    uint8_t whole_id[16];
    uint64_t generation;
    unsigned index;
    uint32_t authority_flags; /* kernel BLK_F_*, distinct from PLAT_DISK_* */
} setup_target_t;

typedef struct setup_image {
    char product[128];
    uint8_t manifest_sha256[32];
    uint64_t esp_bytes, payload_bytes, payload_files, required_bytes;
} setup_image_t;

typedef struct setup_plan {
    uint32_t version, language, keyboard, partitions;
    setup_target_t target;
    setup_image_t image;
    uint64_t first[3], last[3];
    uint64_t required_bytes, system_used_bytes, workspace_bytes;
    uint32_t bios_boot, erase_whole_disk;
} setup_plan_t;

enum setup_phase {
    SETUP_PHASE_PREFLIGHT=1, SETUP_PHASE_WIPE, SETUP_PHASE_ESP,
    SETUP_PHASE_ESP_VERIFY, SETUP_PHASE_SYSTEM, SETUP_PHASE_SYSTEM_VERIFY,
    SETUP_PHASE_LEGACY, SETUP_PHASE_GPT, SETUP_PHASE_LOG, SETUP_PHASE_DONE
};
typedef struct setup_event {
    uint32_t phase, cancellable, destructive, verified_complete;
    uint64_t io_bytes, files_done, files_total;
} setup_event_t;
typedef struct setup_control {
    void *ctx;
    /* 0 = exact source/target still authorized. Nonzero fails closed. The
     * transport binds whole_id/generation to a process-owned claimed target. */
    int (*check)(void *ctx, const setup_plan_t *plan);
    int (*cancel_requested)(void *ctx);
    void (*event)(void *ctx, const setup_event_t *event);
} setup_control_t;

/* These execute actual manifest parsing and the existing ShizukuFS planner.
 * No disk_write or disk_flush is called by either read-only function. */
int setup_image_inspect(const plat_t *, const char *payload, setup_image_t *, setup_result_t *);
int setup_plan_build(const plat_t *, const char *payload, const setup_target_t *,
                     uint32_t language, setup_plan_t *, setup_result_t *);
void setup_run_planned(const plat_t *, const char *answer, const char *payload,
                       const setup_plan_t *, const setup_control_t *, setup_result_t *);
#endif
