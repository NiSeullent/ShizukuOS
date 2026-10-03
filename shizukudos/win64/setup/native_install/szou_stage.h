/* SPDX-License-Identifier: GPL-2.0-only
 * SZOU v1 relocation + staging + cold-boot commit for the original-userland
 * install phase.
 *
 * Protocol (roll-forward, crash-consistent at file granularity):
 *  1. Plan: every manifest path is relocated under an optional target root
 *     (final = <target_root>\<path>) and under a single stage directory
 *     (staged = <stage_root>\<path>). Both must fit SZOU_PATH_MAX and the
 *     stage directory must not collide with any relocated top component.
 *  2. Stage: stream each payload from the retained source into the staged
 *     file while hashing, compare SHA-256, flush, then re-read the staged
 *     file through the sink and hash again (actual readback).
 *  3. Mark: write SZOUPEND.TMP (marker header + verbatim entry table), flush,
 *     rename-replace to SZOUPEND.SYS, flush. The rename is the commit point.
 *  4. Commit (immediately, or on the next cold boot from SZOUPEND.SYS alone):
 *     move each staged file over its final path, apply attributes, verify
 *     already-moved files by hash, remove stage directories, flush, remove
 *     the marker, flush. Every step is idempotent so an interrupted commit
 *     is rerun from the marker; it is never rolled back or retried on a
 *     different backend.
 *
 * The sink is the actual target-volume file authority. This module performs
 * no raw sector I/O. When no file authority is bound the API returns
 * SZOU_E_NO_AUTHORITY; it never pretends files were written.
 */
#ifndef SHZ_SZOU_STAGE_H
#define SHZ_SZOU_STAGE_H
#include "szou_manifest.h"

#define SZOU_MARKER_NAME     "SZOUPEND.SYS"
#define SZOU_MARKER_TMP      "SZOUPEND.TMP"
#define SZOU_MARKER_BYTES    640u      /* fixed marker header before the entry table */
#define SZOU_MARKER_MAGIC    "SZOUPEND"
#define SZOU_ABSENT          1         /* positive sink status: path does not exist */

/* Target-volume file authority. Every call returns 0 on actual completion,
 * SZOU_ABSENT where documented, or a negative SZOU_E_* error. Paths are
 * volume-relative, backslash-separated, already validated. */
typedef struct szou_sink_ops {
    void *ctx;
    void *(*alloc)(void *ctx, size_t bytes);            /* zeroed or NULL */
    void (*free)(void *ctx, void *p);
    int (*mkdir)(void *ctx, const char *path);           /* SZOU_E_EXISTS if present */
    int (*rmdir)(void *ctx, const char *path);           /* empty dir; SZOU_ABSENT if missing */
    int (*create)(void *ctx, const char *path, uint64_t size, void **file); /* fails SZOU_E_EXISTS */
    int (*open)(void *ctx, const char *path, void **file, uint64_t *size);  /* SZOU_ABSENT if missing */
    int (*read)(void *ctx, void *file, uint64_t off, void *buf, uint32_t len);
    int (*write)(void *ctx, void *file, uint64_t off, const void *buf, uint32_t len);
    int (*close)(void *ctx, void *file);                 /* always consumes; reports flush failure */
    int (*rename_replace)(void *ctx, const char *from, const char *to); /* atomic in-volume */
    int (*remove)(void *ctx, const char *path);          /* SZOU_ABSENT if missing */
    int (*set_attr)(void *ctx, const char *path, uint32_t attributes);
    int (*flush)(void *ctx);                             /* volume metadata + data durable */
    /* v2 long-name ops (required when SZLN records are present; never emulated
     * by dropping the long name). lname = UTF-16 units of the final component,
     * bound to the exact existing 8.3 alias of `path`/`to`.
     * mkdir_named: 0 created; SZOU_E_EXISTS if the directory exists with exactly
     * this long name (attributes re-applied); SZOU_E_CONFLICT otherwise. */
    int (*mkdir_named)(void *ctx, const char *path, const uint16_t *lname, uint16_t units, uint32_t attributes);
    /* rename_named: like rename_replace, destination published with its LFN chain. */
    int (*rename_named)(void *ctx, const char *from, const char *to, const uint16_t *lname, uint16_t units);
} szou_sink_ops_t;

typedef struct szou_plan_opts {
    const char *target_root; /* "" or a validated relative directory, e.g. "WINDOWS" root prefix */
    const char *stage_root;  /* single component, e.g. "SZSTAGE.NEW" */
} szou_plan_opts_t;

typedef struct szou_stage_result {
    uint32_t files_staged, files_committed, files_already_final, dirs_created;
    uint64_t bytes_written, bytes_read_back;
    int marker_written, committed, failed_index; /* failed_index -1 if none */
} szou_stage_result_t;

/* Build relocated final/staged path for entry e. 0 or SZOU_E_PATH. */
int szou_plan_path(const szou_plan_opts_t *o, const char *rel, int staged, char out[SZOU_PATH_FIELD]);

/* Validate the whole relocation plan without touching the target. */
int szou_plan_check(const szou_plan_opts_t *o, const szou_entry_t *entries, uint32_t count);

/* v2: relocated directory paths of the SZLN records also fit and do not collide. */
int szou_plan_check_names(const szou_plan_opts_t *o, const szou_name_t *names, uint32_t count);

/* Steps 1..3 for v1 images. A v2 header is refused (SZOU_E_VERSION): long
 * names are never silently discarded; use szou_stage_named. */
int szou_stage(const szou_plan_opts_t *o, const szou_header_t *h, const szou_entry_t *entries,
               szou_read_fn rd, void *rd_ctx, const szou_sink_ops_t *sink,
               uint8_t *buf, uint32_t buf_bytes, szou_stage_result_t *res);

/* Steps 1..3 for v1 (names NULL, count 0) or v2 (validated SZLN records).
 * v2 marker = header(version 2, name count at 0x240) + entry table + SZLN
 * header + canonical records, so the cold-boot commit needs nothing else. */
int szou_stage_named(const szou_plan_opts_t *o, const szou_header_t *h, const szou_entry_t *entries,
                     const szou_name_t *names, uint32_t name_count,
                     szou_read_fn rd, void *rd_ctx, const szou_sink_ops_t *sink,
                     uint8_t *buf, uint32_t buf_bytes, szou_stage_result_t *res);

/* Step 4 from the persisted marker only (cold-boot safe). Returns SZOU_ABSENT
 * when no marker is pending. */
int szou_commit_pending(const szou_sink_ops_t *sink, uint8_t *buf, uint32_t buf_bytes,
                        szou_stage_result_t *res);
#endif
