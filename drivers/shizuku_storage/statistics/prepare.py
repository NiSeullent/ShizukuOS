#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Strict transforms for newly copied, opt-in paired SeaBIOS sources."""
from pathlib import Path


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"Source seam is not unique: {old[:100]!r}")
    return text.replace(old, new, 1)


def instrument(corrected, capacity):
    if capacity not in (2048, 16384):
        raise ValueError("Only the matched 2KiB/16KiB profiles are admitted")
    text = replace_once(corrected, "u32 bounce_buf_size VARFSEG;",
                        'u32 bounce_buf_size VARFSEG;\n#include "shzstorage_statistics.h"')
    text = replace_once(text, "u32 size = 16384;", "u32 size = SHZ_STORAGE_PROFILE_CAPACITY;")
    text = replace_once(text, "    if (!buf) {\n        size = CDROM_SECTOR_SIZE;",
                        "    if (!buf && size != CDROM_SECTOR_SIZE) {\n        size = CDROM_SECTOR_SIZE;")
    text = replace_once(text, "    bounce_buf_size = size;", "    bounce_buf_size = size;\n    shz_storage_stats.actual_capacity = size;")
    text = replace_once(text, "    u16 orig_count = op->count;\n    if (!orig_count)\n        return 0;\n\n    u8 *bounce = GET_GLOBAL(bounce_buf_fl);\n    u32 capacity = GET_GLOBAL(bounce_buf_size);\n    u16 blksize = GET_FLATPTR(op->drive_fl->blksize);",
                        "    u16 orig_count = op->count;\n    u16 blksize = orig_count ? GET_FLATPTR(op->drive_fl->blksize) : 0;\n    u32 capacity = GET_GLOBAL(bounce_buf_size);\n    int observed = shz_stats_begin(op, blksize, capacity);\n    if (!orig_count) {\n        shz_stats_finish(observed, 0, 0, 0);\n        return 0;\n    }\n\n    u8 *bounce = GET_GLOBAL(bounce_buf_fl);")
    text = replace_once(text, "        op->count = 0;\n        return DISK_RET_EPARAM;\n    }\n    u16 max_chunk",
                        "        op->count = 0;\n        shz_stats_finish(observed, 0, DISK_RET_EPARAM, 1);\n        return DISK_RET_EPARAM;\n    }\n    u16 max_chunk")
    text = replace_once(text, "        rc = call32(process_op_32, MAKE_FLATPTR(GET_SEG(SS), op),\n                    DISK_RET_EPARAM);\n        u16 completed = op->count;",
                        "        shz_stats_dispatch(observed);\n        rc = call32(process_op_32, MAKE_FLATPTR(GET_SEG(SS), op),\n                    DISK_RET_EPARAM);\n        u16 completed = op->count;\n        int oversized = completed > this_count;")
    text = replace_once(text, "        if (!iswrite && completed)\n            memcpy_fl(this_buf, bounce, (u32)completed * blksize);",
                        "        shz_stats_chunk(observed, this_count, completed, blksize,\n                        op->command, rc, oversized);\n        if (!iswrite && completed)\n            memcpy_fl(this_buf, bounce, (u32)completed * blksize);")
    text = replace_once(text, "    op->count = done;\n    op->lba = orig_lba;\n    return rc;",
                        "    op->count = done;\n    op->lba = orig_lba;\n    shz_stats_finish(observed, done, rc, 0);\n    return rc;")
    return text


def write_private(tree, corrected, capacity):
    source = Path(__file__).with_name("statistics.h")
    (tree / "src/shzstorage_statistics.h").write_bytes(source.read_bytes())
    (tree / "src/shzstorage_profile.h").write_text(
        "/* Private opt-in matched profile; no default config change. */\n"
        f"#define SHZ_STORAGE_PROFILE_CAPACITY {capacity}\n")
    (tree / "src/block.c").write_text(instrument(corrected, capacity))
