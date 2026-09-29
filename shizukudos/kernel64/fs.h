/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 in-memory file system (C:\), backed by kernel heap memory, plus a read-only
 * view of the initial RAM archive. NT-style path resolution: case-insensitive components
 * separated by backslashes; names are stored as UTF-8 and compared with ASCII case folding.
 */
#ifndef K64_FS_H
#define K64_FS_H
#include "proc_internal.h"

typedef struct fsnode fsnode_t;
struct fsnode {
    char name[96];
    int is_dir;
    int readonly;                       /* initrd files */
    int delete_pending;
    uint32_t open_count;
    uint32_t attrs;                     /* FILE_ATTRIBUTE_* */
    fsnode_t *parent, *child, *sibling;
    uint8_t *data;
    uint64_t size, cap;
    uint64_t ctime, mtime;
};

typedef struct {
    fsnode_t *node;
    uint64_t pos;
    uint32_t access;                    /* GENERIC/FILE_* rights granted */
    int console;                        /* 0 none, 1 input, 2 output */
    int append;
    uint64_t dir_index;                 /* NtQueryDirectoryFile cursor */
} file_t;

#define FILE_SUPERSEDE 0
#define FILE_OPEN 1
#define FILE_CREATE 2
#define FILE_OPEN_IF 3
#define FILE_OVERWRITE 4
#define FILE_OVERWRITE_IF 5
#define FILE_DIRECTORY_FILE 1
#define FILE_NON_DIRECTORY_FILE 0x40
#define FILE_DELETE_ON_CLOSE 0x1000
#define FILE_ATTRIBUTE_READONLY 1
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define FILE_ATTRIBUTE_NORMAL 0x80

void fs_init(void);
int fs_load_archive(const uint8_t *archive, uint64_t size);          /* returns file count or -1 */
fsnode_t *fs_lookup(const char *path_utf8);                          /* "C:\a\b" or "\a\b" */
fsnode_t *fs_create(const char *path_utf8, int is_dir, int *created); /* creates parents' leaf only */
int fs_read(fsnode_t *n, uint64_t off, void *buf, uint64_t len, uint64_t *done);
int fs_write(fsnode_t *n, uint64_t off, const void *buf, uint64_t len);
int fs_truncate(fsnode_t *n, uint64_t size);
void fs_remove(fsnode_t *n);
fsnode_t *fs_root(void);
uint64_t fs_total_bytes(void);

/* UTF-16 <-> UTF-8 helpers used by the syscall layer. */
int utf16_to_utf8(const uint16_t *src, uint64_t chars, char *dst, uint64_t cap);

/* Archive format produced by tools/mkinitrd.py:
 *   "SHZARC01", u32 count, u32 reserved; count x { char path[120]; u64 offset; u64 size } ; file data. */
#endif
