/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 file-system name space: an in-memory file system (C:\), backed by kernel heap memory, plus a read-only
 * view of the initial RAM archive, plus mounted disk volumes (D:\ ... from disk.c: FAT32 over the block registry;
 * read/write when the device and the volume allow it: create, write, extend, truncate, flush; no delete/rename). NT-style path resolution: case-insensitive components separated by backslashes; names are stored as
 * UTF-8 and compared with ASCII case folding. Disk directories are enumerated into fsnodes on first use, so every
 * consumer (lookup, NtQueryDirectoryFile, the loader) sees one node type; disk data is read through the volume's
 * fsvol_t operations instead of a heap buffer.
 */
#ifndef K64_FS_H
#define K64_FS_H
#include "proc_internal.h"

#define FS_NAME_MAX 128                     /* UTF-8 bytes including the terminator (VFAT: up to 255 UTF-16 units) */
enum { FSB_RAM = 0, FSB_DISK = 1 };         /* fsnode backing */

typedef struct fsnode fsnode_t;
typedef struct fsvol fsvol_t;
struct fsnode {
    char name[FS_NAME_MAX];
    int is_dir;
    int readonly;                       /* initrd files and every disk node */
    int delete_pending;
    uint32_t open_count;
    uint32_t attrs;                     /* FILE_ATTRIBUTE_* */
    fsnode_t *parent, *child, *sibling;
    uint8_t *data;                      /* FSB_RAM: heap buffer or a pointer into the initrd */
    uint64_t size, cap;
    uint64_t ctime, mtime;              /* FSB_RAM: kernel ticks (ms) */
    uint64_t id;                        /* unique, stable for the life of the node (FileInternalInformation.IndexNumber) */
    int64_t ft_create, ft_access, ft_write;   /* FILETIME values set with NtSetInformationFile; 0 = derive from ctime/mtime */
    uint8_t backing;                    /* FSB_RAM / FSB_DISK */
    uint8_t populated;                  /* FSB_DISK directory: children enumerated */
    uint32_t first_cluster;             /* FSB_DISK: on-volume location */
    uint32_t dir_cluster, dir_offset;   /* FSB_DISK: where the node's directory entry lives (for size/time updates) */
    fsvol_t *vol;                       /* FSB_DISK: the volume */
    void *chain;                        /* FSB_DISK file: extent cache (owned by the volume code) */
    uint64_t ftime_c, ftime_m;          /* FSB_DISK: FILETIME create / write (0 = unknown) */
    void *view;                         /* kernel file view (kwin.c) while the file backs an image: no writes then */
    char alias[13];                     /* FSB_DISK: 8.3 alias "NAME~1.EXT" when the name has an LFN, else empty */
};

/* A mounted volume: how its nodes are read, enumerated and (when `write` is set) modified. Mutating operations
 * return 0, -1 (I/O error, name refused, read-only) or -2 (volume full). */
struct fsvol {
    char letter;                        /* 'D' ... */
    int (*read)(fsvol_t *v, fsnode_t *n, uint64_t off, void *buf, uint64_t len, uint64_t *done);   /* 0 = ok (short at EOF) */
    int (*populate)(fsvol_t *v, fsnode_t *dir);                                                    /* creates the children */
    int (*write)(fsvol_t *v, fsnode_t *n, uint64_t off, const void *buf, uint64_t len);           /* NULL: read-only */
    int (*truncate)(fsvol_t *v, fsnode_t *n, uint64_t size);
    fsnode_t *(*create)(fsvol_t *v, fsnode_t *dir, const char *name, int is_dir);                 /* NULL on failure */
    int (*flush)(fsvol_t *v);                                                                      /* device cache to media */
    void *priv;
};

typedef struct {
    fsnode_t *node;
    uint64_t pos;
    uint32_t access;                    /* GENERIC/FILE_* rights granted */
    int console;                        /* 0 none, 1 input, 2 output */
    int append;
    uint64_t dir_index;                 /* NtQueryDirectoryFile cursor */
    uint16_t *dir_pattern;              /* NtQueryDirectoryFile FileName filter (heap, NUL-terminated), NULL = all */
    int dir_started;                    /* the first query fixed the pattern */
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
#define FILE_ATTRIBUTE_HIDDEN 2
#define FILE_ATTRIBUTE_SYSTEM 4
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define FILE_ATTRIBUTE_ARCHIVE 0x20
#define FILE_ATTRIBUTE_NORMAL 0x80

void fs_init(void);
int fs_load_archive(const uint8_t *archive, uint64_t size);          /* returns file count or -1 */
fsnode_t *fs_lookup(const char *path_utf8);                          /* "C:\a\b", "\??\D:\a" or "\a\b" (= C:) */
fsnode_t *fs_create(const char *path_utf8, int is_dir, int *created); /* creates parents' leaf only */
fsnode_t *fs_new_child(fsnode_t *dir, const char *name, int is_dir); /* bare node appended to dir (no checks) */
int fs_read(fsnode_t *n, uint64_t off, void *buf, uint64_t len, uint64_t *done);
int fs_write(fsnode_t *n, uint64_t off, const void *buf, uint64_t len);
int fs_truncate(fsnode_t *n, uint64_t size);
int fs_flush(fsnode_t *n);                                           /* disk nodes: device write cache to media */
void fs_remove(fsnode_t *n);
fsnode_t *fs_root(void);
uint64_t fs_total_bytes(void);
/* Mounted volumes: `root` becomes "<letter>:\". 'C' is the RAM root and cannot be replaced. 0 = ok. */
int fs_mount(char letter, fsnode_t *root);
fsnode_t *fs_root_of(char letter);                                   /* NULL when nothing is mounted there */
unsigned fs_volume_number(char letter);                              /* N of \Device\HarddiskVolumeN: C: 1, D: 2, ... (0 = not a letter) */
char fs_volume_letter(unsigned number);                              /* the inverse (0 = none) */
char fs_letter_of(const fsnode_t *n);                                /* drive letter of the volume holding n (0 = unmounted) */
void fs_populate(fsnode_t *dir);                                     /* enumerates a disk directory once (no-op otherwise) */
void fs_node_times(const fsnode_t *n, uint64_t *create_ft, uint64_t *write_ft);   /* FILETIMEs for any backing */

/* UTF-16 <-> UTF-8 helpers used by the syscall layer. */
int utf16_to_utf8(const uint16_t *src, uint64_t chars, char *dst, uint64_t cap);
int utf8_to_utf16(const char *src, uint16_t *dst, uint64_t cap_chars);           /* returns UTF-16 units, -1 if it does not fit */

/* Archive format produced by tools/mkinitrd.py:
 *   "SHZARC01", u32 count, u32 reserved; count x { char path[120]; u64 offset; u64 size } ; file data. */
#endif
