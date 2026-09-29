/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 on-disk layout: byte offsets and constants of the ext4 format (little-endian) and of the jbd2
 * journal (big-endian), as described in Documentation/filesystems/ext4/ of the Linux kernel. Structures are
 * accessed through offset helpers rather than packed structs so the code has no alignment assumptions.
 */
#ifndef SFS_DISK_H
#define SFS_DISK_H
#include <stdint.h>

/* ---- superblock (1024 bytes at byte offset 1024 of the volume) ---- */
#define SB_OFFSET 1024u
#define SB_MAGIC 0xEF53u
#define SB_inodes_count 0x00
#define SB_blocks_count_lo 0x04
#define SB_r_blocks_count_lo 0x08
#define SB_free_blocks_count_lo 0x0C
#define SB_free_inodes_count 0x10
#define SB_first_data_block 0x14
#define SB_log_block_size 0x18
#define SB_log_cluster_size 0x1C
#define SB_blocks_per_group 0x20
#define SB_clusters_per_group 0x24
#define SB_inodes_per_group 0x28
#define SB_mtime 0x2C
#define SB_wtime 0x30
#define SB_mnt_count 0x34
#define SB_max_mnt_count 0x36
#define SB_magic 0x38
#define SB_state 0x3A
#define SB_errors 0x3C
#define SB_minor_rev_level 0x3E
#define SB_lastcheck 0x40
#define SB_checkinterval 0x44
#define SB_creator_os 0x48
#define SB_rev_level 0x4C
#define SB_def_resuid 0x50
#define SB_def_resgid 0x52
#define SB_first_ino 0x54
#define SB_inode_size 0x58
#define SB_block_group_nr 0x5A
#define SB_feature_compat 0x5C
#define SB_feature_incompat 0x60
#define SB_feature_ro_compat 0x64
#define SB_uuid 0x68
#define SB_volume_name 0x78
#define SB_last_mounted 0x88
#define SB_algorithm_usage_bitmap 0xC8
#define SB_prealloc_blocks 0xCC
#define SB_prealloc_dir_blocks 0xCD
#define SB_reserved_gdt_blocks 0xCE
#define SB_journal_uuid 0xD0
#define SB_journal_inum 0xE0
#define SB_journal_dev 0xE4
#define SB_last_orphan 0xE8
#define SB_hash_seed 0xEC
#define SB_def_hash_version 0xFC
#define SB_jnl_backup_type 0xFD
#define SB_desc_size 0xFE
#define SB_default_mount_opts 0x100
#define SB_first_meta_bg 0x104
#define SB_mkfs_time 0x108
#define SB_jnl_blocks 0x10C
#define SB_blocks_count_hi 0x150
#define SB_r_blocks_count_hi 0x154
#define SB_free_blocks_count_hi 0x158
#define SB_min_extra_isize 0x15C
#define SB_want_extra_isize 0x15E
#define SB_flags 0x160
#define SB_raid_stride 0x164
#define SB_mmp_interval 0x166
#define SB_mmp_block 0x168
#define SB_raid_stripe_width 0x170
#define SB_log_groups_per_flex 0x174
#define SB_checksum_type 0x175
#define SB_kbytes_written 0x178
#define SB_snapshot_inum 0x180
#define SB_error_count 0x194
#define SB_first_error_time 0x198
#define SB_last_error_time 0x1CC
#define SB_mount_opts 0x200
#define SB_usr_quota_inum 0x240
#define SB_grp_quota_inum 0x244
#define SB_overhead_clusters 0x248
#define SB_backup_bgs 0x24C
#define SB_encrypt_algos 0x254
#define SB_encrypt_pw_salt 0x258
#define SB_lpf_ino 0x268
#define SB_prj_quota_inum 0x26C
#define SB_checksum_seed 0x270
#define SB_wtime_hi 0x274
#define SB_mtime_hi 0x275
#define SB_mkfs_time_hi 0x276
#define SB_lastcheck_hi 0x277
#define SB_first_error_time_hi 0x278
#define SB_last_error_time_hi 0x279
#define SB_encoding 0x27C
#define SB_encoding_flags 0x27E
#define SB_orphan_file_inum 0x280
#define SB_checksum 0x3FC

#define SB_STATE_VALID 1u
#define SB_STATE_ERROR 2u
#define SB_STATE_ORPHAN 4u
#define SB_FLAG_SIGNED_HASH 1u
#define SB_FLAG_UNSIGNED_HASH 2u
#define SB_CHECKSUM_CRC32C 1u
#define SB_REV_DYNAMIC 1u
#define SB_GOOD_OLD_INODE_SIZE 128u
#define SB_GOOD_OLD_FIRST_INO 11u

/* feature_compat */
#define COMPAT_DIR_PREALLOC 0x1u
#define COMPAT_IMAGIC_INODES 0x2u
#define COMPAT_HAS_JOURNAL 0x4u
#define COMPAT_EXT_ATTR 0x8u
#define COMPAT_RESIZE_INODE 0x10u
#define COMPAT_DIR_INDEX 0x20u
#define COMPAT_SPARSE_SUPER2 0x200u
#define COMPAT_FAST_COMMIT 0x400u
#define COMPAT_STABLE_INODES 0x800u
#define COMPAT_ORPHAN_FILE 0x1000u
/* feature_incompat */
#define INCOMPAT_COMPRESSION 0x1u
#define INCOMPAT_FILETYPE 0x2u
#define INCOMPAT_RECOVER 0x4u
#define INCOMPAT_JOURNAL_DEV 0x8u
#define INCOMPAT_META_BG 0x10u
#define INCOMPAT_EXTENTS 0x40u
#define INCOMPAT_64BIT 0x80u
#define INCOMPAT_MMP 0x100u
#define INCOMPAT_FLEX_BG 0x200u
#define INCOMPAT_EA_INODE 0x400u
#define INCOMPAT_DIRDATA 0x1000u
#define INCOMPAT_CSUM_SEED 0x2000u
#define INCOMPAT_LARGEDIR 0x4000u
#define INCOMPAT_INLINE_DATA 0x8000u
#define INCOMPAT_ENCRYPT 0x10000u
#define INCOMPAT_CASEFOLD 0x20000u
#define INCOMPAT_SUPPORTED (INCOMPAT_FILETYPE | INCOMPAT_RECOVER | INCOMPAT_META_BG | INCOMPAT_EXTENTS | INCOMPAT_64BIT | \
                            INCOMPAT_FLEX_BG | INCOMPAT_EA_INODE | INCOMPAT_CSUM_SEED | INCOMPAT_LARGEDIR | \
                            INCOMPAT_INLINE_DATA | INCOMPAT_ENCRYPT | INCOMPAT_CASEFOLD)
/* feature_ro_compat */
#define RO_COMPAT_SPARSE_SUPER 0x1u
#define RO_COMPAT_LARGE_FILE 0x2u
#define RO_COMPAT_BTREE_DIR 0x4u
#define RO_COMPAT_HUGE_FILE 0x8u
#define RO_COMPAT_GDT_CSUM 0x10u
#define RO_COMPAT_DIR_NLINK 0x20u
#define RO_COMPAT_EXTRA_ISIZE 0x40u
#define RO_COMPAT_HAS_SNAPSHOT 0x80u
#define RO_COMPAT_QUOTA 0x100u
#define RO_COMPAT_BIGALLOC 0x200u
#define RO_COMPAT_METADATA_CSUM 0x400u
#define RO_COMPAT_REPLICA 0x800u
#define RO_COMPAT_READONLY 0x1000u
#define RO_COMPAT_PROJECT 0x2000u
#define RO_COMPAT_VERITY 0x8000u
#define RO_COMPAT_ORPHAN_PRESENT 0x10000u
#define RO_COMPAT_SUPPORTED (RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE | RO_COMPAT_HUGE_FILE | RO_COMPAT_GDT_CSUM | \
                             RO_COMPAT_DIR_NLINK | RO_COMPAT_EXTRA_ISIZE | RO_COMPAT_METADATA_CSUM | RO_COMPAT_PROJECT)
#define RO_COMPAT_FORCES_RO (RO_COMPAT_QUOTA | RO_COMPAT_READONLY | RO_COMPAT_VERITY | RO_COMPAT_ORPHAN_PRESENT)

/* ---- block group descriptor (32 bytes, 64 with INCOMPAT_64BIT and s_desc_size >= 64) ---- */
#define GD_block_bitmap_lo 0x00
#define GD_inode_bitmap_lo 0x04
#define GD_inode_table_lo 0x08
#define GD_free_blocks_count_lo 0x0C
#define GD_free_inodes_count_lo 0x0E
#define GD_used_dirs_count_lo 0x10
#define GD_flags 0x12
#define GD_exclude_bitmap_lo 0x14
#define GD_block_bitmap_csum_lo 0x18
#define GD_inode_bitmap_csum_lo 0x1A
#define GD_itable_unused_lo 0x1C
#define GD_checksum 0x1E
#define GD_block_bitmap_hi 0x20
#define GD_inode_bitmap_hi 0x24
#define GD_inode_table_hi 0x28
#define GD_free_blocks_count_hi 0x2C
#define GD_free_inodes_count_hi 0x2E
#define GD_used_dirs_count_hi 0x30
#define GD_itable_unused_hi 0x32
#define GD_exclude_bitmap_hi 0x34
#define GD_block_bitmap_csum_hi 0x38
#define GD_inode_bitmap_csum_hi 0x3A
#define GD_MIN_SIZE 32u
#define GD_MIN_SIZE_64BIT 64u
#define BG_INODE_UNINIT 0x1u
#define BG_BLOCK_UNINIT 0x2u
#define BG_INODE_ZEROED 0x4u

/* ---- inode (s_inode_size bytes; the first 128 are the classic layout) ---- */
#define IN_mode 0x00
#define IN_uid 0x02
#define IN_size_lo 0x04
#define IN_atime 0x08
#define IN_ctime 0x0C
#define IN_mtime 0x10
#define IN_dtime 0x14
#define IN_gid 0x18
#define IN_links_count 0x1A
#define IN_blocks_lo 0x1C
#define IN_flags 0x20
#define IN_version 0x24
#define IN_block 0x28
#define IN_generation 0x64
#define IN_file_acl_lo 0x68
#define IN_size_high 0x6C
#define IN_obso_faddr 0x70
#define IN_blocks_high 0x74
#define IN_file_acl_high 0x76
#define IN_uid_high 0x78
#define IN_gid_high 0x7A
#define IN_checksum_lo 0x7C
#define IN_reserved 0x7E
#define IN_extra_isize 0x80
#define IN_checksum_hi 0x82
#define IN_ctime_extra 0x84
#define IN_mtime_extra 0x88
#define IN_atime_extra 0x8C
#define IN_crtime 0x90
#define IN_crtime_extra 0x94
#define IN_version_hi 0x98
#define IN_projid 0x9C
#define IN_BLOCK_BYTES 60u

#define IFL_SECRM 0x1u
#define IFL_IMMUTABLE 0x10u
#define IFL_APPEND 0x20u
#define IFL_INDEX 0x1000u
#define IFL_HUGE_FILE 0x40000u
#define IFL_EXTENTS 0x80000u
#define IFL_EA_INODE 0x200000u
#define IFL_INLINE_DATA 0x10000000u
#define IFL_ENCRYPT 0x800u
#define IFL_CASEFOLD 0x40000000u
#define IFL_VERITY 0x100000u

#define INO_BAD 1u
#define INO_ROOT 2u
#define INO_USR_QUOTA 3u
#define INO_GRP_QUOTA 4u
#define INO_BOOT_LOADER 5u
#define INO_UNDEL_DIR 6u
#define INO_RESIZE 7u
#define INO_JOURNAL 8u

/* ---- extent tree ---- */
#define EXT_MAGIC 0xF30Au
#define EH_magic 0x00
#define EH_entries 0x02
#define EH_max 0x04
#define EH_depth 0x06
#define EH_generation 0x08
#define EH_SIZE 12u
#define EE_block 0x00          /* extent: first logical block */
#define EE_len 0x04            /* > 0x8000 means unwritten, length = ee_len - 0x8000 */
#define EE_start_hi 0x06
#define EE_start_lo 0x08
#define EE_SIZE 12u
#define EI_block 0x00          /* index: covers logical blocks from ei_block */
#define EI_leaf_lo 0x04
#define EI_leaf_hi 0x08
#define EI_SIZE 12u
#define EXT_INIT_MAX_LEN 32768u
#define EXT_UNWRITTEN_MAX_LEN 32767u
#define EXT_MAX_DEPTH 5u
#define EXT_MAX_LBLK 0xFFFFFFFFu

/* ---- directory entries ---- */
#define DE_inode 0x00
#define DE_rec_len 0x04
#define DE_name_len 0x06
#define DE_file_type 0x07
#define DE_name 0x08
#define DE_HDR 8u
#define DE_TAIL_SIZE 12u       /* ext4_dir_entry_tail: inode 0, rec_len 12, name_len 0, file_type 0xDE, checksum */
#define DE_TAIL_FT 0xDEu
#define DX_ROOT_INFO 0x18      /* dx_root_info follows "." (12 bytes) and ".." (12 bytes) */
#define DXI_reserved_zero 0x00
#define DXI_hash_version 0x04
#define DXI_info_length 0x05
#define DXI_indirect_levels 0x06
#define DXI_unused_flags 0x07
#define DX_ROOT_ENTRIES 0x20   /* dx_countlimit + first block at 0x20 in the root */
#define DX_NODE_ENTRIES 0x08   /* in interior nodes: fake dirent (8 bytes) then countlimit */
#define DXE_hash 0x00
#define DXE_block 0x04
#define DXE_SIZE 8u
#define DX_TAIL_SIZE 8u        /* dx_tail: dt_reserved, dt_checksum */
#define DX_HASH_LEGACY 0
#define DX_HASH_HALF_MD4 1
#define DX_HASH_TEA 2
#define DX_HASH_LEGACY_UNSIGNED 3
#define DX_HASH_HALF_MD4_UNSIGNED 4
#define DX_HASH_TEA_UNSIGNED 5
#define DX_HASH_SIPHASH 6

/* ---- jbd2 journal (big-endian) ---- */
#define JBD2_MAGIC 0xC03B3998u
#define JBD2_DESCRIPTOR_BLOCK 1u
#define JBD2_COMMIT_BLOCK 2u
#define JBD2_SUPERBLOCK_V1 3u
#define JBD2_SUPERBLOCK_V2 4u
#define JBD2_REVOKE_BLOCK 5u
#define JH_magic 0x00
#define JH_blocktype 0x04
#define JH_sequence 0x08
#define JH_SIZE 12u
#define JS_blocksize 0x0C
#define JS_maxlen 0x10
#define JS_first 0x14
#define JS_sequence 0x18
#define JS_start 0x1C
#define JS_errno 0x20
#define JS_feature_compat 0x24
#define JS_feature_incompat 0x28
#define JS_feature_ro_compat 0x2C
#define JS_uuid 0x30
#define JS_nr_users 0x40
#define JS_dynsuper 0x44
#define JS_max_transaction 0x48
#define JS_max_trans_data 0x4C
#define JS_checksum_type 0x50
#define JS_num_fc_blks 0x54
#define JS_head 0x58
#define JS_checksum 0xFC
#define JS_users 0x100
#define JS_SIZE 1024u
#define JBD2_COMPAT_CHECKSUM 0x1u
#define JBD2_INCOMPAT_REVOKE 0x1u
#define JBD2_INCOMPAT_64BIT 0x2u
#define JBD2_INCOMPAT_ASYNC_COMMIT 0x4u
#define JBD2_INCOMPAT_CSUM_V2 0x8u
#define JBD2_INCOMPAT_CSUM_V3 0x10u
#define JBD2_INCOMPAT_FAST_COMMIT 0x20u
#define JBD2_INCOMPAT_SUPPORTED (JBD2_INCOMPAT_REVOKE | JBD2_INCOMPAT_64BIT | JBD2_INCOMPAT_ASYNC_COMMIT | \
                                 JBD2_INCOMPAT_CSUM_V2 | JBD2_INCOMPAT_CSUM_V3 | JBD2_INCOMPAT_FAST_COMMIT)
#define JBD2_CRC32C_CHKSUM 4u
#define JBD2_FLAG_ESCAPE 1u
#define JBD2_FLAG_SAME_UUID 2u
#define JBD2_FLAG_DELETED 4u
#define JBD2_FLAG_LAST_TAG 8u
#define JC_chksum_type 0x0C    /* commit header after the 12-byte header */
#define JC_chksum_size 0x0D
#define JC_chksum 0x10
#define JC_commit_sec 0x30
#define JC_commit_nsec 0x38
#define JR_count 0x0C          /* revoke header: r_count = bytes used including this 16-byte header */
#define JR_HDR 16u
#define JBD2_DEFAULT_MAX_COMMIT_AGE 5u
#endif
