# ShizukuFS v0 disk format and host tools

> **Deprecated.** ShizukuFS v0 (this Python format) is superseded by **ShizukuFS v1**, which *is* the ext4 on-disk
> format (bidirectionally compatible with Linux ext2/3/4 and e2fsprogs): the portable C library, its host tests and
> the Kernel64 mount live in [`v1/`](v1/) and are documented in
> [`docs/shizukudos10/SHIZUKUFS.md`](../docs/shizukudos10/SHIZUKUFS.md). v0 is kept only so existing v0 images and
> tests keep working; no new code should target it.

ShizukuFS v0 is a new block filesystem experiment for the Windows 98
Shizuku's Second Edition project. Its host creator/reader can create a disk
image, store and extract files, create and remove directories, allocate and
free blocks, and verify integrity. It is **not** a DOS or Windows 98 IFS
driver, boot partition, or FAT32-compatible volume. The current ShizukuDOS
boot experiment still uses its separate FAT12 image.

The source and format documentation are GPL-2.0-only project work. No Wine,
ReactOS, or FAT implementation is copied here. The on-disk structures use
fixed-width little-endian fields so a future real-mode reader and Win9x IFS
can implement the same parser without a Python runtime.

## Host use

Run these commands from the repository root with Python 3.10 or newer:

```powershell
New-Item -ItemType Directory -Force shizukufs/build | Out-Null
python -m shizukufs create shizukufs/build/example.img --blocks 256
python -m shizukufs mkdir shizukufs/build/example.img /docs
python -m shizukufs put shizukufs/build/example.img README.md /docs/readme.txt
python -m shizukufs ls shizukufs/build/example.img /docs
python -m shizukufs get shizukufs/build/example.img /docs/readme.txt shizukufs/build/copy.txt
python -m shizukufs verify shizukufs/build/example.img
python -m shizukufs rm shizukufs/build/example.img /docs/readme.txt
```

An 8-GiB **logical** image, larger than FAT32's maximum single file, can be
created on a host filesystem that supports sparse files (for example NTFS):

```powershell
python -m shizukufs create shizukufs/build/sparse-8g.img --blocks 2097152
python -m shizukufs put shizukufs/build/sparse-8g.img README.md /readme.txt
python -m shizukufs get shizukufs/build/sparse-8g.img /readme.txt shizukufs/build/readme-copy.txt
python -m shizukufs verify shizukufs/build/sparse-8g.img
```

The JSON report includes `logical_bytes` and `allocated_bytes`. On Windows,
the creator marks the file sparse before extending it with a 64-bit Win32 file
offset; the ordinary C runtime truncate path can allocate large zero ranges.
The host measures physical allocation with `GetCompressedFileSizeW`; on POSIX
hosts it uses `st_blocks`. For images of at least 4 GiB, creation fails and
removes its new file if sparse support or allocation measurement is unavailable,
or if the empty image needs over 64 MiB of physical storage. Actual allocation
grows as file content is added. A FAT32 host volume cannot store this image.

`put` replaces an existing regular file at the same path. `get` requires a
destination that does not exist. Paths inside the image are absolute,
forward-slash-separated, case-sensitive NFC Unicode paths. Each component is
1–255 UTF-8 bytes; `.` and `..` are forbidden. Directory records preserve
long UTF-8 names without FAT's 8.3 alias or LFN record scheme. There are no
hard links. `rm` removes regular files or empty directories.

To run meaningful roundtrip, allocation, and corruption tests:

```powershell
python -m unittest discover -s shizukufs/tests -v
```

The host creator and reader limit images to 32–4,194,304 blocks (128 KiB–16
GiB logical), which bounds each allocation bitmap to 512 KiB and keeps the
metadata in memory. The on-disk total is 64-bit and block links are 32-bit;
the host's 16-GiB cap is stricter than the field range. A single host copy-on-
write operation is limited to 65,536 payload blocks (about 255 MiB) so its
block list and validation work remain bounded. `read_file` returns at most
64 MiB in memory; `get` streams extraction. The fixed 256-entry inode table is
another v0 capacity limit. These are host-tool limits, not guest support.
The distinct v0 features are versioned metadata generations, checksummed
contents, native UTF-8 names, and copy-on-write updates.

## Block layout

Every block is exactly 4,096 bytes. The image length is exactly
`total_blocks × 4096` and must be block aligned.

- Blocks 0 and 1: alternate superblocks. A valid superblock selects the
  metadata slot with the same index. The reader chooses the highest valid
  generation whose superblock and metadata CRC both pass.
- Metadata slot 0 begins at block 2. Metadata slot 1 immediately follows it.
  Each slot consists of `bitmap_blocks` allocation-bitmap blocks followed by
  eight inode-table blocks. `bitmap_blocks = ceil(total_blocks / 32768)`.
- Data begins at `2 + 2 × (bitmap_blocks + 8)`. Every earlier block is
  reserved. In the bitmap, bit `block % 8` of byte `block / 8` is 1 when
  allocated. Bits beyond `total_blocks` in the last bitmap block are also 1.
- Data blocks have a 16-byte header and 4,080-byte payload. A file or
  directory occupies a singly linked chain of data blocks. An empty regular
  file has no chain; a directory always has its eight-byte directory header.

All unmentioned/reserved bytes must be zero. CRC32 is the standard reflected
IEEE CRC32, represented as an unsigned little-endian 32-bit integer. The
checksum inputs are byte-exact; CRC32 does not provide cryptographic
authenticity.

### Superblock at block 0 or 1

The first 80 bytes contain these fields; bytes 80–4095 are zero:

```text
offset  size  field
0       8     magic = ASCII "SHIZFS00"
8       2     major version = 0
10      2     minor version = 0
12      4     header size = 128
16      4     block size = 4096
20      8     total_blocks
28      4     bitmap_blocks
32      4     inode_blocks = 8
36      4     inode_count = 256
40      4     data_start
44      4     active metadata slot = superblock index (0 or 1)
48      8     generation (starts at 1)
56      8     free data block count
64      4     free inode count (2..255)
68      4     CRC32 of the entire active bitmap + inode table
72      4     root inode = 1
76      4     CRC32 of bytes 0..127 with this field set to zero
```

The superblock CRC detects a torn header; the metadata CRC detects a partial
or corrupted metadata slot. A supported format version with an invalid
length, derived layout, slot index, reserved byte, or counter is rejected.

### Inode table

There are 256 fixed 128-byte entries. All-zero entries are free. Inode 0 is
reserved and must remain zero. Inode 1 is the root directory and its parent
is itself. Inodes 2–255 can hold files or directories.

```text
offset  size  field
0       4     magic = ASCII "SZIN"
4       4     inode number, equal to table index
8       1     kind: regular file = 1, directory = 2
9       1     flags = 0
10      2     reserved = 0
12      4     parent inode
16      8     logical byte size
24      4     first data block, or 0 for an empty regular file
28      4     data block count = ceil(size / 4080)
32      4     CRC32 of exactly `size` logical bytes
36      8     generation that last changed this inode
44      84    reserved zeroes
```

Data block header:

```text
offset  size  field
0       4     magic = ASCII "SZDB"
4       4     owner inode number
8       4     next data block, or 0 at chain end
12      4     CRC32 of all 4080 payload bytes (including zero padding)
16      4080  payload
```

The whole-content CRC in the inode protects logical contents; the per-block
CRC also protects unused payload bytes. A chain length mismatch, loop,
out-of-range block, reused block, wrong owner, or bitmap mismatch is corrupt.

### Directory payload

A directory's logical contents are a normal checksummed inode data chain.
The byte stream begins with `"SZDR"` (4 bytes) and a little-endian 32-bit
entry count. Each entry then has a 32-bit child inode, 8-bit kind, 8-bit name
length, 16-bit zero reserved field, `name length` UTF-8 bytes, and zero bytes
to align the next entry to a 4-byte boundary. Entries are strictly sorted by
raw UTF-8 name bytes and cannot duplicate a name. Each child must be
referenced exactly once by its declared parent and with the same kind as its
inode. The root must be the only inode without a directory reference.

## Update and recovery rule

A mutation first validates the current image. It allocates blocks from the
current free bitmap, writes new data chains without changing blocks still
referenced by the current generation, and records old chains for release.
It then writes the complete alternate bitmap/inode slot, flushes it, writes
the alternate superblock with `generation + 1`, and flushes again. The new
bitmap releases old chains only after the new content is reachable. The
reader ignores a torn or CRC-invalid new generation and can select the
previous valid generation. It does **not** silently roll back when the
highest valid generation has a corrupt data block; `verify` reports that
failure.

This host sequence uses `fsync` but is not a proof of crash consistency on
an actual BIOS/Win9x storage stack. A future driver must provide suitable
write ordering and barriers. Two metadata generations are recovery slots,
not permanent snapshots: after later commits, blocks unique to an older
generation can be reused. A copy-on-write update needs free blocks for the
new content and any changed parent directory. On a completely full volume,
even `rm` may need space to rewrite its parent directory and can fail with
`NoSpace`; a production version needs an emergency reserve or journaled
deletion path.

## Integrity checks and scope

`verify` checks both checksums and structural invariants: exact image size,
version and reserved fields, root and inode counters, all data-chain CRCs,
logical file CRCs, unique block ownership, directory ordering and UTF-8,
parent/child agreement, reachability, bitmap equality with live chains, and
free-space counts. Bitmap comparison works on bitmap bytes and allocated
chains, rather than reading every unallocated 4-KiB block. Tests cover an
8-GiB sparse file with under 64 MiB allocated, a real data chain beyond the
4-GiB byte offset, file roundtrip/extraction, and high-offset corruption, as
well as roundtrip and replacement across multiple
blocks, nested UTF-8 names, extraction, deletion and block reuse, full-disk
rollback, data corruption, metadata fallback, superblock damage, unknown
version, path rejection, and truncation.

The v0 format has no permissions, timestamps, hard links, symlinks, in-volume
sparse files, compression, case-insensitive lookup, or concurrent writer protocol.
Its 256-inode limit and linear block allocator are development constraints.
No Windows 98 application can mount or boot this image yet.

## Porting boundary for ShizukuDOS and Win98

A read-only implementation should begin with: read 4-KiB blocks through a
real block device; validate both superblocks and metadata CRCs; select the
latest valid generation; traverse the inode chains and directory records;
and reject corruption using the same invariants. The DOS side then needs a
drive/device interface, while Windows 98 needs a real Installable File System
integration and its path, cache, sharing, and error contracts. Writing needs
block allocation, copy-on-write metadata commit, and verified storage write
ordering. The existing FAT12 ShizukuDOS boot path remains independent until
such code actually loads this volume in a guest test.
