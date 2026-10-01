# FAT32 rename failure repair checkpoint

The isolated repair lives in `/root/Win98-Modern-theme-6970`. It changes
`kernel64/fat32.c`, `fat32.h`, `disk.c` and adds two production-code host tests
and their bounded runner. The main publisher worktree, its index, VM/media and
historical evidence are unchanged by this lane. Root manages this isolated
lane's source commits and public handoff separately from the sole main publisher.

Kernel64 is a ShizukuDOS component serving genuine Windows 98. These storage
results are prerequisites for PMA/storage consistency. They do not establish
ShizukuDOS → WIN.COM → VMM, a native VxD/PMA bridge or complete NT compatibility.

## Defects and implemented behavior

The original production rename removed the destination before creating its
replacement. A later failure could lose the previous file. A failure after
publication could leave two names pointing at the source chain; the theme
caller's temporary cleanup could then free the destination data. The original
disk bridge also published fsnode metadata after failed FAT writes and reported
writable from its callback pointer alone.

The existing generic rename body now joins an outer in-memory undo operation.
Before mutation, it snapshots every mounted FAT page, the exact dirty bitmap,
free-cluster count, allocation hint and FSInfo dirty state. Callbacks and their
context remain unchanged. Each distinct-sector node is allocated and populated
through the raw read callback before the first attempted write. Repeated writes
reuse that first before-image, including failed writes which applied all or part
of their data. An allocation/read/write error prevents more forward writes.

Journal growth uses the current body's geometry ceiling:
`nfats * min(fat_sectors, fat_npages * 8) + 2 * spc + 32` distinct sectors.
This covers cached mirrored FAT sectors, bounded directory growth, source and
destination long entries, `..` and FSInfo. There is no 128-sector file-layout
limit. The FAT snapshot uses the existing 4096-page/16 MiB mount limit.

Rollback restores attempted sectors in reverse capture order and separately
reads back every before-image. It allocates nothing. It restores FAT caches,
dirty state and allocation counters, invalidates the bounce buffer and retains
actual sector I/O counters. Ordinary error follows verified rollback. An undo
error, readback error or mismatch latches `FAT32_E_RECOVERY` on the live volume;
mutation and data-read APIs reject that state. Callback reentrant mutation
returns `FAT32_E_BUSY`. Normal callers still hold the existing volume mutex.

The disk bridge publishes node first cluster, size, time and attributes only
after successful FAT metadata commit. Poisoned write/truncate stops before
installing a node extent cache. Ordinary partial-error commit still keeps
allocated clusters reachable. Recovery blocks flush and reports not writable.

## Actual test history

All roots are direct children of private `build/fat32-rename-6970` in this
worktree. Existing roots are preserved. Each proof counts binaries, logs and
receipt toward its same 8 MiB bound.

| Attempt | Actual outcome | Receipt SHA-256 |
| --- | --- | --- |
| Initial admission for `20261001-red-6970-a1` | BLOCKED before output creation: available 21,293,449,216 B; required 21,483,225,088 B | No root or receipt |
| `20261001-red-6970-a1` retry | Overall FAIL: FAT assertion exposed data loss, but disk link lacked the host `blk_read` boundary; not complete RED | `972707571934b44515f73b3dfc1620e76cc8bc2c97703f6f6cb83bfcc1892890` |
| `20261001-red-6970-a2` | Actual RED: both GCC compiles exited 0, both real-code tests exited 1 at expected assertions against unchanged production | `d3b2fed94e17385f93ea8bbcbb64a7fd79a6e13e52fd53d67c552477cfdddb22` |
| `20261001-green-6970-b1` | HOST/SAN PASS: 1,377 FAT trials and 34 disk checks; all ten command exits 0 | `e4f29f4bd77f81b78a32641ca26f944e5ef8f61d4bd7f3718539023813dbcef7` |
| `20261001-green-6970-b2` | Final HOST/SAN PASS: 1,378 FAT trials and 38 disk checks; all ten command exits 0 | `6d88ef2a5267446a0fb140f7101a294ba9e73df601d1d6944c10f1a927abd1dc` |

Final b2 aggregate: **4,141,873 bytes**, including the receipt. Minimum observed
available space: **21,514,727,424 bytes**, above the 20 GiB reserve. No resource
failure or aborted child occurred. HOST and ASan/UBSan completed identical
results: 105,948,791 byte/cache assertions across 1,378 FAT trials, plus 38 disk
checks. The assertion total includes individual bytes; trials describe executions.

The independently formatted 65525-cluster, two-FAT block array exists only in
process memory. Its FAT copies and FSInfo are checked after fresh remounts.
Both tests execute actual `fat32.c`; the bridge test includes actual `disk.c`.
Host boundaries replace kernel allocation/clock/mutex and route block operations
to actual RAM sectors rather than returning synthetic block success.

Coverage includes same/different sectors, long-name cluster boundaries,
cross-directory replacement, new-target growth, directory `..` moves and a
fragmented destination across 100 FAT sectors/204 writes. Every successful-path
read, write and allocation position is faulted. Before-write, full-write/error
and torn/error cases preserve all original device bytes after verified undo.
Rollback allocation is independently denied and attempts counted after any first
fault. Permanent undo error, dishonest zero-result undo and readback failure
require quarantine. Tests snapshot all FAT pages, dirty bits, free/hint/FSInfo
state and caller extent outputs.

b2 additionally verifies pre-existing pending source-chain and dirty/FSInfo state
survive failed rename, followed by actual cleanup on that same live volume and
fresh remount. It directly exercises bridge read, write, truncate, commit,
temporary removal, flush and writable reporting under recovery. Production FAT
and disk sources were identical between b1 and b2; b2 added focused tests and
HOST/SAN result consistency checking.

## Frozen implementation and final tests

| File under `shizukudos/` | SHA-256 |
| --- | --- |
| `kernel64/fat32.c` | `ee9d5280772b2354ea3351e56c18f01735f6656c03f3854c39ddf369529e07f7` |
| `kernel64/fat32.h` | `28900931b26e57274b7e1e5f30ef85a9ada038e4fdd307b4dae18da3d029a82a` |
| `kernel64/disk.c` | `a19848cbd72b768f00312e8ed0fc87f5a682bcfd4827a9c68161c3f5028f6414` |
| `tests/test_fat32_rename_failures.c` | `dbe635f0b8567f0cf4155a99752c757b9ca631324bebafe261350b4426a15a25` |
| `tests/test_disk_rename_quarantine.c` | `cfa17bd45ca0b5157dcc6cadf109a759d74e1f95d8b2d2401083635539954337` |
| `tests/test_fat32_rename_failures.py` | `c69959396b0dbfd46c8634a5e3ddb94d56dbc576ec077da8b888544573dbb0cd` |

The receipt hashes project headers in the actual compile closure and records
resolved GCC/Clang hashes/versions, exact argv and actual exits. Temporary compiler
outputs use `/dev/shm`. Admission requires 20 GiB plus 8 MiB before output creation
and each process. Live guards bound diagnostics, compiler file sizes and aggregate
outputs, pin the fresh directory and latch reserve failures. Resource or compile
failure cannot become expected RED or PASS.

## Integration and remaining evidence

This is a repair-only additive handoff. Historical owned source lacks main's
independent four-sector FAT batching, `cb_read_many`, `mount_next`/common shutdown
flush registration and interactive raw-installer no-mount guard. The sole main
publisher must preserve all of those changes during three-way integration;
whole-file replacement is inappropriate. This lane creates no PMA scheduler or
cross-domain ABI layout.

RAM undo does not survive reset or power loss and adds no persistent journal or
ordered post-rename durability barrier. HOST/SAN does not link the complete VFS/NT
endpoint, execute kernel code on hardware, exercise the actual Win98 theme GUI or
prove the replacement boot chain. The broad image-based FAT suite was not run:
this lane excludes physical fixtures and VM execution. Those validation and
integration gates remain required; narrow passing receipts do not complete them.
