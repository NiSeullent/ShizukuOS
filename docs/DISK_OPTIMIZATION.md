# ShizukuOS disk I/O candidate — Windows 98 foundation

ShizukuDOS replaces MS-DOS for actual Microsoft Windows 98. Kernel32 and
Kernel64 belong to that foundation. This helper optimizes owned installation
build artifacts while preserving the Windows 98 integration path, source,
licenses, original evidence and all boot-readable logical bytes. Host image
checks do not establish native Windows 98 startup, installation or modern-app
completion. ShizukuOS 1.0.0 remains a development candidate. Official ISOs belong
only on m98.nyase.kr; GitHub hosts source and patches.

`tools/shizuku_image_io.py` supplies three bounded operations:

- `copy_new_sparse`: copies a whole regular image or one bounded range into a
  new file. It hashes the source while copying, verifies its open descriptor
  stayed unchanged, validates an optional expected SHA-256, flushes and reads
  back the exact target hash. Only then does an exclusive hardlink publish the
  new name. Existing targets, symlinks, non-regular sources and invalid ranges
  are refused. All-zero 4 KiB blocks become holes; the final unaligned tail and
  logical file size remain exact. RAM is bounded by 1 MiB chunks.
- `overlay_sparse_partial`: writes a bounded source range into an explicitly
  owned `*.partial` build image. It checks the source pin before any write,
  preserves bytes outside the range, and skips zero writes only when existing
  target bytes are actually zero. Dirty target bytes are cleared. A failed
  partial build is unaccepted and must be discarded by its builder. This API
  must never target original media or a running VM.
- `deduplicate_stage`: verifies a complete selected builder manifest before
  joining identical frozen staged files as hardlinks. Equality includes exact
  size/SHA-256, permissions, owner/group and fixed modification time. Every path
  remains and is rechecked afterwards. Follow with xorriso `--hardlinks` to
  share ISO data extents. It is intended for an owned disposable stage, with
  no subsequent per-alias writes; a failed stage cannot be shipped.

## Minimal integration proposal

The three existing media builder source files are owned by the installer agent
and were not edited by this task. Apply these changes only to an owned build:

1. Import the new helper in `tools/shizuku_se_media.py`. In `make_fat`'s offset
   branch, use `overlay_sparse_partial(fs, image, destination_offset=offset)`
   when `image.name.endswith('.partial')`; retain the existing copy behavior
   for other existing API callers. Preserve the current FAT member readbacks
   and fsck checks.
2. In `tools/build_shizuku_se_disk.py:verify_disk`, use
   `copy_new_sparse(disk, part, source_offset=PART_START * SECTOR)` for the new
   disposable partition scratch image. Read only `SECTOR` bytes from the disk
   and partition for MBR/VBR parsing instead of `read_bytes()[:SECTOR]`.
   Retain the exact syslinux comparison, all member readbacks and FAT check.
3. In `tools/build_shizuku_se_iso.py`, after building `payload` and before
   xorriso, call `pin_stage_times(stage_root)` and build a manifest of only
   payload paths whose final component is `WIN64.IMG`, with existing
   `len(data)` and `sha256(data)` values. Call `deduplicate_stage` on that map,
   then add `--hardlinks` to the existing mkisofs arguments. Keep
   `isolinux.bin`, `boot.cat`, the EFI image, private Windows overlays and
   all boot-patched content outside this selected alias map. Preserve the
   original ISO member/extraction, El Torito, MBR/GPT and EFI proofs. The ISO
   layout and hash will change, so a final BIOS/UEFI boot proof remains required.

This preserves alternate actual boot paths rather than deleting a supposedly
redundant loader, DOS component or runtime. Source notices and corresponding
GPL/LGPL/OFL sources remain present. Proprietary Windows inputs stay private.

## Observed controls and limits

Run the focused suite:

```sh
python3 -B -W error::ResourceWarning -m unittest discover \
  -s tools/tests -p test_shizuku_image_io.py -v
```

Eighteen host tests pass, including actual xorriso image creation where two
retained paths have the same reported extent and both extract to their exact
original bytes. Failure controls include short/zero writes, source mutation,
incorrect pins, flush/readback/link failure, concurrent destination creation,
invalid paths/symlinks, dirty partial targets and preservation of unselected
prefix/suffix bytes. There is no VM execution or native installation result.

One exact receipt-pinned public DOS16 component copy had logical size
33,546,240 bytes, SHA-256
`ae8c441fa6f8e8abdf861432d1a82dd8e5ce9fb3e888ee592cbc145e3ea988d5`.
Dense allocation was 33,546,240 bytes; sparse allocation was 204,800 bytes,
99.389% less, with unchanged logical content and original source fingerprint.
A matched single local copy/source-hash/readback run took 2.337243 seconds dense
and 1.862360 seconds sparse. Earlier cached measurements varied and the earlier
two-pass helper was slower. These are host observations, not a general speed
guarantee or final ISO/USB/install size.

The integration build measured 1,169,063,413 logical regular-file bytes and
1,159,745,536 allocated bytes during an active build. The preserved lab build
measured 242,585,880,284 logical versus 42,426,269,696 allocated bytes, mostly
sparse historical VM/trial images. None were deleted, changed or shipped.
An old installer profile's ESP was 128 MiB dense, `ESP.SIM`16,089,696 bytes,
`SYSTEM.ARC`13,532,580 bytes and `INSTALL.IMG`43,269,464 bytes. These historical
values are not the current final release.

Current `desktop_profile.py` already removes the QA suite while retaining the
actual shell, required runtime DLLs, Wine libraries/fonts and T_HELLO launcher.
The installer boot, installed ESP runtime and installed system tree are
separate consumers. Removing their copies or switching them to compressed
archives requires a new loader/installer ABI and fresh actual boot tests.
`SHZSIMG1` already omits zero blocks in ESP.SIM; it does not allow the guest
installer to assume old target sectors are zero. Current ISO EFI is fitted
FAT16; installed ESP and USB are FAT32. No partition/FAT/cluster/zero-fill/Windows
installation contract is changed here.

Before native Windows98 integration acceptance, verify the original requirements:
ShizukuDOS-to-VMM startup, the user's Windows98 FAT volume and installation,
UEFI GOP scanout, native file persistence, required drivers and acceleration,
Chromium browsing, Discord functionality, Office documents and Steam functions.
Retain source/receipt hashes and compare original app files at their actual paths.
