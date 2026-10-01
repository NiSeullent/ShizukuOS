# Original Windows 98 IO.SYS UEFI entry port

This profile prepares the actual Microsoft Windows 98 IO.SYS first stage for
an opt-in CSMWrap UEFI bootstrap. The original IO.SYS continues loading its own
remaining bytes through SeaBIOS disk services and retains the original DOS and
Windows 98 VMM boot path. The GOP handoff comes from the existing firmware GOP
integration. This is an IO.SYS bootstrap and runtime entry-hook port; it does
not recompile Microsoft's IO.SYS source or use an independent operating system.

`prepare.py` is original GPL-2.0-only project code. It contains generic MBR,
FAT32 and capsule algorithms, small entry-identification signatures, and no
embedded Windows file. CSMWrap and SeaBIOS retain their own upstream licenses.
Capsules contain private original Windows bytes and must stay with the owner's
local media under the ignored `build/` tree. Do not commit or redistribute them.

## Read-only preparation

From the repository root, with a private raw disk image and the independently
recorded SHA-256 of its complete original IO.SYS:

```sh
python3 -B shizukudos/iosys_uefi/prepare.py \
  build/shizukudos/csm/run-win98-native-clean-pc-tcg-control/windows-native.raw \
  --io-sha256 1df17834b5c7744a3af92c20e4edaa8e0fdb78eca6da7a01db3538d59b2d1430 \
  --output build/shizukudos/iosys-uefi-port/IOSYS.BIN
```

The output parent directory must already exist. The command opens the disk
read-only, analyzes one immutable snapshot, and creates the capsule using `xb`.
An existing output is an error. It checks the original disk's complete digest,
inode, size and modification metadata before and after writing. A source change
rejects preparation and removes only the output created by that invocation.
The JSON report goes to stdout; errors go to stderr with exit status 2. There
are no downloads, guest launches, disk writes or application execution. Importing
the module does not run the CLI.

`create_capsule(disk_bytes, expected_io_sha256)` returns `(capsule_bytes, report)`.
`parse_capsule(capsule_bytes)` validates the wire contract and returns JSON-safe
metadata. Both require immutable `bytes`; invalid input raises `CapsuleError`.
The report binds the raw image, complete IO.SYS, raw VBR and capsule hashes,
derived geometry and entry registers. `guest_executed` is false and
`runtime_compatibility` remains `unverified`.

The supported input has one active primary MBR partition of type `0b` or `0c`,
a signed original VBR beginning with `EB` and an unmodified byte 2 of `90`, and
512-byte FAT32 sectors. The BPB drive byte must designate a BIOS hard disk
(`80..ff`). Sectors per cluster must be a power of two from 4 to
128, so the original four-sector prefix is contiguous within its first cluster.
The FAT32 cluster count must be at least 65,525, and its FAT capacity, reserved
area, hidden sectors, root cluster, partition extents and 32-bit LBAs must agree.
GPT, overlapping partitions, ambiguous active flags and invalid geometry fail
closed. The original loader uses the first FAT, so an alternate active FAT is
unsupported. When mirroring is enabled, every traversed entry must agree across
the FAT copies.

The preparer follows the complete root-directory chain and finds exactly one
short-name `IO      SYS` file. Deleted entries and long-filename records are
ignored. Invalid attributes, directory loops, file loops, free/bad/reserved
clusters, premature end-of-chain, an overlong chain and root/file overlap are
errors. The full file must be at least 2,048 bytes, match the supplied full-file
SHA-256, start with `MZ`, contain `42 4a 8b 46 fc 8b 56 fe` at file offset `200`,
and contain `MS` at `7fe`. These identify the supported first-stage contract;
the caller's digest pins the precise input. They do not establish provenance or
compatibility of every Windows version.

## Capsule ABI

The capsule contains exactly 2,688 bytes: a 128-byte header, the untouched
512-byte original VBR, and the untouched first 2,048 bytes of IO.SYS. Integers
are little-endian. The sum of all 672 unsigned 32-bit words, including the
checksum word, must be zero modulo `2^32`.

| Header offset | Size | Value |
| --- | --- | --- |
| `00` | 8 | `SHZIO98` followed by NUL |
| `08` | 2 | Version `1` |
| `0a` | 2 | Header bytes `128` |
| `0c` | 4 | Total bytes `2688` |
| `10` | 4 | Additive checksum |
| `14` | 4 | Required flags `3`: disk binding and GOP entry hook |
| `18` | 4 | Active partition start LBA |
| `1c` | 4 | Absolute first data LBA |
| `20` | 4 | IO.SYS first cluster |
| `24` | 4 | Complete IO.SYS file bytes |
| `28` | 4 | IO.SYS first absolute LBA |
| `2c` | 4 | Prefix bytes `2048` |
| `30` | 4 | VBR/BPB bytes `512` |
| `34` | 4 | Reserved, zero |
| `38` | 32 | Complete IO.SYS SHA-256 |
| `58` | 32 | Raw original VBR SHA-256 |
| `78` | 1 | Drive byte from raw BPB offset `40` |
| `79` | 1 | Runtime-only marker `partition_type OR 02` |
| `7a` | 1 | Original partition type `0b` or `0c` |
| `7b` | 1 | Reserved, zero |
| `7c` | 4 | Reserved, zero |
| `80` | 512 | Raw original VBR |
| `280` | 2048 | Raw IO.SYS first stage |

The checksum detects accidental corruption; it is not an authenticity signature.
The parser verifies the raw VBR hash and all sizes, signatures, constants,
reserved fields and derived cluster/LBA relationships. The capsule carries a
full IO.SYS digest but only a prefix: the parser cannot recompute the full-file
digest without the original disk. The preparer does verify that complete digest.

## Original entry evidence

The local source checkpoint is
`build/shizukudos/csm/run-win98-native-clean-pc-tcg-control/windows-native.raw`.
Its active FAT32 partition starts at LBA 63. Its BPB has 32 reserved sectors,
two 4,091-sector FATs, eight sectors per cluster and root cluster 2. Consequently
the absolute first data LBA is 8,277. The extracted original IO.SYS is 224,150
bytes with SHA-256
`1df17834b5c7744a3af92c20e4edaa8e0fdb78eca6da7a01db3538d59b2d1430`.
Its first cluster is 58,184 and first absolute LBA is 473,733. These checkpoint
values are evidence examples; the preparer derives every field from its input.

Private extraction and disassembly evidence lives in
`build/shizukudos/iosys-uefi-port/io-entry-audit/`:

- `FAT32-boot3.bin`: raw VBR, FSInfo and actual second-stage sectors.
- `FAT32-sector2.disasm.txt`: second-stage sector decoded at physical `8000`.
- `IO-SYS-offset200.disasm.txt`: original IO.SYS decoded from file offset `200`.
- `IO.SYS`, `MSDOS.SYS`, `WIN.COM` and `VMM32.VXD`: private identity inputs.

`FAT32-sector2.disasm.txt` shows `mov bx,0700` at `80d5`, `mov cx,4` at `80d9`,
the disk-read helper call at `80dc`, `MZ` and `BJ` checks at `80e4` and `80ea`,
and bytes `ea 00 02 70 00` at `80f8`, the far jump to `0070:0200`.
The VBR therefore loads exactly the first 2,048 IO.SYS bytes to physical `0700`.
The complete file is not placed there. Original MSLOAD reads the remaining file.

| State at original entry | Required value or derivation |
| --- | --- |
| `CS:IP` | `0070:0200` |
| `DS`, `ES`, `SS` | `0000` |
| `SS:SP` | `0000:7bf0` |
| `BP` | `7c00`, pointing to the VBR |
| `BX`, `CX` | `0700`, `0000` |
| `SI`, `DI` | High and low 16 bits of the IO.SYS first cluster |
| Direction and interrupt flags | `DF=0`, `IF=1` |
| `[0000:7bfc]` | Absolute first data LBA, 32 bits |
| `[0000:7bf8]` | `ffffffff`, original FAT-cache scratch sentinel |
| Words at `7bf0`, `7bf2`, `7bf4`, `7bf6` | `0078`, `0000`, previous INT1E offset, previous INT1E segment |
| VBR at `0000:7c00` | Original 512 bytes, with memory-only byte `7c02` changed to `partition_type OR 02` |

IO.SYS at `202` and `205` consumes `[SS:BP-4]` and `[SS:BP-2]`; at `211` and
`215` it saves `DI` and `SI`. Four pops at `219..21c` consume the original VBR
stack words, preserving the previous INT1E pointer. The runtime bridge must
snapshot the actual SeaBIOS INT1E vector at physical `78` after preparing CSM16.
It must not invent vector contents.

There is no assumed `DL=80` entry contract. The original disk-read helper uses
`PUSHA`/`POPA` and leaves the caller's LBA-related `DX`; the later EDD path gets
its drive byte from copied BPB offset `40`. The capsule preserves that drive
byte. Binding it to the actual firmware disk is a runtime requirement.

Original MSLOAD first uses INT12 to choose its higher conventional-memory
relocation; the bridge must retain the BIOS environment. At IO.SYS offset `25a`,
it saves the raw VBR word at `[SS:BP+1ee]`, copies 90 BPB bytes, then copies a
NUL-terminated string from that saved offset using `SS`. In the inspected VBR
the raw word is `017e`. Preserve it exactly and retain the existing low-memory
BIOS state; replacing it with an invented `7d7e` pointer is unsupported.

Original MSLOAD at `5ec..617` chooses its EDD path using copied VBR byte 0 of
`eb` and byte 2 of `0c` or `0e`. The original VBR first-stage partition lookup
supplies the memory-only type marker; the raw disk's byte 2 remains `90`.
Subsequent INT13 service, error-path INT10/INT16 and conventional-memory BIOS
services remain necessary. This profile ports bootstrap entry while SeaBIOS
provides those original Windows boot interfaces.

## Integration and validation boundary

The isolated `build.py` stages the locally cached, pinned CSMWrap source and its
SeaBIOS submodule into a new private build tree. It rejects a different commit
or modified tracked source and does not download dependencies. It applies the
existing helper and firmware GOP patches plus
`patches/0001-direct-iosys.patch`. The normal CSMWrap path remains selected by
default; direct entry requires both `gop_only=true` and `iosys_boot=true`.

```sh
python3 -B shizukudos/iosys_uefi/build.py --jobs 1
```

Default build output is `build/shizukudos/iosys-uefi-port/firmware/`, containing
`CSMWRAP.EFI`, `Csm16.bin`, `vgabios.bin`, `make.log` and `build-result.json`.
The receipt binds upstream pins, applied patch hashes, the builder source and
the emitted firmware hashes. The build contains the original project hook;
IO.SYS bytes are supplied separately by the owner's capsule at runtime.

The saved patch implements these steps:

1. Read the private `EFI/BOOT/IOSYS.BIN` capsule before ExitBootServices and
   validate its signatures, checksum and geometry. Read the actual EFI boot
   partition's original VBR and four IO.SYS sectors through BlockIO and require
   an exact match to the capsule payload.
2. After PCI relocation and the existing firmware GOP handover publication,
   copy and validate the finalized 96-byte `SHZGOP1` descriptor. This first
   consumer accepts a bounded, linear BGRX32 framebuffer below 4 GiB.
3. Complete ordinary CSM16 `Legacy16PrepareToBoot`. Seed the original IO.SYS
   prefix at `0700`, original VBR at `7c00`, BIOS stack and derived entry state.
   Apply the type marker only to the in-memory VBR.
4. Change the in-memory IO.SYS entry's eight bytes to `e9 fd 56` plus five NOPs.
   `0070:0200` now reaches the original real-mode hook at physical `6000`.
   The hook validates the descriptor snapshot at `6800`, emits the 32-byte
   `IO98GOP1` consumed marker at `6880` and bounded UART evidence, restores
   registers and flags, replays the displaced eight original bytes,
   and jumps to original MSLOAD at `0070:0208` (physical `0908`).

Only guest RAM is patched. The original IO.SYS file, VBR and source archive are
retained. The bridge deliberately skips the original VBR's scratch copy to
physical `0522`, which overlaps the low coreboot handover table at `0500`.
Later original Windows code still depends on the BIOS environment supplied by
CSMWrap/SeaBIOS. Entry consumption of the GOP descriptor does not by itself
establish a Windows display-driver binding.

`boot.py` wraps the existing native Windows 98 runner, creates a new private
disk clone, adds the private capsule and EFI files to that clone, and readbacks
and revalidates original IO.SYS after injection. It permits only the audited
complete IO.SYS hash shown above. All existing runner media/receipt controls
apply. Supply `--csm-dir` explicitly to select the isolated firmware build:

```sh
python3 -B shizukudos/iosys_uefi/boot.py \
  --io-sha256 1df17834b5c7744a3af92c20e4edaa8e0fdb78eca6da7a01db3538d59b2d1430 \
  --archive /path/to/owner-checkpoint.qcow2.xz \
  --checkpoint-record /path/to/owner-checkpoint.json \
  --csm-dir build/shizukudos/iosys-uefi-port/firmware \
  --firmware-gop --machine q35 --accel kvm --smp 2 --memory 128 \
  --timeout 120 --run-name original-iosys-uefi-entry
```

This command requires local QEMU, GDB, firmware and the receipt-bound checkpoint.
It launches a bounded guest without a NIC and writes only its private run tree
and clone. Unlike `prepare.py`, the boot wrapper executes the original guest
and permits guest writes to that disposable clone. It never boots the source
archive or an earlier run's disk in place.

The wrapper pauses its owned guest for a private GDB hardware breakpoint at
physical `0908`. Before detaching, it captures original MSLOAD resume registers,
entry bytes, the GOP descriptor and consumed marker, the original stack/VBR,
and the independent INT1E vector. It checks the audited registers and `DF/IF`,
the entry redirect, complete original VBR with its one memory marker change,
four stack words, FAT-cache sentinel and first-data LBA. The debugger phase is
bounded and completes before the ordinary runner starts checking guest health.
Evidence is retained under
`build/shizukudos/iosys-uefi-port/runs/<run-name>/native-entry/`, with the
aggregate `iosys-entry-result.json` beside the native runner's `result.json`.

Host capsule tests establish safe parsing and preparation. A firmware build
establishes compile/link integration. A successful entry result establishes
the captured original MSLOAD resume and GOP consumption within that guest run.
Windows desktop, driver support and modern application execution require their
own retained evidence; they are not inferred from an entry marker. See
`docs/PREVIEW_EVIDENCE.md` for the wider evidence boundary and parallel-session
handoff.

`test_runtime_contract.py` compiles the actual C capsule parser from the source
patch and verifies a valid volume, the exact 32-bit LBA limit, and rejection of
volume-end overflow even when the four IO.SYS sectors fit. It also verifies that
a passing entry proof cannot hide a failed native GUI/file test. The wrapper
records the separate native status/exit code and its result digest, and returns
failure when either the requested native checks or the entry proof fail.

```sh
python3 -B -m unittest discover -s shizukudos/iosys_uefi \
  -p 'test_runtime_contract.py' -v
```

The 2026-09-30 `win98-iosys-gop-83bd-20260930b` actual OVMF/KVM trial passes
all ten entry checks in
`build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-83bd-20260930b/iosys-entry-result.json`.
The debugger captured `CS=0070, IP=0208, SS/DS/ES=0, SP=7bf0, BP=7c00,
SI=0, DI=e348, BX=0700, CX=0, FLAGS=0202`, the checksum-valid GOP descriptor,
its independently written consumed marker, the complete stack/VBR and INT1E
vector. Archive and original IO.SYS hashes remain unchanged. This establishes
the original Windows entry port. Later c/d trials connect the corrected main
GOP driver and reach the actual Windows 98 desktop and Notepad. Trial d reads
the physical GOP framebuffer at `80000000`; its 1280x800 BGRX32 image matches
the independent screen at all but 16 of 1,024,000 RGB pixels. The helper
`review_framebuffer.py --run <completed-run> --capture 25` checks retained
entry/locator/hash evidence and writes a decoded raster plus exact comparison
counts, without inferring application or file-save success. Root visually
reviewed the actual Windows desktop, Notepad and Save As dialog.

The strict fresh-file save/readback trials c/d failed. Trial d's returned file
retains an inherited token. Those failed native runner receipts remain intact,
separate from the passing IO.SYS entry and GOP screen comparison. See
`docs/IO_SYS_UEFI_COORDINATION_83BD.md` for the exact run receipts and scope.
The earlier `...20260930a` trial is retained as a failed capture: GDB treated
quoted dump filenames literally. The wrapper now uses its private working
directory and relative dump filenames, and preserves its exact executed source.

For an explicitly selected quiescent owned source run, `--reflink-source`
creates a distinct private COW inode. The private runner and allocation helper
are frozen by their actual source hashes. The canonical CSM runner is unchanged.
Linux XFS FIEMAP observations distinguish shared from exclusive extents; ordinary
`st_blocks` growth cannot measure COW overwrites. Unsupported filesystems,
unstable maps, unexpected flags, changed source anchors or ownership ambiguity
abort the run. Keep the source inode alive throughout the trial.
Runtime samples briefly pause the already running owned VM and verify its
paused state before observing allocations. The wrapper resumes it only after
the strict observation, quota, free-space and five-second checks pass; it also
verifies the resumed state. A failed observation is never followed by `cont`.

`--dirty-budget-mib 128` selects a stricter net exclusive data allocation quota;
the default is 256 MiB. Both keep the independent filesystem reserve at least
20 GiB. Allocation uncertainty, a quota violation or any unhandled monitored
runtime failure immediately kills only the owned VM before final diagnostics.
The final accounting observation runs after the VM stops. This measures current
mapped file data, excluding metadata, COW staging and cumulative historical
writes. The free-space guard remains necessary for those excluded allocations.

`--max-guest-file-mib 64` explicitly permits digest-bound private inputs up to
64 MiB **in total**, still with at most eight inputs and the existing absent-path,
backup, receipt and no-NIC requirements. This allows a genuine statically linked
WTF/ICU executable without relaxing native component acceptance. The default
per-file limit remains 1 MiB. Original IO.SYS entry checks and native application
verdicts remain separate from allocation review.
