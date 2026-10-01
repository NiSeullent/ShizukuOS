# Private RAM disk checkpoint helper

`private_checkpoint.py` is an API-only producer for a fresh private raw disk
checkpoint. **It is not integrated into `run_vm.py`.** It starts no VM, opens
no QMP socket, resumes no guest, releases no source lease and rewrites no input
disk or ESP. Canonical 163f owns the existing controller and native Win98 hooks;
their separate adapter integration/ACK is required before a real capture.

The current native ATA model writes only the loader-owned `info.disk_base`
RAM. A checkpoint captures that backing before the controller quits its QEMU
child. This does not implement a live physical storage backend or an actual
Windows shutdown/reboot path. Actual Windows 98 VMM/USER/GDI/Explorer remains
the product; Kernel32/Kernel64 are its backend components.

## Required controller adapter

Call `capture_private_checkpoint(adapter, reservation, fresh_output)` only
from the controller that already owns the running QEMU child, its source-bound
plan and live original-input read leases, on the Python main thread so that
Linux output-lease notifications can be handled. There is intentionally no standalone
CLI accepting a socket or arbitrary physical address.

`ControllerAdapter` contains:

- `call(command, arguments=None)`: the existing **owned** QMP method, retaining
  its exact request-ID, socket-peer and request-deadline checks. The helper calls
  only `stop`, `query-status` and bounded `pmemsave` requests. It does not extend
  the QMP deadline. The owner must separately admit the capture interval and
  set its existing controller deadline before calling the helper.
- `assert_owned()`: a fresh observation that must return the same `owner`
  dictionary, or raise. Required keys are `pid`, Linux `/proc/PID/stat`
  `starttime`, SHA-256 of the exact `/proc/PID/cmdline` bytes, `qmp_peer_pid` and
  `qmp_peer_uid`. The adapter must retain the actual Popen/pidfd identity, prove
  that this exact child is alive, and reread `SO_PEERCRED` on its existing QMP
  connection. The helper verifies matching PID/UID and rejects identity drift;
  it cannot manufacture the owner's Popen proof from a supplied dictionary.
- `observe_ram()`: the owner-derived observation dictionary with exactly
  `ranges`, `source_ref` and `qemu_ref`. `ranges` are ordered, disjoint,
  page-aligned **exclusive-end physical RAM spans** observed from that owned
  runtime's applicable system-memory FlatView, excluding overlapping ROM/MMIO
  mappings. `source_ref` identifies the immutable, leased observation transcript;
  `qemu_ref` identifies the leased QEMU binary that produced it. The adapter must
  derive the ranges from the actual observation and revalidate the same child,
  machine and physical layout while paused. A total-memory count, default Q35
  formula, ELF mapping or caller assertion is not a RAM observation.
- `sources`: a tuple of `ReadLease(name, path, fd, sha256, bytes, checkpoint)`.
  These are the already-held canonical regular-file read descriptors and
  SIGIO-aware lease checkpoints, not paths to be reopened as mutable inputs.
  The helper checks actual `F_GETLEASE`, read-only descriptor access, full
  descriptor/path identity, exact extents and independent pread SHA before and
  after capture. It retains all leases for the caller. The caller must perform
  its final lease checks and reap its exact child before releasing them.
- `references`: exactly the eight role-to-source-name mappings `controller`,
  `qemu`, `ram_observation`, `info_header`, `info_parser`, `layout_receipt`,
  `budget`, `checkpoint_helper`. The loaded `info_module.__file__` and helper
  itself must match their leased source paths. The remaining mappings identify
  the owner's real controller source closure, observed QEMU/layout/budget proof
  and immutable inputs; host fixture references are not runtime attestations.
- `info_module` and `layout_bytes`: the owner's source-pinned current SHZ parser
  and **previously executed C/Python layout check** against the referenced
  `shz_info.h`. The layout receipt must pin those exact header/parser bytes and
  successful size/offset results. This helper does not invoke a compiler.

These callbacks are an explicit trusted integration boundary. The existing
`OwnedQMP` alone does not implement Popen lifetime or physical RAM observation,
and no validated native adapter is supplied by this change. The helper's receipt
always records `controller_adapter_runtime_integration=false` and
`VM_verified=false`; actual integration needs a separate source-bound receipt.

Upstream QEMU 10.1 splits Q35 RAM between low and high physical ranges. For
example its default 4 GiB calculation allocates 2 GiB low RAM and 2 GiB high RAM;
high RAM is not bounded by the 4 GiB byte count. This explains the required
runtime observation, and is not a claim about a particular downstream `q35`
alias. See the original [Q35 initialization](https://github.com/qemu/qemu/blob/v10.1.0/hw/i386/pc_q35.c)
and [physical RAM alias mappings](https://github.com/qemu/qemu/blob/v10.1.0/hw/i386/pc.c).
Firmware can overlay ROM/MMIO on an underlying RAM alias, so use the applicable
FlatView rather than accepting all addresses of the alias.

## Output and resource reservation

`Reservation(approved_lane, source_ref, disk_bytes, capture_bytes, total_bytes,
retained_free_bytes, timeout_seconds=120)` must reference the owner's actual
budget proof through `references['budget']`. A real output must be a **fresh**
directory inside an explicitly approved lane beneath
`/mnt/shizukuos-native-workspace-fada-20261001`. The lane and output parent must
already be owned mode 0700; the helper neither mounts NAS nor creates a lane.
Readiness, sole mounting, lane-wide allocation and transport integrity must be
revalidated by the NAS owner before real writes.

The disk reservation is exactly 2 GiB. The separate small-capture reservation
is at most 16 MiB and must cover one 8 MiB chunk, a memory map of at most 1 MiB,
a receipt of at most 1 MiB and two 8192-byte info captures. For example,
`disk_bytes=2<<30`, `capture_bytes=16<<20`, and their exact sum are admissible
within the owner's separately approved whole-lane allowance. The retained
floor is at least the unchanged 17 GiB. Remaining allocation and current free
space are checked throughout; the overall timeout is explicitly bounded to
1–900 seconds. Existing global diagnostic limits (16 MiB single capture,
256 MiB total) are not modified or bypassed: this helper owns and accounts for
its separate disk and small-capture reservation.

After acknowledged `stop` and current `query-status` reporting exactly paused,
the helper reads current 8192-byte SHZ info and validates its signature, current
layout, exact native 128 MiB/2 GiB geometry, VMX/domain identity, complete
physical spans and non-overlapping loader regions. It reads the retained UEFI
memory map and requires the **whole** disk to be covered by non-overlapping
`EFI_LOADER_DATA` descriptors. Each disk chunk is captured to an exclusively
created mode-0600 file, independently read back, copied into the new raw disk
and hashed. The temporary chunk is then removed; diagnostic captures remain
private. All data files are mode 0600 and the new output directory is mode 0700.

After the complete raw disk has been fsynced, its exact size and full SHA are
independently read back. SHZ info is reread while still paused and must be
byte-identical; source hashes and lease checks must still match. The helper
reopens the same raw inode read-only, acquires an actual Linux read lease, and
independently verifies its full SHA again. It publishes `checkpoint.raw` without
replacing any existing file and pins its inode, exact extent, metadata and lease
through receipt publication. Both canonical names are linked directly from their
held verified descriptors using Linux procfs/linkat semantics, so replacing a
partial pathname cannot supply a different inode. It then publishes `checkpoint.json` last with file
fsync, exact serialization readback, its own read lease and inode checks through
the final directory fsync. Output lease handlers chain the existing SIGIO handler
and restore it on exit; a break request fails the operation and can also mark the
caller's source checks failed. The caller retains its source leases and handlers.

A later failure, including a terminal descriptor-close error, removes the
producer's canonical success receipt with best-effort cleanup and directory
fsync, while preserving private raw/partial data. Cleanup cannot promise crash
durability when the filesystem itself rejects fsync or access. No success
receipt means no accepted checkpoint; partial
files are not automatically retried, adopted or deleted by this API.

Successful receipts explicitly keep Windows boot, clean shutdown, cold-boot
persistence and live storage flush flags false. The checkpoint can become a
new SHA-pinned `DISK.IMG` input to the existing builder only after its owner
reviews and accepts this private checkpoint. Original inputs remain immutable.

## Host verification and remaining acceptance

Run the bounded host tests from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 shizukudos/supervisor/native_win98/tests/test_private_checkpoint.py
```

Tests use a real owned Unix QMP protocol child with observed PID/starttime,
real regular files, Linux read leases, actual readback and fsync. **Physical
RAM, controller/QEMU/layout/budget observation references and disk contents
are explicit host models.** Tests reduce only disk/chunk policy geometry and
use a temporary private lane with mocked free-space capacity; they never write
an actual 2 GiB image, access NAS/media or start a VM. Error injection covers
paused-state loss, wrong physical spans, loader-map ownership, short capture,
peer loss, process identity drift, source SHA/lease loss, actual output corruption,
late changes, fsync failure, publication collisions and resource refusal.
Publication controls also exercise raw/receipt replacement, real nonblocking
writer attempts against output read leases, handler restoration, chmod-error
descriptor cleanup and terminal file/directory close failures.

Actual acceptance still requires the canonical runtime adapter and an owned
ShizukuDOS-to-Windows98 boot. A Windows-created file must be closed/flushed,
captured, and independently read after a **new cold boot** from the resulting
checkpoint. Live storage flush and actual Windows shutdown/reboot remain
separate acceptance gates. Keep all Windows disks, memory dumps, transcripts
and private receipts out of GitHub and the public m98 installer/ISO.
