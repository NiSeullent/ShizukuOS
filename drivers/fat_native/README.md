# Windows 98 Shizuku's Second Edition — original FAT32 boot-file reader

This original freestanding C component reads a bounded root-directory file
from FAT32 through a caller-supplied sector interface. It is the filesystem
boundary needed between the existing AHCI sector reader and a future DOS boot
loader. It does not execute files, provide DOS services, install a filesystem,
call firmware, mount the private Windows installation, or boot Windows.

The API is `ntwf_read_root83` in `fat.h`. The caller supplies immutable media
geometry, an explicit primary partition index, an exact padded uppercase short
name, a private workspace, and separate destination/metadata outputs. The
workspace contains about 512 KiB of staging bytes and bounded sector/cluster
scratch; allocate it outside the boot stack. There are no allocations, global
mutable state, libc dependencies, or write callbacks. Calls with independent
objects can coexist; callbacks must not reenter the same live call.

## Supported read profile

- Legacy MBR with four checked primary records and a selected type `0b`/`0c`
  partition. An active flag is not required because selection is explicit.
  Empty records, flags, extents and pairwise overlaps are checked. Protective
  GPT, a selected extended partition and other selected types are unsupported.
- FAT32 revision zero, 512-byte sectors, power-of-two sectors per cluster from
  1 through 64, and one or two FATs. Geometry and FAT capacity must agree with
  the data-cluster count. The informational filesystem label is not a type
  discriminator. Partition and volume bounds both constrain every LBA.
- `BPB_ExtFlags` selects the active FAT when mirroring is disabled. Mirrored
  reads compare every consulted entry after masking its reserved high nibble.
  Different unused entries are not examined. Reserved FAT entries are checked;
  dirty/hard-error flags are accepted as information, not repaired. This does
  not establish filesystem integrity or permission to write the volume.
- Root directory and regular files use their actual cluster chains, including
  fragmentation. Root-chain validation continues after an end-of-directory
  entry, without interpreting subsequent directory bytes. Deleted, LFN and
  volume-label entries are skipped. Short names support only the documented
  ASCII set; long-name and subdirectory lookup are unsupported. A unique
  matching directory is unsupported; duplicate matching live names fail.
- Read-only, hidden and system file attributes are supported, so a later
  authorized binding can request `IO      SYS`. No Windows file is included
  in this implementation or its tests.

File-chain allocation must match the rounded-up directory size exactly and
end with EOC. This conservative boot profile rejects extra preallocated tails,
truncation, free/bad/reserved/out-of-range links, cycles and collisions with
the complete traversed root chain. Unrelated file chains are not traversed;
this reader is not a whole-volume consistency checker. FSInfo free-space hints
and backup boot records are not used for addressing or automatic repair.

The maximum file size is 512 KiB, with 1,024 file clusters and 64 root clusters.
The total callback-read budget is at most 8,192, and the requested elapsed-time
budget is at most 5,000,000 microseconds. A caller may lower either budget.
Partition and cluster-sector arithmetic widens before multiplication/addition;
no 64-bit division is needed on i486. Cluster lists have fixed bounds and
detect loops without scanning an attacker-selected whole FAT.

## Failure and lifetime contract

`io`, `request`, `workspace`, the entire destination capacity, and `info` must
be valid pairwise disjoint objects. Numeric range/overlap checks target flat
x86 addresses; they cannot validate an arbitrary unmapped pointer. The caller
must provide stable, exclusively owned/read-only media throughout the call.
Callbacks must not alter other arguments, retain scratch pointers, or change
the media. That excludes concurrent filesystem writes and hot removal.

The read callback receives a positive remaining-time allowance and must return
within it, including device cleanup. Clock callbacks must return promptly.
The reader checks time before and after each read, catches backwards clocks,
and checks again before publication. A frozen clock remains bounded by read
and traversal counts. These are cooperative budgets: C cannot preempt a hung
callback, so an eventual hardware integration still needs an independent
watchdog and its driver's DMA quarantine rules.

On every error, destination and metadata remain byte-for-byte unchanged.
The workspace may contain incomplete file bytes. On success, only the exact
file length is copied into destination and the zero-initialized metadata is
published; destination tail bytes remain unchanged. An empty file requires
cluster zero and changes no destination bytes. Neither a successful read nor
an `IO.SYS` filename constitutes executable validation or a DOS handoff.

## Build and evidence

From the repository root:

```sh
python3 -B drivers/fat_native/test.py
```

This command uses existing GCC, Clang, nm and Python, writing only `build/`
below this directory. It compiles and runs an independently authored sparse
sector model under strict GCC/Clang and nonrecovering ASan/UBSan, then checks
standalone freestanding i486 objects for zero undefined symbols and bounded
stack frames. No disk image, block device, VM, network or Windows media is
opened. Results and current source hashes are recorded in
`build/test-result.json`.

The 2026-09-27 host validation passed strict GCC, strict Clang and nonrecovering
ASan/UBSan. Its independent model checks fragmented payload bytes, the complete
512-KiB/1,024-cluster file limit, 64-root-cluster limit, partition LBAs crossing
2^32, mirrored/active FAT selection, malformed geometry and chains, callback
failures, deadlines, alias rejection and unchanged failure outputs. Both i486
objects have zero undefined symbols; the largest reported stack frames are
384 bytes (GCC) and 260 bytes (Clang). Frame measurements exclude platform
callbacks; they are not a complete future kernel-stack bound. Exact scenario
and assertion counts belong to the source-bound receipt.

An AHCI adapter and actual UEFI/KVM file-byte verification remain separate
future work. No existing driver or UEFI image is changed by this component.
Source provenance is recorded in [REFERENCES.md](REFERENCES.md).
