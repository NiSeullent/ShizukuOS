# Native FAT32 volume-image relocation plan

FADA acknowledged these exact six new paths on 2026-10-02. ROOT owns the new
header, C helper and two documents in this isolated b1448683 worktree. The
policy agent owns the two new host-test files. Existing install.c, host CORE,
private ingestion/schema/GPT/target identity and native execution belong to
FADA; this change does not modify them.

Actual Windows 98 remains the OS body. ShizukuDOS replaces MS-DOS; component
controls cannot close desktop, apps, persistence, SMP, installer or final ISO.

1. Freeze a pure four-sector stage and bounded-window overlay interface. The
   native source is a logical FAT32 volume image starting at LBA zero, at most
   2304 MiB. Require exact buffer sizes, source geometry/extent, FAT32 cluster
   and FAT capacity, mirrored pair, valid FSInfo and BPB-derived reserved-sector
   positions. Require a positive representable target LBA and exact inclusive
   capacity. Failure preserves all caller output bytes.
2. Independently construct synthetic sector controls and an unrelocated legacy
   behavior baseline. Observe meaningful relocation failures without weakening
   assertions, then run unchanged controls against the implementation.
3. Preserve both VBRs except their hidden-sector DWORDs. Overlay only those
   two spans across arbitrary bounded windows. Store the four snapshots and
   derived metadata, revalidate them before mutation, reject output aliases and
   range overflow. A consistent caller-forged plan is outside custody proof.
4. Run finite GCC/Clang controls, sanitizer controls and actual i386/x64
   freestanding consumer compiles. Bound each compile to 60 seconds and other
   commands to 25 seconds, with 0.5-second TERM and 1.5-second KILL cleanup.
   Preserve the original 25-second compile failures and single-compile
   measurement. Pin source and actual outputs, verify owned subprocess cleanup
   and unchanged inputs, and obtain independent review. Per-file 8 MiB and
   observed 64 MiB leaf checks are not aggregate allocation or PIPE RAM quotas.
5. Commit exactly the six new files and hand the API/source/evidence to FADA.
   Owner integration must validate canonical source encoding, independently
   compute original S and relocated R before wipe, retain held source custody,
   recheck S/R on the write pass and read back flushed R. Existing public
   2048-to-2048 behavior stays in its existing path.

No private media, NAS workspace, VM, target disk, site or client configuration
is accessed by these component controls. Host fixture success is not an
installed-volume, filesystem-tree, BIOS/UEFI coldboot or native-Windows result.
