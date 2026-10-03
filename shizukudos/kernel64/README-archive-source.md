# External optical origin and sealed archive input

`k64_boot_storage_bind` now adopts actual loader/archive observations using
`archive_source_bind_origin` after the real `fs_load_archive` succeeds. It checks
UEFI/domain/version/size, exact physical GPA-to-kernel pointer and RAM range,
complete bounded SHZARC metadata, and matching boot/archive physical locators.
Metadata is copied into kernel-owned memory once; the origin cannot be silently
replaced later. The existing registered-role path remains supported. For an
observed readonly/removable 2048-byte whole that is absent from the registry,
`blk_authority_bind_archive_origin` reads only that adopted origin and retains an
explicit external backing record. No fictional boot blk or unknown/no-backing
exemption is used. Every candidate target must have a valid actual driver
hardware locator and must differ in physical controller/unit, even when media
geometry or EUI changed. Duplicate known physical-unit registration is refused,
so two per-boot registry identities cannot bypass exclusive ownership.

`archive_source_open` resolves the actual namespace through `fs_lookup` and
requires a readonly RAM node whose pointer and length match exactly one entry in
the accepted loader archive metadata. A newly created C: file or fabricated
readonly attribute cannot establish archive origin. Only that selected file is
copied into private PMM pages. The kernel heap is only12MiB, so the byte snapshot
uses real page allocation and a bounded page-pointer array, not one huge heap
allocation. The snapshot maximum is256MiB/file, eight live source slots; missing
memory refuses and releases partial allocation. The rest of C: stays writable.

SHA-256 is measured before copying, from the private copied bytes and afterward.
All three must agree. The mint returns a kernel owner handle, nonzero random ID,
monotonic generation, exact byte length, digest and observed physical origin.
Reads and close require that exact minted identity, so a stale reused slot or
another process cannot read/close a later source. Reads are bounded and span the
private pages. The original archive may subsequently change or its namespace
node disappear without changing the sealed input. File data/path pointers are
not retained as authority after snapshot creation.

The shared block claim now accepts separately typed archive source pins while
preserving registered-device source pins. Claim acquisition retains both exact
source snapshots for the same kernel owner, rolling back partial retention.
Closing source owner handles does not free pages needed by a claim. Successful
safe target release drops claim references; uncertain target I/O retains the
poisoned claim and its source pages. No force-close or fake quiescence is added.

This is source-byte custody and block-storage authority. **The digest does not
prove an independent DOS3/native producer.** Existing native_provider's mandatory
trusted backend source/hash/admission checks must still be supplied by the real
producer/lease path, and its versioned process-owned syscall bridge remains
absent. setup_main's native provider remains NULL. Do not convert snapshot SHA,
caller paths, manifest declarations or a user approval bit into producer trust.
Storage-policy host tests can claim a modeled target; actual Windows installation
and native acceptance are not proven by those tests.

Host verification compiles actual fs.c/archive parser/namespace, archive source,
boot binder, block registry/partitions/authority and shared SHA-256. Only PMM/IRQ,
RNG/driver and firmware observations are explicit host models. Tests cover
missing/truncated origin, exact file membership, multi-page bytes, independent
Python hashlib digest, allocation rollback, later original-byte mutation, owner
and generation refusal, physical-origin exclusion independent of geometry,
duplicate hardware identity, missing target locator, owner-close retention,
partial two-source retention rollback, safe cleanup and poisoned retention.
No VM, private media or actual native producer executes in those tests.

Run `python3 -B shizukudos/kernel64/host/test_archive_source.py`; use
`NATIVE_HOST_COMPILER=/usr/bin/clang` for ASan/UBSan. Existing authority regression
also now compiles the actual fs.c rather than extracting mount function bodies.
