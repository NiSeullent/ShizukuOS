# Native installer provider assembly

`win64/setup/native_provider.c` adopts the actual FAT32 relocation stage into
`native_setup_ops_v1` and pairs the native installer with a claim-bound storage
backend. `shz_native_provider_init` requires a fresh zeroed stable provider,
platform services, independently trusted source/target/SHA authority, and all
four target backend methods. It copies the supplied tables and calls no
callbacks during admission; missing methods or a nonfresh/aliased output refuse
without changing output. `shz_native_provider_run` consumes one synchronous
attempt and invokes the actual `setup_run_native` entry.

The backend's `authority.prepare_relocation` is ignored: this provider always
uses the real `shz_native_fat32_relocate_stage` against four source snapshots,
then emits exactly two four-byte hidden-sector overlays. Source authentication
is the native core/provider's separate responsibility. Invalid geometry or
output/input aliasing leaves the adapter output unchanged. Valid unequal FSInfo
copies and BPB-derived backup offsets remain supported. The adopted helper's
2304 MiB bound is intentionally tighter than the core's generic 4 GiB cap.

File reads require a tracked, successfully admitted source and checked custody
before and after reading. Source admission delegates to the independent trusted
backend and must prove actual native producer lineage, namespace identity and
retained input custody. Hashing a caller-provided digest is insufficient.
Checked close is mandatory even after failed admission. Legacy void file close
is never used. Two exact distinct source handles and one target claim are
retained for the attempted epoch; the core verifies actual source bytes/member
inventory and hashes before destructive operations.

Read/write/flush never call the legacy platform raw disk methods. They dispatch
only to the backend with the exact retained claim and full target tuple:
whole-device identity, generation, index and disk geometry. Each backend method
must validate authority/exclusions atomically with its real storage operation,
under the same backend ownership lock/epoch, rather than precheck and call an
unrelated raw syscall. The provider rejects other devices, out-of-range or
oversized/zero I/O, invalid buffers and missing claims before dispatch. Once a
backend I/O fails, the provider latches refusal of further read/write/flush.
An acquisition that returns an owned handle with failure preserves that handle
for mandatory finalization. Checked release consumes the client handle, while
the backend must retain any unresolved physical I/O and exclusive authority.
Failure never promises rollback or a clean target.

This assembly does not fabricate physical authority. **Kernel64 has no matching
whole identity/generation/source backing/current-boot exclusions/exclusive claim
and atomic claimed-I/O interface yet.** Its legacy blkio syscalls and cached
names/serials cannot populate this backend. `setup_main.c` remains unchanged and
its absent native provider still refuses before input/target access. This
increment must not be activated by copying legacy callbacks or by a command
line manifest hash. Real runtime ingestion must issue independently verified
producer/source handles, and the Kernel64 backend must implement/retain the
required authority through each storage operation and all unresolved failures.

Host validation:

```sh
python3 -B shizukudos/install/tests/test_native_provider_host.py
NATIVE_HOST_COMPILER=/usr/bin/clang python3 -B shizukudos/install/tests/test_native_provider_host.py
```

Controls invoke the actual provider, installer and pure relocation against the
existing synthetic 34 MiB FAT32 volume, with backup sector9/FSInfo sector2 and
valid unequal FSInfo copies. Independent Python readback checks every installed
byte, both hidden-sector DWORDs, all GPT entries/CRCs and unselected target
preservation. Linux file identity, read/write leases, SHA, exact I/O and flush
are real; prior producer admission and physical whole/source/boot/current-system
roles are explicitly modeled. Each case also proves absent backend refusal,
preclaim/wrong-device/range/claim-generation refusal, failed-I/O latch,
relocation refusal without mutation, no legacy I/O and single-use execution.
The reused historical fixture has local misleading-indentation diagnostics
suppressed only around its include; new provider source builds with strict
freestanding GCC/Clang `-Werror`.

No VM or private media is used. All actual Windows boot, DOS replacement,
native applications, cold-boot persistence, SMP and ISO fields remain false.
After the missing guest authority exists, actual private target installation,
UEFI Supervisor/GOP handoff and native Windows98/VMM/desktop/cold-boot file
acceptance remain required. UEFI firmware console protocols cannot be called
after ExitBootServices; transferred GOP framebuffer state and native drivers
must implement the continuing display path. See the primary
[UEFI 2.10 console/GOP specification](https://uefi.org/specs/UEFI/2.10/12_Protocols_Console_Support.html).
