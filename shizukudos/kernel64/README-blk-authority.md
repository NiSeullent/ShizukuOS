# Kernel64 native installation block authority

`blk_authority.c` is linked by the existing Kernel64 source glob and connected
at the actual `blk_register`, shared block I/O and volume mount paths. It does
not create a parallel device registry or a user approval token. Whole-device
objects get independently generated nonzero unique per-boot IDs and monotonic
epochs. Names/serials/array positions remain enumeration labels. The authority
retains driver callbacks/private backing/geometry/flags and rejects observed
changes. Kernel64 currently has a static device registry and no supported
hotplug authority; drivers must not silently replace live backing identities.

The kernel-only API accepts actual registered device pointers, kernel owner,
source pins and reviewed identity. User manifests, command-line hashes and
bools cannot supply role authority. Boot and current-system devices must both
be independently resolved from the loader/runtime's actual storage observations
before review or claim. No production caller currently has the complete facts,
so both roles remain unknown and **native target review/claim refuse by default**.
The positive host controls explicitly model those kernel observations.

Source pins bind actual whole objects and their current identities/epochs.
They do not authenticate file bytes, source handles, input read custody or DOS3
producer lineage. Those checks remain mandatory in the reviewed native provider
and future Kernel64 file-import backend. A target cannot equal boot/current
system or either source whole, be a partition/removable/read-only/mounted
object, lack a real flush capability, or have asynchronous driver queues. Both
sources must also lack asynchronous driver callbacks; outstanding queued I/O
is not fabricated as quiescent. A source protected by a live claim cannot be
claimed as another target, or changed through generic writes/discard/control.

One shared mutex serializes eligibility, claim acquisition, retained owner,
source/role epochs, backend operation and release. `blk_read/write/flush` resolve
partition LBAs with bounded chain/overflow/whole bounds and invoke the actual
whole driver under that same lock. They do not recursively reacquire the lock
through partition forwarding. Generic I/O/control/discard on a claimed whole
refuses. Claimed read/write/flush checks the exact kernel owner, original token,
complete identity and current exclusions under the lock immediately around the
real driver call. A separate userspace precheck followed by raw setup syscalls
is not introduced. Synchronous fallbacks of async helpers use these guarded
operations; async-backed wholes are outside admitted target/source capabilities.

`vfs_mount_next` resolves its kernel-owned registry device name and marks it
mounted under the same authority lock before exposing a namespace root. Unknown
or claimed devices refuse mounting; a failed subsequent namespace publication
keeps conservative exclusion. The actual D: FAT32 and ShizukuFS callers already
supply observed registered device names. This also fixes the missing mounted
exclusion for ShizukuFS rather than inferring roles from filesystem labels.

Successful release changes the target generation before clearing ownership;
old reviews/tokens cannot be reused. Control calls change the device epoch even
if metadata appears unchanged. Any actual driver error poisons the whole/claim
and retains exclusive custody; further I/O/release refuses. There is no force,
boolean quiescence assertion or fake recovery path. A later independently
observed reset/recovery protocol is needed before reclaiming an uncertain
backend; until then reboot is required. This does not promise rollback.

The global mutex intentionally serializes device operations for this first
admission increment; per-device arbitration can follow with equivalent source
union/claim proofs. Kernel mutexes are currently BSP scheduler-owned, as are the
existing block paths; this does not claim multicore storage support. Driver
callbacks must not recursively enter blk_* while this lock is held.

Validation:

```sh
python3 -B shizukudos/kernel64/host/test_blk_authority.py
NATIVE_HOST_COMPILER=/usr/bin/clang python3 -B shizukudos/kernel64/host/test_blk_authority.py
```

The actual production registry/authority/partition functions compile against
actual blk.h. IRQ/kernel allocator/RNG boundaries are modeled; pthread mutexes
and concurrent callers are real. Per write/read/flush-failure mode, controls
prove unknown-role refusal, whole/source/boot/mount exclusions, exact identity
and owner, stale epochs, source mutation refusal, partition/generic async
fallback refusal, actual direct driver byte readback and full lock retention
against a competing raw writer. Each uncertain I/O mode retains its claim and
rejects release/reuse. These use small synthetic memory devices, not media or a
VM. Sanitized Clang and strict GCC compile/run the same actual source bodies.
Freestanding compilation validates the real kernel headers and mount hook.

Remaining concrete integration gates:

1. Loader bootinfo does not currently transfer a physical boot-device identity
   tied to the kernel registry (UEFI loaded-image/device path→PCI/storage
   transport/whole device or equivalent BIOS proof). Kernel source initrd is
   copied RAM; its original physical backing identity is absent. Add a bounded
   source-bound handoff and independently verify it against actual driver
   observations before calling bind_boot_roles. Unknown is not 'no device'.
2. Resolve current-system/runtime image backing and source file nodes using
   actual mount/handle provenance, retain source custody/hash/producer admission,
   and expose only independently minted kernel capabilities. RAM-source roles
   require genuine loader provenance; do not fabricate physical source pins.
3. Add versioned claimed-I/O/source-import syscall or equivalent trusted bridge
   to the reviewed native_provider backend, preserving process ownership,
   generated whole ID/generation, exclusions and pending I/O through cleanup.
   Current setup_sys/blkio raw ABI and setup_main's NULL native provider remain
   unchanged. Never fill the new provider with legacy raw callbacks.
4. Bind durable flush capability and actual controller epoch, then perform
   private disk installation, UEFI native Windows98/VMM/GOP desktop and cold-boot
   file readback. Host tests, per-boot IDs and component ISO success do not prove
   hardware identity, Windows startup, persistence or application acceptance.
