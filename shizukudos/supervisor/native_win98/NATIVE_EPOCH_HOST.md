# Prospective owned host device gate

`native_epoch_host.py` is an unintegrated counterpart to the reviewed native
constructor gate. It supplies policy256 and the READY48 / CHALLENGE48 /
REPORT256 / GRANT272 exchange. It does not change the current guardian,
controller, QEMU recipe, loader, source list, device configuration ABI, or
default boot. Existing VGACFG136 and W98PERS192 blobs are byte expectations;
they do not authorize physical access.

The module has no CLI. A future owner must supply a single real `Popen`, its
original pidfd, the exact canonical executable/source read leases and returned
input pins, one sole admitted `OwnedQMP` instance, and the owned writable ESP
descriptor. A duplicated guardian QMP socket cannot satisfy this contract.
The caller must approve the actual executable, recipe, source/ROM provenance,
current ESP preparation, and exclusive resource epoch before construction.
The library cannot independently prove that another process or FD does not
read the same stream. The current controller/guardian provide no such optional
wiring; actual optional runtime promotion remains blocked.

The API sequence is:

1. Wrap the caller's exact held canonical config/ROM, executable and
   `owned_capture.py` descriptors in `PinnedFD`. Pins have exactly `path`,
   `bytes`, and `sha256`; the caller retains actual read leases, handles SIGIO,
   and holds the complete admitted source/tool closure. These objects borrow
   descriptors and never install a signal handler or close those descriptors.
2. Construct `Attempt` with the selected config/ROM pair, optional persistence
   config, exact six raw BAR DWORDs per selected role, and the original
   controller deadline in host `monotonic_ns`. It generates its own fresh
   32-byte nonce and an exact256-byte immutable policy in a write/grow/shrink/
   seal-sealed memfd. The original deadline and input bytes are rechecked.
3. Create one `PrivateListener` in an actual fresh owned0700 leaf. It binds
   relative to a held directory FD, uses an owned0600 socket name shorter than
   104 bytes, and accepts one connecting child. QEMU must connect as a client
   (`server=off`). Precreated socketpairs report their creator via SO_PEERCRED
   and convey no connecting-QEMU proof. The future custodian must retain the
   leaf and policy FD until exact reap.
4. Bind the actual child with `ProcessBinding`: current original pidfd,
   starttime, executable inode/full SHA, exact cmdline, UID, direct parent and
   cgroup are checked. `HostGrant` requires the scoped Q35/KVM/4GiB/oneCPU/no
   network/no display recipe, known VGA and Supervisor-owned virtio-blk,
   exact policy FD, and the one connecting COM2 channel. This is an additional
   narrow recipe check; outer preparation/firmware/ESP and device ownership
   admission is still required.
   Policy/listener ownership attaches before recipe, ESP or monitor checks;
   constructor refusal with an already-created child retains those resources
   until the exact original pidfd is reaped.
5. `SoleQMP` uses the existing actual monitor and its buffered request/event
   state. It compares method code to the caller's held source, pins the
   original deadline/socket, rechecks actual SO_PEERCRED against the current
   child before and after every operation, and permits only stop or bounded
   readonly observations. No second monitor/parser is introduced. The caller
   must supply the genuinely exclusive context and prevent pump/global or
   source execution changes; class-code matching alone is not a complete
   Python interpreter or dependency proof.
6. `HostGrant.exchange()` consumes the attempt before any exchange. It waits
   for current READY before sending CHALLENGE. A fixed additional10s bound
   starts after READY and is capped by the original host deadline; neither
   deadline is refreshed. The existing monitor's5s per-request limit must fit
   this reserve. Local native report TSC and host nanosecond domains stay
   distinct; a report TSC value does not extend host admission.

The host stops and confirms actual `running=false,status=paused`. It parses a
bounded complete current FlatView to observe the actual `memory/system` RAM
ranges and ECAM; it does not guess a q35 address or assume RAM is contiguous
below4GiB. It parses every selected FlatView row, derives the selected40-byte
ECAM reads and issues only bounded readonly HMP `xp /10wx`. Current raw PCI,
full query-pci region sizes/types, selected roles/BDFs, RAM exclusion, and
duplicate/overlapping resources must agree. Every reported assigned endpoint
BAR is considered when refusing collisions with a selected BAR, including
foreign devices; selected memory also excludes the observed ECAM span.
`SoleQMP` starts with no physical read authority, clears the allowlist before
each FlatView request, and admits only the selected exact40-byte ECAM spans
derived from that complete current result. Two complete paused observations
must match. Query-block/named-node facts supply filename/cache strings; their
filenames do not establish an opened inode. Before GRANT, the host separately
requires `OwnedESP.observe_backend()` to observe the exact held owned2304MiB
raw ESP open in the current owned process, with writeback enabled, direct
disabled and no-flush disabled in the current graph. No image content is read
or hashed by this library, no
BAR-size probe/config write is made, and no reset, VGA/DISPI or DMA operation
is performed. Outer actual ESP hash/lineage, BAR assignment, exclusive DMA
ownership and original recipe checks remain necessary.

The backend observer inspects at most256 actual process descriptors and
bounded fdinfo/readlink metadata under before/after original process guards.
It requires one unambiguous canonical private0600 single-link inode matching
the caller's held writable FD, actual read-write/no-O_DIRECT/no-append flags,
and two identical complete FD inventories. Deleted, aliased, replaced,
foreign same-name, duplicate or changed opens refuse. This proves an observed
process open inode alongside the current QMP graph/recipe. It does not prove
QEMU's internal node-to-FD pointer, content immutability of a writable image,
or exclusive physical authority. The current approved recipe/software and
outer exclusive custody remain mandatory. Missing open-inode observation
refuses GRANT. No read lease is acquired on the writable owned image.

GRANT echoes the entire canonical report. Success means those bytes were
transmitted under the checks while QEMU remains paused. The actual native
constructor may still refuse or its local budget may already have expired;
there is no native ACK in this protocol. The returned flags therefore keep
constructor/host runtime wiring, observed native admission, physical device
initialization, Windows boot and coldboot persistence false. The owner must
resume only within its original deadline. A late failure records how many
GRANT bytes were transmitted; it cannot undo bytes or claim no grant reached
the native side.

Failure permanently consumes the attempt. It retains the policy, listener,
accepted peer and borrowed context until an actual delegated pidfd reap.
`ProcessBinding.reap_owned()` requires real `waitid(P_PIDFD)` EXITED/KILLED/
DUMPED evidence; `Popen.poll()`, an ECHILD-synthesized status, or a terminal
domain enumeration cannot substitute. The existing guardian owns its own
reaper and has no delegation/handoff to this API. That missing integration
and external custody across owner exit block real optional use.
`close_after_reap()` closes only newly owned policy/channel resources after
that exact evidence; borrowed QMP, pidfd, ESP and source descriptors remain
the caller's responsibility. No bounded in-process object substitutes for
external custody after CLI death.
The exact original descriptor number/kernel identity/PID is checked before
destructive waitid and again for resource release after the kernel reports
the original pidfd reaped. A substituted ready foreign pidfd cannot be reaped.
Listener pathname checks use the final entry without following symlinks;
failure cleanup preserves foreign replacements.

Host controls distinguish actual Linux facts from models. Real private files,
read leases, sealed memfds, connecting Unix credentials, owned Python child
processes, pidfds, strict kernel reap and source-bound existing QMP parser
execution are exercised. Those children are protocol fixtures, not QEMU.
Literal PCI, FlatView, block/cache and firmware/device values are models.
Tiny private-file controls observe real Linux child open-inode/flags and
foreign/deleted/alias/replacement/readonly/duplicate refusals. Their files are
not ESP images, and their Python children are not QEMU. These controls do not
establish a QEMU block-node mapping or actual device authority.
The production exchange/transport is also tested with an explicitly bypassed
QEMU constructor and modeled hardware boundary; that cannot satisfy actual
HostGrant construction or physical authority. No actual QEMU/VM, media/NAS
read, device I/O, native initializer, Windows or coldboot test is performed.

The caller still needs reviewed guardian-only sole QMP ownership/RPC,
fw_cfg inherited-FD recipe generation, original deadline propagation,
current process/channel and complete source/tool custody, current actual
block/cache/BAR assignment and ESP admission, and postgrant native evidence.
Host source/primary Python pins establish only the observed closure recorded
in the handoff; external Python standard library/shared libraries and child
tool dependencies are not a complete reproducible execution closure.
