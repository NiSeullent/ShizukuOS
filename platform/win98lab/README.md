# Private Windows 98 installation lab

This original harness boots authorized installation media on one isolated KVM
guest. It is installation tooling for Windows 98 Shizuku's Second Edition;
reaching setup does not prove that Windows 98 or the new wrappers work.

The default command reserves 6 GiB of host RAM and 20 GiB of host disk space,
in addition to the guest allowance and its full 2 GiB virtual disk plus 256 MiB
for qcow2 metadata/snapshots. It requires
the existing `compat_vm.py preflight` and refuses another compatibility guest.
The CD's SHA256 is pinned in `lab.py`. QEMU has one CPU, no NIC, no public display
listener, and only a private Unix QMP socket. It never attaches host disks.
One exclusive `flock` covers each entire run or manual persistence operation.
Every QMP connection checks Linux peer credentials against the verified owned
QEMU PID before sending protocol commands.

From the repository root:

```sh
python3 platform/win98lab/test_storage.py
python3 platform/win98lab/lab.py run --max-seconds 1200 --resume
python3 platform/win98lab/lab.py status
python3 platform/win98lab/lab.py snapshot descriptive-name
python3 platform/win98lab/lab.py key ret
python3 platform/win98lab/lab.py stop
```

Omit `--resume` only for a first installation with no existing guest disk.
The supervisor allows 60–1800 seconds and always stops its own child. A
`snapshot` command records a screenshot; it does not create a VM snapshot.
Internal snapshots must be saved/restored through the verified owned QMP
connection. The latest private `install-file-copy` snapshot captures setup
copying files at 20%; installation and native probe execution remain incomplete.

## Optional RAM working copy

When reserving another full 2 GiB on the host filesystem would cross the disk
reserve, an existing stopped installation may use:

```sh
python3 platform/win98lab/lab.py run --max-seconds 1200 --resume --ram-working-copy
```

This explicitly reserves the full 2 GiB disk plus 256 MiB for qcow2 metadata and
snapshots in both available host RAM and `/dev/shm`. The 6 GiB host RAM reserve,
384 MiB guest allowance and 20 GiB root filesystem reserve still apply. A
child-only `RLIMIT_FSIZE` caps each QEMU file at 2 GiB + 256 MiB in either mode.
File extent and physical allocation are checked before copying, and the copy
loop independently enforces the same bound if its source grows. Reaching this
limit is a guest failure, not permission to consume additional host resources.

Only the stopped owned qcow2 is copied into a random private 0700 directory;
the working file is 0600. Before creating that RAM directory, the helper also
requires enough disk space to persist the current image's sparse-copy allocation
while retaining the 20 GiB reserve and 128 MiB margin. It refuses to start if
even an unchanged guest could not be copied back. Later guest growth and other
host activity can still reduce headroom, so the final persistence checks remain
mandatory. No mounts or global settings change. The original
stays intact throughout the VM run. On exit, the supervisor checks qcow2
integrity and verifies sufficient host disk space for the actual sparse copy
plus a 128 MiB margin. It creates an exclusive temporary file, checks its
hash and qcow2 integrity, fsyncs it, hard-links the original as a backup, and
atomically replaces the persistent disk. A verified final copy allows removal
of the RAM copy. Backups remain for explicit later review.

Each RAM allocation has a private persistent `ram-copy-*.json` journal written
with file and directory fsync. Recovery recognizes a verified backup and either
the old or newly published disk hash, so interrupted publication can be retried.
The completed journal becomes durable before RAM data is removed. A crash
between RAM cleanup and the supervisor state update therefore retains enough
information to recover. Foreign target/backup hashes are never overwritten.

If persistence cannot safely complete, `install-state.json` records the RAM
directory and failure. The original and RAM working copy are retained, and
new boots are refused to avoid losing the newer state. After resolving the
recorded condition, retry without starting a VM:

```sh
python3 platform/win98lab/lab.py persist-ram
```

An incomplete writeback is printed with its reason and returns a nonzero exit
after saving the receipt; successful guest termination alone is not reported
as a durable checkpoint.

RAM working copies are volatile until persistence succeeds; host restart would
lose their newer state. The original disk and any verified backups remain on
disk. This option is intended for one coordinated bounded installation attempt.

## Private evidence and keys

Run receipts, screenshots, media and guest disks stay in `build/win98-lab/`.
Do not publish or commit Windows media, disks, RAM snapshots, or product keys.
Stop at the product-key screen if the owner has not supplied their key through
a private channel. Never obtain external product keys or pass keys as shell
arguments. `lab.py text` is for nonsecret installer commands and labels.

The 32 storage tests exercise real sparse file copying and atomic publication in
private disposable directories, mocked qcow2 validation failure paths, exact
resource boundaries, eight interrupted persistence boundaries with repeated
recovery, two-process lock contention, QMP peer rejection, and isolation of the
child file limit. They also check initial copyback headroom before any RAM
allocation, its exact boundary, sparse/partial chunks, and scan-time growth.
They start no VM. Synthetic success fixtures mock ample disk
space so CI capacity does not weaken or accidentally determine production guards.
Recovery also covers a crash before the first PID/global state is recorded: the
sole durable journal is used only after a read-only process ownership scan finds
no matching guest. An unreadable process or ambiguous journal stops recovery.

## Original probe CD

After building the platform DLL/probe and VxD/probe, prepare a separate CD:

```sh
python3 platform/win98lab/make_probe_media.py
```

The helper snapshots the four original binaries, checks their build manifests,
builds an ISO with `xorriso`, and extracts it again to compare every filename
and byte. It verifies the inputs stayed unchanged before publishing
`build/win98-lab/ntw-native-probes.iso` and a hash receipt. The CD contains only
`NTW32.DLL`, `NTWPROBE.EXE`, `NTWRAP9X.VXD`, `NTWQUERY.EXE`, instructions and
checksums. It contains no Windows installation files or keys.

On a disposable installed Windows 98 snapshot without KernelEx, copy the four
binaries to `C:\NTWLAB`, run both probes there, and collect their exit codes
and `NTWPROBE.LOG` / `NTWQUERY.LOG`. Building this CD is preparation only;
successful native execution requires those separate guest results.
