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
connection. The owner subsequently supplied the registration value and setup
reached the Windows 98 SE desktop. A private `windows98-clean-installed`
snapshot preserves the fresh installation without KernelEx. The
[first native trial](../../docs/NATIVE_FIRST_TRIAL.md) passed the original DLL
probe, failed opening the VxD with error 2 and consequently did not run GDI.
Installed-disk persistence is recorded separately; successful setup or a
stopped QEMU process does not establish durable storage.

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

## Optional compressed checkpoints

An existing installation can instead use a private RAM working copy with
byte-exact XZ persistence:

```sh
python3 platform/win98lab/lab.py run --max-seconds 1200 --resume --packed-checkpoint
```

This opt-in mode retains the original base and all earlier backups. Compression
preserves the complete qcow2 byte stream, including its internal snapshots.
Each generation gets an immutable `install-packed-*.qcow2.xz` archive and a
durable `packed-copy-*.json` journal. After the archive is fsynced and its
decoded bytes and checksums are verified, an atomic `install-packed-current.json`
pointer selects it. The completed journal becomes durable before the RAM copy
is removed. A later boot restores that selected generation and checks qcow2
integrity. Raw boot and raw persistence refuse an existing packed pointer to
prevent silently returning to the older uncompressed installation.

The 6 GiB memory and 20 GiB disk reserves remain enforced. This mode additionally
reserves 256 MiB for the codec, the full 2.25 GiB working image, the guest
allowance, and a 128 MiB persistence margin. Before allocating RAM it measures
the current compressed size and requires enough persistent storage for another
generation. Persistence rechecks capacity before creating and writing the new
archive; guest growth or other host activity can still prevent writeback.
In that case both the old checkpoint and newer RAM working copy are retained,
and `persist-ram` retries the recorded backend after the guest is proven stopped.

Restoration accepts one bounded CRC64 XZ stream with a 64 MiB decoder memory
limit. Truncation, trailing or concatenated streams, checksum or length mismatch,
oversized expansion, changed originals and stale generations stop publication.
The codec, interruption recovery and supervisor routing have separate host tests:

```sh
python3 platform/win98lab/test_packed.py -v
python3 platform/win98lab/test_lab_packed.py -v
```

These tests use synthetic data and start no guest. Compressed Windows media,
disks and snapshots remain private under the same rules as raw images.

## Optional immutable base archive

After a verified packed checkpoint exists, the stopped lab can explicitly
replace its preserved raw **base** with a byte-exact XZ archive. The current
packed checkpoint remains the installation selected for the next boot. This
operation compresses the older base; it does not replace the latest checkpoint
with that older installation or remove any earlier packed generation.

Review `install-packed-current.json` in the private lab directory and obtain
the checksum of that exact pointer file:

```sh
sha256sum build/win98-lab/install-packed-current.json
python3 platform/win98lab/lab.py archive-base --expected-packed-sha256 REVIEWED_64_HEX_SHA256
```

Replace `REVIEWED_64_HEX_SHA256` with the reviewed lowercase checksum. The command
requires the same exclusive lab lock, absent recorded PID and a process scan
that finds no owned guest. The candidate pointer checksum must remain unchanged.
Pending raw-copy journals block archival. One valid stopped packed-copy journal
may remain: its original identity and generation are checked, and its newer RAM
file is retained. This permits base compaction before retrying a packed writeback
that was refused for insufficient disk space. Multiple or foreign pending
journals require explicit recovery review.

Archival first writes `install-base-archive-journal.json`, then creates an
exclusive compressed file, verifies its bounded CRC64 XZ stream, independently
restores the exact raw bytes into private RAM and checks qcow2 integrity. Only
then does it publish the immutable `install-base-archive.json` pointer. The raw
base is unlinked only after a durable retirement state and renewed source,
checkpoint, process and journal checks. File and directory fsync protect each
publication boundary. New JSON publication uses Linux `RENAME_NOREPLACE`;
unsupported hosts refuse publication rather than overwrite an existing record.

The existing 6 GiB RAM and 20 GiB disk reserves, full working-image reservation,
256 MiB codec allowance and 128 MiB disk margin remain in force. Initial archival
needs enough space for the complete measured archive while the raw base still
exists. Low headroom refuses the operation; it does not lower these limits.
The command binds `lab.py`, `storage.py`, `packed.py` and `base_archive.py` hashes
in its private `archive-base-result.json` receipt.

After retirement, `--resume --packed-checkpoint` verifies the archived base and
restores the latest packed generation. An archive pointer counts as an existing
installation even when the raw path is absent. Every raw launch and raw
persistence route refuses any base pointer, including a corrupt file or dangling
symlink. Missing or corrupt archive/history evidence never creates a fresh disk
or falls back to the older raw file.

After an interruption, repeat `archive-base` with the still-current reviewed
pointer checksum. The durable journal recognizes completed archive publication
or raw retirement; unknown partial files remain for review. Once compaction
completes, retry any stopped pending packed copy with `lab.py persist-ram` before
starting another guest. No operation automatically deletes older archives.

```sh
python3 platform/win98lab/test_base_archive.py -v
python3 platform/win98lab/test_lab_base_archive.py -v
```

The 32 base-module tests and 24 integration tests use disposable synthetic files.
They cover byte-exact snapshots, interrupted publication/retirement, archived
resume and persistence, stale generations, damaged pointers, source changes,
real lock contention, process refusal and recovery after a durable packed
candidate is blocked by copyback headroom. They start no VM and use no installed
Windows disk or media.

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

After separately building `ntwddm/win98/build.py`, add `--graphics` to include
its original `NTWGPROB.EXE`. The helper also verifies that executable against
its successful build/import-audit receipt. Run it in the same writable guest
directory and collect `NTWGPROB.LOG` plus the visible five-second window;
[its acceptance contract](../../ntwddm/win98/README.md) distinguishes DIB
pixel checks, native GDI results and actual Win98 identity.

The helper snapshots the four original binaries, checks their build manifests,
builds an ISO with `xorriso`, and extracts it again to compare every filename
and byte. It verifies the inputs stayed unchanged before publishing
`build/win98-lab/ntw-native-probes.iso` and a hash receipt. The CD contains only
`NTW32.DLL`, `NTWPROBE.EXE`, `NTWRAP9X.VXD`, `NTWQUERY.EXE`, instructions and
checksums, plus the optional graphics executable. It contains no Windows
installation files or keys.

For actual process-exit collection, build and host-test the original supervisor:

```sh
python3 platform/win98lab/test_native_runner.py
python3 platform/win98lab/make_probe_media.py --runner
```

`--runner` includes graphics and writes a separate `ntw-native-probes-runner.iso`
and `probe-media-runner.json`, preserving the earlier CD. Copy all six binaries
to a fresh, exclusively owned `C:\NTWLAB` directory in installed Windows 98,
then run `NTWRUN.EXE` from an MS-DOS Prompt inside Windows. Do not run its child
probes first: the runner preserves and refuses existing probe logs and creates
its own log exclusively. It checks Windows 98 identity, uses absolute executable
paths, waits up to 120 seconds per child, records actual DWORD exit codes and
stops after any failure. A termination request gets a separate bounded wait;
an unconfirmed termination is logged as unknown. Keep the external VM watchdog.

Collect `NTWRUN.LOG`, the three child logs and the visible GDI window. The runner
does not verify executable hashes or child-log contents. Successful log text
does not replace the media/build hashes, fresh guest provenance and actual exit
results. The 5,632-byte runner imports only 13 classic KERNEL32 functions and
links no CRT or KernelEx. Its GCC, Clang and sanitizer models each pass 115,375
assertions across 537 scenarios with 504 injected faults. Its first actual
Windows 98 execution correctly recorded DLL exit 0, VxD exit 1 and an overall
failure; the complete native suite has not passed.

For the original Windows 98 `COMMAND.COM` prompt, `make_probe_media.py --batch`
adds `RUNTEST.BAT` and writes a third, separate `ntw-native-probes-runner-batch.iso`.
Copy the script with the binaries and run it once from fresh `C:\NTWLAB`.
Descending `IF ERRORLEVEL` branches record the runner's expected exit 0..3 in
`NTWEXIT.TXT`; another code is recorded as `unexpected`. `GUESTVER.TXT` also
captures the prompt's version report. The batch uses no modern CMD variable
expansion. Its media bytes are re-extracted and checked; the script itself
does not establish that the native probes passed.

`verify_native_logs.py LOG_DIRECTORY` checks the exact four log grammars,
ordered stages, matching Windows identity, child exits and GDI observations.
Supply `--runner-exit-code` only with the separately captured runner result.
A missing or nonzero runner result remains incomplete, because the runner can
fail its final log close after flushing a PASS line. The parser always reports
`native_execution_verified=false`: it checks guest-reported consistency and
still requires the independently collected execution evidence. Its 16 synthetic
tests include all 1,444 byte truncations and 1,444 high-bit mutations; they do
not constitute native logs or Windows execution.

On a disposable installed Windows 98 snapshot without KernelEx, copy the four
binaries to `C:\NTWLAB`, run both probes there, and collect their exit codes
and `NTWPROBE.LOG` / `NTWQUERY.LOG`. Building this CD is preparation only;
successful native execution requires those separate guest results.
## Disposable native QA trials

For repeated diagnostics, `run --ephemeral-qa` restores a reviewed packed
checkpoint into private RAM. It never encodes a new installation archive or
changes the current checkpoint pointer. Normal packed/raw installation runs keep
their existing writeback behavior and resource checks.

```sh
python3 platform/win98lab/lab.py run --resume --max-seconds 600 \
  --ephemeral-qa --baseline-pointer-sha256 REVIEWED_CURRENT_POINTER_SHA256
```

The hash identifies the exact `install-packed-current.json` bytes, not only the
archive. Inspect that pointer and its checkpoint before selecting it. The QA
mode retains the normal 6GiB memory and 20GiB disk reserves, full RAM working-copy
allowance, codec allowance and 128MiB disk margin. It omits the additional full
compressed-copyback allocation because no copyback occurs.

When the bounded guest stops, its RAM disk remains `stopped_awaiting_evidence`.
Collect and review logs, actual process exit codes, tested artifact/media hashes,
supervisor/source receipts and any relevant screenshots. Create a JSON object
mapping simple evidence filenames to absolute regular-file paths; at most 32
files and 16MiB total may be sealed. These commands do not interpret a probe's
success: a failed diagnostic must retain its failure evidence.

```sh
python3 platform/win98lab/lab.py qa-seal-evidence \
  --journal /ABSOLUTE/LAB/qa-trial-TOKEN.json --inputs /ABSOLUTE/evidence-inputs.json
python3 platform/win98lab/lab.py qa-discard \
  --journal /ABSOLUTE/LAB/qa-trial-TOKEN.json \
  --evidence-sha256 REVIEWED_SEALED_MANIFEST_SHA256
```

Discard requires the explicitly reviewed evidence hash, an unchanged baseline,
unchanged stopped RAM contents/identity, the common lab lock, and proof that no
owned guest or recorded PID remains. It removes only the owned disposable RAM
image and its empty private directory. The sealed evidence, journal, baseline
archive and current pointer remain. A crash during discard can be retried with
the same verified evidence hash. Unknown files and replacement directories are
retained.

Pending QA journals block all new installation/QA boots, persistent-copy recovery
and base archival, including when the main state receipt is missing. After a
supervisor crash, `qa-record-stopped --journal ...` can record a complete stopped
image before evidence collection. Partial initial restoration, missing RAM after
a host reboot, or uncertain ownership requires explicit inspection and recovery;
it is never silently declared successful or discarded.

The `trial.py` backend and `test_lab_trial.py` routing tests use synthetic files
and fake processes. Their host passes do not constitute a Windows guest pass.
