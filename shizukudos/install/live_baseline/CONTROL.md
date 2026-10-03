# Fresh original-Windows nonce observation control

This control observes actual historical Windows booting through its original
Microsoft DOS, on a disposable clone. It cannot approve a source or demonstrate
Windows on ShizukuDOS, default GOP, applications, license validity or SE identity.
`control.py` does not launch at import. The root coordinator must review its
exact source/request/tool/artifact pins and loan the one VM slot before execution.

A private `shizukuos.private-baseline-control.v1` request has exactly `source`,
`observer`, `observer_receipt`, `qemu`, `mcopy` pins (absolute path/bytes/SHA256),
`lock`, `output`, and integer `guest_seconds` 1..600. Source must be the independently
reviewed powered-off owned0400 original2GiB image, not a report or caller assertion.
The output must not exist; its owned parent is0700. Original paths and private
image hashes stay outside public Git. Root independently checks the build receipt
and actual executable; the request and receipt are never approval capabilities.

The helper retains real Linux original/source/tool read leases and fullSHA input
readbacks. It uses FICLONE into a fresh600 clone and mcopy only before launch. It
requires absence of all three observer names, appends BASEOBS.EXE and this owner's
random32B BASENONC.BIN, and checks every original FAT member plus MBR/VBR unchanged.
It does not modify Windows startup, registry or boot code. The actual observer
producer source/header/tool/import pins remain leased through reap/readback.

Cold QEMU is newly launched by this process, with actual Popen/pidfd/executable
inode/argv checks and a single peerPID-checked OwnedQMP reader. It uses no NIC,
ISO, RAM restore or monitor attachment. Launch requires20535312384 free bytes;
the live floor is17GiB. A private PNG is captured every10s, at most91 images of
16MiB each and64MiB aggregate. Do not expose key screens. Total preparation/guest/readback phase is
900s; guest is at most600s. Cleanup continues until the owned child is reaped.
A log pipe has its own bounded drain. No production cgroup/independent peer RPC
service or launch-cleanup-unit attestation is claimed by this component.

The coordinator examines a current private screenshot from this owned cold boot.
Only after actual Windows desktop observation, it creates `OBSERVE` in the owned
output with exactly `EXECUTE_AFTER_OBSERVED_WIN98_DESKTOP\n`. The sole reader then
sends Win+R followed by C:\BASEOBS.EXE. This explicit action selects invocation;
it is not desktop proof, and no timer issues that action. The coordinator can
create `STOP` after allowing the Windows program to finish. Missing/failed guest
report, elapsed deadline or any failed guard refuses the result.

After quit/TERM/KILL and actual reap, the clone is opened readonly and read-leased.
The helper decodes and validates actual VFAT root longname/checksum/order because
BASEOBS.JSON is not8.3. It independently reads that actual FAT file and checks
its exact schema, current32B nonce, Win9x4.10 and unique Display Enum entries.
Original/source/tool and final clone fullSHA readbacks finish before input release.
The published private result is FRESH_GUEST_OBSERVATION_ONLY, never Windows grade.
Caller-created action/report/JSON or an arbitrary successful child is insufficient
for production admission; an independently approved lineage and live custody
service/policy integration remain required.

Tests execute the actual Python parser and existing FAT reader, real mkfs/mcopy
on disposable synthetic FAT12/FAT32 images, and an owned Linux child/pidfd cleanup.
They do not execute Windows, QEMU or licensed media.
