# Live original-source custody primitive

`native_baseline_custody.py` implements **SOURCE_CUSTODY_ONLY**, a live
process-local custody capability. It does not verify genuine Windows, approve
private media, issue a release or implement a QMP/RPC client. Production
`native_release_policy.verify_private_source_custody` remains unchanged and
refuses until an independent private actual Windows service is connected.

The trusted owner starts in its own actual delegated systemd unit (MainPID is
itself, sole process, RuntimeMax infinity so cleanup can retain leases). It opens
an owned0400 regular non-symlink/non-hardlinked original, holds its actual Linux
RDLK and verifies full bytes. It FICLONEs into a fresh owned0700 private directory,
verifies the initial copied bytes, and internally launches its exact pinned
control executable using Popen/pidfd. No attaching PID, caller Popen, borrowed
QMP socket or second reader API exists. Child exit is observed via wait and
pidfd; the actual sole unit's descendants must be gone before source readback
and clone RDLK/final full readback. Descendants are terminated only through
pidfds confirmed in this unit. Observation/cleanup failures retain original
leases until actual unit quiescence. SIGIO/cancellation/identity/namespace/lease
handler changes refuse; normal cancellation preserves cleanup. SIGKILL or host
failure cannot be recovered by Python; these are not graceful success paths.

Only this live owner can enter a one-shot owner-random challenge callback. Its
capability checks exact process/thread/lifetime and matches an actual caller-held
original FD/pin/identity/readlease, with full SHA. Original/executable/completed
clone descriptions remain leased through callback and final readback. Capability
serialization, reuse, stale lifetime, namespace replacement, wrong nonce,
failed child and Windows-identity promotion refuse. Source/tool pins are byte
custody, never independent source approval. Executable descendants/dynamic
libraries are not claimed as a complete SDK/tool closure. File cloning requires
actual FICLONE filesystem support; no sparse copy/hardlink fallback exists.

Use the owner as a context manager and keep its process alive through all build
callbacks. Its SIGIO handler is checked; don't nest another lease union in the
same owner process. The production ingester lives in a different process and
uses its own handler. This trusted producer primitive is not a security sandbox
against arbitrary Python mutation or a same-privilege attacker. Public callers
must not construct approvals or select private service identity using request
JSON. The private independently controlled service, its source/tool approval
and original install/media lineage are separate trust inputs.

## Concrete positive Windows route to implement

1. An independently approved private control owner supplies original installation
   media/install lineage outside Git; baseline fingerprints alone do not prove
   Windows. It holds the original0400 source and creates a fresh clone. Existing
   historical JSON/screenshots are records, not live capabilities.
2. The owner chooses a fresh nonce before launch and stages an independently
   source/tool-built readonly Win98 observer into this owned clone, after
   verifying the report is absent. The observer checks GetVersionEx Win9x4.10,
   reads only Display Enum Class/Driver, and creates a **fresh** nonce-bound
   report with CREATE_NEW. Existing GPENUM has version/Enum checks but lacks
   this nonce contract; it cannot yet meet this route by itself.
3. That same private owner launches the exact approved QEMU/firmware recipe,
   owns actual Popen/pidfd and the sole QMP reader, observes actual cold Windows
   observer execution and completion, then stops/reaps its actual unit. It is
   the only clone writer. A generic exit0 or caller-provided report cannot
   substitute for these live source/tool/execution bindings. No current VM
   attachment is allowed.
4. After actual exit/quiescence, read the held completed clone through the actual
   source-pinned FAT reader; require fresh report nonce, readonly observer
   identity/version/Enum output and private approved original lineage together.
   Retain original and clone RDLKs/full readbacks through build admission.
5. The private live service gives the build controller a pidfd/peer-PID/nonce
   binding from the independently owned launch, never a request-selected socket
   identity. The verifier sends a fresh challenge over its sole private RPC,
   matches request source/profile to actual held descriptors, and installs
   owner-exit/lease/nonce guards in `held.guards` for the full compiler lifetime.
   Owner close/exit or repeat challenge revokes admission. Only this separate
   versioned verified route may return genuine-baseline evidence to policy;
   **SOURCE_CUSTODY_ONLY must still be rejected**. It proves historical control
   Windows only, not Windows running on ShizukuDOS, default GOP or x64 apps.

No Windows verifier or arbitrary callback issuer is supplied here. This is a
working FD/clone/owned-process foundation for that route, not a successful stub.
Product-key personalization remains a distinct final installation requirement;
private keys, media, reports and baseline hashes never belong in public Git.

## Host controls

Run `tests/test_native_baseline_custody.py` in its own Delegate=yes systemd unit,
with SHZ_BASELINE_TEST_UNIT set to that unit's full name. Tests execute actual
Linux RDLK/FICLONE/pidfd, /usr/bin/true/false, short-lived Python and sleep children
inside only this independent unit. They verify actual blocked-writer SIGIO,
source preservation, detached-child cleanup, timeouts, cancellation, forked
caller refusal, readonly modes, symlink/hardlink/namespace drift, fake caller
pins, fresh clone/nonce, nonserializable lifetime, and failed Windows promotion.
These tiny host fixtures are not Windows media or actual Windows/QMP evidence.
