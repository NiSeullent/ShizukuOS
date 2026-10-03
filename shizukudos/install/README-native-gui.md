# Source-bound native installation from the default Setup window

SHZSETUP's ordinary interactive entry now queries the actual kernel's native
release capability. Only actual absence (`-2`) selects the existing public
component installer. A present release with missing/changed private inputs or
an unavailable backend fails before writing; it cannot fall back to legacy raw
I/O. A present private release requires interactive target review, so an
unattended answer file cannot bypass that path. The explicit `/native` CLI is
still available but is not required for the default window.

The read-only `SHZ_NATIVE_RELEASE_INFO` operation (13) retains version 1 and the
440-byte request layout. Roles 0/1 return only bytes and SHA from the compiled
manifest/SIM record. Source IDs, generations and apparent handles/target facts
are zero. It does not register approval, allocate the 64 KiB transfer buffer,
open source files or claim disks. Unknown roles and absent records refuse.
Existing real source OPEN/ADMIT, process ownership and device authority remain
required. The public kernel has no release record.

`native_gui` prepares both sealed sources before disk selection, using their
compiled role pins. The window retains those same handles through preview,
ERASE confirmation and the actual provider run. One-shot runtime handoff reuses
those snapshots rather than reopening the mutable C: namespace. Idempotent
source admission still rechecks the real kernel-held identity, role and SHA.
Candidates and confirmation use actual source checks and kernel whole-device
review. Both confirmation and the start of installation independently refresh
and compare the full whole ID/generation/index/geometry/labels tuple. Existing
exclusive claim, atomic target I/O, full byte verification and unresolved-I/O
custody remain in the provider/core. Cancellation/failure closes both sources;
failed mandatory close reports failure. A disk-copy failure is not described as
successful rollback or Windows boot.

## Required private packaging input

The private installer loader's accepted WIN64 initial archive must contain:

- `C:\SHZ\SETUP\NATIVE\MANIFEST.JSON`: exact saved, independently admitted manifest.
- `C:\SHZ\SETUP\NATIVE\ESP.SIM`: exact admitted encoded SIM bytes.

`kernel64/main.c` loads the initrd archive and `boot_storage.c` binds its actual
loader physical provenance. These two files must be real nodes in that accepted
archive. Arbitrary caller paths, later RAM copies or a separately extracted
archive do not establish source authority. Packaging is owned by the media/
producer pipeline; this change does not modify it or generate Windows images.
The **consumer private installer initrd** must remain distinct from the normal
**target WIN64.IMG** embedded in the target ESP, just as installer K64S is
separate from target K64. Otherwise embedding the input SIM in its own target
would introduce recursion. All private archives/receipts/fingerprints stay out
of public Git and public ISO output.

## Verification and limits

Actual GUI/runtime/syscall/archive/device authority bodies are exercised by
`kernel64/host/test_native_gui.py` under GCC and Clang sanitizers. Default
production absence opens no source and performs no disk I/O. Explicit host-only
modeled producer pins for malformed tiny inputs prove real preview custody,
loader-backing target exclusion, stale generation refusal, ERASE validation,
same-snapshot handoff to the existing core, cancellation and OPEN/ADMIT/CLOSE
reply-failure cleanup. The real core rejects that malformed manifest without
a target write. These controls do not certify genuine Windows inputs, successful
native installation or boot. Existing syscall/runtime/ABI controls and actual
Win64/K64 strict object compilation cover the connected interfaces. Whole real
kernel/Win64 builds, source packaging, actual approved producer/baseline and VM
installation/cold boot remain separate pending gates. GOP14 issuer/source absence
and the public five-payload development profile are unchanged.
