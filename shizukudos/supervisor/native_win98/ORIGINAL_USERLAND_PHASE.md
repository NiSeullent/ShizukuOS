# Original Windows userland observation phase

This phase connects an explicitly selected, private original Windows disk to
the existing native VM guardian. It is a step towards the user's ShizukuCore
Kernel hierarchy: ShizukuDOS, Shizuku32, Shizuku64 and Windows 98 userland are
subordinate execution layers. The retained legacy boot adapter is a current
implementation dependency; it is not a permanent architectural ceiling.

The native ESP builder already accepts the original disk. Historically, the
task guardian accepted only DOS replacement profiles and their three ordered
receipts. Supplying fake replacement receipts to run an original disk would
misrepresent the phase. The new manifest schema selects a separate observation
route, while the existing replacement manifest and its parser remain strict.

## Produce a private observation profile

`tools/native_original_userland.py` takes an explicitly pinned JSON request:

```json
{
  "schema": "shizukuos.original-userland-profile-request.v1",
  "source_disk": {"path": "/private/original.img", "bytes": 2147483648, "sha256": "ACTUAL_SHA256"},
  "windows_directory": "WINDOWS",
  "boot_policy": "shz.foundation=win98",
  "producer_inputs": [
    {"path": "/actual/repository/tools/native_original_userland.py", "bytes": "ACTUAL_BYTES", "sha256": "ACTUAL_SHA256"},
    {"path": "/actual/repository/shizukudos/win98_boot/prepare_replacement.py", "bytes": "ACTUAL_BYTES", "sha256": "ACTUAL_SHA256"}
  ]
}
```

The placeholders are deliberately invalid until replaced with actual pins;
byte extents must be JSON integers. The output parent must be owned mode 0700
and the selected output leaf must be fresh and private. Use:

```text
python3 tools/native_original_userland.py --request REQUEST --request-sha256 ACTUAL_SHA256 --out FRESH_PRIVATE_OUTPUT
```

The producer holds the original disk, request and both source files under read
leases. It executes the exact held FAT-reader source, checks the active FAT
partition and original MSDOS path selection, and reads seven nonempty regular
members: IO.SYS, MSDOS.SYS, COMMAND.COM and the selected Windows directory's
WIN.COM, SYSTEM.INI, SYSTEM/VMM32.VXD and IFSHLP.SYS. It records original MBR/VBR
and member hashes, checks full input hashes again, and writes one mode-0600
`original-userland-profile.json`. It does not call the DOS constructor, modify
the source, make a disk copy or start a VM.

## Guardian connection

Use the existing native builder and `prepare_vm.py` with the exact same disk
pin and one coherent kernel/firmware/source cohort. The native task manifest
has the usual plan, repository, runtime source pins, limits and timeout. For
this phase only:

- `schema` is `shizukuos.native-original-userland-custody-manifest.v1`.
- `lineage` contains exactly the one original observation profile pin.
- `producers` contains exactly the two ordered producer pins above.

The guardian holds the actual profile and its request, checks all source/disk
crosslinks, and loads the observer and FAT reader from their held source FDs.
It then re-reads the seven member observations and both boot-sector hashes
from its own retained original disk FD and requires an exact profile match.
The shared ESP/builder/source verification, optional VGA input verification,
reconstructed QEMU recipe, independently admitted bootstrap, task limits,
pidfd/QMP ownership, deadline, actual reap and final original hash checks
continue through the existing guardian. The source ESP remains immutable;
the prepared runtime ESP is the separate mutable copy used by the trial.

This first original observation phase rejects replacement GOP cohorts and
internal live epoch grants. Optional VGA inputs keep their existing independent
builder checks, but neither those inputs nor this profile prove a default GOP
driver was installed. A later staged original-userland driver/application
cohort needs its own preserving copy and live epoch connection.

## Evidence and remaining installation work

An observation profile proves a selected byte and metadata relationship. It
does not authenticate genuine Windows licensing/version, prove Windows boot,
claim DOS replacement or demonstrate ShizukuCore services from Windows USER/GDI.
Every runtime, app, persistence and public-release assertion stays false.
The same limitation applies to synthetic FAT and guardian host tests.

The existing installer ingestion and C manifest parser still require the old
replacement phase. This change does not issue a native installer or ISO, alter
release policy, publish private Windows bytes or change m98.nginx. Follow-up
work must connect an explicit original-userland installation manifest and the
current privately approved source/build cohort, then run real boot, service,
target installation, ISO-detached reboot and installed driver checks. Full
modern applications require the native GUI frame/input bridge as well.
