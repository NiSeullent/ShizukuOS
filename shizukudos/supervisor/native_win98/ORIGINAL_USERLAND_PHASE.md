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

The original observation phase always rejects replacement GOP cohorts, the
DOS3 GOP staging producers and DOS3 live-epoch contexts.

## Optional original-observation device epoch (StdVGA + persistence)

Original USER/GDI/Explorer needs the retained StdVGA device and, for guest
writeback, the persistence device. These use the same `native_epoch_host`
Attempt/COM2/fw_cfg HostGrant as the DOS3 cohort, through a distinct intent:

```json
{
  "schema": "shizukuos.native-original-userland-epoch-intent.v1",
  "repo": "/actual/clone", "sources": {"...": "runtime pins incl. native_epoch_host.py, no gop_nonce_staging/prepare_replacement"},
  "limits": {"memory.high": 0, "memory.max": 0, "pids.max": 0, "cpu.max": "N M"}, "timeout": 600,
  "lineage": ["original-userland-profile.json pin"], "producers": ["native_original_userland.py pin", "prepare_replacement.py pin"],
  "native_inputs": {"DISK.IMG": "the profile source_disk pin", "SEABIOS.BIN": {}, "WIN98CFG.BIN": {}, "KERNEL32.BIN": {}, "KERNEL64.BIN": {}, "WIN64.IMG": {}},
  "optional_native_inputs": {"VGACFG.BIN": {}, "VGAROM.BIN": {}, "W98PERS.BIN": "optional"},
  "optional_native_provenance": {"vga-build-receipt": {}},
  "raw_bars": {"1": ["six VGA BAR DWORDs"], "2": ["six persistence BAR DWORDs, only with W98PERS.BIN"]},
  "firmware": {"firmware_code": {}, "firmware_vars": {}, "qemu": {}},
  "private_root": "/owned/0700/fresh-root", "assembly_scratch": null
}
```

Inside the sole guardian (`task_custody.prepare_original_intent`) shape is
checked before any lease. Every input is then full-SHA admitted into the one
lease union; `DISK.IMG` must equal the observed profile's `source_disk`. The
held epoch source mints one `Attempt` from the leased config/ROM/persistence
descriptors and literal BAR words, reserves its single pre-exec clone, and the
held native builder copies the original disk into a fresh ESP. The original
source is only read. The held `prepare_vm` produces the plan with the
`policy_fd`/`epoch.sock` binding and the guardian creates the private
listener. The generated manifest uses the original schema plus
`original_device_epoch` (live policy/nonce/deadline digests, selected roles and
literal false grants: no DOS3 profile, GOP registration, release, genuine
Windows, ISO, app or VM claim).

`admit_manifest` then requires: original schema, no `gop_cohort`, the field
present exactly when the in-process context exists, a context tagged as the
original phase, a real unbound unconsumed staged `Attempt` of the held module
class, current live sources/leases/sealed policy, a declared policy equal to the
live one, Attempt sources equal to the declared VGA/persistence pins, and the
identical recipe binding. The full observer re-derivation still runs. A
saved manifest without the same live Attempt is refused, and DOS3 manifests
cannot carry this field. The DOS3 GOP intent and its strict parser are
unchanged. The usual `--guardian-epoch` controller, HostGrant exchange, sole
QMP monitor and exact reap/close follow.

Controls: `tests/test_original_device_epoch.py` uses a real Attempt over real
leased descriptors (no VM). Passing it is admission evidence only.

## Evidence and remaining installation work

An observation profile proves a selected byte and metadata relationship. It
does not authenticate genuine Windows licensing/version, prove Windows boot,
claim DOS replacement or demonstrate ShizukuCore services from Windows USER/GDI.
Every runtime, app, persistence and public-release assertion stays false.
The same limitation applies to synthetic FAT and guardian host tests.

The explicit original-userland installer route now has source-integrated SZOU
v1/v2 host ingestion, the append-only SZLN long-name extension, guest manifest
parsing and staged role selection. The existing strict replacement profile is
retained. This wiring does not issue a qualified installer or ISO, authenticate
source authority, grant target-write authority, or establish installation and
reboot success. A current owned source/build cohort still needs real boot,
service, target-write/readback, installer-detached cold boot and installed
driver checks. Native application functions also need actual frame/input and
process completion evidence. Private Windows bytes and runtime notes remain
private. This is an optional legacy-profile procedure under the current
ShizukuOS architecture, not its root-platform definition.
