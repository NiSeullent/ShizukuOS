# Win98 Modern parallel integration work order

Current Status: The operator approved all work and clarified that Microsoft
Windows 98 IO.SYS itself must boot on UEFI with GOP. This chat now implements
early IO.SYS BIOS/GOP compatibility and tests that continue into the real Windows
boot sector. Independent ShizukuDOS output is not native Windows acceptance.

## Active native boot port ownership (2026-09-30)

- Chat `01a0f296-83bd-7970-a00e-c665ee12ae8a` explicitly reported owning the
  original IO.SYS entry ABI and direct CSMWrap bootstrap integration. This chat
  does not duplicate that loader.
- Chat `01a0f109-1a36-7ea2-843d-62ad65c68466` retains the GOP descriptor and
  persistent locator patch, native display driver and installed-driver VM trials.
- This chat owns NEW `shizukudos/csm/ios_gop/`: optional SeaVGABIOS legacy mode03
  geometry patch, isolated profile build, early MBR diagnostic/Windows VBR chain,
  source lineage and focused host/guest checks. Existing CSM builder/patches,
  display driver, IO.SYS binary and original disk remain with their owners.
- Child `win98_parallel_audit` owns `ios_gop/patches/`, geometry helper/tests and
  its source lineage. Child `repository_context` owns `ios_gop/boot_probe/`.
  Root owns `ios_gop/build.py`, `ios_gop/test_qemu.py` and integration receipts.

The isolated build freezes the current GOP patch before compilation. Only new
`build/shizukudos/csm-ios-gop-7acd*` build directories and uniquely named disposable
guest artifacts are written. Cached pinned source is read without fetching. Guest
networking is disabled. Any MBR probe installation affects a new cloned disk only;
its partition table, disk signature, original Windows VBR and IO.SYS are preserved.
Contracts passing in an authored diagnostic are recorded separately from actual
Windows IO.SYS startup and native Windows GUI acceptance.

Native integration now has an isolated build at
`build/shizukudos/csm-ios-gop-7acd-direct` combining the cooperating
`shizukudos/iosys_uefi/patches/0001-direct-iosys.patch` with the mode03 patch.
No peer source is modified. Early BIOS contract and actual Windows startup
evidence is described in `shizukudos/csm/ios_gop/VALIDATION.md`. Unique root-owned
direct-entry run names also live below `build/shizukudos/iosys-uefi-port/runs`;
these are new private clones, not modifications to peer-owned run directories.

Integration handoff: the combined direct run `run-ios-gop-7acd-direct-02`
passed all 10 IO.SYS entry/resume checks; ordinary early BIOS text/EDD/VBR
contracts passed under the same SeaVGABIOS image. The separate visually steered
run `build/shizukudos/csm/run-ios-gop-7acd-20260930T145428` reached USER.EXE
failure after the nonfatal mshbios prompt. Its `plain-text/BOOTLOG.TXT` records
DISPLAY.drv/vga.drv loading immediately before USER.EXE failure and additional
mshbios/VPD/GULIM.TTC failures; no causal relationship is established. Its
manual review binds the screenshot and receipt. Driver owners can use this
evidence while continuing their separately installed SHZGOP trial; this chat
does not overwrite their driver build or registry state.

Target State: Reduce duplicated work, give preview authors an inspectable current
evidence summary, and keep driver/guest execution with its existing owner.

## Ownership

| Owner | Scope | Write boundary |
| --- | --- | --- |
| Existing chat `01a0f109-1a36-7ea2-843d-62ad65c68466` | Active Win98 GOP driver, firmware, native VM trials, desktop/runtime fixes and distribution/preview site | Preserve its existing dirty files and guest artifacts |
| Collaboration chat `01a0f296-7acd-7900-9570-7e9ab0a5ab23` | Evidence-to-preview integration and focused verification | `tools/export_preview_status.py`, `tests/test_export_preview_status.py`, this document |
| Child `repository_context` of the collaboration chat | Implement the status exporter | `tools/export_preview_status.py` only |
| Child `win98_parallel_audit` of the collaboration chat | Independent receipt review and regression tests | `tests/test_export_preview_status.py` only |
| Peer chat `01a0f296-83bd-7970-a00e-c665ee12ae8a` | Observed implementing application preflight and reviewing preview evidence | Preserve `tools/app_preflight.py`, `tools/tests/test_app_preflight.py`, `docs/APP_PREFLIGHT.md` and `docs/PREVIEW_EVIDENCE.md` |

The exporter does not start a guest, invoke a compiler, download files, access
the network, change services, or alter global client configuration. Only its
explicit JSON destination is written. Raw guest logs and disk images stay local.
No source file owned by another chat is staged or committed by this work order.

## Latest retained evidence

These are historical run results tied to their own measured inputs. They do not
certify later dirty source changes.

- `build/gop-provenance/20260930T131556/result.json` records 85 of 85 QA programs
  passing, 26 guest checks passing, and nine input/provenance checks passing.
  Its bound `guest-result.json` identifies the independent ShizukuDOS/Kernel64
  runtime, not Microsoft Windows 98. QEMU exit 1 is the expected successful
  `isa-debug-exit` encoding of `SHZ-EXIT:0` in this specific harness.
- `build/desktop-harness-iso/20260930T132352-fr68teka/result.json` records a PASS
  for the shipped ISO, 43 common checks, and two cold boots with 28 and 27
  checks. The independently read-back 25-byte file has SHA-256
  `22d8f82bf677991bcd1e0c07ebe4c8de20f1e04b1f4e8181d348849a4237bd99`.
- Both runs identify revision `abc160b429f5498a2a5328b05af29e099964d54a`, branch
  `codex/uefi-desktop`, and dirty source fingerprint
  `4bd2479baaa8988e9d0c26d8c91fc621d95b6f801f916cda6314bff78cda2210`.
- Microsoft Windows 98 GUI, native driver loading, third-party modern apps,
  and hardware GPU acceleration require separate receipts. Independent-runtime
  QA does not establish any of these capabilities.

The new exporter chooses the newest run rather than the newest passing run.
Missing, malformed, incomplete, or contradictory evidence cannot promote a
capability. Each selected receipt is identified by its exact SHA-256; source
identity and run-specific counts remain inspectable.

## Driver review for the existing owner

Read-only review of `drivers/shizuku_gop/backend.c` found that
`FBHDA_access_begin` and `FBHDA_access_rect` mark dirty pixels without incrementing
`fb_lock_cnt`, while `FBHDA_access_end` decrements it. The upstream timer in
`build/vmdisp9x-reference/vxd_async.c` calls its draw callback whenever the count
is zero. `FBHDA_lock` in `vxd_fbhda.c` acquires a semaphore, but does not update
the count. The reference VBE backend increments the count on begin/rectangle.

This makes a timer blit during an active DIB write possible by inspection.
It is a review finding, not an observed guest failure. The driver owner should
check the access contract and cover begin/timer/end and nested access before
changing the live backend. This chat does not modify the owner's driver.

## Integration commands

Run from `/root/Win98-Modern-boot`:

```sh
python3 -B -m unittest discover -s tests -p test_export_preview_status.py
python3 -B tools/export_preview_status.py --root /root/Win98-Modern-boot --output build/parallel-preview-status.json
```

Preview authors can consume `build/parallel-preview-status.json` after reviewing
the selected receipt states and limitations. A successful export means the
summary was produced; it is not a new guest execution or a deployment result.

## Focused verification

The approved unittest command passed all 20 tests. Cases cover a newer failed,
missing, malformed or contradictory run; artifact tampering; changed source;
the exact shipped medium and two distinct cold boots; and separation of native
Windows 98, internal QA, modern apps and GPU acceleration. These are exporter
regressions using temporary authored metadata and artifacts, not new guest runs.

Current-source capability flags additionally require source hashes to match;
a retained historical PASS is reported separately from current source freshness.

The approved export command completed with exit code 0 and produced
`build/parallel-preview-status.json`. The final focused test rerun also passed
all 20 tests after verifying that a later live build-receipt replacement does
not invalidate the separately retained historical ISO result.

The generated snapshot retains the GOP 85/85 and shipped desktop two-boot
historical PASS records. The active chat subsequently changed `subsys64.c`
and rebuilt the kernel, so current-source flags remain false until the changed
source is tested. The native GUI record is independently SHA-bound. The newest
native VxD record now passes its diagnostic fixture; production driver, modern
application and GPU-acceleration flags remain false. Regenerate after the owner
finishes its next run instead of treating this snapshot as live monitoring.
