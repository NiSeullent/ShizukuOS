# Windows 98 -> Shizuku64 connection: root VM run sequence

Scope: handoff for the root-owned native VM run of the real path
original Win98 USER/GDI/Explorer -> `NTW64RUN.EXE`/`NTW64GUI.EXE` -> `NTW32.DLL` -> `NTWRAP9X.VXD`
(DIOC) -> Supervisor channel2 -> Kernel64 PE32+ process. This document specifies source wiring and a run procedure; it does not assert a
completed VM run or guest result. The host runner is
`tools/run_w98w64_connection.py`; VM execution belongs to the separate custody guardian.

This is an optional legacy compatibility-profile procedure. Its Windows 98
USER/GDI/Explorer path does not define the ShizukuOS root platform or the native
shell acceptance. The current system definition is
[Absolute Architecture Definition](SHIZUKUOS_ARCHITECTURE_CONTRACT.md).
The source contracts below are integrated; this publication edit adds no VM,
installation, GUI or application execution result.

## Inputs the VM owner must supply

| Input | Notes |
| --- | --- |
| Privately owned baseline disk | Supply `<private-baseline.img>` and `<baseline-sha256>` locally under the operator's read-only lease; preserve the original and stage an owned clone. Its local identifier, path, checksum, bytes and private coordination notes are not public inputs. |
| `NTWRAP9X.VXD`, `NTW32.DLL`, `NTW64RUN.EXE`, `NTW64GUI.EXE` | Matching build from the build lane (same source commit), each pinned by sha256. |
| Kernel64 runtime containing `\SHZ\TESTS\T_HELLO.EXE` (and the GUI fixture for the GUI case) | `shizukudos/win64/build.py` places T_HELLO in the Kernel64 initrd; it is NOT copied into the Win98 disk. |
| Supervisor ESP with native Win98 flag | Produced by the ACTIVE `shizukudos/supervisor/native_win98/build.py` (needs BOTH supervised KERNEL32.BIN and KERNEL64.BIN, plus disk/rom/config pins, optional WIN64.IMG). `tools/build_win98_supervisor_candidate.py` is the historical frozen-preimage builder and is not used. `loader_flags` is exactly `1`; `run_vm.py` rejects anything else. |
| Guest write-back (`W98PERS.BIN` 192 B, plus `VGACFG.BIN` 136 B + `VGAROM.BIN` 64 KiB + `vga-build-receipt`) | build.py accepts them (each with `-sha256`; VGA trio all-or-none) but they cannot be hand-made. The original route exists: `task_custody.py` epoch intent schema `shizukuos.native-original-userland-epoch-intent.v1` (`ORIGINAL_EPOCH_INTENT_SCHEMA`, `prepare_original_intent`, `admit_manifest`, `main`). It REQUIRES the StdVGA pair + `vga-build-receipt` (VGAROM/receipt from `tools/build_stdvga_rom.py`); `W98PERS.BIN` is optional only inside that route and never without the StdVGA pair. The `native_epoch_host` Attempt is minted in-process by the guardian and cannot be supplied by file; `raw_bars` come from the owned native-epoch encoder / paused firmware probe described in `shizukudos/supervisor/native_win98/NATIVE_EPOCH_HOST.md` and `ORIGINAL_USERLAND_PHASE.md` -- no values are invented here. Console-first (original custody manifest, no epoch) has NO write-back, so `verify` returns `INCOMPLETE_NO_GUEST_EVIDENCE` by design. |

## Sequence

Root holds the read lease on the private baseline externally for the whole sequence; `stage` takes no lease (plain pinned reads).

1. Stage the private guest disk (host only, ~2 GiB copy, `--i-own-this-vm` mandatory):
   ```
   python3 tools/run_w98w64_connection.py stage --i-own-this-vm \
     --baseline-disk <abs> --baseline-sha256 <h> \
     --vxd <abs> --vxd-sha256 <h> --ntw32 <abs> --ntw32-sha256 <h> \
     --ntw64run <abs> --ntw64run-sha256 <h> --ntw64gui <abs> --ntw64gui-sha256 <h> \
     --out <fresh abs dir under build/> [--gui-image \SHZ\TESTS\T_GUI_NATIVE.EXE]
   ```
   It injects into `C:\VXDLAB` (fresh paths only), writes `W64RUN.BAT`, adds `run=C:\VXDLAB\W64RUN.BAT` to `[windows]` in `WIN.INI`
   (refuses if a `run=` value exists), reads back every file by sha256, checks MBR/boot sector unchanged, and writes `stage-receipt.json`
   (`STAGED_NOT_RUN`, `injected_disk_sha256`).
2. Build matching supervised kernels from the selected source revision; archived receipts do not grant authority for a fresh attempt:
   `python3 shizukudos/kbuild.py --out <fresh>/kbuild` (KERNEL32.BIN + supervisor KERNEL64.BIN, not KERNEL64S.BIN) and
   `python3 shizukudos/win64/build.py` (WIN64.IMG with `\SHZ\TESTS\T_HELLO.EXE`, at most 32 MiB). Record each sha256 yourself.
   `python3 shizukudos/supervisor/native_win98/build.py --make-config <fresh>/WIN98CFG.BIN` (16 bytes).
3. Original observer over the INJECTED disk (not the baseline): write a request JSON (schema `shizukuos.original-userland-profile-request.v1`,
   `source_disk` = `<stage>/win98-w64-injected.img`, `windows_directory` `WINDOWS`, `boot_policy` `shz.foundation=win98`, `producer_inputs` =
   `tools/native_original_userland.py` + `shizukudos/win98_boot/prepare_replacement.py` with exact bytes/sha256), then
   `python3 tools/native_original_userland.py --request <req.json> --request-sha256 <h> --out <0700 fresh parent>/profile`
   (-> `original-userland-profile.json`). The guardian requires the manifest/intent `DISK.IMG` to equal the profile `source_disk`, so the
   injected disk must NOT change after the profile is made; any re-stage means re-observe.
4. Choose ONE manifest route (`task_custody.py` `main`; never mix):
   - **3a console-first, no write-back**: `shizukuos.native-original-userland-custody-manifest.v1` -- the original custody manifest with NO
     `original_device_epoch` and NO `gop_cohort` (fields `schema, plan, repo, sources, lineage=[1 profile pin], producers=[2 pins], limits, timeout`).
     Root hand-runs build.py and prepare_vm.py:
     ```
     python3 shizukudos/supervisor/native_win98/build.py --disk <injected> --disk-sha256 <receipt injected_disk_sha256> \
       --rom <seabios 256 KiB> --rom-sha256 R --config <WIN98CFG.BIN> --config-sha256 C \
       --kernel32 <KERNEL32.BIN> --kernel32-sha256 K32 --kernel64 <KERNEL64.BIN> --kernel64-sha256 K64 \
       --win64-img <WIN64.IMG> --win64-img-sha256 W --validate-only      # then again with --out <fresh>/native
     ```
     Receipt `<native>/result.json`: `status=PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN`, `private`, `members{SHZDOS/*}`, `artifact{path,bytes,sha256}`.
     Then `prepare_vm.py --esp <native>/esp-win98.img --esp-sha256 .. --build-receipt <native>/result.json --build-receipt-sha256 .. --firmware-code/-vars (+sha256, 4 MiB total) --qemu /usr/libexec/qemu-kvm --qemu-sha256 .. --out <fresh short>/vm`.
   - **3b write-back**: `shizukuos.native-original-userland-epoch-intent.v1` (epoch intent, StdVGA pair + `vga-build-receipt` + `raw_bars`, optional `W98PERS.BIN`).
     The guardian runs build.py and prepare_vm.py itself under its `private_root`: SKIP the hand-run build/prepare above. `verify` then needs
     `<private_root>/native/result.json` as `--build-receipt` and `<private_root>/vm` as `--run-dir`.
5. Run (root only, VM custody): `python3 shizukudos/supervisor/native_win98/task_custody.py --manifest <manifest.json> --manifest-sha256 <h> --guardian-unit <unit>`.
   The guardian spawns `run_vm.py`; never run `run_vm.py` directly (`--guardian-epoch` is internal). Produces `<vm>/native-result.json`,
   `custody-result.json`, `serial.log`, `native-NNN.png`, `native-NNN-info.json`.
6. Parse evidence (host only):
   `python3 tools/run_w98w64_connection.py verify --i-own-this-vm --stage-receipt <r> --build-receipt <result.json> --run-dir <vm> --profile connected --out <fresh>`
   `verify` REQUIRES `<vm>/custody-result.json` with `custody_admitted`, `VM_executed` and `owned_child_reaped` true, so a run outside the guardian cannot pass.
   Also checked: build receipt PASS and `members[SHZDOS/DISK.IMG].sha256` equal to the staged disk, K32/K64/WIN64 members, `vm-plan.json` ESP pin, and
   `native-result.json` (`VM_executed`, `collection_verified`, `receipt_persisted`, `lease_integrity_verified`, `qemu_exit_code==0`, `original_disk_unchanged`, `last_info`).
   It extracts `SHZDOS/DISK.IMG` from the run's `esp.img`, requires that it differs from the staged disk, and reads the guest-written
   `RESULT.LOG`, `VER.LOG`, `Q.LOG`, `HELLO.LOG` at the recorded partition offset.

### Console-first (3a) outcome

Without W98PERS the guest ATA writes stay in guest RAM, so `mcopy -i <vm>/esp.img ::/SHZDOS/DISK.IMG` after the guardian reaps the child (what `verify`
does) returns the unchanged disk and `verify` correctly returns `INCOMPLETE_NO_GUEST_EVIDENCE`. The only evidence from this route is the real
`serial.log`, `native-NNN.png` and `native-NNN-info.json` captured by `owned_capture.py` through `run_vm.py` (`collection_verified`), reviewed by root as
boot-progress evidence, not as a connected PASS. A PASS (`/q` + T_HELLO + `RC_HELLO=7` from the guest files) requires route 3b.

## What the guest produces (all by real programs)

`W64RUN.BAT` runs under the real Win98 `command.com` started by Explorer through `run=`:
`ver>VER.LOG`; `echo SHELLUP>>RESULT.LOG`; `NTW64RUN /q>Q.LOG`; `NTW64RUN \SHZ\TESTS\T_HELLO.EXE first>HELLO.LOG`;
after each a descending `if errorlevel N if not errorlevel N+1` ladder appends `RC_<stage>=<exit>`.
The exit code is measured, not asserted. Optional last step `NTW64GUI <image>` records `RC_GUI`.

## Pass/fail parsing (per profile)

Required for `connected` (all or FAIL; absent logs give INCOMPLETE):
- Supervisor receipt: `loader_flags==1`, `boot_path==1`, 128 MiB / 2 GiB, stage not `0xdead`, `WIN98` domain
  `exits>0` and not failed, `KERNEL64` domain present and not failed, original disk member unchanged, QEMU child reaped.
- `ver` banner contains `Windows 98`; `SHELLUP` once (the shell executed the `run=` entry); `DONE` once.
- `/q`: `RC_Q=0` and `WIN64 subsystem: ABI x.y, subsystem x.y, capabilities 0x..` plus `channel N generation M`.
- `HELLO.LOG` contains `hello from Win64 PE32+: argc=2 argv1=first` and `RC_HELLO=7`.

Negative profiles reuse the same batch and differ only in the expected exit (from `ntwin32/win64/ntw64run.c`;
`stderr` text cannot be captured by `command.com`, so the distinct exit code is the evidence):

| Profile | Expected `RC_HELLO` | VM-side condition root must provide |
| --- | --- | --- |
| `connected` | 7 | normal Kernel64 channel2 |
| `no-bridge` | 254 | needs a K64 variant that does NOT announce a channel (build.py requires a K64 member, so the ESP still carries `KERNEL64.BIN`; verify expects no KERNEL64 domain). Unreachable until Core supplies it. |
| `revoked-channel` | 252 | Supervisor retires the channel generation / handle (Win32 error 6) before the run |
| `foreign-owner` | 253 | a second process/handle that does not own the channel (error 5/288/1314) |

The 252/253 triggers need a Core/VxD fixture that is not in this lane; until one exists those profiles cannot be run,
and `combine` refuses to report success unless all four verdicts exist with four distinct exit codes.

## GUI case (interactive PE64 in an original 98 window)

Stage with `--gui-image <Kernel64 path>`. `NTW64GUI.EXE <image>` presents the process in a real Win98 HWND. Root drives
owned QMP `send-key`/pointer events and closes the window; the fixture must exit with a code reachable only after the
injected input. `verify --gui-expected-exit N` then requires `RC_GUI=N` and at least two distinct QMP screenshots.
This cannot prove visual correctness or that input reached the HWND beyond the fixture's own exit code; keep the
screenshots for review. Source now includes a hash-pinned `input_recipe` route:
`task_custody.py` leases and validates it, then forwards paired `--input-recipe`
and `--input-recipe-sha256` options to `run_vm.py` under the owned guardian.
The optional `owned_input` route also binds the original device epoch and
`W98INPT.BIN` producer. Input must use that owned QMP/native-provider path.
A QMP acknowledgement proves command acceptance, not guest delivery; actual
fixture behavior and reviewed frames remain required. This document reports
no native input or GUI execution pass.

## Limits (honest)

- The shared GUI ABI and source transport exist in `shizukudos/abi/shz_w64_gui.h`,
  `ntwin32/win64/ntw64_gui.h`, `ntwrapper/vxd/w64_owner.h` and
  `shizukudos/kernel64/w64_gui_service.c`. Live attestation, per-handle owner,
  generation and frame/input/exit contracts still need current-artifact native
  runtime evidence. Source integration is not a connection or application pass.
- "Explorer up" is established as: the shell executed `run=` (batch reached) plus a screenshot; no pixel-level Explorer check.
- Reproducibility of `command.com` `errorlevel` for exit codes >255 or NTSTATUS crashes: they land in `255`/`OTHER`.
- Persistence (`W98PERS.BIN`) is a prerequisite owned by the native custody producer (route 3b), not by this runner.
